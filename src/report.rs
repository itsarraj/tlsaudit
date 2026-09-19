//! Severity classification and report rendering.
//!
//! Everything in here is pure — no sockets, no clock — so the parts most
//! likely to be quietly wrong (which findings count as "critical", how the
//! exit code is derived, how a line is laid out) are unit-testable without
//! touching the network.

use std::fmt;

/// How bad a single finding is.
///
/// Ordered deliberately: `Ok < Warn < Critical`, so the worst finding in a
/// report is just `max()` over all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Nothing wrong. Also used for "the server correctly refused this".
    Ok,
    /// Deprecated but still widely deployed — worth fixing, not an emergency.
    Warn,
    /// Broken in a way with a public, named attack against it.
    Critical,
}

impl Severity {
    /// The four-character marker printed at the start of every finding line.
    /// Fixed width on purpose so the labels after it stay in one column.
    pub fn marker(self) -> &'static str {
        match self {
            Severity::Ok => " ok ",
            Severity::Warn => "WARN",
            Severity::Critical => "CRIT",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Ok => "ok",
            Severity::Warn => "warning",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// One audited property of the endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Short left-column name, e.g. `TLS 1.0` or `hostname`.
    pub label: String,
    /// The observed result, in the tool's own words.
    pub detail: String,
}

impl Finding {
    pub fn new(severity: Severity, label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity,
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// A named group of findings (`protocols`, `ciphers`, `certificate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: &'static str,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub target: String,
    pub sections: Vec<Section>,
}

/// What severity should make the process exit non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Warn,
    Critical,
    Never,
}

impl Report {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            sections: Vec::new(),
        }
    }

    pub fn section(&mut self, name: &'static str, findings: Vec<Finding>) {
        self.sections.push(Section { name, findings });
    }

    /// The worst severity anywhere in the report. `Ok` for an empty report —
    /// "we found nothing bad" is the only honest reading of no findings.
    pub fn worst(&self) -> Severity {
        self.sections
            .iter()
            .flat_map(|s| s.findings.iter())
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.sections
            .iter()
            .flat_map(|s| s.findings.iter())
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Exit code: 0 clean, 1 at/over the `--fail-on` threshold. Kept pure so
    /// the cron/CI contract is pinned by a test rather than by reading `main`.
    pub fn exit_code(&self, fail_on: FailOn) -> i32 {
        let worst = self.worst();
        let tripped = match fail_on {
            FailOn::Never => false,
            FailOn::Warn => worst >= Severity::Warn,
            FailOn::Critical => worst >= Severity::Critical,
        };
        i32::from(tripped)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("tlsaudit  {}\n", self.target));

        // One label column width for the whole report, not per-section, so
        // the details line up vertically across section boundaries too.
        let width = self
            .sections
            .iter()
            .flat_map(|s| s.findings.iter())
            .map(|f| f.label.chars().count())
            .max()
            .unwrap_or(0);

        for section in &self.sections {
            out.push_str(&format!("\n{}\n", section.name));
            for f in &section.findings {
                out.push_str(&format!(
                    "  [{}] {:width$}  {}\n",
                    f.severity.marker(),
                    f.label,
                    f.detail,
                    width = width
                ));
            }
        }

        let criticals = self.count(Severity::Critical);
        let warnings = self.count(Severity::Warn);
        out.push_str(&format!(
            "\nRESULT: {} critical, {} warning(s) — worst: {}\n",
            criticals,
            warnings,
            self.worst()
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report::new("example.com:443");
        r.section(
            "protocols",
            vec![
                Finding::new(Severity::Ok, "TLS 1.3", "accepted"),
                Finding::new(
                    Severity::Warn,
                    "TLS 1.0",
                    "accepted — deprecated by RFC 8996",
                ),
            ],
        );
        r.section(
            "ciphers",
            vec![Finding::new(Severity::Critical, "RC4", "accepted")],
        );
        r
    }

    #[test]
    fn severity_orders_ok_below_warn_below_critical() {
        assert!(Severity::Ok < Severity::Warn);
        assert!(Severity::Warn < Severity::Critical);
    }

    #[test]
    fn worst_is_the_max_severity_present() {
        assert_eq!(sample().worst(), Severity::Critical);

        let mut clean = Report::new("example.com:443");
        clean.section(
            "protocols",
            vec![Finding::new(Severity::Ok, "TLS 1.3", "accepted")],
        );
        assert_eq!(clean.worst(), Severity::Ok);
    }

    #[test]
    fn an_empty_report_is_ok_not_a_failure() {
        // No findings must not be reported as a problem — an audit that
        // somehow produced nothing should not silently fail a CI job.
        assert_eq!(Report::new("x:443").worst(), Severity::Ok);
        assert_eq!(Report::new("x:443").exit_code(FailOn::Warn), 0);
    }

    #[test]
    fn counts_each_severity_across_all_sections() {
        let r = sample();
        assert_eq!(r.count(Severity::Ok), 1);
        assert_eq!(r.count(Severity::Warn), 1);
        assert_eq!(r.count(Severity::Critical), 1);
    }

    #[test]
    fn exit_code_respects_the_fail_on_threshold() {
        let mut warn_only = Report::new("example.com:443");
        warn_only.section(
            "protocols",
            vec![Finding::new(Severity::Warn, "TLS 1.0", "accepted")],
        );

        // A warning trips --fail-on=warn but deliberately not --fail-on=critical.
        assert_eq!(warn_only.exit_code(FailOn::Warn), 1);
        assert_eq!(warn_only.exit_code(FailOn::Critical), 0);
        assert_eq!(warn_only.exit_code(FailOn::Never), 0);

        assert_eq!(sample().exit_code(FailOn::Critical), 1);
        assert_eq!(sample().exit_code(FailOn::Never), 0);
    }

    #[test]
    fn render_pads_labels_to_one_shared_column_width() {
        let rendered = sample().render();
        // "TLS 1.3" is padded out to the width of the longest label in the
        // whole report, so details start at the same column in every section.
        assert!(
            rendered.contains("[ ok ] TLS 1.3  accepted"),
            "got:\n{rendered}"
        );
        assert!(rendered.contains("[WARN] TLS 1.0  accepted — deprecated by RFC 8996"));
        assert!(
            rendered.contains("[CRIT] RC4      accepted"),
            "got:\n{rendered}"
        );
    }

    #[test]
    fn render_includes_target_section_names_and_a_summary_line() {
        let rendered = sample().render();
        assert!(rendered.starts_with("tlsaudit  example.com:443\n"));
        assert!(rendered.contains("\nprotocols\n"));
        assert!(rendered.contains("\nciphers\n"));
        assert!(rendered.contains("RESULT: 1 critical, 1 warning(s) — worst: critical"));
    }

    #[test]
    fn markers_are_all_the_same_width() {
        // If these ever drift the whole report loses its alignment.
        assert_eq!(Severity::Ok.marker().len(), 4);
        assert_eq!(Severity::Warn.marker().len(), 4);
        assert_eq!(Severity::Critical.marker().len(), 4);
    }
}
