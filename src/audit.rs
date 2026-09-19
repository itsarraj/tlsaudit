//! Orchestration: run every probe against one endpoint and turn the results
//! into a `Report`.

use std::time::{Duration, SystemTime};

use crate::cert::{self, HostMatch, LeafCert};
use crate::ciphers::{self, Family};
use crate::modern::{self, TrustOutcome};
use crate::probe::{self, Outcome};
use crate::proto::{TlsVersion, ALL};
use crate::report::{Finding, Report, Severity};

pub struct Options {
    pub timeout: Duration,
    /// Skip the weak-cipher probes. They are six extra connections and some
    /// WAFs treat "offered only NULL ciphers" as an attack, so it is worth
    /// being able to turn off.
    pub skip_ciphers: bool,
    /// Warn when the certificate expires within this many days.
    pub warn_days: i64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            skip_ciphers: false,
            warn_days: 30,
        }
    }
}

/// Audits one endpoint. Every individual probe failure becomes a finding
/// rather than aborting the run — a server that refuses SSLv3 by resetting
/// the connection should still get its certificate checked.
pub fn audit(host: &str, port: u16, opts: &Options) -> Report {
    let mut report = Report::new(format!("{host}:{port}"));

    let (protocol_findings, accepted, fallback_chain) = audit_protocols(host, port, opts);
    report.section("protocols", protocol_findings);

    if !opts.skip_ciphers {
        report.section("ciphers", audit_ciphers(host, port, &accepted, opts));
    }

    report.section(
        "certificate",
        audit_certificate(host, port, &accepted, fallback_chain, opts),
    );

    report
}

fn audit_protocols(
    host: &str,
    port: u16,
    opts: &Options,
) -> (Vec<Finding>, Vec<TlsVersion>, Option<Vec<Vec<u8>>>) {
    let mut findings = Vec::new();
    let mut accepted = Vec::new();
    // A chain harvested from a cleartext handshake, kept as a fallback for
    // servers rustls will not speak to at all (TLS 1.0-only, say).
    let mut fallback_chain: Option<Vec<Vec<u8>>> = None;

    for version in ALL.iter().copied() {
        let result = if version.needs_raw_probe() {
            raw_version_finding(host, port, version, opts, &mut fallback_chain)
        } else {
            modern_version_finding(host, port, version, opts)
        };
        if result.1 {
            accepted.push(version);
        }
        findings.push(result.0);
    }

    // Report the ordering oldest-first, matching how people read a protocol
    // support matrix.
    (findings, accepted, fallback_chain)
}

fn raw_version_finding(
    host: &str,
    port: u16,
    version: TlsVersion,
    opts: &Options,
    fallback_chain: &mut Option<Vec<Vec<u8>>>,
) -> (Finding, bool) {
    match probe::probe_version(host, port, version, opts.timeout) {
        Ok(outcome) => {
            if outcome.accepted_version(version).is_some() {
                if let Outcome::Accepted {
                    cipher_suite,
                    chain,
                    ..
                } = &outcome
                {
                    if fallback_chain.is_none() && !chain.is_empty() {
                        *fallback_chain = Some(chain.clone());
                    }
                    let reason = version
                        .reason()
                        .map(|r| format!(" — {r}"))
                        .unwrap_or_default();
                    return (
                        Finding::new(
                            version.severity_if_accepted(),
                            version.label(),
                            format!("accepted ({}){reason}", ciphers::suite_name(*cipher_suite)),
                        ),
                        true,
                    );
                }
            }
            let detail = match outcome {
                Outcome::Rejected { alert } => {
                    format!("refused (alert {alert}: {})", probe::alert_name(alert))
                }
                Outcome::Accepted { version: got, .. } => match TlsVersion::from_wire(got) {
                    Some(v) => format!("not offered (server answered with {})", v.label()),
                    None => format!("not offered (server answered with 0x{got:04x})"),
                },
                Outcome::NoAnswer(why) => format!("not offered ({why})"),
            };
            (Finding::new(Severity::Ok, version.label(), detail), false)
        }
        Err(e) => (
            // A probe that could not be run is not evidence of anything, and
            // must not be quietly rendered as a pass.
            Finding::new(
                Severity::Warn,
                version.label(),
                format!("not checked — {e:#}"),
            ),
            false,
        ),
    }
}

fn modern_version_finding(
    host: &str,
    port: u16,
    version: TlsVersion,
    opts: &Options,
) -> (Finding, bool) {
    let rustls_version = match version {
        TlsVersion::Tls12 => &rustls::version::TLS12,
        TlsVersion::Tls13 => &rustls::version::TLS13,
        _ => unreachable!("only 1.2 and 1.3 go through rustls"),
    };
    match modern::probe_version(host, port, rustls_version, opts.timeout) {
        Ok(neg) => (
            Finding::new(
                version.severity_if_accepted(),
                version.label(),
                format!("accepted ({})", neg.cipher_suite),
            ),
            true,
        ),
        // A TLS-level rejection is real evidence the version is off. A
        // connection-level failure is not evidence of anything, and must not
        // be dressed up as a passing "not offered".
        Err(modern::HandshakeError::Tls(e)) => (
            Finding::new(Severity::Ok, version.label(), format!("not offered ({e})")),
            false,
        ),
        Err(modern::HandshakeError::Other(msg)) => (
            Finding::new(
                Severity::Warn,
                version.label(),
                format!("not checked — {msg}"),
            ),
            false,
        ),
    }
}

/// Picks the versions worth trying a weak-cipher probe against: the weak
/// suites only exist below TLS 1.3, and there is no point offering them at a
/// version the server has already refused.
pub fn cipher_probe_versions(accepted: &[TlsVersion]) -> Vec<TlsVersion> {
    let mut versions: Vec<TlsVersion> = accepted
        .iter()
        .copied()
        .filter(|v| *v <= TlsVersion::Tls12 && *v != TlsVersion::Ssl30)
        .collect();
    // Highest first: a server that still has RC4 usually has it on its
    // oldest listener, but trying the newest accepted version first keeps
    // the common case to a single connection.
    versions.sort_by(|a, b| b.cmp(a));
    versions
}

fn audit_ciphers(host: &str, port: u16, accepted: &[TlsVersion], opts: &Options) -> Vec<Finding> {
    let versions = cipher_probe_versions(accepted);
    if versions.is_empty() {
        // Deliberately neutral wording: this branch covers both "the server
        // is TLS 1.3-only" and "nothing was reachable at all", and claiming
        // the former when it was really the latter would be a lie.
        return vec![Finding::new(
            Severity::Ok,
            "weak suites",
            "not probed — no TLS 1.0-1.2 listener was reached, and TLS 1.3 has no weak suites to offer",
        )];
    }

    let mut findings = Vec::new();
    for family in ciphers::FAMILIES.iter().copied() {
        findings.push(probe_family(host, port, family, &versions, opts));
    }
    findings
}

fn probe_family(
    host: &str,
    port: u16,
    family: Family,
    versions: &[TlsVersion],
    opts: &Options,
) -> Finding {
    let mut refusals = Vec::new();
    for version in versions {
        match probe::probe(host, port, *version, family.suites(), opts.timeout) {
            Ok(Outcome::Accepted { cipher_suite, .. }) => {
                // Trust the suite the server actually named, not the fact
                // that it answered: a broken server that picks something
                // outside the offered list must not be reported as weak.
                if ciphers::family_of(cipher_suite) == Some(family) {
                    return Finding::new(
                        family.severity_if_accepted(),
                        family.label(),
                        format!(
                            "ACCEPTED at {} ({}) — {}",
                            version.label(),
                            ciphers::suite_name(cipher_suite),
                            family.reason()
                        ),
                    );
                }
                refusals.push(format!(
                    "{}: server picked an unoffered suite {}",
                    version.label(),
                    ciphers::suite_name(cipher_suite)
                ));
            }
            Ok(Outcome::Rejected { alert }) => {
                refusals.push(format!("{}: {}", version.label(), probe::alert_name(alert)));
            }
            Ok(Outcome::NoAnswer(why)) => {
                refusals.push(format!("{}: {why}", version.label()));
            }
            Err(e) => {
                return Finding::new(
                    Severity::Warn,
                    family.label(),
                    format!("not checked — {e:#}"),
                );
            }
        }
    }
    Finding::new(
        Severity::Ok,
        family.label(),
        format!("refused ({})", refusals.join("; ")),
    )
}

fn audit_certificate(
    host: &str,
    port: u16,
    accepted: &[TlsVersion],
    fallback_chain: Option<Vec<Vec<u8>>>,
    opts: &Options,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Prefer rustls for the chain (it handles TLS 1.3, where the certificate
    // is encrypted and unreachable from a raw probe); fall back to whatever
    // a cleartext legacy handshake handed us.
    let chain = match modern::fetch_chain(host, port, opts.timeout) {
        Ok(chain) => Some(chain),
        Err(e) => match fallback_chain {
            Some(chain) => Some(chain),
            None => {
                findings.push(Finding::new(
                    Severity::Warn,
                    "certificate",
                    format!("could not be retrieved — {e:#}"),
                ));
                None
            }
        },
    };

    if let Some(chain) = chain {
        match chain.first().map(|der| cert::parse_leaf(der)) {
            Some(Ok(leaf)) => {
                findings.extend(leaf_findings(&leaf, host, chain.len(), opts.warn_days));
            }
            Some(Err(e)) => findings.push(Finding::new(
                Severity::Warn,
                "certificate",
                format!("could not be parsed — {e:#}"),
            )),
            None => findings.push(Finding::new(
                Severity::Warn,
                "certificate",
                "server presented an empty chain",
            )),
        }
    }

    let modern_reachable = accepted
        .iter()
        .any(|v| matches!(v, TlsVersion::Tls12 | TlsVersion::Tls13));
    let trust = if modern_reachable {
        modern::verify_trust(host, port, opts.timeout)
    } else {
        TrustOutcome::Unavailable(
            "server offers no TLS 1.2/1.3 listener for a validating client to use".to_string(),
        )
    };
    findings.push(match trust {
        TrustOutcome::Trusted => Finding::new(
            Severity::Ok,
            "chain trust",
            "verified against the Mozilla root store (incl. hostname)",
        ),
        TrustOutcome::Rejected(why) => Finding::new(Severity::Critical, "chain trust", why),
        TrustOutcome::Unavailable(why) => Finding::new(
            Severity::Warn,
            "chain trust",
            format!("not verified — {why}"),
        ),
    });

    findings
}

fn leaf_findings(leaf: &LeafCert, host: &str, chain_len: usize, warn_days: i64) -> Vec<Finding> {
    let now = SystemTime::now();
    let mut findings = Vec::new();

    findings.push(Finding::new(
        Severity::Ok,
        "subject",
        format!("{} (issuer {})", leaf.subject, leaf.issuer),
    ));

    let days = cert::days_until(leaf.not_after, now);
    let expiry_detail = format!(
        "not_after {} ({days} day(s))",
        cert::format_date(leaf.not_after)
    );
    findings.push(if now < leaf.not_before {
        Finding::new(
            Severity::Critical,
            "validity",
            format!(
                "NOT YET VALID — not_before {}",
                cert::format_date(leaf.not_before)
            ),
        )
    } else if days < 0 {
        Finding::new(
            Severity::Critical,
            "validity",
            format!("EXPIRED — {expiry_detail}"),
        )
    } else if days <= warn_days {
        Finding::new(
            Severity::Warn,
            "validity",
            format!("expires soon — {expiry_detail}"),
        )
    } else {
        Finding::new(Severity::Ok, "validity", expiry_detail)
    });

    findings.push(match cert::match_host(leaf, host) {
        HostMatch::San(name) => Finding::new(
            Severity::Ok,
            "hostname",
            format!("matches SAN dNSName {name}"),
        ),
        HostMatch::CommonNameOnly(cn) => Finding::new(
            Severity::Warn,
            "hostname",
            format!(
                "matches only the CommonName ({cn}) and no SAN — browsers have rejected CN-as-hostname since RFC 2818"
            ),
        ),
        HostMatch::None => Finding::new(
            Severity::Critical,
            "hostname",
            format!(
                "NO MATCH for {host} in {} SAN(s){}",
                leaf.dns_names.len(),
                leaf.common_name
                    .as_deref()
                    .map(|cn| format!(" or CN {cn}"))
                    .unwrap_or_default()
            ),
        ),
    });

    findings.push(if leaf.looks_self_signed && chain_len == 1 {
        Finding::new(
            Severity::Critical,
            "self-signed",
            "yes — subject equals issuer and the chain has no intermediates",
        )
    } else if leaf.looks_self_signed {
        Finding::new(
            Severity::Warn,
            "self-signed",
            format!("subject equals issuer, but {chain_len} certificates were sent"),
        )
    } else {
        Finding::new(
            Severity::Ok,
            "self-signed",
            format!("no — {chain_len} certificate(s) in the presented chain"),
        )
    });

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_probes_skip_tls13_only_servers() {
        // TLS 1.3 removed every weak suite from the protocol, so offering
        // them is meaningless there; a 1.3-only server has nothing to probe.
        assert!(cipher_probe_versions(&[TlsVersion::Tls13]).is_empty());
        assert!(cipher_probe_versions(&[]).is_empty());
    }

    #[test]
    fn cipher_probes_run_newest_accepted_version_first() {
        let versions =
            cipher_probe_versions(&[TlsVersion::Tls10, TlsVersion::Tls12, TlsVersion::Tls13]);
        assert_eq!(versions, vec![TlsVersion::Tls12, TlsVersion::Tls10]);
    }

    #[test]
    fn cipher_probes_never_target_sslv3() {
        // An SSLv3 hello carries no SNI, so a "refused" there would be
        // ambiguous rather than informative.
        let versions = cipher_probe_versions(&[TlsVersion::Ssl30, TlsVersion::Tls10]);
        assert_eq!(versions, vec![TlsVersion::Tls10]);
    }

    fn leaf_at(not_after_days: i64, sans: &[&str], self_signed: bool) -> LeafCert {
        let now = SystemTime::now();
        let not_after = if not_after_days >= 0 {
            now + Duration::from_secs(not_after_days as u64 * 86400 + 3600)
        } else {
            now - Duration::from_secs((-not_after_days) as u64 * 86400)
        };
        LeafCert {
            subject: "CN=example.com".into(),
            issuer: if self_signed {
                "CN=example.com".into()
            } else {
                "CN=Example CA".into()
            },
            common_name: Some("example.com".into()),
            dns_names: sans.iter().map(|s| s.to_string()).collect(),
            not_before: now - Duration::from_secs(86400),
            not_after,
            looks_self_signed: self_signed,
        }
    }

    fn detail_for<'a>(findings: &'a [Finding], label: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.label == label)
            .unwrap_or_else(|| panic!("no finding labelled {label}"))
    }

    #[test]
    fn a_healthy_certificate_produces_no_warnings() {
        let f = leaf_findings(&leaf_at(200, &["example.com"], false), "example.com", 3, 30);
        assert_eq!(
            f.iter().map(|x| x.severity).max(),
            Some(Severity::Ok),
            "got {f:#?}"
        );
    }

    #[test]
    fn an_expired_certificate_is_critical() {
        let f = leaf_findings(&leaf_at(-10, &["example.com"], false), "example.com", 3, 30);
        let validity = detail_for(&f, "validity");
        assert_eq!(validity.severity, Severity::Critical);
        assert!(validity.detail.starts_with("EXPIRED"));
    }

    #[test]
    fn a_soon_to_expire_certificate_warns_at_the_threshold_but_not_past_it() {
        let soon = leaf_at(10, &["example.com"], false);
        assert_eq!(
            detail_for(&leaf_findings(&soon, "example.com", 3, 30), "validity").severity,
            Severity::Warn
        );
        // Same certificate, a threshold it clears: no longer a warning.
        assert_eq!(
            detail_for(&leaf_findings(&soon, "example.com", 3, 5), "validity").severity,
            Severity::Ok
        );
    }

    #[test]
    fn a_hostname_mismatch_is_critical() {
        // The fixture's CN is example.com, so the audited host has to differ
        // from that too — otherwise this would be testing the CN-only path
        // below rather than a genuine mismatch.
        let f = leaf_findings(&leaf_at(200, &["other.test"], false), "wrong.host", 3, 30);
        let hostname = detail_for(&f, "hostname");
        assert_eq!(hostname.severity, Severity::Critical);
        assert!(hostname.detail.contains("NO MATCH for wrong.host"));
        assert!(hostname.detail.contains("CN example.com"));
    }

    #[test]
    fn matching_only_the_common_name_warns_rather_than_passing() {
        // A certificate with SANs that do not cover the host but a CN that
        // does is rejected by every modern browser, so it cannot be an `ok`.
        let f = leaf_findings(&leaf_at(200, &["other.test"], false), "example.com", 3, 30);
        let hostname = detail_for(&f, "hostname");
        assert_eq!(hostname.severity, Severity::Warn);
        assert!(hostname.detail.contains("only the CommonName"));
    }

    #[test]
    fn a_single_self_issued_certificate_is_flagged_self_signed() {
        let f = leaf_findings(&leaf_at(200, &["example.com"], true), "example.com", 1, 30);
        let ss = detail_for(&f, "self-signed");
        assert_eq!(ss.severity, Severity::Critical);
    }

    #[test]
    fn a_self_issued_root_sent_alongside_a_chain_is_only_a_warning() {
        // Servers that (wrongly) include their own root in the chain are
        // sloppy, not compromised — not the same finding as a genuinely
        // self-signed leaf.
        let f = leaf_findings(&leaf_at(200, &["example.com"], true), "example.com", 3, 30);
        assert_eq!(detail_for(&f, "self-signed").severity, Severity::Warn);
    }
}
