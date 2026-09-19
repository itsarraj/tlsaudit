//! Certificate inspection: what the leaf actually says, and whether it says
//! it about the host we asked for.
//!
//! All pure once the DER bytes exist — the fetching lives in `modern.rs` and
//! `probe.rs` — so the fiddly parts (wildcard matching, the civil-date
//! conversion) are testable without a network.

use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use x509_parser::extensions::GeneralName;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCert {
    pub subject: String,
    pub issuer: String,
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// Subject equals issuer. A strong hint, not proof — see
    /// `looks_self_signed`.
    pub looks_self_signed: bool,
}

pub fn parse_leaf(der: &[u8]) -> Result<LeafCert> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).context("parsing X.509 certificate DER")?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string);

    let mut dns_names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                dns_names.push((*dns).to_string());
            }
        }
    }

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    Ok(LeafCert {
        looks_self_signed: subject == issuer,
        common_name,
        dns_names,
        not_before: asn1_to_system_time(cert.validity().not_before.timestamp()),
        not_after: asn1_to_system_time(cert.validity().not_after.timestamp()),
        subject,
        issuer,
    })
}

fn asn1_to_system_time(ts: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(ts.max(0) as u64)
}

/// Whole days between `now` and `not_after` — negative once expired.
pub fn days_until(not_after: SystemTime, now: SystemTime) -> i64 {
    match not_after.duration_since(now) {
        Ok(remaining) => (remaining.as_secs() / 86400) as i64,
        Err(elapsed) => -((elapsed.duration().as_secs() / 86400) as i64) - 1,
    }
}

/// Formats a `SystemTime` as `YYYY-MM-DD` in UTC.
///
/// Hand-rolled (Howard Hinnant's civil-from-days algorithm) rather than
/// pulling in `chrono` for one line of output — this crate already carries a
/// TLS stack and an X.509 parser, and a date formatter is not worth a fourth
/// dependency tree.
pub fn format_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Does one certificate name pattern cover `host`?
///
/// Implements the wildcard rule browsers actually apply: a `*` is only
/// allowed as the entire leftmost label, it matches exactly one label, and
/// it does not match the bare parent domain. `*.example.com` covers
/// `api.example.com` but neither `example.com` nor `a.b.example.com`.
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let Some(rest) = pattern.strip_prefix("*.") else {
        return pattern == host;
    };
    // A wildcard anywhere but the leftmost label (`a.*.example.com`) is not
    // a thing; likewise a bare `*`.
    if rest.contains('*') || rest.is_empty() {
        return false;
    }
    match host.split_once('.') {
        // The label the `*` stands in for must be non-empty and must itself
        // be a single label.
        Some((label, parent)) => !label.is_empty() && parent == rest,
        None => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    /// Matched a SAN dNSName entry — the only thing modern clients accept.
    San(String),
    /// Matched only the subject CommonName.
    ///
    /// Reported separately because CN-as-hostname has been deprecated since
    /// RFC 2818 and is rejected outright by every current browser, so "it
    /// matches the CN" is a finding, not a pass.
    CommonNameOnly(String),
    None,
}

pub fn match_host(cert: &LeafCert, host: &str) -> HostMatch {
    for name in &cert.dns_names {
        if name_matches(name, host) {
            return HostMatch::San(name.clone());
        }
    }
    if let Some(cn) = &cert.common_name {
        if name_matches(cn, host) {
            return HostMatch::CommonNameOnly(cn.clone());
        }
    }
    HostMatch::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(cn: Option<&str>, sans: &[&str]) -> LeafCert {
        LeafCert {
            subject: "CN=test".into(),
            issuer: "CN=test-ca".into(),
            common_name: cn.map(str::to_string),
            dns_names: sans.iter().map(|s| s.to_string()).collect(),
            not_before: SystemTime::UNIX_EPOCH,
            not_after: SystemTime::UNIX_EPOCH,
            looks_self_signed: false,
        }
    }

    #[test]
    fn exact_names_match_case_insensitively() {
        assert!(name_matches("example.com", "example.com"));
        assert!(name_matches("EXAMPLE.com", "example.COM"));
        assert!(!name_matches("example.com", "example.org"));
        assert!(!name_matches("example.com", "www.example.com"));
    }

    #[test]
    fn a_trailing_root_dot_does_not_break_matching() {
        assert!(name_matches("example.com.", "example.com"));
        assert!(name_matches("example.com", "example.com."));
    }

    #[test]
    fn a_leftmost_wildcard_covers_exactly_one_label() {
        assert!(name_matches("*.example.com", "api.example.com"));
        assert!(name_matches("*.example.com", "www.example.com"));
        // One label only — this is the rule people most often get wrong.
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        // And it does not cover the parent domain itself.
        assert!(!name_matches("*.example.com", "example.com"));
    }

    #[test]
    fn wildcards_are_rejected_anywhere_but_the_leftmost_label() {
        assert!(!name_matches("a.*.example.com", "a.b.example.com"));
        assert!(!name_matches("*", "example.com"));
        assert!(!name_matches("*.", "example.com"));
        assert!(!name_matches("www.*", "www.example.com"));
    }

    #[test]
    fn empty_input_never_matches() {
        assert!(!name_matches("", "example.com"));
        assert!(!name_matches("example.com", ""));
    }

    #[test]
    fn prefers_a_san_match_over_the_common_name() {
        let c = leaf(Some("example.com"), &["other.com", "*.example.com"]);
        assert_eq!(
            match_host(&c, "api.example.com"),
            HostMatch::San("*.example.com".into())
        );
    }

    #[test]
    fn a_cn_only_match_is_reported_as_cn_only_not_as_a_clean_pass() {
        // Browsers stopped honouring CN-as-hostname years ago, so this has
        // to be visibly different from a SAN match.
        let c = leaf(Some("legacy.example.com"), &["unrelated.example.com"]);
        assert_eq!(
            match_host(&c, "legacy.example.com"),
            HostMatch::CommonNameOnly("legacy.example.com".into())
        );
    }

    #[test]
    fn no_match_at_all_is_reported_as_none() {
        let c = leaf(Some("example.com"), &["example.com", "www.example.com"]);
        assert_eq!(match_host(&c, "attacker.test"), HostMatch::None);

        let no_names = leaf(None, &[]);
        assert_eq!(match_host(&no_names, "example.com"), HostMatch::None);
    }

    #[test]
    fn counts_whole_days_and_goes_negative_once_expired() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(days_until(now + Duration::from_secs(10 * 86400), now), 10);
        assert_eq!(days_until(now, now), 0);
        assert!(days_until(now - Duration::from_secs(5 * 86400), now) < 0);
    }

    #[test]
    fn formats_dates_including_leap_years_and_epoch() {
        assert_eq!(format_date(SystemTime::UNIX_EPOCH), "1970-01-01");
        assert_eq!(
            format_date(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14"
        );
        // 2024-02-29 — a real leap day, the classic off-by-one in a
        // hand-rolled civil-date conversion.
        assert_eq!(
            format_date(SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "2024-02-29"
        );
        // 2000-03-01, just past the century leap-year exception.
        assert_eq!(
            format_date(SystemTime::UNIX_EPOCH + Duration::from_secs(951_868_800)),
            "2000-03-01"
        );
    }

    #[test]
    fn parses_subject_issuer_sans_and_validity_from_a_real_certificate() {
        let (der, cn) = rcgen_test_helpers::self_signed_der("tlsaudit-test.example", 30);
        let leaf = parse_leaf(&der).unwrap();
        assert!(leaf.subject.contains(&cn));
        assert_eq!(leaf.common_name.as_deref(), Some(cn.as_str()));
        assert!(
            leaf.dns_names.contains(&cn),
            "SAN dNSName should be extracted, got {:?}",
            leaf.dns_names
        );
        assert!(
            leaf.looks_self_signed,
            "a self-signed cert is its own issuer"
        );
        assert!(leaf.not_before < leaf.not_after);
        assert!(days_until(leaf.not_after, SystemTime::now()) >= 28);
        // And the SAN is what the hostname check actually finds.
        assert_eq!(match_host(&leaf, &cn), HostMatch::San(cn));
    }

    #[test]
    fn a_wildcard_san_on_a_real_certificate_matches_a_subdomain() {
        let (der, _) = rcgen_test_helpers::self_signed_der("*.tlsaudit-test.example", 30);
        let leaf = parse_leaf(&der).unwrap();
        assert_eq!(
            match_host(&leaf, "api.tlsaudit-test.example"),
            HostMatch::San("*.tlsaudit-test.example".into())
        );
        assert_eq!(match_host(&leaf, "tlsaudit-test.example"), HostMatch::None);
    }

    #[test]
    fn garbage_bytes_are_a_clean_error_not_a_panic() {
        assert!(parse_leaf(b"not a certificate").is_err());
        assert!(parse_leaf(&[]).is_err());
    }

    /// A tiny self-signed-certificate generator used only by this module's
    /// own tests. Kept here rather than as a real dependency: `tlsaudit`
    /// only ever reads certificates, never issues them.
    mod rcgen_test_helpers {
        use rcgen::{CertificateParams, DnType, KeyPair};

        pub fn self_signed_der(name: &str, days_valid: i64) -> (Vec<u8>, String) {
            let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(1);
            params.not_after = now + time::Duration::days(days_valid);
            let key = KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            (cert.der().to_vec(), name.to_string())
        }
    }
}
