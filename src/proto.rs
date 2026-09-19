//! TLS protocol versions: wire codes, display names, and the judgement call
//! about which ones are still acceptable in 2026.

use crate::report::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// Every version this tool probes, oldest first.
pub const ALL: &[TlsVersion] = &[
    TlsVersion::Ssl30,
    TlsVersion::Tls10,
    TlsVersion::Tls11,
    TlsVersion::Tls12,
    TlsVersion::Tls13,
];

impl TlsVersion {
    /// The two-byte code that goes on the wire in a ClientHello /
    /// ServerHello `legacy_version` field.
    pub fn wire(self) -> u16 {
        match self {
            TlsVersion::Ssl30 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
        }
    }

    pub fn from_wire(code: u16) -> Option<Self> {
        ALL.iter().copied().find(|v| v.wire() == code)
    }

    pub fn label(self) -> &'static str {
        match self {
            TlsVersion::Ssl30 => "SSL 3.0",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
        }
    }

    /// How bad it is that the server *accepts* this version.
    pub fn severity_if_accepted(self) -> Severity {
        match self {
            // POODLE. Withdrawn outright by RFC 7568 — there is no argument
            // for still having this on.
            TlsVersion::Ssl30 => Severity::Critical,
            // Deprecated by RFC 8996 (2021). Still turned on in a lot of
            // places for genuinely old clients, so: a warning, not critical.
            TlsVersion::Tls10 | TlsVersion::Tls11 => Severity::Warn,
            TlsVersion::Tls12 | TlsVersion::Tls13 => Severity::Ok,
        }
    }

    /// Short justification printed next to a non-`Ok` protocol finding.
    /// `None` for versions that are simply fine.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            TlsVersion::Ssl30 => Some("SSLv3 is broken by POODLE and withdrawn by RFC 7568"),
            TlsVersion::Tls10 => Some("TLS 1.0 is deprecated by RFC 8996"),
            TlsVersion::Tls11 => Some("TLS 1.1 is deprecated by RFC 8996"),
            TlsVersion::Tls12 | TlsVersion::Tls13 => None,
        }
    }

    /// Whether this version is probed with a hand-built ClientHello rather
    /// than through rustls. rustls only speaks 1.2 and 1.3 and will not be
    /// talked into anything older, so the legacy versions are the ones that
    /// need raw socket work — see `probe.rs`.
    pub fn needs_raw_probe(self) -> bool {
        matches!(
            self,
            TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_match_the_rfcs() {
        assert_eq!(TlsVersion::Ssl30.wire(), 0x0300);
        assert_eq!(TlsVersion::Tls10.wire(), 0x0301);
        assert_eq!(TlsVersion::Tls11.wire(), 0x0302);
        assert_eq!(TlsVersion::Tls12.wire(), 0x0303);
        assert_eq!(TlsVersion::Tls13.wire(), 0x0304);
    }

    #[test]
    fn from_wire_round_trips_every_known_version() {
        for v in ALL {
            assert_eq!(TlsVersion::from_wire(v.wire()), Some(*v));
        }
    }

    #[test]
    fn from_wire_rejects_unknown_codes() {
        // 0x0002 is SSLv2, which this tool does not probe; 0xffff is junk.
        assert_eq!(TlsVersion::from_wire(0x0002), None);
        assert_eq!(TlsVersion::from_wire(0xffff), None);
    }

    #[test]
    fn sslv3_is_critical_tls10_and_11_warn_modern_is_ok() {
        assert_eq!(TlsVersion::Ssl30.severity_if_accepted(), Severity::Critical);
        assert_eq!(TlsVersion::Tls10.severity_if_accepted(), Severity::Warn);
        assert_eq!(TlsVersion::Tls11.severity_if_accepted(), Severity::Warn);
        assert_eq!(TlsVersion::Tls12.severity_if_accepted(), Severity::Ok);
        assert_eq!(TlsVersion::Tls13.severity_if_accepted(), Severity::Ok);
    }

    #[test]
    fn only_the_deprecated_versions_carry_a_reason() {
        assert!(TlsVersion::Ssl30.reason().is_some());
        assert!(TlsVersion::Tls10.reason().unwrap().contains("RFC 8996"));
        assert!(TlsVersion::Tls11.reason().unwrap().contains("RFC 8996"));
        assert!(TlsVersion::Tls12.reason().is_none());
        assert!(TlsVersion::Tls13.reason().is_none());
    }

    #[test]
    fn exactly_the_pre_12_versions_need_the_hand_built_clienthello() {
        let raw: Vec<_> = ALL.iter().filter(|v| v.needs_raw_probe()).collect();
        assert_eq!(
            raw,
            vec![&TlsVersion::Ssl30, &TlsVersion::Tls10, &TlsVersion::Tls11]
        );
    }

    #[test]
    fn versions_order_oldest_to_newest() {
        assert!(TlsVersion::Ssl30 < TlsVersion::Tls10);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }
}
