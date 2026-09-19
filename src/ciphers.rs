//! The weak-cipher catalog.
//!
//! Each `Family` is a group of cipher suites that share one concrete defect.
//! The audit offers *only* one family's suites in a ClientHello and sees
//! whether the server picks one — the same "offer nothing but the bad stuff"
//! technique `testssl.sh` uses, which is the only way to find out what a
//! server would accept rather than what it merely prefers.

use crate::report::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Null,
    Export,
    Rc4,
    Des,
    TripleDes,
    Anon,
}

pub const FAMILIES: &[Family] = &[
    Family::Null,
    Family::Export,
    Family::Rc4,
    Family::Des,
    Family::TripleDes,
    Family::Anon,
];

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Null => "NULL cipher",
            Family::Export => "export-grade",
            Family::Rc4 => "RC4",
            Family::Des => "single DES",
            Family::TripleDes => "3DES",
            Family::Anon => "anonymous DH",
        }
    }

    /// How bad it is that the server accepts a suite from this family.
    pub fn severity_if_accepted(self) -> Severity {
        match self {
            // No encryption at all, 40/56-bit keys, a stream cipher with
            // known plaintext-recovery biases, and 56-bit DES — all of these
            // mean the traffic is readable, not merely weakly protected.
            Family::Null | Family::Export | Family::Rc4 | Family::Des => Severity::Critical,
            // No server authentication: trivially MITM-able.
            Family::Anon => Severity::Critical,
            // Sweet32 needs a very long-lived connection to be practical, so
            // this is a real finding but not the same class as the above.
            Family::TripleDes => Severity::Warn,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Family::Null => "traffic is not encrypted at all",
            Family::Export => "40/56-bit keys, breakable offline (FREAK/Logjam class)",
            Family::Rc4 => "RC4 is prohibited by RFC 7465",
            Family::Des => "56-bit DES, brute-forceable",
            Family::TripleDes => "64-bit block cipher, vulnerable to Sweet32 (CVE-2016-2183)",
            Family::Anon => "no server authentication — trivially machine-in-the-middle-able",
        }
    }

    /// The suites offered when probing for this family, and nothing else.
    pub fn suites(self) -> &'static [u16] {
        match self {
            Family::Null => &[
                0x0001, // TLS_RSA_WITH_NULL_MD5
                0x0002, // TLS_RSA_WITH_NULL_SHA
                0x003B, // TLS_RSA_WITH_NULL_SHA256
                0xC006, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
                0xC010, // TLS_ECDHE_RSA_WITH_NULL_SHA
            ],
            Family::Export => &[
                0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
                0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
                0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
                0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
                0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
                0x0060, // TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
                0x0062, // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
                0x0064, // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
            ],
            Family::Rc4 => &[
                0x0004, // TLS_RSA_WITH_RC4_128_MD5
                0x0005, // TLS_RSA_WITH_RC4_128_SHA
                0xC007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
                0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
            ],
            Family::Des => &[
                0x0009, // TLS_RSA_WITH_DES_CBC_SHA
                0x0012, // TLS_DHE_DSS_WITH_DES_CBC_SHA
                0x0015, // TLS_DHE_RSA_WITH_DES_CBC_SHA
            ],
            Family::TripleDes => &[
                0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
                0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
                0xC008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
                0xC012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            ],
            Family::Anon => &[
                0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
                0x001B, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
                0x0034, // TLS_DH_anon_WITH_AES_128_CBC_SHA
                0x003A, // TLS_DH_anon_WITH_AES_256_CBC_SHA
                0xC015, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
                0xC018, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
            ],
        }
    }
}

/// A broad, deliberately old-fashioned suite list used for the SSLv3 /
/// TLS 1.0 / TLS 1.1 *version* probes.
///
/// Only pre-TLS-1.2 suites are offered: AEAD suites like AES-GCM do not
/// exist below TLS 1.2, so offering them in a TLS 1.0 ClientHello would just
/// invite a broken server to pick something it cannot actually use. The
/// weak suites are included here on purpose — a server that only has RC4
/// left on its TLS 1.0 listener must still be detected as offering TLS 1.0.
pub const LEGACY_COMPATIBLE_SUITES: &[u16] = &[
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
    0xC012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x0005, // TLS_RSA_WITH_RC4_128_SHA
    0x0004, // TLS_RSA_WITH_RC4_128_MD5
];

/// Suites offered for the raw TLS 1.2 probe used to fetch a cleartext
/// certificate chain — the modern set plus the legacy ones, so it works
/// against both an nginx from this year and one from 2014.
pub const TLS12_COMPATIBLE_SUITES: &[u16] = &[
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
];

/// Which weak family, if any, a negotiated suite id belongs to.
pub fn family_of(suite: u16) -> Option<Family> {
    FAMILIES
        .iter()
        .copied()
        .find(|f| f.suites().contains(&suite))
}

/// Human-readable name for a cipher suite id.
///
/// Covers every suite this tool offers plus the modern suites a healthy
/// server is likely to pick, so the report can name what was negotiated
/// instead of printing a bare hex code. Anything outside that set is
/// rendered as its hex id rather than guessed at.
pub fn suite_name(suite: u16) -> String {
    let known = match suite {
        0x0001 => "TLS_RSA_WITH_NULL_MD5",
        0x0002 => "TLS_RSA_WITH_NULL_SHA",
        0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0006 => "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0008 => "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0009 => "TLS_RSA_WITH_DES_CBC_SHA",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0011 => "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0012 => "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        0x0014 => "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0015 => "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        0x0016 => "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0018 => "TLS_DH_anon_WITH_RC4_128_MD5",
        0x001B => "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0034 => "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x003A => "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        0x003B => "TLS_RSA_WITH_NULL_SHA256",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0060 => "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
        0x0062 => "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        0x0064 => "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xC006 => "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        0xC007 => "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        0xC008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC010 => "TLS_ECDHE_RSA_WITH_NULL_SHA",
        0xC011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0xC012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xC015 => "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        0xC018 => "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => return format!("unknown suite 0x{suite:04X}"),
    };
    known.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_offered_suite_maps_back_to_its_own_family() {
        for family in FAMILIES {
            for suite in family.suites() {
                assert_eq!(
                    family_of(*suite),
                    Some(*family),
                    "suite 0x{suite:04X} should belong to {}",
                    family.label()
                );
            }
        }
    }

    #[test]
    fn family_suite_lists_do_not_overlap() {
        // If a suite appeared in two families, `family_of` would silently
        // return whichever came first and one family's probe would be
        // misattributed.
        let mut seen: Vec<u16> = Vec::new();
        for family in FAMILIES {
            for suite in family.suites() {
                assert!(
                    !seen.contains(suite),
                    "0x{suite:04X} appears in more than one family"
                );
                seen.push(*suite);
            }
        }
    }

    #[test]
    fn strong_modern_suites_are_not_flagged_as_weak() {
        for suite in [0x1301u16, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA8, 0x009C] {
            assert_eq!(family_of(suite), None, "0x{suite:04X} is not weak");
        }
    }

    #[test]
    fn classifies_each_family_at_the_intended_severity() {
        assert_eq!(Family::Null.severity_if_accepted(), Severity::Critical);
        assert_eq!(Family::Export.severity_if_accepted(), Severity::Critical);
        assert_eq!(Family::Rc4.severity_if_accepted(), Severity::Critical);
        assert_eq!(Family::Des.severity_if_accepted(), Severity::Critical);
        assert_eq!(Family::Anon.severity_if_accepted(), Severity::Critical);
        // 3DES is deliberately the one warning, not a critical — Sweet32
        // needs an impractically long-lived connection.
        assert_eq!(Family::TripleDes.severity_if_accepted(), Severity::Warn);
    }

    #[test]
    fn rc4_suites_classify_as_rc4_not_as_something_else() {
        assert_eq!(family_of(0x0005), Some(Family::Rc4));
        assert_eq!(family_of(0xC011), Some(Family::Rc4));
        // 3DES-with-anon-DH is catalogued under anon, the more serious of
        // the two defects.
        assert_eq!(family_of(0x001B), Some(Family::Anon));
    }

    #[test]
    fn suite_name_names_known_suites_and_hexes_unknown_ones() {
        assert_eq!(suite_name(0x0005), "TLS_RSA_WITH_RC4_128_SHA");
        assert_eq!(suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(suite_name(0xDEAD), "unknown suite 0xDEAD");
    }

    #[test]
    fn every_suite_this_tool_ever_offers_has_a_real_name() {
        // A probe result printing "unknown suite 0x..." for something we
        // ourselves offered would be an embarrassing gap in the catalog.
        let offered = FAMILIES
            .iter()
            .flat_map(|f| f.suites().iter().copied())
            .chain(LEGACY_COMPATIBLE_SUITES.iter().copied())
            .chain(TLS12_COMPATIBLE_SUITES.iter().copied());
        for suite in offered {
            assert!(
                !suite_name(suite).starts_with("unknown"),
                "0x{suite:04X} is offered but unnamed"
            );
        }
    }

    #[test]
    fn the_legacy_version_probe_offers_no_post_tls11_only_suites() {
        // AEAD/GCM suites do not exist below TLS 1.2; offering them in a
        // TLS 1.0 ClientHello is a real interop hazard.
        for suite in LEGACY_COMPATIBLE_SUITES {
            let name = suite_name(*suite);
            assert!(
                !name.contains("GCM") && !name.contains("CHACHA20") && !name.contains("SHA256"),
                "{name} is TLS 1.2-only and must not be in the legacy probe list"
            );
        }
    }
}
