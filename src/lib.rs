//! `tlsaudit` — a TLS configuration and hygiene audit of a live endpoint.
//!
//! Three kinds of check, in three layers:
//!
//! * [`probe`] builds TLS ClientHello messages by hand and reads the
//!   server's reply off a raw socket. This is the only way to ask "do you
//!   still accept TLS 1.0?" or "would you take RC4?", because a correct TLS
//!   client refuses to make those offers.
//! * [`modern`] uses rustls for the TLS 1.2/1.3 probes and for real chain
//!   validation against the Mozilla root store.
//! * [`cert`], [`proto`], [`ciphers`] and [`report`] are pure: parsing,
//!   classification and formatting, all testable without a network.

pub mod audit;
pub mod cert;
pub mod ciphers;
pub mod modern;
pub mod probe;
pub mod proto;
pub mod report;

const DEFAULT_PORT: u16 = 443;

/// Parses a `host` or `host:port` target, defaulting to 443.
///
/// Kept pure and separate from CLI parsing so the "what does
/// `tls-v1-0.badssl.com:1010` mean" question has its own tests — this tool
/// is pointed at non-443 ports often enough (badssl's own protocol-specific
/// listeners live on 1010/1011/1012) that getting it wrong would be a
/// constant papercut.
pub fn parse_target(s: &str) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (s.to_string(), DEFAULT_PORT),
        },
        None => (s.to_string(), DEFAULT_PORT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_hostname_defaults_to_443() {
        assert_eq!(parse_target("github.com"), ("github.com".to_string(), 443));
    }

    #[test]
    fn an_explicit_port_is_honoured() {
        assert_eq!(
            parse_target("tls-v1-0.badssl.com:1010"),
            ("tls-v1-0.badssl.com".to_string(), 1010)
        );
    }

    #[test]
    fn a_colon_that_is_not_a_port_falls_back_to_the_default() {
        assert_eq!(parse_target("weird:host").1, DEFAULT_PORT);
        assert_eq!(parse_target("weird:host").0, "weird:host");
    }

    #[test]
    fn a_port_above_u16_is_not_silently_truncated() {
        // 99999 does not fit in a port; treating the whole string as a
        // hostname produces a clean DNS failure rather than a connection to
        // port 34463.
        assert_eq!(parse_target("example.com:99999").0, "example.com:99999");
        assert_eq!(parse_target("example.com:99999").1, DEFAULT_PORT);
    }
}
