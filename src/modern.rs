//! rustls-driven probes: TLS 1.2 / TLS 1.3 support, the certificate chain,
//! and the one check that genuinely needs a real TLS client — whether the
//! chain verifies against the Mozilla root store.
//!
//! The hand-built probes in `probe.rs` can tell you a server sent a
//! ServerHello. They cannot tell you a certificate chains to a trusted root,
//! because that needs full path building and signature verification. rustls
//! already does that correctly, so this module uses it rather than
//! reimplementing X.509 path validation badly.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme, SupportedProtocolVersion,
};

use crate::probe::connect;

/// **Deliberately accepts every certificate, valid or not.**
///
/// A tool whose purpose is to find *bad* TLS configuration cannot use normal
/// trust validation for the inspection handshakes — that would make the
/// handshake fail on exactly the endpoints it exists to examine. This
/// verifier exists only so a handshake completes far enough to read the real
/// certificate chain and the negotiated parameters back; it is never used to
/// decide whether anything is trustworthy. The actual trust question is
/// answered separately by `verify_trust`, which uses a real webpki verifier
/// against the Mozilla root store.
#[derive(Debug)]
struct AcceptAnyCert(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What a completed rustls handshake told us.
#[derive(Debug, Clone)]
pub struct Negotiated {
    pub version: u16,
    pub cipher_suite: String,
    pub chain: Vec<Vec<u8>>,
}

fn accept_any_config(versions: &[&'static SupportedProtocolVersion]) -> Result<ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = Arc::new(AcceptAnyCert(provider.clone()));
    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .context("configuring TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

fn handshake(
    host: &str,
    port: u16,
    config: ClientConfig,
    timeout: Duration,
) -> Result<ClientConnection, HandshakeError> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| HandshakeError::Other(format!("'{host}' is not a valid server name")))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| HandshakeError::Other(format!("creating TLS connection: {e}")))?;
    let mut sock =
        connect(host, port, timeout).map_err(|e| HandshakeError::Other(format!("{e:#}")))?;

    // Driven directly rather than via a zero-length `Stream::write_all`,
    // which is a silent no-op and never reaches the socket at all.
    conn.complete_io(&mut sock).map_err(|e| {
        match e.into_inner().map(|b| b.downcast::<rustls::Error>()) {
            Some(Ok(tls_err)) => HandshakeError::Tls(*tls_err),
            _ => HandshakeError::Other("TLS handshake did not complete".to_string()),
        }
    })?;
    Ok(conn)
}

#[derive(Debug)]
pub enum HandshakeError {
    /// rustls's own structured error — precise enough to say *why* a chain
    /// was rejected.
    Tls(rustls::Error),
    /// Anything else: DNS, TCP, a bad hostname.
    Other(String),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Tls(e) => write!(f, "{e}"),
            HandshakeError::Other(s) => f.write_str(s),
        }
    }
}

fn describe(conn: &ClientConnection) -> Negotiated {
    let version = conn.protocol_version().map(u16::from).unwrap_or(0);
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string());
    let chain = conn
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
        .unwrap_or_default();
    Negotiated {
        version,
        cipher_suite,
        chain,
    }
}

/// Handshakes with exactly one protocol version allowed. Success means the
/// server genuinely speaks it; `Err` means it refused (or is unreachable).
pub fn probe_version(
    host: &str,
    port: u16,
    version: &'static SupportedProtocolVersion,
    timeout: Duration,
) -> Result<Negotiated, HandshakeError> {
    let config =
        accept_any_config(&[version]).map_err(|e| HandshakeError::Other(format!("{e:#}")))?;
    let conn = handshake(host, port, config, timeout)?;
    Ok(describe(&conn))
}

/// Handshakes with both modern versions allowed, purely to read the
/// certificate chain back.
pub fn fetch_chain(host: &str, port: u16, timeout: Duration) -> Result<Vec<Vec<u8>>> {
    let config = accept_any_config(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("building inspection TLS config")?;
    let conn = handshake(host, port, config, timeout)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("fetching certificate chain")?;
    let chain = describe(&conn).chain;
    if chain.is_empty() {
        anyhow::bail!("server presented no certificates");
    }
    Ok(chain)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustOutcome {
    /// Full path validation succeeded against the Mozilla root store,
    /// including hostname matching.
    Trusted,
    /// Validation failed, with the reason rustls gave.
    Rejected(String),
    /// Could not be determined — e.g. the server does not offer TLS 1.2 or
    /// 1.3 at all, so rustls will not talk to it. Reported as its own state
    /// rather than being guessed either way.
    Unavailable(String),
}

/// Turns a rustls error into a sentence a human can act on.
///
/// Pure, so the wording is pinned by tests. Each "expired"/"wrong name" case
/// has two rustls variants — a bare one and a `…Context` one carrying the
/// offending times or names — and both have to be matched, because which one
/// you get depends on the verifier. The catch-all deliberately falls back to
/// rustls's own message rather than inventing a friendlier but possibly
/// wrong explanation for an error we did not anticipate.
pub fn describe_trust_failure(err: &rustls::Error) -> String {
    let rustls::Error::InvalidCertificate(cert_err) = err else {
        return err.to_string();
    };
    match cert_err {
        CertificateError::Expired => "certificate has expired".to_string(),
        CertificateError::ExpiredContext { .. } => {
            format!("certificate has expired ({cert_err})")
        }
        CertificateError::NotValidYet => "certificate is not valid yet".to_string(),
        CertificateError::NotValidYetContext { .. } => {
            format!("certificate is not valid yet ({cert_err})")
        }
        CertificateError::NotValidForName => {
            "certificate is not valid for this hostname".to_string()
        }
        CertificateError::NotValidForNameContext { .. } => {
            format!("certificate is not valid for this hostname ({cert_err})")
        }
        CertificateError::UnknownIssuer => {
            "issuer is not in the Mozilla root store (self-signed or untrusted CA)".to_string()
        }
        CertificateError::Revoked => "certificate has been revoked".to_string(),
        other => other.to_string(),
    }
}

/// The real trust check: a normal, fully-validating rustls handshake against
/// the Mozilla root store bundled in `webpki-roots`.
///
/// Note this validates the *whole* chain including hostname matching, so it
/// is stricter than the individual certificate checks in `cert.rs` and can
/// legitimately fail even when the leaf looks fine on its own (a missing
/// intermediate, for instance).
pub fn verify_trust(host: &str, port: u16, timeout: Duration) -> TrustOutcome {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    match handshake(host, port, config, timeout) {
        Ok(_) => TrustOutcome::Trusted,
        Err(HandshakeError::Tls(e)) => match &e {
            rustls::Error::InvalidCertificate(_) => {
                TrustOutcome::Rejected(describe_trust_failure(&e))
            }
            // A protocol/version failure is not a statement about the
            // certificate — a TLS-1.0-only server rejects rustls before any
            // certificate is even considered.
            other => TrustOutcome::Unavailable(format!(
                "rustls could not complete a validating handshake: {other}"
            )),
        },
        Err(HandshakeError::Other(msg)) => TrustOutcome::Unavailable(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_root_store_is_actually_populated() {
        // An empty root store would make every `verify_trust` call fail with
        // UnknownIssuer, which looks exactly like a real finding.
        assert!(
            webpki_roots::TLS_SERVER_ROOTS.len() > 50,
            "expected a real Mozilla root bundle, got {}",
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
    }

    #[test]
    fn describes_the_certificate_failures_this_tool_exists_to_find() {
        assert_eq!(
            describe_trust_failure(&rustls::Error::InvalidCertificate(
                CertificateError::Expired
            )),
            "certificate has expired"
        );
        assert_eq!(
            describe_trust_failure(&rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName
            )),
            "certificate is not valid for this hostname"
        );
        assert!(describe_trust_failure(&rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
        .contains("self-signed or untrusted CA"));
        assert_eq!(
            describe_trust_failure(&rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet
            )),
            "certificate is not valid yet"
        );
    }

    #[test]
    fn the_context_carrying_variants_are_described_too() {
        // This is the variant rustls's webpki verifier actually returns for
        // a real expired certificate — matching only the bare `Expired` made
        // live output fall through to the raw rustls string.
        let expired = rustls::Error::InvalidCertificate(CertificateError::ExpiredContext {
            time: rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                1_789_820_354,
            )),
            not_after: rustls::pki_types::UnixTime::since_unix_epoch(
                std::time::Duration::from_secs(1_428_883_199),
            ),
        });
        let described = describe_trust_failure(&expired);
        assert!(
            described.starts_with("certificate has expired"),
            "got {described}"
        );
        // ...and the concrete timestamps survive into the message.
        assert!(described.contains("1428883199"), "got {described}");

        let wrong_name =
            rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                expected: rustls::pki_types::ServerName::try_from("example.com")
                    .unwrap()
                    .to_owned(),
                presented: vec!["DnsName(\"other.test\")".to_string()],
            });
        assert!(describe_trust_failure(&wrong_name)
            .starts_with("certificate is not valid for this hostname"));
    }

    #[test]
    fn unrecognised_errors_fall_back_to_rustls_own_wording() {
        // Better a verbatim rustls message than a confidently wrong
        // paraphrase of an error we did not anticipate.
        let err = rustls::Error::DecryptError;
        assert_eq!(describe_trust_failure(&err), err.to_string());
    }

    #[test]
    fn an_accept_any_config_can_be_built_for_each_modern_version() {
        assert!(accept_any_config(&[&rustls::version::TLS12]).is_ok());
        assert!(accept_any_config(&[&rustls::version::TLS13]).is_ok());
    }
}
