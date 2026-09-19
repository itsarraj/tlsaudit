//! Hand-built TLS ClientHello probes.
//!
//! rustls will not speak SSLv3, TLS 1.0 or TLS 1.1, and will not negotiate a
//! weak cipher suite, by design — which is exactly right for a TLS *client*
//! and exactly wrong for a tool whose job is to find out whether a server
//! still offers those things. So this module constructs the ClientHello
//! itself, writes it to a plain `TcpStream`, and reads back just enough of
//! the server's reply to learn two facts: which version it agreed to, and
//! which cipher suite it picked.
//!
//! It deliberately stops there. No key exchange, no cipher is ever
//! implemented — the connection is dropped right after the server's first
//! flight. "Did the server send a ServerHello or an alert" is the entire
//! question, and it is answerable without any cryptography, which is why
//! this is a few hundred lines rather than a second TLS stack.
//!
//! The message-building and message-parsing halves are pure functions over
//! byte slices, so they are tested against fixture bytes without a socket.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::ciphers;
use crate::proto::TlsVersion;

const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0e;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// What the server said in response to a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A ServerHello came back: the server agreed to `version` and picked
    /// `cipher_suite`. `chain` holds the certificate chain if the server
    /// sent a cleartext Certificate message in the same flight (it does for
    /// everything below TLS 1.3).
    Accepted {
        version: u16,
        cipher_suite: u16,
        chain: Vec<Vec<u8>>,
    },
    /// A TLS alert: the server refused. This is the *good* answer when
    /// probing for something weak.
    Rejected { alert: u8 },
    /// The server hung up, sent something that is not TLS, or sent a
    /// handshake message we did not expect. Reported verbatim rather than
    /// being folded into "rejected", because "connection reset" and "sent a
    /// protocol_version alert" are different facts about a server.
    NoAnswer(String),
}

impl Outcome {
    /// Whether the server agreed to exactly the version that was probed.
    ///
    /// The version check matters: a server whose maximum is TLS 1.0, asked
    /// for TLS 1.1, answers with a TLS 1.0 ServerHello rather than an alert.
    /// Counting that as "TLS 1.1 accepted" would be a false positive on the
    /// single most important thing this tool reports.
    pub fn accepted_version(&self, probed: TlsVersion) -> Option<u16> {
        match self {
            Outcome::Accepted { version, .. } if *version == probed.wire() => Some(*version),
            _ => None,
        }
    }
}

/// Names for the alert codes a probe actually runs into, so the report can
/// say *why* a server said no.
pub fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        112 => "unrecognized_name",
        _ => "unknown alert",
    }
}

// ---------------------------------------------------------------------------
// Building the ClientHello (pure)
// ---------------------------------------------------------------------------

fn extension(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn sni_extension(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut entry = vec![0x00]; // name_type = host_name
    entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    entry.extend_from_slice(host);

    let mut body = (entry.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&entry);
    extension(EXT_SERVER_NAME, &body)
}

fn u16_list_extension(id: u16, items: &[u16]) -> Vec<u8> {
    let mut list = Vec::with_capacity(items.len() * 2);
    for item in items {
        list.extend_from_slice(&item.to_be_bytes());
    }
    let mut body = (list.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    extension(id, &body)
}

/// Builds a complete TLS record containing a ClientHello for `version`
/// offering exactly `suites`.
///
/// `random` is a parameter rather than generated in here so the output is
/// byte-for-byte deterministic under test.
///
/// SSLv3 predates the extensions mechanism entirely, so an SSLv3 hello is
/// built without an extensions block — including without SNI. That is a real
/// limitation: a name-based virtual host that only answers for the right SNI
/// may refuse an SSLv3 hello for reasons unrelated to SSLv3 being disabled.
/// In practice SSLv3 has been off by default everywhere for a decade, so a
/// refusal is overwhelmingly likely to be the right answer anyway.
pub fn build_client_hello(
    host: &str,
    version: TlsVersion,
    suites: &[u16],
    random: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.wire().to_be_bytes());
    body.extend_from_slice(random);
    body.push(0x00); // empty session id

    let mut suite_bytes = Vec::with_capacity(suites.len() * 2);
    for s in suites {
        suite_bytes.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&(suite_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&suite_bytes);

    body.push(0x01); // one compression method...
    body.push(0x00); // ...null. Compression is a CRIME vector; never offered.

    if version != TlsVersion::Ssl30 {
        let mut exts = Vec::new();
        exts.extend_from_slice(&sni_extension(host));
        // x25519, secp256r1, secp384r1, secp521r1 — needed for the ECDHE
        // suites to be selectable at all.
        exts.extend_from_slice(&u16_list_extension(
            EXT_SUPPORTED_GROUPS,
            &[0x001d, 0x0017, 0x0018, 0x0019],
        ));
        // ec_point_formats: uncompressed only.
        exts.extend_from_slice(&extension(EXT_EC_POINT_FORMATS, &[0x01, 0x00]));
        if version >= TlsVersion::Tls12 {
            // signature_algorithms is a TLS 1.2 addition; sending it to a
            // 1.0/1.1 server is legal-but-ignored, so it is simply left off.
            exts.extend_from_slice(&u16_list_extension(
                EXT_SIGNATURE_ALGORITHMS,
                &[
                    0x0403, 0x0503, 0x0603, // ecdsa + sha2
                    0x0804, 0x0805, 0x0806, // rsa_pss_rsae + sha2
                    0x0401, 0x0501, 0x0601, // rsa_pkcs1 + sha2
                    0x0201, 0x0203, // sha1 fallbacks, for genuinely old servers
                ],
            ));
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
    }

    let mut handshake = vec![0x01]; // ClientHello
    let len = body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    // Record-layer version is the widely-compatible 0x0301 for everything
    // except SSLv3, matching what real clients put on the wire; some old
    // middleboxes drop records claiming a version they do not know.
    let record_version: u16 = if version == TlsVersion::Ssl30 {
        0x0300
    } else {
        0x0301
    };
    let mut record = vec![CONTENT_TYPE_HANDSHAKE];
    record.extend_from_slice(&record_version.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

// ---------------------------------------------------------------------------
// Parsing the server's reply (pure)
// ---------------------------------------------------------------------------

/// Bounds-checked forward reader. Every field read from the network goes
/// through this, so a truncated or hostile response is an `Err`, never a
/// panic or an out-of-bounds index.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).context("TLS length overflow")?;
        let slice = self
            .buf
            .get(self.pos..end)
            .context("truncated TLS message")?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    /// The version the server actually agreed to, already accounting for
    /// TLS 1.3's `supported_versions` indirection.
    pub version: u16,
    pub cipher_suite: u16,
}

/// Parses a ServerHello handshake-message body (everything after the 4-byte
/// type+length header).
///
/// TLS 1.3 servers pin `legacy_version` at 0x0303 and put the real version in
/// a `supported_versions` extension; that extension wins here when present,
/// so a 1.3 ServerHello is not misreported as 1.2.
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    let mut r = Reader::new(body);
    let legacy_version = r.u16().context("ServerHello version")?;
    r.take(32).context("ServerHello random")?;
    let session_id_len = r.u8().context("ServerHello session id length")? as usize;
    r.take(session_id_len).context("ServerHello session id")?;
    let cipher_suite = r.u16().context("ServerHello cipher suite")?;
    r.u8().context("ServerHello compression method")?;

    let mut version = legacy_version;
    if r.remaining() >= 2 {
        let ext_total = r.u16()? as usize;
        let ext_bytes = r.take(ext_total.min(r.remaining()))?;
        let mut e = Reader::new(ext_bytes);
        while e.remaining() >= 4 {
            let id = e.u16()?;
            let len = e.u16()? as usize;
            let data = e.take(len)?;
            if id == EXT_SUPPORTED_VERSIONS && data.len() == 2 {
                version = u16::from_be_bytes([data[0], data[1]]);
            }
        }
    }

    Ok(ServerHello {
        version,
        cipher_suite,
    })
}

/// Parses a Certificate handshake-message body into raw DER certificates,
/// leaf first. This is what makes it possible to inspect the certificate of
/// a TLS-1.0-only server that rustls refuses to talk to at all: below
/// TLS 1.3 this message is sent in the clear, before any key exchange.
pub fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let total = r.u24().context("certificate list length")?;
    let list = r.take(total.min(r.remaining()))?;
    let mut certs = Vec::new();
    let mut c = Reader::new(list);
    while c.remaining() >= 3 {
        let len = c.u24()?;
        certs.push(c.take(len)?.to_vec());
    }
    Ok(certs)
}

/// Everything recovered so far from the server's first flight.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Flight {
    pub hello: Option<ServerHello>,
    /// Certificate chain, leaf first, if the server sent a cleartext
    /// Certificate message. Empty for TLS 1.3, where it is encrypted.
    pub chain: Vec<Vec<u8>>,
    /// ServerHelloDone seen: there is nothing further to wait for, so the
    /// caller can stop reading instead of blocking until its timeout.
    pub complete: bool,
}

/// Walks a buffer of concatenated handshake messages and pulls out the first
/// ServerHello and Certificate.
///
/// Tolerates a partial trailing message rather than erroring on it: servers
/// routinely split their first flight across several TLS records, so the
/// caller reads another record and calls this again with a longer buffer.
pub fn parse_handshake_flight(buf: &[u8]) -> Result<Flight> {
    let mut r = Reader::new(buf);
    let mut flight = Flight::default();

    while r.remaining() >= 4 {
        let msg_type = r.u8()?;
        let len = r.u24()?;
        if r.remaining() < len {
            break; // partial trailing message; wait for more bytes
        }
        let body = r.take(len)?;
        match msg_type {
            // The guards keep the *first* of each message type: the first
            // ServerHello is the one that answers the question we asked.
            HANDSHAKE_SERVER_HELLO if flight.hello.is_none() => {
                flight.hello = Some(parse_server_hello(body)?);
            }
            HANDSHAKE_CERTIFICATE if flight.chain.is_empty() => {
                flight.chain = parse_certificate_message(body).unwrap_or_default();
            }
            HANDSHAKE_SERVER_HELLO_DONE => {
                flight.complete = true;
                break;
            }
            _ => {}
        }
    }

    Ok(flight)
}

impl Flight {
    /// Whether there is any point reading another record.
    ///
    /// Stopping at the ServerHello alone would be enough to answer "is this
    /// version accepted", but it would throw away the certificate the server
    /// is about to send in the very next record — and that certificate is
    /// the only way to inspect a server rustls refuses to talk to at all.
    fn is_settled(&self) -> bool {
        self.hello.is_some() && (self.complete || !self.chain.is_empty())
    }

    fn into_outcome(self) -> Option<Outcome> {
        self.hello.map(|h| Outcome::Accepted {
            version: h.version,
            cipher_suite: h.cipher_suite,
            chain: self.chain,
        })
    }
}

// ---------------------------------------------------------------------------
// Actually talking to the server
// ---------------------------------------------------------------------------

/// Resolves and connects with a real timeout on both the connect and the
/// subsequent reads — a probe against a silently-dropping firewall must fail
/// in seconds, not hang a cron job.
pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("{host}:{port} resolved to no addresses");
    }
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => {
                sock.set_read_timeout(Some(timeout)).ok();
                sock.set_write_timeout(Some(timeout)).ok();
                return Ok(sock);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "connecting to {host}:{port}: {}",
        last_err.expect("at least one address was tried")
    ))
}

fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    // Borrowed from the crypto provider we already depend on rather than
    // pulling in `rand`. A ClientHello random is not security-relevant here
    // (no handshake is ever completed) but a fixed one would be rude to any
    // server doing replay detection.
    if rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut buf)
        .is_err()
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        buf[..4].copy_from_slice(&nanos.to_be_bytes());
    }
    buf
}

fn read_outcome(sock: &mut TcpStream) -> Result<Outcome> {
    let mut handshake = Vec::new();
    let mut best = Flight::default();

    // Eight records is far more than any real first flight needs; it just
    // stops a chatty or malicious peer from making this loop forever.
    for _ in 0..8 {
        let mut header = [0u8; 5];
        if let Err(e) = sock.read_exact(&mut header) {
            // A server that hangs up after its ServerHello still answered
            // the question, so an incomplete read is only a failure when
            // nothing useful arrived first.
            return Ok(best.into_outcome().unwrap_or_else(|| {
                Outcome::NoAnswer(if handshake.is_empty() {
                    format!("no TLS response ({e})")
                } else {
                    format!("truncated TLS response ({e})")
                })
            }));
        }
        let content_type = header[0];
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > 16_640 {
            return Ok(Outcome::NoAnswer(format!(
                "oversized TLS record ({len} bytes)"
            )));
        }
        let mut body = vec![0u8; len];
        if sock.read_exact(&mut body).is_err() {
            return Ok(best
                .into_outcome()
                .unwrap_or_else(|| Outcome::NoAnswer("truncated TLS record body".to_string())));
        }

        match content_type {
            CONTENT_TYPE_ALERT => {
                let alert = body.get(1).copied().unwrap_or(0);
                return Ok(Outcome::Rejected { alert });
            }
            CONTENT_TYPE_HANDSHAKE => {
                handshake.extend_from_slice(&body);
                best = parse_handshake_flight(&handshake)?;
                if best.is_settled() {
                    return Ok(best.into_outcome().expect("settled implies a ServerHello"));
                }
            }
            other => {
                return Ok(best.into_outcome().unwrap_or_else(|| {
                    Outcome::NoAnswer(format!("unexpected TLS record type 0x{other:02x}"))
                }));
            }
        }
    }
    Ok(best.into_outcome().unwrap_or_else(|| {
        Outcome::NoAnswer("no ServerHello in the server's first flight".to_string())
    }))
}

/// One probe: connect, send a ClientHello for `version` offering `suites`,
/// read the reply, hang up.
pub fn probe(
    host: &str,
    port: u16,
    version: TlsVersion,
    suites: &[u16],
    timeout: Duration,
) -> Result<Outcome> {
    let hello = build_client_hello(host, version, suites, &random_bytes());
    let mut sock = connect(host, port, timeout)?;
    sock.write_all(&hello)
        .with_context(|| format!("sending ClientHello to {host}:{port}"))?;
    sock.flush().ok();
    read_outcome(&mut sock)
}

/// Probes whether `version` is accepted at all, offering a broad set of
/// period-appropriate cipher suites.
pub fn probe_version(
    host: &str,
    port: u16,
    version: TlsVersion,
    timeout: Duration,
) -> Result<Outcome> {
    let suites = if version >= TlsVersion::Tls12 {
        ciphers::TLS12_COMPATIBLE_SUITES
    } else {
        ciphers::LEGACY_COMPATIBLE_SUITES
    };
    probe(host, port, version, suites, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_RANDOM: [u8; 32] = [0u8; 32];

    fn hello(version: TlsVersion, suites: &[u16]) -> Vec<u8> {
        build_client_hello("example.com", version, suites, &ZERO_RANDOM)
    }

    /// Re-parses a ClientHello the way a server would, to prove the length
    /// prefixes we wrote actually describe the bytes that follow them. A
    /// hand-built handshake message with one wrong length is the single most
    /// likely bug in this module and is invisible to "does it compile".
    fn reparse_client_hello(record: &[u8]) -> (u16, u16, Vec<u16>, usize) {
        assert_eq!(record[0], CONTENT_TYPE_HANDSHAKE);
        let record_version = u16::from_be_bytes([record[1], record[2]]);
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(
            record_len,
            record.len() - 5,
            "record length must match the bytes actually present"
        );

        let mut r = Reader::new(&record[5..]);
        assert_eq!(r.u8().unwrap(), 0x01, "handshake type must be ClientHello");
        let hs_len = r.u24().unwrap();
        assert_eq!(
            hs_len,
            r.remaining(),
            "handshake length must match the body present"
        );

        let client_version = r.u16().unwrap();
        r.take(32).unwrap();
        let sid = r.u8().unwrap() as usize;
        r.take(sid).unwrap();
        let suites_len = r.u16().unwrap() as usize;
        let suite_bytes = r.take(suites_len).unwrap();
        let suites: Vec<u16> = suite_bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let comp_len = r.u8().unwrap() as usize;
        r.take(comp_len).unwrap();

        let ext_len = if r.remaining() >= 2 {
            let n = r.u16().unwrap() as usize;
            let ext = r.take(n).unwrap();
            assert_eq!(ext.len(), n);
            n
        } else {
            0
        };
        assert_eq!(r.remaining(), 0, "no trailing bytes after extensions");
        (record_version, client_version, suites, ext_len)
    }

    #[test]
    fn client_hello_lengths_are_internally_consistent() {
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12] {
            let record = hello(version, ciphers::LEGACY_COMPATIBLE_SUITES);
            let (_, client_version, suites, ext_len) = reparse_client_hello(&record);
            assert_eq!(client_version, version.wire());
            assert_eq!(suites, ciphers::LEGACY_COMPATIBLE_SUITES);
            assert!(
                ext_len > 0,
                "{} hello should carry extensions",
                version.label()
            );
        }
    }

    #[test]
    fn sslv3_hello_carries_no_extensions_block_at_all() {
        // SSLv3 predates extensions; sending one is a real interop risk.
        let record = hello(TlsVersion::Ssl30, ciphers::LEGACY_COMPATIBLE_SUITES);
        let (record_version, client_version, _, ext_len) = reparse_client_hello(&record);
        assert_eq!(record_version, 0x0300);
        assert_eq!(client_version, 0x0300);
        assert_eq!(ext_len, 0);
    }

    #[test]
    fn hello_offers_only_the_suites_it_was_given() {
        // The whole weak-cipher technique depends on this: if anything extra
        // leaked into the list, a server picking a strong suite would be
        // misread as accepting a weak one.
        let only_rc4 = ciphers::Family::Rc4.suites();
        let record = hello(TlsVersion::Tls12, only_rc4);
        let (_, _, suites, _) = reparse_client_hello(&record);
        assert_eq!(suites, only_rc4);
    }

    #[test]
    fn hello_offers_null_compression_only() {
        let record = hello(TlsVersion::Tls12, &[0x002f]);
        // ...compression_methods sits right after the cipher suites: one
        // method, id 0. Offering DEFLATE would be a CRIME vector.
        let needle = [0x01u8, 0x00];
        let suites_marker = [0x00u8, 0x02, 0x00, 0x2f];
        let at = record
            .windows(4)
            .position(|w| w == suites_marker)
            .expect("suite list present");
        assert_eq!(&record[at + 4..at + 6], &needle);
    }

    #[test]
    fn hello_contains_the_sni_hostname_verbatim() {
        let record = build_client_hello("badssl.com", TlsVersion::Tls12, &[0x002f], &ZERO_RANDOM);
        assert!(record.windows(10).any(|w| w == b"badssl.com".as_slice()));
    }

    #[test]
    fn parses_a_tls12_server_hello() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xAA; 32]);
        body.push(0x00); // no session id
        body.extend_from_slice(&[0xC0, 0x2F]); // ECDHE-RSA-AES128-GCM-SHA256
        body.push(0x00); // null compression
        let hello = parse_server_hello(&body).unwrap();
        assert_eq!(hello.version, 0x0303);
        assert_eq!(hello.cipher_suite, 0xC02F);
    }

    #[test]
    fn a_tls13_server_hello_is_not_misread_as_tls12() {
        // TLS 1.3 freezes legacy_version at 0x0303 and puts the real version
        // in supported_versions. Reading legacy_version alone would report
        // every 1.3 server as 1.2 — a silent, plausible-looking wrong answer.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xBB; 32]);
        body.push(0x20);
        body.extend_from_slice(&[0xCC; 32]); // echoed session id
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x00);
        let ext = [0x00u8, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&ext);

        let hello = parse_server_hello(&body).unwrap();
        assert_eq!(hello.version, 0x0304);
        assert_eq!(hello.cipher_suite, 0x1301);
    }

    #[test]
    fn a_session_id_shifts_the_cipher_suite_offset_correctly() {
        let mut body = vec![0x03, 0x01];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x04);
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        body.extend_from_slice(&[0x00, 0x05]); // RC4-SHA
        body.push(0x00);
        let hello = parse_server_hello(&body).unwrap();
        assert_eq!(hello.version, 0x0301);
        assert_eq!(hello.cipher_suite, 0x0005);
    }

    #[test]
    fn truncated_server_hello_is_an_error_not_a_panic() {
        assert!(parse_server_hello(&[0x03]).is_err());
        assert!(parse_server_hello(&[0x03, 0x03, 0x00]).is_err());
        assert!(parse_server_hello(&[]).is_err());
    }

    #[test]
    fn parses_a_certificate_message_into_der_blobs_leaf_first() {
        let leaf = vec![0x30, 0x82, 0x01, 0x02];
        let intermediate = vec![0x30, 0x82, 0x02, 0x03, 0x04];
        let mut list = Vec::new();
        for c in [&leaf, &intermediate] {
            list.extend_from_slice(&[0, 0, c.len() as u8]);
            list.extend_from_slice(c);
        }
        let mut body = vec![0, 0, list.len() as u8];
        body.extend_from_slice(&list);

        let chain = parse_certificate_message(&body).unwrap();
        assert_eq!(chain, vec![leaf, intermediate]);
    }

    #[test]
    fn a_flight_yields_both_the_hello_and_the_chain() {
        let mut sh_body = vec![0x03, 0x03];
        sh_body.extend_from_slice(&[0x01; 32]);
        sh_body.push(0x00);
        sh_body.extend_from_slice(&[0xC0, 0x13]);
        sh_body.push(0x00);

        let cert = vec![0x30, 0x03, 0x01, 0x02];
        let mut list = vec![0, 0, cert.len() as u8];
        list.extend_from_slice(&cert);
        let mut cert_body = vec![0, 0, list.len() as u8];
        cert_body.extend_from_slice(&list);

        let mut flight = Vec::new();
        for (ty, body) in [
            (HANDSHAKE_SERVER_HELLO, &sh_body),
            (HANDSHAKE_CERTIFICATE, &cert_body),
        ] {
            flight.push(ty);
            let l = body.len();
            flight.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
            flight.extend_from_slice(body);
        }

        let parsed = parse_handshake_flight(&flight).unwrap();
        // A hello plus a certificate settles the probe even without a
        // ServerHelloDone — there is nothing else worth waiting for.
        assert!(parsed.is_settled());
        match parsed.into_outcome().unwrap() {
            Outcome::Accepted {
                version,
                cipher_suite,
                chain,
            } => {
                assert_eq!(version, 0x0303);
                assert_eq!(cipher_suite, 0xC013);
                assert_eq!(chain, vec![cert]);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn a_hello_alone_is_not_settled_so_the_certificate_is_not_thrown_away() {
        // The bug this pins: returning at the ServerHello discards the
        // Certificate message that arrives in the very next record, which is
        // the only way to inspect a TLS-1.0-only server's certificate at all.
        let mut sh_body = vec![0x03, 0x01];
        sh_body.extend_from_slice(&[0x01; 32]);
        sh_body.push(0x00);
        sh_body.extend_from_slice(&[0xC0, 0x14]);
        sh_body.push(0x00);

        let mut only_hello = vec![HANDSHAKE_SERVER_HELLO];
        let l = sh_body.len();
        only_hello.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        only_hello.extend_from_slice(&sh_body);

        let parsed = parse_handshake_flight(&only_hello).unwrap();
        assert!(parsed.hello.is_some());
        assert!(parsed.chain.is_empty());
        assert!(
            !parsed.is_settled(),
            "must keep reading for the certificate"
        );

        // ...but a ServerHelloDone with no certificate (TLS 1.3 encrypts it)
        // does settle: nothing more is coming in the clear.
        let mut with_done = only_hello.clone();
        with_done.extend_from_slice(&[HANDSHAKE_SERVER_HELLO_DONE, 0, 0, 0]);
        assert!(parse_handshake_flight(&with_done).unwrap().is_settled());
    }

    #[test]
    fn an_incomplete_flight_asks_for_more_bytes_instead_of_guessing() {
        // Says "nothing yet" rather than erroring, so a server that
        // fragments its ServerHello across two records still works.
        let partial = parse_handshake_flight(&[0x02, 0x00, 0x01]).unwrap();
        assert_eq!(partial, Flight::default());
        assert!(!partial.is_settled());
        assert_eq!(parse_handshake_flight(&[]).unwrap(), Flight::default());
    }

    #[test]
    fn a_version_downgrade_in_the_server_hello_does_not_count_as_acceptance() {
        // Asked for TLS 1.1, server answered TLS 1.0: that is a TLS-1.0-max
        // server, and reporting "TLS 1.1 accepted" here would be a false
        // positive on the most load-bearing thing this tool prints.
        let downgraded = Outcome::Accepted {
            version: 0x0301,
            cipher_suite: 0x002f,
            chain: vec![],
        };
        assert_eq!(downgraded.accepted_version(TlsVersion::Tls11), None);
        assert_eq!(downgraded.accepted_version(TlsVersion::Tls10), Some(0x0301));
    }

    #[test]
    fn rejections_and_silence_never_count_as_acceptance() {
        let rejected = Outcome::Rejected { alert: 70 };
        let silent = Outcome::NoAnswer("connection reset".into());
        for v in crate::proto::ALL {
            assert_eq!(rejected.accepted_version(*v), None);
            assert_eq!(silent.accepted_version(*v), None);
        }
    }

    #[test]
    fn alert_names_cover_the_refusals_a_probe_actually_provokes() {
        assert_eq!(alert_name(40), "handshake_failure");
        assert_eq!(alert_name(70), "protocol_version");
        assert_eq!(alert_name(71), "insufficient_security");
        assert_eq!(alert_name(200), "unknown alert");
    }

    #[test]
    fn reader_refuses_to_read_past_the_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.take(4).is_err());
        assert_eq!(r.take(3).unwrap(), &[1, 2, 3]);
        assert!(r.u8().is_err());
    }
}
