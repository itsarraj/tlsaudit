# tlsaudit

A deep TLS *configuration* audit of a live endpoint: which protocol versions
a server still accepts, whether it would take a genuinely weak cipher, and
whether its certificate chain holds up. The tool everyone reaches for here is
`testssl.sh` — excellent, and 20k lines of Bash driving a patched OpenSSL
binary, which makes it awkward to drop into a container or a CI job. This is
a single static binary that does the same class of check.

Distinct from this workspace's `certwatch`, deliberately: that one answers
"when does this cert expire", which is a cron-and-forget question. This one
answers "is this endpoint's TLS configuration actually defensible", which is
a thing you ask once per deploy and then argue about in a ticket.

## Usage

```bash
tlsaudit github.com                          # defaults to :443
tlsaudit tls-v1-0.badssl.com:1010            # host:port
tlsaudit api.example.com www.example.com     # several at once

tlsaudit example.com --warn-days 60          # stricter expiry threshold
tlsaudit example.com --fail-on critical      # only criticals exit non-zero
tlsaudit example.com --no-cipher-probes      # skip the six weak-suite probes
```

Exit code is `1` when anything at or above `--fail-on` (default `warn`) is
found, `0` otherwise — cron- and CI-friendly by design.

## How it actually probes

The interesting problem is that **a correct TLS client is the wrong tool for
this job.** rustls will not speak TLS 1.0, will not offer RC4, and cannot be
configured into doing either — which is exactly right for a client and
useless for finding out whether a server would have said yes.

So `tlsaudit` splits the work:

- **SSLv3 / TLS 1.0 / TLS 1.1** — `src/probe.rs` builds the ClientHello byte
  by byte, writes it to a plain `TcpStream`, and parses the ServerHello (or
  alert) that comes back. No cryptography is implemented and no handshake is
  ever completed: the connection is dropped right after the server's first
  flight, because "did you send a ServerHello or an alert" is the whole
  question and it is answerable without doing any key exchange.
- **TLS 1.2 / TLS 1.3** — rustls, pinned to one version at a time. It is a
  real TLS implementation and there is no reason to hand-roll what it
  already does correctly.
- **Weak ciphers** — a hand-built ClientHello offering *nothing but* one weak
  family (NULL, export-grade, RC4, single DES, 3DES, anonymous DH), retried
  at each accepted version below TLS 1.3. This is the same "offer only the
  bad stuff and see if it bites" technique `testssl.sh` uses; it finds what a
  server *would accept*, not merely what it prefers.
- **Certificate trust** — a normal, fully-validating rustls handshake against
  the Mozilla root store from `webpki-roots`. Real path building and
  signature verification, not a reimplementation.

Two consequences of that split are worth stating plainly. The certificate
inspection handshake uses an accept-anything verifier, for the same reason
`certwatch` does: normal trust validation would make the handshake fail on
exactly the endpoints this tool exists to examine. It is never used to decide
whether anything is trustworthy — that is what the separate `verify_trust`
pass is for, and the two are reported as separate findings.

And because the pre-TLS-1.3 `Certificate` message is sent in the clear, the
raw probe can read a certificate off a server **rustls refuses to talk to at
all**. That is not a nicety: it is the only reason `tls-v1-0.badssl.com:1010`
gets a certificate report below instead of a shrug.

## What it deliberately does not check

Being precise about this, because a security tool that implies coverage it
does not have is worse than no tool:

- **SSLv2 is not probed.** A v2 ClientHello is a different record format
  entirely, not a version field change, so it needs a second message builder.
  Deferred, and the practical cost is near zero in 2026.
- **The SSLv3 probe sends no SNI.** SSLv3 predates the extensions mechanism,
  so there is nowhere to put a hostname. Against a name-based virtual host, a
  refusal could in principle be "wrong vhost" rather than "SSLv3 is off". In
  practice every endpoint tested below refused it outright, which is the
  expected answer either way — but it is a real ambiguity, not a solved one.
- **Cipher coverage is the six catalogued families, not an enumeration.** A
  full "what does this server support" sweep is ~350 single-suite probes.
  This asks six specific questions with known-bad answers instead.
- **Chain trust cannot be established for a pre-TLS-1.2-only server.** rustls
  will not complete a validating handshake at TLS 1.0/1.1, so there is no
  honest way to say whether such a server's chain is trusted. It is reported
  as `not verified — …` rather than guessed in either direction. The
  certificate's *own* properties (expiry, SANs, hostname) are still checked
  from the cleartext chain.
- **Self-signed detection is a heuristic**: subject equals issuer, and the
  presented chain has no intermediates. It does not verify the leaf's
  signature against its own public key. A self-issued root sent alongside a
  real chain is reported as a warning rather than a critical, since that is
  sloppiness rather than compromise.
- **No revocation checking** (OCSP, CRL) — a genuinely different problem.
- **No key-size or DH-parameter checks.** Logjam-style small DH groups and
  undersized RSA keys need the `ServerKeyExchange` parsed and the public key
  measured; neither is done. Nor are SHA-1 certificate signatures, TLS
  compression, or renegotiation flagged. All real gaps, all deferred.
- **Probes are sequential**, one connection at a time — about a dozen
  connections per target. Fine for a deploy check, would want parallelising
  for a large fleet.

## Status: built, and every finding below is real output against a live internet endpoint

- **72 unit tests** (`cargo test --lib`), all pure — no test in the suite
  opens a socket, so CI on a network-restricted runner is unaffected (the
  same arrangement `certwatch` uses). They cover: the severity classification
  for every protocol version and every cipher family; the wire codes against
  the RFCs; **the hand-built ClientHello re-parsed the way a server would
  parse it**, asserting each length prefix actually describes the bytes that
  follow it, that an SSLv3 hello carries no extensions block, that only null
  compression is offered, and that the hello offers *exactly* the suites it
  was handed and nothing extra (the whole weak-cipher technique is worthless
  if that leaks); ServerHello parsing including **a TLS 1.3 hello not being
  misread as 1.2** via the `supported_versions` indirection, and a non-empty
  session id correctly shifting the cipher-suite offset; that a truncated or
  garbage response is an error rather than a panic; that a *downgraded*
  ServerHello does not count as acceptance; wildcard SAN matching against the
  real browser rules (one label only, not the parent domain, not a non-
  leftmost `*`); a hand-rolled civil-date conversion checked against a real
  leap day; and certificate parsing against **an actual certificate generated
  with `rcgen`**, not a hand-written DER fixture.

- **Live-verified against badssl.com and github.com.** The outputs below are
  copied from real runs, not reconstructed:

  - `github.com` — the clean reference. Zero findings:

    ```
      [ ok ] TLS 1.0       refused (alert 70: protocol_version)
      [ ok ] TLS 1.2       accepted (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
      [ ok ] TLS 1.3       accepted (TLS13_AES_128_GCM_SHA256)
      [ ok ] RC4           refused (TLS 1.2: handshake_failure)
      [ ok ] chain trust   verified against the Mozilla root store (incl. hostname)

    RESULT: 0 critical, 0 warning(s) — worst: ok
    ```

    Exit code `0`. Raising `--warn-days` past the cert's remaining 71 days
    correctly flipped `validity` from `ok` to `WARN`.

  - `tls-v1-0.badssl.com:1010` — **the case that justifies the hand-built
    ClientHello.** rustls cannot reach this server at all; the raw probe
    negotiates with it:

    ```
      [ ok ] SSL 3.0       refused (alert 40: handshake_failure)
      [WARN] TLS 1.0       accepted (TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA) — TLS 1.0 is deprecated by RFC 8996
      [ ok ] TLS 1.1       not offered (server answered with TLS 1.0)
      [ ok ] TLS 1.2       not offered (received fatal alert: HandshakeFailure)
      [ ok ] subject       CN=*.badssl.com (issuer C=US, O=Let's Encrypt, CN=YR2)
      [WARN] chain trust   not verified — server offers no TLS 1.2/1.3 listener for a validating client to use
    ```

    Note the TLS 1.1 line: the server answered a TLS 1.1 hello with a *TLS
    1.0* ServerHello, and that is correctly reported as "not offered" rather
    than counted as acceptance. And the certificate was read out of the
    cleartext `Certificate` message of a TLS 1.0 handshake — a chain rustls
    could never have fetched.

  - `tls-v1-1.badssl.com:1011` — `[WARN] TLS 1.1 accepted
    (TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)`, with SSLv3 and TLS 1.0 both
    reported as not offered (this listener answers those with a TCP reset
    rather than an alert, which is reported verbatim: `no TLS response
    (Connection reset by peer (os error 104))` — "reset the connection" and
    "sent a protocol_version alert" are different facts about a server and
    are not collapsed into one).

  - `rc4.badssl.com` — weak cipher genuinely caught:

    ```
      [CRIT] RC4           ACCEPTED at TLS 1.1 (TLS_ECDHE_RSA_WITH_RC4_128_SHA) — RC4 is prohibited by RFC 7465
      [ ok ] NULL cipher   refused (TLS 1.1: handshake_failure; TLS 1.0: handshake_failure)
      [ ok ] 3DES          refused (TLS 1.1: handshake_failure; TLS 1.0: handshake_failure)
    ```

  - `3des.badssl.com` — `[WARN] 3DES ACCEPTED at TLS 1.1
    (TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)`, correctly a warning rather than a
    critical (Sweet32 needs an impractically long-lived connection).

  - `expired.badssl.com` — two criticals, from two independent paths:

    ```
      [CRIT] validity      EXPIRED — not_after 2015-04-12 (-4178 day(s))
      [CRIT] chain trust   certificate has expired (certificate expired: verification time
                           1789820477 (UNIX), but certificate is not valid after 1428883199)
    ```

    The first is this crate's own X.509 parsing, the second is rustls's
    verifier — they agree, which is the point of running both. This endpoint
    also turned up findings badssl does not advertise: TLS 1.0, TLS 1.1 *and*
    3DES are all still enabled on it.

  - `self-signed.badssl.com` — `[CRIT] self-signed yes — subject equals
    issuer and the chain has no intermediates`, alongside `[CRIT] chain trust
    issuer is not in the Mozilla root store (self-signed or untrusted CA)`.
    The certificate itself is read successfully despite being untrusted,
    which is what proves the accept-any inspection verifier does what it
    claims rather than merely compiling.

  - `wrong.host.badssl.com` — `[CRIT] hostname NO MATCH for
    wrong.host.badssl.com in 2 SAN(s) or CN *.badssl.com`, matching rustls's
    own verdict (`certificate is only valid for DnsName("*.badssl.com") or
    DnsName("badssl.com")`). The wildcard rules are applied correctly: the
    cert's `*.badssl.com` covers `rc4.badssl.com` but not this four-label
    name.

  - **`null.badssl.com` did not behave as its name suggests** — it refuses
    every version this tool probes (`handshake_failure` at SSLv3 through
    TLS 1.1, and to rustls at 1.2/1.3), so no NULL-cipher acceptance could be
    confirmed against it. Reported here as what it is: a negative result from
    an endpoint that appears no longer to serve a working TLS listener, not a
    validation of the NULL-cipher probe. `dh480.badssl.com` was likewise not
    exercised, since undersized DH parameters are outside what this tool
    checks at all.

  - A port with nothing listening (`badssl.com:4499`) produces a clean
    per-probe `not checked — connecting to …` warning rather than a hang, a
    panic, or — importantly — a misleading `not offered`. A connection
    failure is not evidence that a protocol version is disabled, and an
    earlier version of this reported it as one; that distinction is now
    explicit in the code and in the output.

**Not done / deliberately deferred**: everything in "What it deliberately
does not check" above — SSLv2, full cipher enumeration, revocation, key and
DH parameter sizing, SHA-1 signatures, and concurrent probing.
