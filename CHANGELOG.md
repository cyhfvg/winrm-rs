# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **CRITICAL** — CredSSP outer TLS now validates the server certificate
  chain by default. Previously the outer HTTPS leg used a hardcoded
  `NoVerifier`, making the channel that carries CredSSP TSRequests
  vulnerable to MITM. The inner CredSSP TLS continues to use
  `SslVerifyMode::NONE` because authentication is provided by
  `pubKeyAuth` (MS-CSSP §3.1.5.1), which the client now also documents
  inline. (`src/auth/credssp.rs`)
- **HIGH** — Kerberos mutual authentication failures are now propagated.
  Previously `ctx.step(server_token)` was assigned to `_`, so a forged
  or missing server token silently passed. (`src/auth/kerberos.rs`)
- **HIGH** — Basic auth credentials are now stored in `SecretString` and
  built inside a `Zeroizing` buffer, ensuring the cleartext is wiped
  from heap memory immediately after base64-encoding. (`src/auth/basic.rs`)
- **HIGH** — NTLM CBT fallback (cert capture None while TLS active) now
  emits a `tracing::warn` so operators can detect silent regression to
  non-CBT auth. (`src/auth/ntlm.rs`)
- **MEDIUM** — `WinrmConfig.max_output_bytes` (new field, default 64
  MiB) caps cumulative stdout+stderr per command, preventing OOM via a
  malicious server streaming an unbounded base64 chunk sequence. Set to
  `None` to restore unbounded behaviour. (`src/config.rs`, `src/shell.rs`,
  `src/client.rs`)
- **MEDIUM** — NTLM unseal HMAC-MD5 comparison switched to
  `subtle::ConstantTimeEq`. (`src/ntlm/mod.rs`)
- **MEDIUM** — ASN.1 `decode_integer` rejects DER INTEGER payloads of
  length 0 or > 4 bytes, preventing silent u32 overflow on hostile
  TSRequests. (`src/asn1.rs`)
- **MEDIUM** — Type 2 NTLM challenge `target_info` parse now uses
  `checked_add` for offset+length bounds (32-bit safety).
  (`src/ntlm/messages.rs`)
- **MEDIUM** — HTTP redirects are no longer followed
  (`Policy::none()`); a 30x from the WinRM endpoint surfaces as an
  error rather than risking Authorization-header forwarding.
  Construction also emits `tracing::warn` when
  `accept_invalid_certs=true`. (`src/transport.rs`)
- **MEDIUM** — `encode_ts_credentials` returns `Zeroizing<Vec<u8>>`;
  intermediate plaintext credential buffers are wiped after CredSSP
  seal. (`src/asn1.rs`)
- **MEDIUM** — `endpoint()` sanitises the host argument (strips
  scheme / userinfo / path / port; preserves IPv6 literals) and logs a
  WARN when it had to clean anything. (`src/transport.rs`)
- **LOW** — PSRP Create envelope now `xml_escape`s the ShellId
  defensively. (`src/soap/envelope.rs`)
- **LOW** — `CertCapturingVerifier` logs an error when the mutex is
  poisoned, instead of silently dropping the captured cert.
  (`src/tls.rs`)
- **DEPS** — `cargo update -p rustls-webpki` (0.103.10 → 0.103.13)
  closes RUSTSEC-2026-0098, -0099, -0104.

### Added

- New dev-test `tests/security_regression.rs` pins HTTP redirect
  refusal as a public-API behaviour.
- `subtle 2.6` dependency (already present transitively through
  rustls/ring; promoted to a direct dep for the constant-time HMAC
  compare).

### Changed

- `WinrmConfig.accept_invalid_certs` doc comment now includes a
  `# Security` section explicitly stating the flag also disables CredSSP
  outer-TLS verification.

## [1.0.0] - 2026-04-12

### Highlights

First stable release. The public API (`WinrmClient`, `WinrmConfig`,
`WinrmCredentials`, `Shell`, `CommandOutput`, `WinrmError`) is now
considered stable and covered by SemVer guarantees.

### Breaking (relative to 0.5.0)

- Public surface reduced. The following items are no longer re-exported
  from the crate root and are now crate-internal:
  `create_authenticate_message_with_key`, `parse_challenge`,
  `parse_shell_id`, `parse_command_id`, `parse_receive_output`,
  `check_soap_fault`. They remain accessible to fuzz targets via the
  internal-only `__internal` feature (not part of the SemVer contract).

### Changed

- CredSSP (`--features credssp`) is now explicitly marked **experimental**
  in the crate docs and README. The handshake is not yet validated
  end-to-end; do not rely on it in production.

### Documentation

- `lib.rs` now documents the purpose of the `secrecy::SecretString` /
  `ExposeSecret` and `tokio_util::sync::CancellationToken` re-exports.
- README documents integration-test environment variables
  (`WINRM_TEST_HOST`, `WINRM_TEST_USER`, `WINRM_TEST_PASS`,
  `WINRM_TEST_PORT`) and how to invoke them.
- `Cargo.toml` now explains why `credssp` needs `openssl` (Microsoft
  CredSSP server incompatibility with `rustls` in-memory TLS).

## [0.5.0] - 2026-03-29

### Added

- File transfer: upload/download via PowerShell base64 chunking
- Streaming output: `start_command` + `receive_next` for incremental polling
- HTTP proxy support for all WinRM requests
- CI pipeline with fmt, clippy, test (Linux/macOS/Windows), coverage, doc, MSRV, audit, deny, fuzz, semver checks
- Integration tests for real WinRM endpoints
- Fuzz targets for NTLM, SOAP, and PowerShell encoding
- Release automation via GitHub Actions

## [0.4.0]

### Added

- Kerberos authentication via `cross-krb5` (feature-gated with `--features kerberos`)
- Certificate authentication (TLS client certificate)

## [0.3.0]

### Added

- NTLM sealing (message encryption)
- Credential security with `secrecy` and `zeroize`
- Retry with exponential backoff for transient HTTP errors

## [0.2.0]

### Added

- Shell reuse across multiple commands
- Stdin piping support

## [0.1.0]

### Added

- NTLMv2 authentication (pure Rust, no OpenSSL)
- Basic authentication
- PowerShell command execution (UTF-16LE Base64 encoded)
- Raw command execution (`cmd.exe` or any executable)
- Full shell lifecycle: create, execute, receive, signal, delete

[Unreleased]: https://github.com/muchiny/winrm-rs/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/muchiny/winrm-rs/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/muchiny/winrm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/winrm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/winrm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/winrm-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/winrm-rs/releases/tag/v0.1.0
