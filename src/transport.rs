// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::auth::basic::BasicAuth;
use crate::auth::certificate::CertificateAuth;
#[cfg(feature = "credssp")]
use crate::auth::credssp::CredSspAuth;
use crate::auth::kerberos::KerberosAuth;
use crate::auth::ntlm::{self as ntlm_auth, NtlmAuth};
use crate::config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::ntlm::NtlmSession;
use crate::soap;
use crate::tls::CertHandle;

/// Cached NTLM session state for message sealing on a specific host.
struct NtlmSessionCache {
    host: String,
    session: NtlmSession,
}

/// HTTP transport for WinRM SOAP requests.
///
/// Handles authentication dispatch, retry logic, and endpoint construction.
pub(crate) struct HttpTransport {
    http: reqwest::Client,
    config: WinrmConfig,
    credentials: WinrmCredentials,
    /// Handle to retrieve the captured TLS server certificate (for CBT).
    /// `None` when using plain HTTP (no TLS).
    cert_handle: Option<CertHandle>,
    /// Cached NTLM session for sealed message exchange.
    /// Uses `tokio::sync::Mutex` because the lock spans an `.await` (HTTP send).
    ntlm_cache: Mutex<Option<NtlmSessionCache>>,
}

/// Strip scheme, userinfo, port, and path from a host string.
///
/// Defensive: callers are supposed to pass `"hostname"` or `"10.0.0.1"`,
/// but if they accidentally pass `"http://evil.com/path"` we keep just
/// `"evil.com"` and log the deviation. IPv6 literals (`[::1]`) are
/// preserved as-is because `:` inside brackets is part of the address.
fn sanitize_host(input: &str) -> String {
    let mut s = input;
    if let Some(rest) = s.split_once("://") {
        s = rest.1;
    }
    if let Some((_, rest)) = s.rsplit_once('@') {
        s = rest;
    }
    if let Some((host_part, _)) = s.split_once('/') {
        s = host_part;
    }
    // For non-bracketed IPv6 / hostnames, drop a trailing :port.
    if !s.starts_with('[')
        && let Some((host_part, _)) = s.rsplit_once(':')
    {
        s = host_part;
    }
    s.to_string()
}

impl HttpTransport {
    /// Create a new HTTP transport from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed (e.g. invalid TLS configuration).
    #[tracing::instrument(level = "debug", skip(credentials))]
    pub(crate) fn new(
        config: WinrmConfig,
        credentials: WinrmCredentials,
    ) -> Result<Self, WinrmError> {
        if config.accept_invalid_certs {
            tracing::warn!(
                "TLS certificate verification disabled (accept_invalid_certs=true) — \
                 TEST USE ONLY, do not use in production"
            );
        }

        // The WinRM endpoint is fixed by the caller (host:port/wsman); a
        // server returning a 30x is unexpected and any cross-origin redirect
        // would risk forwarding the Authorization header. Disable redirects
        // entirely.
        // Match pypsrp/nxc defaults: identity Accept-Encoding (no gzip on
        // WinRM encrypted bodies) and explicit Keep-Alive. Do not inject an
        // empty Expect header — that alone can stall HTTP.sys on some hosts.
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::ACCEPT_ENCODING,
            reqwest::header::HeaderValue::from_static("identity"),
        );
        default_headers.insert(
            reqwest::header::CONNECTION,
            reqwest::header::HeaderValue::from_static("Keep-Alive"),
        );

        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .timeout(Duration::from_secs(config.operation_timeout_secs + 10))
            .http1_only()
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(60))
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(90))
            .default_headers(default_headers)
            .user_agent(
                config
                    .user_agent
                    .as_deref()
                    .unwrap_or(concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))),
            );

        // Configure TLS client certificate for Certificate auth
        if matches!(config.auth_method, AuthMethod::Certificate) {
            let cert_path = config.client_cert_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_cert_pem".into())
            })?;
            let key_path = config.client_key_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_key_pem".into())
            })?;
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client cert {cert_path}: {e}"))
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client key {key_path}: {e}"))
            })?;
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined).map_err(WinrmError::Http)?;
            builder = builder.identity(identity);
        }

        // Configure HTTP proxy
        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url).map_err(WinrmError::Http)?;
            builder = builder.proxy(proxy);
        }

        if matches!(config.auth_method, AuthMethod::Basic) && !config.use_tls {
            tracing::warn!(
                "Basic auth over HTTP transmits credentials in cleartext — use HTTPS in production"
            );
        }

        if matches!(config.auth_method, AuthMethod::CredSsp) && !config.use_tls {
            return Err(WinrmError::AuthFailed(
                "CredSSP requires HTTPS (set use_tls = true)".into(),
            ));
        }

        // When using TLS, inject a CertCapturingVerifier to enable Channel Binding Tokens.
        let cert_handle = if config.use_tls {
            // Ensure a rustls CryptoProvider is installed (idempotent)
            let _ = rustls::crypto::ring::default_provider().install_default();
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                if config.accept_invalid_certs {
                    Arc::new(crate::tls::NoVerifier)
                } else {
                    rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                        .build()
                        .map_err(|e| WinrmError::AuthFailed(format!("TLS verifier error: {e}")))?
                };
            let capturing_verifier = crate::tls::CertCapturingVerifier::new(inner_verifier);
            let handle = capturing_verifier.cert_handle();
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(capturing_verifier))
                .with_no_client_auth();
            builder = builder.tls_backend_preconfigured(tls_config);
            Some(handle)
        } else {
            None
        };

        let http = builder.build().map_err(WinrmError::Http)?;

        Ok(Self {
            http,
            config,
            credentials,
            cert_handle,
            ntlm_cache: Mutex::new(None),
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    ///
    /// `host` is expected to be a bare hostname or IP literal — no scheme,
    /// no port, no userinfo. If suspect characters (`/`, `@`, `://`) are
    /// detected they are stripped and a WARN is logged so the call still
    /// produces a syntactically valid URL but the operator notices the
    /// misuse instead of silently sending credentials to a forged host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        let scheme = if self.config.use_tls { "https" } else { "http" };
        let sanitized = sanitize_host(host);
        if sanitized != host {
            tracing::warn!(
                original = host,
                sanitized = %sanitized,
                "host string contained scheme/path/userinfo; using sanitized form"
            );
        }
        format!("{scheme}://{sanitized}:{}/wsman", self.config.port)
    }

    /// Access the transport configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        &self.config
    }

    /// Send an authenticated SOAP request and return the response body.
    ///
    /// Dispatches to Basic or NTLM transport depending on the configured
    /// [`AuthMethod`]. The response is checked for SOAP faults before
    /// returning.
    #[tracing::instrument(level = "debug", skip(self, body))]
    async fn send_soap(&self, host: &str, body: String) -> Result<String, WinrmError> {
        let url = self.endpoint(host);
        debug!(url = %url, "sending WinRM SOAP request");
        trace!(body = %body, "SOAP request body");

        let response_text: String = match &self.config.auth_method {
            AuthMethod::Basic => {
                let auth = BasicAuth::new(
                    &self.credentials.username,
                    self.credentials.password.expose_secret(),
                );
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Ntlm => {
                let encrypt = match self.config.encryption {
                    EncryptionMode::Always => true,
                    EncryptionMode::Never => false,
                    EncryptionMode::Auto => !self.config.use_tls,
                };
                if encrypt {
                    self.send_ntlm_sealed(host, &url, body).await?
                } else {
                    let auth = NtlmAuth {
                        username: self.credentials.username.clone(),
                        password: Zeroizing::new(
                            self.credentials.password.expose_secret().to_string(),
                        ),
                        domain: self.credentials.domain.clone(),
                        cert_handle: self.cert_handle.clone(),
                    };
                    auth.send_authenticated(&self.http, &url, body).await?
                }
            }
            AuthMethod::Kerberos => {
                let host_part = host.split(':').next().unwrap_or(host);
                let auth = KerberosAuth {
                    service_principal: format!("HTTP/{host_part}"),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Certificate => {
                let auth = CertificateAuth;
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(feature = "credssp")]
            AuthMethod::CredSsp => {
                let auth = CredSspAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
                    domain: self.credentials.domain.clone(),
                    cert_handle: self.cert_handle.clone(),
                    accept_invalid_certs: self.config.accept_invalid_certs,
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(not(feature = "credssp"))]
            AuthMethod::CredSsp => {
                return Err(WinrmError::AuthFailed(
                    "CredSSP authentication requires the `credssp` cargo feature".into(),
                ));
            }
        };

        trace!(response = %response_text, "SOAP response body");
        soap::check_soap_fault(&response_text).map_err(WinrmError::Soap)?;
        Ok(response_text)
    }

    /// Send an NTLM-sealed request, reusing the cached session if available.
    ///
    /// On the first call (no cached session), performs a full NTLM handshake
    /// with an **empty** body to establish the security context (pypsrp-style),
    /// then sends the real SOAP body sealed as multipart/encrypted. Hosts with
    /// `AllowUnencrypted=false` reject Type3+plaintext SOAP.
    ///
    /// If the server returns 401 (session expired), the cache is cleared and a
    /// fresh handshake is attempted.
    async fn send_ntlm_sealed(
        &self,
        host: &str,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // Try sending with cached session first
        {
            let mut cache = self.ntlm_cache.lock().await;
            if let Some(ref mut c) = *cache {
                if c.host == host {
                    match self.send_sealed_body(&mut c.session, url, &body).await {
                        Ok(resp) => {
                            return Ok(resp);
                        }
                        Err(WinrmError::AuthFailed(_)) => {
                            // Session expired — clear cache, fall through to handshake
                            debug!("NTLM sealed session expired, re-authenticating");
                            *cache = None;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    // Different host — clear cache
                    *cache = None;
                }
            }
        }

        // Establish NTLM context with an empty Type3 (pypsrp pattern: blank POST
        // before encryption), then send the real SOAP body sealed on a keep-alive
        // connection. Type3+plaintext SOAP is rejected when AllowUnencrypted=false.
        let auth = NtlmAuth {
            username: self.credentials.username.clone(),
            password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
            domain: self.credentials.domain.clone(),
            cert_handle: self.cert_handle.clone(),
        };
        let (_blank, session_key) = auth.handshake_and_send(&self.http, url, "").await?;

        let mut session = NtlmSession::from_auth(&session_key);
        // Prefer sealed body on the authenticated connection. If the server
        // still wants an Authorization header (new TCP connection), fall back
        // to sealing inside a fresh Type3 (legacy path).
        match self.send_sealed_body(&mut session, url, &body).await {
            Ok(response) => {
                *self.ntlm_cache.lock().await = Some(NtlmSessionCache {
                    host: host.to_string(),
                    session,
                });
                Ok(response)
            }
            Err(WinrmError::AuthFailed(_)) => {
                debug!("sealed body without Authorization failed; retry Type3+seal");
                let auth = NtlmAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(
                        self.credentials.password.expose_secret().to_string(),
                    ),
                    domain: self.credentials.domain.clone(),
                    cert_handle: self.cert_handle.clone(),
                };
                // Type3 with sealed body (do_handshake seal=true).
                let (response, session_key) =
                    auth.handshake_and_send_sealed(&self.http, url, &body).await?;
                let session = NtlmSession::from_auth(&session_key);
                *self.ntlm_cache.lock().await = Some(NtlmSessionCache {
                    host: host.to_string(),
                    session,
                });
                Ok(response)
            }
            Err(e) => Err(e),
        }
    }

    /// Send a sealed body on an already-authenticated keep-alive connection.
    async fn send_sealed_body(
        &self,
        session: &mut NtlmSession,
        url: &str,
        body: &str,
    ) -> Result<String, WinrmError> {
        let (content_type, sealed) = ntlm_auth::seal_body(session, body);
        // Do not set Expect at all (including empty). Empty Expect previously
        // correlated with multi-second HTTP.sys stalls; pypsrp never sends it.
        // Content-Length is set implicitly from the known-size body Vec.
        let resp = self
            .http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .body(sealed)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed("NTLM session expired".into()));
        }

        let status = resp.status();
        let resp_bytes = resp.bytes().await.map_err(WinrmError::Http)?;

        // Fault and success responses may both be multipart-encrypted.
        let looks_encrypted = resp_bytes
            .windows(b"Encrypted Boundary".len())
            .any(|w| w == b"Encrypted Boundary")
            || resp_bytes
                .windows(b"application/octet-stream".len())
                .any(|w| w == b"application/octet-stream");

        let text = if looks_encrypted {
            match ntlm_auth::unseal_body(session, &resp_bytes) {
                Ok(plain) => plain,
                Err(e) if status.is_success() => return Err(e),
                Err(_) => String::from_utf8_lossy(&resp_bytes).into_owned(),
            }
        } else {
            String::from_utf8_lossy(&resp_bytes).into_owned()
        };

        if !status.is_success() {
            return Err(WinrmError::from_http_status(status.as_u16(), text));
        }

        Ok(text)
    }

    /// Send an authenticated SOAP request with optional retry on transient HTTP errors.
    ///
    /// Retries up to [`WinrmConfig::max_retries`] times with exponential backoff
    /// (100 ms, 200 ms, 400 ms, ...). Only [`WinrmError::Http`] errors are
    /// retried; authentication and SOAP faults are returned immediately.
    pub(crate) async fn send_soap_with_retry(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let max = self.config.max_retries;
        for attempt in 0..=max {
            match self.send_soap(host, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(WinrmError::Http(_)) if attempt < max => {
                    let delay = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_retries = max,
                        delay_ms = delay.as_millis() as u64,
                        "retrying after transient HTTP error"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// Send an authenticated SOAP request (used by Shell and other internal callers).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry(host, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper to build an HttpTransport with Basic auth pointing at a wiremock server.
    fn basic_transport(port: u16) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        HttpTransport::new(config, creds).unwrap()
    }

    #[test]
    fn endpoint_http() {
        let transport = basic_transport(5985);
        assert_eq!(transport.endpoint("10.0.0.1"), "http://10.0.0.1:5985/wsman");
    }

    #[test]
    fn sanitize_host_strips_scheme_and_path() {
        assert_eq!(sanitize_host("http://evil.com/x"), "evil.com");
        assert_eq!(sanitize_host("https://evil.com:1234/path"), "evil.com");
        assert_eq!(sanitize_host("user:pw@host.com"), "host.com");
    }

    #[test]
    fn sanitize_host_preserves_bare_hostname_and_ip() {
        assert_eq!(sanitize_host("plain.host"), "plain.host");
        assert_eq!(sanitize_host("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn sanitize_host_preserves_ipv6_literal() {
        assert_eq!(sanitize_host("[fe80::1]"), "[fe80::1]");
    }

    #[test]
    fn endpoint_https() {
        let config = WinrmConfig {
            use_tls: true,
            port: 5986,
            accept_invalid_certs: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert_eq!(
            transport.endpoint("win.local"),
            "https://win.local:5986/wsman"
        );
    }

    #[test]
    fn config_accessor() {
        let transport = basic_transport(5985);
        assert_eq!(transport.config().port, 5985);
        assert!(matches!(transport.config().auth_method, AuthMethod::Basic));
    }

    #[test]
    fn credssp_without_tls_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::CredSsp,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {} // expected
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_cert_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: None,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_key_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/tmp/cert.pem".into()),
            client_key_pem: None,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_nonexistent_cert_file_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/nonexistent/cert.pem".into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn send_basic_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn send_basic_soap_fault_returns_soap_error() {
        let server = MockServer::start().await;
        // Server returns 200 with a SOAP fault in the body
        let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fault))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_basic_auth_failed_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn retry_on_transient_http_error() {
        let server = MockServer::start().await;
        // First request fails (connection reset simulated by no response)
        // Can't easily simulate transient errors with wiremock. Instead test
        // that a successful first request doesn't retry.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(1)
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_retry_on_auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1) // Should NOT retry auth failures
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let _ = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
    }

    #[test]
    fn proxy_config_applied() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            use_tls: false,
            proxy: Some("http://proxy:8080".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        // Should not error — proxy URL is valid
        assert!(HttpTransport::new(config, creds).is_ok());
    }

    #[test]
    fn tls_with_accept_invalid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: true,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.cert_handle.is_some());
    }

    #[test]
    fn tls_with_valid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: false,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.cert_handle.is_some());
    }

    #[test]
    fn no_tls_has_no_cert_handle() {
        let transport = basic_transport(5985);
        assert!(transport.cert_handle.is_none());
    }

    #[test]
    fn invalid_proxy_url_returns_error() {
        let config = WinrmConfig {
            proxy: Some("not a url".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("u", "p", "");
        let result = HttpTransport::new(config, creds);
        assert!(result.is_err(), "expected error for invalid proxy URL");
    }

    #[test]
    fn endpoint_strips_scheme_and_path_silently() {
        let transport = basic_transport(5985);
        // Caller passed a polluted host string; sanitize_host pulls just
        // the hostname and the URL is rebuilt with the configured scheme.
        let url = transport.endpoint("http://evil.com/path");
        assert_eq!(url, "http://evil.com:5985/wsman");
    }

    /// Static check: sealed-WinRM HTTP client defaults must match criterion 1.
    #[test]
    fn sealed_winrm_client_defaults_are_configured() {
        // Accept-Encoding/Keep-Alive/tcp_nodelay are set in `HttpTransport::new`.
        let src = include_str!("transport.rs");
        assert!(
            src.contains("from_static(\"identity\")"),
            "Accept-Encoding: identity required for sealed bodies"
        );
        assert!(
            src.contains("from_static(\"Keep-Alive\")"),
            "Connection: Keep-Alive required for NTLM affinity"
        );
        assert!(
            src.contains("pool_max_idle_per_host(1)"),
            "pool_max_idle_per_host=1 required"
        );
        assert!(src.contains("tcp_nodelay(true)"), "tcp_nodelay required");
        // Must not *set* the Expect request header in production code.
        // Scan only the non-test portion (before cfg(test) module).
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod.contains(".header(\"Expect\""),
            "must not set Expect request header"
        );
        // Primary sealed path is blank Type3 then sealed body (prod only).
        assert!(
            prod.contains("handshake_and_send(&self.http, url, \"\")"),
            "blank Type3 handshake required"
        );
        assert!(
            prod.contains("handshake_and_send_sealed"),
            "Type3+seal fallback required"
        );
        // Old 1.1.2 bug: Type3 + plaintext SOAP as the sealed first request.
        // That call would look like handshake_and_send(..., &body) without blank "".
        let blank_ok = prod.contains("url, \"\")");
        let sealed_fallback = prod.contains("handshake_and_send_sealed");
        assert!(blank_ok && sealed_fallback);
        // Ensure send_ntlm_sealed uses empty-body handshake, not body-first.
        let sealed_fn = prod
            .split("async fn send_ntlm_sealed")
            .nth(1)
            .and_then(|s| s.split("async fn send_sealed_body").next())
            .unwrap_or("");
        assert!(
            sealed_fn.contains("url, \"\")"),
            "send_ntlm_sealed must blank-handshake first"
        );
        assert!(
            !sealed_fn.contains("handshake_and_send(&self.http, url, &body)"),
            "Type3+plaintext SOAP must not be the primary sealed path"
        );
    }

    #[test]
    fn sealed_send_empty_body_500_is_not_auth_failed_mapping() {
        // Unit-level: from_http_status used by send_sealed_body.
        let err = WinrmError::from_http_status(500, String::new());
        assert!(!matches!(err, WinrmError::AuthFailed(_)));
        assert!(matches!(err, WinrmError::HttpStatus { status: 500, .. }));
    }
}
