// Certificate-based authentication for WinRM.
//
// Uses client TLS certificates for authentication. The certificate
// must be configured on the WinRM service.

use reqwest::header::CONTENT_TYPE;

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// Certificate authentication transport.
///
/// Certificate auth uses TLS client cert -- no Authorization header needed.
/// The `reqwest::Client` must be configured with the cert at construction time.
pub(crate) struct CertificateAuth;

impl AuthTransport for CertificateAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            // TLS client-cert rejection is often 401/403; other statuses
            // (e.g. empty 500) must not look like bad credentials.
            if status == 401 || status == 403 {
                return Err(WinrmError::AuthFailed(format!(
                    "Certificate auth HTTP {status}: {body}"
                )));
            }
            return Err(WinrmError::from_http_status(status, body));
        }

        resp.text().await.map_err(WinrmError::Http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn certificate_auth_sends_without_authorization_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = CertificateAuth;
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn certificate_auth_failure_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = CertificateAuth;
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("403") || err.contains("Certificate"),
            "error should mention status or auth type: {err}"
        );
    }
}
