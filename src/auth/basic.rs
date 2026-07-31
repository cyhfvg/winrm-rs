// HTTP Basic authentication transport for WinRM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// Basic authentication transport.
///
/// Sends credentials as a base64-encoded `Authorization: Basic` header on
/// every request. Only safe over HTTPS. The encoded credentials are kept
/// in a [`SecretString`] so the buffer is zeroized on drop.
pub(crate) struct BasicAuth {
    pub(crate) credentials_b64: SecretString,
}

impl BasicAuth {
    /// Create a new `BasicAuth` from username and password.
    pub(crate) fn new(username: &str, password: &str) -> Self {
        // Build "user:pass" inside a Zeroizing buffer so the cleartext
        // never lingers after we've base64-encoded it.
        let raw = Zeroizing::new(format!("{username}:{password}"));
        let encoded = B64.encode(raw.as_bytes());
        Self {
            credentials_b64: SecretString::from(encoded),
        }
    }
}

impl AuthTransport for BasicAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(
                AUTHORIZATION,
                format!("Basic {}", self.credentials_b64.expose_secret()),
            )
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            // 401/403 = credential / access rejection for Basic.
            // Other statuses (empty 500, SOAP faults, …) use the shared
            // layering so post-auth failures are not mislabeled AuthFailed.
            if status == 401 || status == 403 {
                return Err(WinrmError::AuthFailed(format!(
                    "HTTP {status} from WinRM: {body}"
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
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn new_encodes_credentials_base64() {
        let auth = BasicAuth::new("admin", "p@ss");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth.credentials_b64.expose_secret())
            .unwrap();
        assert_eq!(decoded, b"admin:p@ss");
    }

    #[tokio::test]
    async fn send_success_returns_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("admin", "pass");
        let result = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn send_403_returns_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("user", "wrong");
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_500_with_soap_fault_returns_soap_error() {
        let server = MockServer::start().await;
        let fault_body = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(fault_body))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("user", "pass");
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_500_without_soap_fault_returns_http_status_not_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("user", "pass");
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::HttpStatus { status: 500, .. }),
            "expected HttpStatus, got: {err}"
        );
        assert!(
            !matches!(err, WinrmError::AuthFailed(_)),
            "empty/non-fault 500 must not be AuthFailed"
        );
    }

    #[tokio::test]
    async fn send_empty_body_500_is_not_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(""))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("user", "pass");
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        match err {
            WinrmError::HttpStatus { status: 500, body } => assert!(body.is_empty()),
            other => panic!("expected HttpStatus empty 500, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_401_returns_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = BasicAuth::new("user", "wrong");
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }
}
