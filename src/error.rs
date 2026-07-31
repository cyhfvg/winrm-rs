// Consolidated error types for the winrm-rs crate.
//
// All error enums live here to avoid circular dependencies between modules.

/// Errors that can occur during WinRM operations.
///
/// Variants cover the full error surface: HTTP transport, authentication
/// handshake, NTLM protocol, SOAP-level faults, and operation timeouts.
///
/// # Auth vs post-auth failures
///
/// [`WinrmError::AuthFailed`] is reserved for **real authentication rejection**
/// (notably HTTP 401 during NTLM). Post-auth HTTP 500, SOAP AccessDenied, empty
/// body 500, and unseal/MIME failures use other variants so callers (e.g. brute
/// force tools) do not treat "password ok but shell denied" as bad credentials.
#[derive(Debug, thiserror::Error)]
pub enum WinrmError {
    /// HTTP transport error from `reqwest` (connection refused, timeout, TLS, etc.).
    #[error("WinRM HTTP error: {0}")]
    Http(reqwest::Error),
    /// Non-success HTTP status that is **not** an authentication rejection.
    ///
    /// Used for e.g. empty-body HTTP 500 after a successful NTLM Type3, where
    /// the password was accepted but the WinRM operation failed. Never used for
    /// HTTP 401 (that is always [`Self::AuthFailed`]).
    #[error("WinRM HTTP status {status}: {body}")]
    HttpStatus {
        /// HTTP status code (e.g. 500).
        status: u16,
        /// Response body (may be empty).
        body: String,
    },
    /// Authentication was rejected by the server (bad credentials / HTTP 401
    /// during NTLM, missing auth headers, CBT mismatch on Type3).
    #[error("WinRM auth failed: {0}")]
    AuthFailed(String),
    /// NTLM protocol error (malformed challenge message, bad signature, unseal, etc.).
    #[error("WinRM NTLM error: {0}")]
    Ntlm(NtlmError),
    /// SOAP-level fault or XML parsing error returned by the WinRM service.
    #[error("WinRM SOAP error: {0}")]
    Soap(SoapError),
    /// The operation exceeded the configured timeout.
    #[error("WinRM operation timed out after {0}s")]
    Timeout(u64),
    /// File transfer error (upload or download failure).
    #[error("file transfer error: {0}")]
    Transfer(String),
    /// The operation was cancelled via a [`CancellationToken`](tokio_util::sync::CancellationToken).
    #[error("operation cancelled")]
    Cancelled,
    /// CredSSP protocol error.
    #[error("CredSSP error: {0}")]
    CredSsp(CredSspError),
    /// PSRP (PowerShell Remoting Protocol) error.
    #[error("WinRM PSRP error: {0}")]
    Psrp(String),
}

impl WinrmError {
    /// Map a non-success HTTP response after NTLM to the correct variant.
    ///
    /// - 401 → [`Self::AuthFailed`]
    /// - 500 with SOAP fault body → [`Self::Soap`]
    /// - anything else (including empty-body 500) → [`Self::HttpStatus`]
    pub(crate) fn from_http_status(status: u16, body: String) -> Self {
        if status == 401 {
            return Self::AuthFailed(format!("HTTP {status}: {body}"));
        }
        if status == 500
            && let Err(soap_err) = crate::soap::parser::check_soap_fault(&body)
        {
            return Self::Soap(soap_err);
        }
        Self::HttpStatus { status, body }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_http_status_401_is_auth_failed() {
        let err = WinrmError::from_http_status(401, "denied".into());
        assert!(matches!(err, WinrmError::AuthFailed(_)));
    }

    #[test]
    fn from_http_status_empty_500_is_not_auth_failed() {
        let err = WinrmError::from_http_status(500, String::new());
        match err {
            WinrmError::HttpStatus { status: 500, body } => assert!(body.is_empty()),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn from_http_status_500_access_denied_soap_is_soap() {
        let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value>
          <s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code>
          <s:Reason><s:Text>Access is denied.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        let err = WinrmError::from_http_status(500, fault.into());
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap, got {err:?}"
        );
        assert!(!matches!(err, WinrmError::AuthFailed(_)));
    }

    #[test]
    fn from_http_status_503_is_http_status() {
        let err = WinrmError::from_http_status(503, "busy".into());
        match err {
            WinrmError::HttpStatus {
                status: 503,
                body,
            } => assert_eq!(body, "busy"),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}

/// Errors from the CredSSP authentication protocol (MS-CSSP).
#[derive(Debug, thiserror::Error)]
pub enum CredSspError {
    /// ASN.1 DER encoding or decoding error.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),
    /// Server public key verification failed (possible MiTM).
    #[error("server public key mismatch")]
    PublicKeyMismatch,
    /// Server returned an NTSTATUS error code.
    #[error("server error: {0:#010x}")]
    ServerError(u32),
}

/// Errors from SOAP envelope parsing or WS-Management fault responses.
#[derive(Debug, thiserror::Error)]
pub enum SoapError {
    /// A required XML element (e.g. `ShellId`, `CommandId`) was not found in
    /// the response body.
    #[error("missing element: {0}")]
    MissingElement(String),
    /// The response body could not be parsed (e.g. invalid base64 in a stream).
    #[error("parse error: {0}")]
    ParseError(String),
    /// The WinRM service returned a SOAP fault with the given code and reason.
    #[error("SOAP fault [{code}]: {reason}")]
    Fault {
        /// Fault code, typically a WS-Addressing or WS-Management URI.
        code: String,
        /// Human-readable fault reason from the server.
        reason: String,
    },
}

/// Errors from the NTLM authentication protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum NtlmError {
    /// The NTLM message is structurally invalid: too short, bad signature,
    /// wrong message type, or corrupt base64.
    #[error("NTLM error: {0}")]
    InvalidMessage(String),
}
