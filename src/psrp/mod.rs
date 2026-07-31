//! Real PSRP PowerShell execution for `WinrmClient::run_powershell`.
//!
//! All MS-PSRP framing lives in-tree under [`protocol`] (same crate as
//! winrm-rs — not a separate package). This module opens a PowerShell
//! shell, ferries fragments over WinRM, and maps failures to [`WinrmError`].

mod protocol;

use base64::Engine;
use tracing::debug;
use uuid::Uuid;

use crate::command::CommandOutput;
use crate::error::WinrmError;
use crate::soap::namespaces::RESOURCE_URI_PSRP;
use crate::WinrmClient;

use protocol::{
    DEST_SERVER, MT_CREATE_PIPELINE, MT_ERROR_RECORD, MT_PIPELINE_OUTPUT, MT_PIPELINE_STATE,
    MT_RUNSPACE_POOL_STATE, Reassembler, build_creation_fragments, create_pipeline_xml,
    encode_fragments, encode_psrp_message, extract_named_i32, extract_output_text,
};

/// Run a PowerShell script via real PSRP (RunspacePool + CreatePipeline).
///
/// # Errors
///
/// Returns [`WinrmError`] for transport, auth, SOAP, or protocol failures.
pub(crate) async fn run_powershell(
    client: &WinrmClient,
    host: &str,
    script: &str,
) -> Result<CommandOutput, WinrmError> {
    let rpid = Uuid::new_v4();
    let creation = build_creation_fragments(rpid).map_err(map_proto)?;
    let creation_b64 = base64::engine::general_purpose::STANDARD.encode(&creation);

    let shell = client
        .open_psrp_shell(host, &creation_b64, RESOURCE_URI_PSRP)
        .await?;
    let shell_id = shell.shell_id().to_string();
    debug!(%shell_id, %rpid, "PSRP shell opened");

    let mut next_oid = 3u64; // 1=SessionCapability, 2=InitRunspacePool already sent
    let mut reassembler = Reassembler::new();
    let mut command_id = shell_id.clone();

    // Drain until RunspacePool Opened (state code 2).
    let mut opened = false;
    for _ in 0..64 {
        let chunk = recv_chunk(&shell, &command_id).await?;
        for msg in reassembler.feed(&chunk).map_err(map_proto)? {
            if msg.message_type == MT_RUNSPACE_POOL_STATE
                && extract_named_i32(&msg.data, "RunspaceState") == Some(2)
            {
                opened = true;
                break;
            }
        }
        if opened {
            break;
        }
    }
    if !opened {
        let _ = shell.close().await;
        return Err(WinrmError::Psrp(
            "runspace pool did not reach Opened state".into(),
        ));
    }
    debug!("PSRP runspace pool opened");

    // CreatePipeline
    let pid = Uuid::new_v4();
    let pipeline_xml = create_pipeline_xml(script);
    let msg_bytes = encode_psrp_message(DEST_SERVER, MT_CREATE_PIPELINE, rpid, pid, &pipeline_xml);
    let frag = encode_fragments(next_oid, &msg_bytes);
    next_oid += 1;

    let b64 = base64::engine::general_purpose::STANDARD.encode(&frag);
    let pid_str = pid.hyphenated().to_string();
    command_id = shell
        .start_command_with_id("", &[&b64], &pid_str)
        .await?;
    debug!(%command_id, "PSRP CreatePipeline executed");

    // Collect output until PipelineState terminal.
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0i32;
    let mut done = false;

    for _ in 0..256 {
        let chunk = recv_chunk(&shell, &command_id).await?;
        for msg in reassembler.feed(&chunk).map_err(map_proto)? {
            match msg.message_type {
                MT_PIPELINE_OUTPUT => {
                    stdout.push_str(&extract_output_text(&msg.data));
                    if !stdout.ends_with('\n') {
                        stdout.push('\n');
                    }
                }
                MT_ERROR_RECORD => {
                    stderr.push_str(&extract_output_text(&msg.data));
                    if !stderr.ends_with('\n') {
                        stderr.push('\n');
                    }
                }
                MT_PIPELINE_STATE => {
                    if let Some(state) = extract_named_i32(&msg.data, "PipelineState") {
                        // 4=Completed, 5=Failed, 6=Stopped
                        if state == 4 || state == 5 || state == 6 {
                            if state == 5 {
                                exit_code = 1;
                            }
                            done = true;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        if done {
            break;
        }
    }

    if let Err(e) = shell.close().await {
        debug!(error = %e, "PSRP shell close failed (best-effort)");
    }

    if !done {
        return Err(WinrmError::Psrp(
            "pipeline did not reach a terminal state".into(),
        ));
    }

    let _ = next_oid;

    Ok(CommandOutput {
        stdout: stdout.into_bytes(),
        stderr: stderr.into_bytes(),
        exit_code,
    })
}

fn map_proto(e: protocol::PsrpProtocolError) -> WinrmError {
    WinrmError::Psrp(e.to_string())
}

async fn recv_chunk(shell: &crate::Shell<'_>, command_id: &str) -> Result<Vec<u8>, WinrmError> {
    loop {
        match shell.receive_next(command_id).await {
            Ok(out) => {
                if out.stdout.is_empty() && !out.done {
                    continue;
                }
                return Ok(out.stdout);
            }
            Err(WinrmError::Timeout(_)) => continue,
            Err(WinrmError::Soap(crate::error::SoapError::Fault {
                ref code,
                ref reason,
            })) if code.contains("TimedOut") => {
                debug!(%code, %reason, "PSRP long-poll TimedOut — retrying");
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Structural: PowerShell path stays in-tree PSRP, not EncodedCommand / external crate.
    #[test]
    fn run_powershell_is_in_tree_psrp() {
        let src = include_str!("mod.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(prod.contains("mod protocol"));
        assert!(prod.contains("open_psrp_shell"));
        assert!(prod.contains("build_creation_fragments"));
        assert!(!prod.contains("psrp_protocol::"));
        assert!(!prod.contains("EncodedCommand"));
        assert!(!prod.contains("powershell.exe"));
    }
}
