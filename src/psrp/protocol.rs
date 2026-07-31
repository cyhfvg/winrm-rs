//! In-crate MS-PSRP framing (fragments, messages, CLIXML templates).
//!
//! Lives entirely inside `winrm-rs` (`src/psrp/protocol.rs`) — not a separate
//! package. Templates/framing adapted from the MS-PSRP wire format (same
//! lineage as pypsrp / historical psrp-rs notes).

use std::collections::HashMap;

use uuid::Uuid;

/// Fixed PSRP message header length (destination + type + RPID + PID).
pub(crate) const HEADER_LEN: usize = 40;
/// Fragment header length (object id + fragment id + flags + length).
pub(crate) const FRAGMENT_HEADER_LEN: usize = 21;
const FLAG_START: u8 = 0x01;
const FLAG_END: u8 = 0x02;
/// Max payload bytes per fragment (matches pypsrp default).
pub(crate) const MAX_FRAGMENT_PAYLOAD: usize = 32 * 1024;

/// Message type: SessionCapability.
pub(crate) const MT_SESSION_CAPABILITY: u32 = 0x0001_0002;
/// Message type: InitRunspacePool.
pub(crate) const MT_INIT_RUNSPACE_POOL: u32 = 0x0001_0004;
/// Message type: RunspacePoolState.
pub(crate) const MT_RUNSPACE_POOL_STATE: u32 = 0x0002_1005;
/// Message type: CreatePipeline.
pub(crate) const MT_CREATE_PIPELINE: u32 = 0x0002_1006;
/// Message type: PipelineOutput.
pub(crate) const MT_PIPELINE_OUTPUT: u32 = 0x0004_1004;
/// Message type: ErrorRecord.
pub(crate) const MT_ERROR_RECORD: u32 = 0x0004_1005;
/// Message type: PipelineState.
pub(crate) const MT_PIPELINE_STATE: u32 = 0x0004_1006;

/// Destination: server (client-originated).
pub(crate) const DEST_SERVER: u32 = 2;
/// Destination: client (server-originated).
#[allow(dead_code)]
pub(crate) const DEST_CLIENT: u32 = 1;

/// Protocol-layer errors (no HTTP).
#[derive(Debug, thiserror::Error)]
pub(crate) enum PsrpProtocolError {
    /// Malformed fragment stream or message.
    #[error("PSRP protocol error: {0}")]
    Protocol(String),
}

/// A decoded PSRP message body + type.
#[derive(Debug, Clone)]
pub(crate) struct PsrpMessage {
    /// Wire message type code.
    pub(crate) message_type: u32,
    /// CLIXML body (UTF-8, BOM stripped if present).
    pub(crate) data: String,
}

/// Build SessionCapability + InitRunspacePool fragments for WS-Man `<creationXml>`.
///
/// # Errors
///
/// Currently infallible; returns [`PsrpProtocolError`] for future validation.
pub(crate) fn build_creation_fragments(rpid: Uuid) -> Result<Vec<u8>, PsrpProtocolError> {
    let session_cap = session_capability_xml();
    let init = init_runspace_pool_xml();
    let mut buf = Vec::new();
    let m1 = encode_psrp_message(
        DEST_SERVER,
        MT_SESSION_CAPABILITY,
        rpid,
        Uuid::nil(),
        &session_cap,
    );
    buf.extend_from_slice(&encode_fragments(1, &m1));
    let m2 = encode_psrp_message(
        DEST_SERVER,
        MT_INIT_RUNSPACE_POOL,
        rpid,
        Uuid::nil(),
        &init,
    );
    buf.extend_from_slice(&encode_fragments(2, &m2));
    Ok(buf)
}

/// SessionCapability CLIXML body.
#[must_use]
pub(crate) fn session_capability_xml() -> String {
    r#"<Obj RefId="0"><MS><Version N="PSVersion">2.0</Version><Version N="protocolversion">2.3</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>"#
        .to_string()
}

/// InitRunspacePool CLIXML (min/max runspaces = 1, null host).
#[must_use]
pub(crate) fn init_runspace_pool_xml() -> String {
    r#"<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32><Obj N="PSThreadOptions" RefId="1"><TN RefId="2"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj><Obj N="ApartmentState" RefId="3"><TN RefId="4"><T>System.Management.Automation.Runspaces.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>UNKNOWN</ToString><I32>2</I32></Obj><Obj N="HostInfo" RefId="5"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj><Nil N="ApplicationArguments"/></MS></Obj>"#
        .to_string()
}

/// pypsrp-compatible CreatePipeline CLIXML for a single script command.
#[must_use]
pub(crate) fn create_pipeline_xml(script: &str) -> String {
    let script = xml_escape(script);
    format!(
        r#"<Obj RefId="0"><MS><B N="NoInput">true</B><Obj RefId="1" N="ApartmentState"><TN RefId="0"><T>System.Management.Automation.Runspaces.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>UNKNOWN</ToString><I32>2</I32></Obj><Obj RefId="2" N="RemoteStreamOptions"><TN RefId="1"><T>System.Management.Automation.Runspaces.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><B N="AddToHistory">false</B><Obj RefId="3" N="HostInfo"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj><Obj RefId="4" N="PowerShell"><MS><B N="IsNested">false</B><Nil N="ExtraCmds" /><Obj RefId="5" N="Cmds"><TN RefId="2"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId="6"><MS><S N="Cmd">{script}</S><B N="IsScript">true</B><Nil N="UseLocalScope" /><Obj RefId="7" N="MergeMyResult"><TN RefId="3"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="8" N="MergeToResult"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="9" N="MergePreviousResults"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="10" N="Args"><TNRef RefId="2" /><LST /></Obj><Obj RefId="11" N="MergeError"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="12" N="MergeWarning"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="13" N="MergeVerbose"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="14" N="MergeDebug"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId="15" N="MergeInformation"><TNRef RefId="3" /><ToString>None</ToString><I32>0</I32></Obj></MS></Obj></LST></Obj><Nil N="History" /><B N="RedirectShellErrorOutputPipe">false</B></MS></Obj><B N="IsNested">false</B></MS></Obj>"#
    )
}

/// Escape a string for CLIXML / XML text content.
#[must_use]
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("_x{:04X}_", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Serialize a PSRP message (40-byte header + body).
#[must_use]
pub(crate) fn encode_psrp_message(
    destination: u32,
    message_type: u32,
    rpid: Uuid,
    pid: Uuid,
    body: &str,
) -> Vec<u8> {
    let body_bytes = body.as_bytes();
    let mut out = Vec::with_capacity(HEADER_LEN + body_bytes.len());
    out.extend_from_slice(&destination.to_le_bytes());
    out.extend_from_slice(&message_type.to_le_bytes());
    out.extend_from_slice(&rpid.to_bytes_le());
    out.extend_from_slice(&pid.to_bytes_le());
    out.extend_from_slice(body_bytes);
    out
}

/// Split a message payload into concatenated wire fragments.
#[must_use]
pub(crate) fn encode_fragments(object_id: u64, payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return encode_one_fragment(object_id, 0, true, true, &[]);
    }
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = payload.chunks(MAX_FRAGMENT_PAYLOAD).collect();
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.into_iter().enumerate() {
        out.extend_from_slice(&encode_one_fragment(
            object_id,
            i as u64,
            i == 0,
            i == last,
            chunk,
        ));
    }
    out
}

fn encode_one_fragment(
    object_id: u64,
    fragment_id: u64,
    start: bool,
    end: bool,
    blob: &[u8],
) -> Vec<u8> {
    let mut flags = 0u8;
    if start {
        flags |= FLAG_START;
    }
    if end {
        flags |= FLAG_END;
    }
    let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + blob.len());
    out.extend_from_slice(&object_id.to_be_bytes());
    out.extend_from_slice(&fragment_id.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    out.extend_from_slice(blob);
    out
}

/// Stateful reassembler for incoming PSRP fragments.
#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    buffer: Vec<u8>,
    in_flight: HashMap<u64, (Vec<u8>, u64, bool)>,
}

impl Reassembler {
    /// Create an empty reassembler.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of fragment bytes; return any fully reconstructed messages.
    ///
    /// # Errors
    ///
    /// Returns [`PsrpProtocolError`] on fragment id mismatch or decode failure.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<Vec<PsrpMessage>, PsrpProtocolError> {
        self.buffer.extend_from_slice(chunk);
        let mut completed = Vec::new();
        loop {
            if self.buffer.len() < FRAGMENT_HEADER_LEN {
                break;
            }
            let object_id = u64::from_be_bytes(self.buffer[0..8].try_into().unwrap());
            let fragment_id = u64::from_be_bytes(self.buffer[8..16].try_into().unwrap());
            let flags = self.buffer[16];
            let len = u32::from_be_bytes(self.buffer[17..21].try_into().unwrap()) as usize;
            if self.buffer.len() < FRAGMENT_HEADER_LEN + len {
                break;
            }
            let blob = self.buffer[FRAGMENT_HEADER_LEN..FRAGMENT_HEADER_LEN + len].to_vec();
            self.buffer.drain(..FRAGMENT_HEADER_LEN + len);

            let start = flags & FLAG_START != 0;
            let end = flags & FLAG_END != 0;

            if start && end {
                completed.push(blob);
                continue;
            }

            let entry = self
                .in_flight
                .entry(object_id)
                .or_insert_with(|| (Vec::new(), 0, false));
            if start {
                entry.0.clear();
                entry.1 = 0;
                entry.2 = true;
            }
            if !entry.2 && !start {
                continue;
            }
            if fragment_id != entry.1 {
                return Err(PsrpProtocolError::Protocol(format!(
                    "fragment id mismatch: got {fragment_id}, expected {}",
                    entry.1
                )));
            }
            entry.0.extend_from_slice(&blob);
            entry.1 += 1;
            if end {
                let payload = std::mem::take(&mut entry.0);
                self.in_flight.remove(&object_id);
                completed.push(payload);
            }
        }

        let mut msgs = Vec::new();
        for payload in completed {
            msgs.push(decode_message(&payload)?);
        }
        Ok(msgs)
    }
}

/// Decode a complete PSRP message payload (header + body).
///
/// # Errors
///
/// Returns [`PsrpProtocolError`] if the buffer is too short or body is not UTF-8.
pub(crate) fn decode_message(bytes: &[u8]) -> Result<PsrpMessage, PsrpProtocolError> {
    if bytes.len() < HEADER_LEN {
        return Err(PsrpProtocolError::Protocol(format!(
            "message too short: {} bytes",
            bytes.len()
        )));
    }
    let message_type = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let mut body = &bytes[HEADER_LEN..];
    if body.starts_with(&[0xEF, 0xBB, 0xBF]) {
        body = &body[3..];
    }
    let data = String::from_utf8(body.to_vec()).map_err(|e| {
        PsrpProtocolError::Protocol(format!("invalid UTF-8 in PSRP body: {e}"))
    })?;
    Ok(PsrpMessage { message_type, data })
}

/// Extract `<I32 N="name">value</I32>` from a CLIXML fragment.
#[must_use]
pub(crate) fn extract_named_i32(xml: &str, name: &str) -> Option<i32> {
    let needle = format!("N=\"{name}\"");
    let pos = xml.find(&needle)?;
    let after = &xml[pos + needle.len()..];
    let gt = after.find('>')?;
    let rest = &after[gt + 1..];
    let end = rest.find('<')?;
    rest[..end].trim().parse().ok()
}

/// Pull human-readable text from a CLIXML fragment (`<S>` preferred).
#[must_use]
pub(crate) fn extract_output_text(xml: &str) -> String {
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<S") {
        let after = &rest[start + 2..];
        let Some(gt) = after.find('>') else { break };
        if after[..gt].ends_with('/') {
            rest = &after[gt + 1..];
            continue;
        }
        let content = &after[gt + 1..];
        let Some(end) = content.find("</S>") else { break };
        let text = xml_unescape(&content[..end]);
        if !text.is_empty() {
            parts.push(text);
        }
        rest = &content[end + 4..];
    }
    rest = xml;
    while let Some(start) = rest.find("<ToString>") {
        let content = &rest[start + 10..];
        let Some(end) = content.find("</ToString>") else { break };
        let text = xml_unescape(&content[..end]);
        if !text.is_empty() && text != "None" && text != "Default" && text != "UNKNOWN" {
            if parts.is_empty() {
                parts.push(text);
            }
        }
        rest = &content[end + 11..];
    }
    if parts.is_empty() {
        let stripped: String = xml
            .split('<')
            .filter_map(|s| s.split('>').nth(1))
            .collect::<Vec<_>>()
            .join("");
        return stripped.trim().to_string();
    }
    parts.join("\n")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_capability_has_protocol_version() {
        let xml = session_capability_xml();
        assert!(xml.contains("2.3"));
        assert!(xml.contains("<Version N=\"PSVersion\">"));
    }

    #[test]
    fn create_pipeline_escapes_script() {
        let xml = create_pipeline_xml("Write-Output 'a<b&c'");
        assert!(xml.contains("&lt;"));
        assert!(xml.contains("&amp;"));
    }

    #[test]
    fn encode_decode_message_roundtrip() {
        let rpid = Uuid::parse_str("11112222-3333-4444-5555-666677778888").unwrap();
        let bytes = encode_psrp_message(
            DEST_SERVER,
            MT_SESSION_CAPABILITY,
            rpid,
            Uuid::nil(),
            "<Obj/>",
        );
        let msg = decode_message(&bytes).unwrap();
        assert_eq!(msg.message_type, MT_SESSION_CAPABILITY);
        assert_eq!(msg.data, "<Obj/>");
    }

    #[test]
    fn fragment_reassemble_single() {
        let payload = encode_psrp_message(
            DEST_SERVER,
            MT_PIPELINE_OUTPUT,
            Uuid::nil(),
            Uuid::nil(),
            r#"<S>hello</S>"#,
        );
        let frag = encode_fragments(1, &payload);
        let mut r = Reassembler::new();
        let msgs = r.feed(&frag).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].message_type, MT_PIPELINE_OUTPUT);
        assert_eq!(extract_output_text(&msgs[0].data), "hello");
    }

    #[test]
    fn creation_fragments_nonempty() {
        let bytes = build_creation_fragments(Uuid::new_v4()).unwrap();
        assert!(bytes.len() > FRAGMENT_HEADER_LEN * 2);
        assert_eq!(&bytes[0..8], &1u64.to_be_bytes());
    }

    #[test]
    fn extract_named_i32_pipeline_state() {
        let xml = r#"<Obj><MS><I32 N="PipelineState">4</I32></MS></Obj>"#;
        assert_eq!(extract_named_i32(xml, "PipelineState"), Some(4));
    }

    #[test]
    fn protocol_module_is_in_tree_not_separate_crate() {
        // Framing lives under src/psrp/ — not crates/* or an external path dep.
        let this_file = file!();
        assert!(
            this_file.contains("psrp") && this_file.contains("protocol"),
            "expected in-tree path, got {this_file}"
        );
        let root_manifest = include_str!("../../Cargo.toml");
        assert!(
            !root_manifest.contains("psrp-protocol"),
            "root Cargo.toml must not depend on a separate psrp-protocol package"
        );
    }
}
