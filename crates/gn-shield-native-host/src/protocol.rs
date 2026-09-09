//! Native Messaging Wire Protocol and serialization for GN-Shield.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB limit

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ExtensionRequest {
    #[serde(rename = "ping", alias = "Ping")]
    Ping,
    #[serde(rename = "get_status", alias = "GetStatus")]
    GetStatus,
    #[serde(rename = "get_blocklist", alias = "GetBlocklist")]
    GetBlocklist {
        #[serde(default)]
        current_version: Option<String>,
    },
    #[serde(rename = "check_form_action", alias = "CheckFormAction")]
    CheckFormAction {
        page_origin: String,
        action_origin: String,
        #[serde(default)]
        has_password: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeclarativeNetRequestRule {
    pub id: u32,
    pub priority: u32,
    pub action: RuleAction,
    pub condition: RuleCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleAction {
    #[serde(rename = "type")]
    pub action_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleCondition {
    #[serde(rename = "urlFilter")]
    pub url_filter: String,
    #[serde(rename = "resourceTypes")]
    pub resource_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum ExtensionResponse {
    #[serde(rename = "pong")]
    Pong { status: String, version: String },
    #[serde(rename = "status")]
    Status {
        version: String,
        core_connected: bool,
        enforce_domain_blocklist: bool,
        form_action_mismatch_heuristic: bool,
        rules_count: usize,
    },
    #[serde(rename = "blocklist")]
    Blocklist {
        version: String,
        domains: Vec<String>,
        rules: Vec<DeclarativeNetRequestRule>,
    },
    #[serde(rename = "form_action_verdict")]
    FormActionVerdict {
        action: String,
        reason: String,
        is_trusted_idp: bool,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Reads a 4-byte native-endian length-prefixed JSON message from the reader.
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<serde_json::Value>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Native messaging frame too large: {len} bytes > {MAX_MESSAGE_SIZE}"),
        ));
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;

    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Some(value))
}

/// Writes a 4-byte native-endian length-prefixed JSON message to the writer.
pub fn write_message<W: Write>(writer: &mut W, value: &serde_json::Value) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let len = bytes.len() as u32;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_write_message_roundtrip() {
        let msg = serde_json::json!({
            "type": "ping",
            "version": "0.1.0"
        });

        let mut buffer = Vec::new();
        write_message(&mut buffer, &msg).expect("write failed");

        let mut cursor = Cursor::new(buffer);
        let parsed = read_message(&mut cursor)
            .expect("read failed")
            .expect("missing msg");

        assert_eq!(parsed["type"], "ping");
        assert_eq!(parsed["version"], "0.1.0");
    }

    #[test]
    fn test_eof_handling() {
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(read_message(&mut empty).expect("read failed"), None);
    }
}
