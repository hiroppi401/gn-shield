//! GN-Shield Native Messaging Companion Host.
//!
//! Bridges WebExtension (Chrome/Edge/Brave/Firefox) to local GN-Shield decision engine
//! and provides blocklist synchronization and form-action-mismatch anti-phishing evaluation.

pub mod heuristics;
pub mod manifests;
pub mod protocol;

pub use heuristics::{evaluate_form_action, FormActionVerdict};
pub use manifests::{
    generate_chrome_manifest, generate_firefox_manifest, install_manifest_file,
    standard_manifest_paths, CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID, NATIVE_HOST_NAME,
};
pub use protocol::{
    read_message, write_message, DeclarativeNetRequestRule, ExtensionRequest, ExtensionResponse,
    RuleAction, RuleCondition,
};

use gn_shield_config::GnShieldConfig;
use std::io::{self, Read, Write};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Request handler for browser extension communications.
#[derive(Debug, Clone)]
pub struct HostHandler {
    pub config: GnShieldConfig,
    pub blocked_domains: Vec<String>,
}

impl HostHandler {
    #[must_use]
    pub fn new(config: GnShieldConfig, mut blocked_domains: Vec<String>) -> Self {
        blocked_domains.sort();
        blocked_domains.dedup();
        Self {
            config,
            blocked_domains,
        }
    }

    /// Handles a single strongly-typed request.
    #[must_use]
    pub fn handle_request(&self, req: ExtensionRequest) -> ExtensionResponse {
        match req {
            ExtensionRequest::Ping => ExtensionResponse::Pong {
                status: "ok".to_string(),
                version: VERSION.to_string(),
            },
            ExtensionRequest::GetStatus => ExtensionResponse::Status {
                version: VERSION.to_string(),
                core_connected: true,
                enforce_domain_blocklist: self.config.browser_extension.enforce_domain_blocklist,
                form_action_mismatch_heuristic: self
                    .config
                    .browser_extension
                    .form_action_mismatch_heuristic,
                rules_count: self.blocked_domains.len(),
            },
            ExtensionRequest::GetBlocklist { .. } => {
                let mut rules = Vec::new();
                for (idx, domain) in self.blocked_domains.iter().enumerate() {
                    rules.push(DeclarativeNetRequestRule {
                        id: (idx + 1) as u32,
                        priority: 1,
                        action: RuleAction {
                            action_type: "block".to_string(),
                        },
                        condition: RuleCondition {
                            url_filter: format!("||{domain}^"),
                            resource_types: vec![
                                "main_frame".to_string(),
                                "sub_frame".to_string(),
                                "script".to_string(),
                                "xmlhttprequest".to_string(),
                            ],
                        },
                    });
                }

                ExtensionResponse::Blocklist {
                    version: VERSION.to_string(),
                    domains: self.blocked_domains.clone(),
                    rules,
                }
            }
            ExtensionRequest::CheckFormAction {
                page_origin,
                action_origin,
                has_password,
            } => {
                let verdict = evaluate_form_action(
                    &page_origin,
                    &action_origin,
                    has_password,
                    &self.config.browser_extension.trusted_identity_providers,
                    &self.blocked_domains,
                );

                let action_str = match verdict.action {
                    gn_shield_core::Action::Allow => "Allow",
                    gn_shield_core::Action::PromptUser => "PromptUser",
                    gn_shield_core::Action::Block => "Block",
                };

                ExtensionResponse::FormActionVerdict {
                    action: action_str.to_string(),
                    reason: verdict.reason,
                    is_trusted_idp: verdict.is_trusted_idp,
                }
            }
        }
    }

    /// Handles a raw JSON Value message and returns the response JSON Value.
    #[must_use]
    pub fn handle_value(&self, value: serde_json::Value) -> serde_json::Value {
        match serde_json::from_value::<ExtensionRequest>(value) {
            Ok(req) => {
                let res = self.handle_request(req);
                serde_json::to_value(&res).unwrap_or_else(|e| {
                    serde_json::json!({
                        "type": "error",
                        "message": format!("serialization error: {e}")
                    })
                })
            }
            Err(e) => serde_json::json!({
                "type": "error",
                "message": format!("invalid request format: {e}")
            }),
        }
    }

    /// Runs the synchronous standard I/O processing loop.
    pub fn run_loop<R: Read, W: Write>(&self, reader: &mut R, writer: &mut W) -> io::Result<()> {
        while let Some(msg) = read_message(reader)? {
            let resp = self.handle_value(msg);
            write_message(writer, &resp)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_handler() -> HostHandler {
        let config = GnShieldConfig::default();
        let blocked = vec![
            "phish-test.example.com".to_string(),
            "crypto-mining-pool.bad".to_string(),
        ];
        HostHandler::new(config, blocked)
    }

    #[test]
    fn test_ping_roundtrip() {
        let handler = test_handler();
        let req = serde_json::json!({ "type": "ping" });
        let resp = handler.handle_value(req);
        assert_eq!(resp["type"], "pong");
        assert_eq!(resp["status"], "ok");
    }

    #[test]
    fn test_get_status() {
        let handler = test_handler();
        let req = serde_json::json!({ "type": "get_status" });
        let resp = handler.handle_value(req);
        assert_eq!(resp["type"], "status");
        assert_eq!(resp["core_connected"], true);
        assert_eq!(resp["rules_count"], 2);
    }

    #[test]
    fn test_get_blocklist() {
        let handler = test_handler();
        let req = serde_json::json!({ "type": "get_blocklist" });
        let resp = handler.handle_value(req);
        assert_eq!(resp["type"], "blocklist");
        let domains = resp["domains"].as_array().expect("domains array");
        assert_eq!(domains.len(), 2);
        let rules = resp["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["action"]["type"], "block");
    }

    #[test]
    fn test_check_form_action_sso() {
        let handler = test_handler();
        let req = serde_json::json!({
            "type": "check_form_action",
            "page_origin": "https://myapp.dev",
            "action_origin": "https://accounts.google.com/oauth",
            "has_password": true
        });
        let resp = handler.handle_value(req);
        assert_eq!(resp["type"], "form_action_verdict");
        assert_eq!(resp["action"], "Allow");
        assert_eq!(resp["is_trusted_idp"], true);
    }

    #[test]
    fn test_run_loop_stream() {
        let handler = test_handler();
        let req1 = serde_json::json!({ "type": "ping" });
        let req2 = serde_json::json!({ "type": "get_status" });

        let mut input_buf = Vec::new();
        write_message(&mut input_buf, &req1).unwrap();
        write_message(&mut input_buf, &req2).unwrap();

        let mut input_cursor = Cursor::new(input_buf);
        let mut output_buf = Vec::new();

        handler
            .run_loop(&mut input_cursor, &mut output_buf)
            .unwrap();

        let mut output_cursor = Cursor::new(output_buf);
        let resp1 = read_message(&mut output_cursor).unwrap().unwrap();
        let resp2 = read_message(&mut output_cursor).unwrap().unwrap();
        assert_eq!(resp1["type"], "pong");
        assert_eq!(resp2["type"], "status");
    }
}
