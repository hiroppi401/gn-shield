//! Integration and False Positive Regression Suite for Browser Companion (Fase 4).
//!
//! Verifies:
//! 1. Fast startup latency and Native Messaging wire protocol round-trip.
//! 2. Deterministic extension ID bindings (Chrome & Firefox).
//! 3. Form-action-mismatch anti-phishing heuristic:
//!    - Zero false positives on legitimate developer & enterprise SSO (Google, Microsoft, GitHub, Apple, Okta).
//!    - Interception of suspicious cross-origin credential theft (PromptUser).
//!    - Blocking of known malicious/phishing targets (Block).
//! 4. DeclarativeNetRequest dynamic rules generation for page-load blocking.

use gn_shield_config::GnShieldConfig;
use gn_shield_native_host::{
    generate_chrome_manifest, generate_firefox_manifest, read_message, write_message,
    ExtensionRequest, ExtensionResponse, HostHandler, CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID,
    NATIVE_HOST_NAME,
};
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Instant;

fn setup_test_host() -> HostHandler {
    let config_toml = r#"
    [browser_extension]
    enabled = true
    enforce_domain_blocklist = true
    form_action_mismatch_heuristic = true
    trusted_identity_providers = [
        "accounts.google.com",
        "login.microsoftonline.com",
        "github.com",
        "appleid.apple.com",
        "*.okta.com",
        "*.auth0.com"
    ]
    blocklist_refresh_via = "gn-shield-core"
    "#;

    let config = GnShieldConfig::parse_toml(config_toml).expect("parse valid config");
    let blocked_domains = vec![
        "phish-chase-update.com".to_string(),
        "credential-collector.xyz".to_string(),
        "moneroocean.stream".to_string(),
        "coinhive.com".to_string(),
    ];

    HostHandler::new(config, blocked_domains)
}

#[test]
fn test_host_startup_latency() {
    let start = Instant::now();
    let host = setup_test_host();
    let duration = start.elapsed();

    println!("Host initialization took: {:?}", duration);
    // Budget: native host must be very fast to spawn (< 50ms)
    assert!(duration.as_millis() < 50, "Host startup exceeded 50ms");
    assert_eq!(host.blocked_domains.len(), 4);
}

#[test]
fn test_deterministic_extension_ids_and_manifests() {
    let dummy_path = PathBuf::from("/usr/local/bin/gn-shield-native-host");

    // Chrome Manifest Check
    let chrome_manifest = generate_chrome_manifest(&dummy_path);
    assert_eq!(chrome_manifest["name"], NATIVE_HOST_NAME);
    let origins = chrome_manifest["allowed_origins"]
        .as_array()
        .expect("origins");
    assert_eq!(origins.len(), 1);
    assert_eq!(
        origins[0],
        format!("chrome-extension://{CHROME_EXTENSION_ID}/")
    );

    // Firefox Manifest Check
    let firefox_manifest = generate_firefox_manifest(&dummy_path);
    assert_eq!(firefox_manifest["name"], NATIVE_HOST_NAME);
    let extensions = firefox_manifest["allowed_extensions"]
        .as_array()
        .expect("extensions");
    assert_eq!(extensions.len(), 1);
    assert_eq!(extensions[0], FIREFOX_EXTENSION_ID);
}

#[test]
fn test_wire_protocol_stream() {
    let host = setup_test_host();

    let req = serde_json::json!({
        "type": "ping"
    });

    let mut stream = Vec::new();
    write_message(&mut stream, &req).expect("write message");

    let mut reader = Cursor::new(stream);
    let mut writer = Vec::new();

    host.run_loop(&mut reader, &mut writer).expect("run loop");

    let mut resp_reader = Cursor::new(writer);
    let resp = read_message(&mut resp_reader)
        .expect("read resp")
        .expect("resp exists");

    assert_eq!(resp["type"], "pong");
    assert_eq!(resp["status"], "ok");
}

#[test]
fn test_false_positive_regression_sso_identity_providers() {
    let host = setup_test_host();

    let legitimate_sso_scenarios = [
        (
            "https://myapp.io/login",
            "https://accounts.google.com/o/oauth2/v2/auth",
            "Google OAuth",
        ),
        (
            "https://dev-portal.com",
            "https://login.microsoftonline.com/common/oauth2",
            "Microsoft Entra ID",
        ),
        (
            "https://codeshare.dev",
            "https://github.com/login/oauth/authorize",
            "GitHub OAuth",
        ),
        (
            "https://media-app.tv",
            "https://appleid.apple.com/auth/authorize",
            "Sign in with Apple",
        ),
        (
            "https://internal.company.com",
            "https://mycorp.okta.com/app/saml",
            "Okta SSO",
        ),
        (
            "https://saas-tool.net",
            "https://auth.acme.auth0.com/authorize",
            "Auth0 Universal Login",
        ),
    ];

    for (page, target, name) in legitimate_sso_scenarios {
        let req = ExtensionRequest::CheckFormAction {
            page_origin: page.to_string(),
            action_origin: target.to_string(),
            has_password: true,
        };

        let resp = host.handle_request(req);
        match resp {
            ExtensionResponse::FormActionVerdict {
                action,
                is_trusted_idp,
                reason,
            } => {
                assert_eq!(
                    action, "Allow",
                    "False positive on legitimate SSO {name} ({target}): {reason}"
                );
                assert!(
                    is_trusted_idp,
                    "Should identify {name} as trusted identity provider"
                );
            }
            other => panic!("Unexpected response variant: {:?}", other),
        }
    }
}

#[test]
fn test_phishing_detection_and_blocking() {
    let host = setup_test_host();

    // 1. Cross-origin credential submit to unknown third party -> PromptUser
    let req1 = ExtensionRequest::CheckFormAction {
        page_origin: "https://mybank.com/login".to_string(),
        action_origin: "https://unverified-receiver.info/collect".to_string(),
        has_password: true,
    };
    if let ExtensionResponse::FormActionVerdict { action, .. } = host.handle_request(req1) {
        assert_eq!(action, "PromptUser");
    } else {
        panic!("Expected FormActionVerdict");
    }

    // 2. Credential submit to known phishing domain in blocklist -> Block
    let req2 = ExtensionRequest::CheckFormAction {
        page_origin: "https://legitsite.org".to_string(),
        action_origin: "https://phish-chase-update.com/steal".to_string(),
        has_password: true,
    };
    if let ExtensionResponse::FormActionVerdict { action, reason, .. } = host.handle_request(req2) {
        assert_eq!(action, "Block");
        assert!(reason.contains("malicious_phishing_destination"));
    } else {
        panic!("Expected FormActionVerdict");
    }

    // 3. Form without password field -> Allow (not a credential vector)
    let req3 = ExtensionRequest::CheckFormAction {
        page_origin: "https://shop.com/search".to_string(),
        action_origin: "https://external-search-provider.com".to_string(),
        has_password: false,
    };
    if let ExtensionResponse::FormActionVerdict { action, .. } = host.handle_request(req3) {
        assert_eq!(action, "Allow");
    } else {
        panic!("Expected FormActionVerdict");
    }
}

#[test]
fn test_declarative_net_request_rules_generation() {
    let host = setup_test_host();

    let req = ExtensionRequest::GetBlocklist {
        current_version: None,
    };
    if let ExtensionResponse::Blocklist { domains, rules, .. } = host.handle_request(req) {
        assert_eq!(domains.len(), 4);
        assert_eq!(rules.len(), 4);

        for (idx, rule) in rules.iter().enumerate() {
            assert_eq!(rule.id, (idx + 1) as u32);
            assert_eq!(rule.priority, 1);
            assert_eq!(rule.action.action_type, "block");
            assert!(rule.condition.url_filter.starts_with("||"));
            assert!(rule.condition.url_filter.ends_with('^'));
        }
    } else {
        panic!("Expected Blocklist response");
    }
}
