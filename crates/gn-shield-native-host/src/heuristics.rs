//! Form-action-mismatch anti-phishing heuristic evaluator for GN-Shield.

use gn_shield_core::Action;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormActionVerdict {
    pub action: Action,
    pub reason: String,
    pub is_trusted_idp: bool,
}

/// Normalizes and extracts the host string from a URL or origin string.
pub fn extract_host(url_str: &str) -> Option<String> {
    let trimmed = url_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = Url::parse(trimmed) {
        return parsed
            .host_str()
            .map(|h| h.trim_end_matches('.').to_lowercase());
    }

    // Try prepending https:// if protocol was omitted
    if !trimmed.contains("://") {
        if let Ok(parsed) = Url::parse(&format!("https://{trimmed}")) {
            return parsed
                .host_str()
                .map(|h| h.trim_end_matches('.').to_lowercase());
        }
    }

    // Fallback: strip port and path manually
    let host_part = trimmed
        .split('/')
        .next()?
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_lowercase();

    if host_part.is_empty() {
        None
    } else {
        Some(host_part)
    }
}

/// Checks if a hostname matches any entry in the trusted identity provider allowlist.
/// Supports wildcard prefixes (e.g., `*.okta.com`, `*.auth0.com`) and exact hostnames.
pub fn matches_trusted_idp(host: &str, trusted_list: &[String]) -> bool {
    let h = host.trim().trim_end_matches('.').to_lowercase();
    for entry in trusted_list {
        let pattern = entry.trim().trim_end_matches('.').to_lowercase();
        if let Some(base) = pattern.strip_prefix("*.") {
            if h == base {
                return true;
            }
            if let Some(prefix) = h.strip_suffix(base) {
                if prefix.ends_with('.') {
                    return true;
                }
            }
        } else if h == pattern {
            return true;
        }
    }
    false
}

/// Evaluates whether a form submission containing credentials represents a potential phishing threat.
///
/// Principles:
/// 1. Zero false positives against legitimate developer SSO/OAuth providers (Google, Microsoft, GitHub, Apple, Okta).
/// 2. If no password field is present, submission is non-credential and allowed.
/// 3. Cross-origin credential submissions to untrusted third-parties trigger `PromptUser` (banner/confirmation).
/// 4. Submissions to known phishing/malicious blocklist domains trigger `Block`.
pub fn evaluate_form_action(
    page_origin: &str,
    action_origin: &str,
    has_password: bool,
    trusted_idps: &[String],
    blocked_domains: &[String],
) -> FormActionVerdict {
    // 1. If form has no password field, it is not a credential theft vector
    if !has_password {
        return FormActionVerdict {
            action: Action::Allow,
            reason: "no_password_field".to_string(),
            is_trusted_idp: false,
        };
    }

    let page_host = match extract_host(page_origin) {
        Some(h) => h,
        None => {
            return FormActionVerdict {
                action: Action::Allow,
                reason: "unparseable_page_origin".to_string(),
                is_trusted_idp: false,
            }
        }
    };

    let action_host = match extract_host(action_origin) {
        Some(h) => h,
        None => {
            return FormActionVerdict {
                action: Action::Allow,
                reason: "same_page_relative_action".to_string(),
                is_trusted_idp: false,
            }
        }
    };

    // 2. Same host / same site form submission
    if page_host == action_host {
        return FormActionVerdict {
            action: Action::Allow,
            reason: "same_origin_form_action".to_string(),
            is_trusted_idp: false,
        };
    }

    // 3. Trusted Identity Provider (SSO / OAuth 2.0 / SAML)
    if matches_trusted_idp(&action_host, trusted_idps) {
        return FormActionVerdict {
            action: Action::Allow,
            reason: format!("trusted_identity_provider: {action_host}"),
            is_trusted_idp: true,
        };
    }

    // 4. Known Phishing / Malicious Domain in Blocklist
    let is_blocked = blocked_domains.iter().any(|bad| {
        let b = bad.trim().trim_end_matches('.').to_lowercase();
        action_host == b || action_host.ends_with(&format!(".{b}"))
    });

    if is_blocked {
        return FormActionVerdict {
            action: Action::Block,
            reason: format!("malicious_phishing_destination: {action_host}"),
            is_trusted_idp: false,
        };
    }

    // 5. Cross-origin credential submission to unverified third-party -> Prompt User
    FormActionVerdict {
        action: Action::PromptUser,
        reason: format!(
            "suspicious_cross_origin_password_submit: page '{page_host}' submits to '{action_host}'"
        ),
        is_trusted_idp: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_idps() -> Vec<String> {
        vec![
            "accounts.google.com".to_string(),
            "login.microsoftonline.com".to_string(),
            "github.com".to_string(),
            "appleid.apple.com".to_string(),
            "*.okta.com".to_string(),
            "*.auth0.com".to_string(),
        ]
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://accounts.google.com/signin"),
            Some("accounts.google.com".to_string())
        );
        assert_eq!(
            extract_host("http://example.com:8080/submit"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host("myapp.okta.com"),
            Some("myapp.okta.com".to_string())
        );
    }

    #[test]
    fn test_trusted_idp_matching() {
        let idps = sample_idps();
        assert!(matches_trusted_idp("accounts.google.com", &idps));
        assert!(matches_trusted_idp("login.microsoftonline.com", &idps));
        assert!(matches_trusted_idp("github.com", &idps));
        assert!(matches_trusted_idp("appleid.apple.com", &idps));
        assert!(matches_trusted_idp("company.okta.com", &idps));
        assert!(matches_trusted_idp("sub.domain.auth0.com", &idps));

        assert!(!matches_trusted_idp("evil-google.com", &idps));
        assert!(!matches_trusted_idp(
            "accounts.google.com.attacker.com",
            &idps
        ));
        assert!(!matches_trusted_idp("notokta.com", &idps));
    }

    #[test]
    fn test_form_action_eval_allow_legitimate_sso() {
        let idps = sample_idps();
        let blocked = vec!["phish-steal.com".to_string()];

        // Google SSO from an external app
        let v1 = evaluate_form_action(
            "https://myapp.dev/login",
            "https://accounts.google.com/o/oauth2/auth",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v1.action, Action::Allow);
        assert!(v1.is_trusted_idp);

        // GitHub login from dev tool
        let v2 = evaluate_form_action(
            "https://mydevservice.io",
            "https://github.com/login",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v2.action, Action::Allow);
        assert!(v2.is_trusted_idp);

        // Okta enterprise SSO
        let v3 = evaluate_form_action(
            "https://internal-portal.corp",
            "https://mycompany.okta.com/login",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v3.action, Action::Allow);
        assert!(v3.is_trusted_idp);
    }

    #[test]
    fn test_form_action_eval_suspicious_and_blocked() {
        let idps = sample_idps();
        let blocked = vec!["phish-steal.com".to_string()];

        // Cross-origin password submission to unknown site -> PromptUser
        let v1 = evaluate_form_action(
            "https://legitbank.com/login",
            "https://suspicious-receiver.xyz/collector",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v1.action, Action::PromptUser);

        // Cross-origin password submission to known phishing domain -> Block
        let v2 = evaluate_form_action(
            "https://somewebsite.com",
            "https://phish-steal.com/steal.php",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v2.action, Action::Block);

        // Same origin submission -> Allow
        let v3 = evaluate_form_action(
            "https://legitbank.com/login",
            "https://legitbank.com/api/v1/auth",
            true,
            &idps,
            &blocked,
        );
        assert_eq!(v3.action, Action::Allow);
    }
}
