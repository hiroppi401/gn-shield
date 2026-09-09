//! Sensitive pattern detector for clipboard and upload monitoring.
//!
//! Scans text for high-risk secrets (SSH keys, AWS access keys, GitHub tokens, Slack tokens)
//! and provides sanitized, masked representations to strictly prevent secret exposure.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveDataKind {
    SshPrivateKey,
    AwsAccessKey,
    GitHubToken,
    SlackToken,
    GenericSecretAssignment,
}

impl std::fmt::Display for SensitiveDataKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SshPrivateKey => write!(f, "SSH Private Key"),
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::GitHubToken => write!(f, "GitHub Personal Access Token"),
            Self::SlackToken => write!(f, "Slack API Token"),
            Self::GenericSecretAssignment => write!(f, "Generic Secret Assignment"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveFinding {
    pub kind: SensitiveDataKind,
    pub masked_preview: String,
}

static SSH_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----").expect("valid regex")
});

static AWS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").expect("valid regex"));

static GITHUB_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})\b")
        .expect("valid regex")
});

static SLACK_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b")
        .expect("valid regex")
});

pub struct SensitiveDataDetector;

impl SensitiveDataDetector {
    /// Mask a secret string, leaving at most 4 prefix characters visible
    /// and replacing the rest with asterisks.
    #[must_use]
    pub fn mask_secret(secret: &str) -> String {
        if secret.len() <= 6 {
            return "*".repeat(secret.len());
        }
        let visible_len = 4.min(secret.len() / 4);
        let prefix = &secret[..visible_len];
        format!("{}{}", prefix, "*".repeat(secret.len() - visible_len))
    }

    /// Scans a text buffer for high-risk sensitive patterns.
    /// Returns a list of findings with safely masked previews.
    #[must_use]
    pub fn scan_text(text: &str) -> Vec<SensitiveFinding> {
        let mut findings = Vec::new();

        if SSH_KEY_REGEX.is_match(text) {
            findings.push(SensitiveFinding {
                kind: SensitiveDataKind::SshPrivateKey,
                masked_preview: "-----BEGIN ... PRIVATE KEY----- [REDACTED]".to_string(),
            });
        }

        for cap in AWS_KEY_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                findings.push(SensitiveFinding {
                    kind: SensitiveDataKind::AwsAccessKey,
                    masked_preview: Self::mask_secret(m.as_str()),
                });
            }
        }

        for cap in GITHUB_TOKEN_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                findings.push(SensitiveFinding {
                    kind: SensitiveDataKind::GitHubToken,
                    masked_preview: Self::mask_secret(m.as_str()),
                });
            }
        }

        for cap in SLACK_TOKEN_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                findings.push(SensitiveFinding {
                    kind: SensitiveDataKind::SlackToken,
                    masked_preview: Self::mask_secret(m.as_str()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_secret() {
        let masked = SensitiveDataDetector::mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(masked, "AKIA****************");
        assert!(!masked.contains("EXAMPLE"));
    }

    #[test]
    fn test_detect_ssh_private_key() {
        let text = "sample config\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----";
        let findings = SensitiveDataDetector::scan_text(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SensitiveDataKind::SshPrivateKey);
        assert!(findings[0].masked_preview.contains("[REDACTED]"));
    }

    #[test]
    fn test_detect_aws_access_key() {
        let text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = SensitiveDataDetector::scan_text(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SensitiveDataKind::AwsAccessKey);
        assert_eq!(findings[0].masked_preview, "AKIA****************");
    }

    #[test]
    fn test_detect_github_token() {
        let text = "token is ghp_123456789012345678901234567890123456";
        let findings = SensitiveDataDetector::scan_text(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SensitiveDataKind::GitHubToken);
        assert!(findings[0].masked_preview.starts_with("ghp_"));
        assert!(findings[0].masked_preview.contains("****"));
    }

    #[test]
    fn test_clean_text_no_findings() {
        let text = "Hello world, this is a normal developer text with git and cargo build.";
        let findings = SensitiveDataDetector::scan_text(text);
        assert!(findings.is_empty());
    }
}
