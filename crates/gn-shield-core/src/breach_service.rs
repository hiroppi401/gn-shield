//! Breach detection service and sensitive data scanner.
//!
//! Provides k-anonymity password breach verification and opt-in sensitive data detection
//! for clipboard and upload contents. Strictly enforces Zero Transmission of raw secrets.

use gn_shield_config::DataBreachConfig;
use gn_shield_rules::breach::{BreachMatchResult, KAnonymityChecker};
use gn_shield_rules::sensitive_data::{SensitiveDataDetector, SensitiveFinding};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub trait RangeProvider: Send + Sync {
    fn fetch_range(&self, prefix: &str) -> Result<String, String>;
}

/// In-memory / Mock range provider for hermetic testing and local databases.
#[derive(Default)]
pub struct MockRangeProvider {
    database: Arc<RwLock<HashMap<String, String>>>,
}

impl MockRangeProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            database: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert_range(&self, prefix: &str, range_body: &str) {
        if let Ok(mut db) = self.database.write() {
            db.insert(prefix.to_ascii_uppercase(), range_body.to_string());
        }
    }
}

impl RangeProvider for MockRangeProvider {
    fn fetch_range(&self, prefix: &str) -> Result<String, String> {
        let db = self.database.read().map_err(|e| e.to_string())?;
        db.get(&prefix.to_ascii_uppercase())
            .cloned()
            .ok_or_else(|| format!("Prefix '{prefix}' not found in range store"))
    }
}

pub struct BreachService {
    config: DataBreachConfig,
    provider: Arc<dyn RangeProvider>,
}

impl BreachService {
    #[must_use]
    pub fn new(config: DataBreachConfig, provider: Arc<dyn RangeProvider>) -> Self {
        Self { config, provider }
    }

    /// Checks if a credential has been breached using the k-anonymity model.
    ///
    /// The raw credential is hash-split locally into a 5-char prefix and 35-char suffix.
    /// ONLY the 5-char prefix is queried from the range provider.
    pub fn check_credential(&self, credential: &str) -> Result<BreachMatchResult, String> {
        let (prefix, suffix) = KAnonymityChecker::split_sha1_hash(credential);
        let range_response = self.provider.fetch_range(&prefix)?;
        let result = KAnonymityChecker::evaluate_range_response(&prefix, &suffix, &range_response);
        Ok(result)
    }

    /// Scans text content for high-risk sensitive patterns (SSH keys, API tokens).
    /// Respects the `enabled` and `scan_clipboard`/`scan_uploads` flags.
    #[must_use]
    pub fn scan_clipboard(&self, text: &str) -> Vec<SensitiveFinding> {
        if !self.config.enabled || !self.config.scan_clipboard {
            return Vec::new();
        }
        SensitiveDataDetector::scan_text(text)
    }

    #[must_use]
    pub fn scan_upload(&self, text: &str) -> Vec<SensitiveFinding> {
        if !self.config.enabled || !self.config.scan_uploads {
            return Vec::new();
        }
        SensitiveDataDetector::scan_text(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breach_service_k_anonymity_check() {
        let mock_provider = Arc::new(MockRangeProvider::new());
        // "password" SHA1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        mock_provider.insert_range(
            "5BAA6",
            "0018A45C4D1787236E33B0CF63AB333AC10:2\n\
             1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n\
             FE8A99C09944A9F24FE3487DE697B76D49F:1",
        );

        let config = DataBreachConfig {
            enabled: true,
            scan_clipboard: true,
            scan_uploads: true,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        };

        let service = BreachService::new(config, mock_provider);
        let result = service
            .check_credential("password")
            .expect("check should succeed");

        assert!(result.is_breached);
        assert_eq!(result.count, 3861493);
        assert_eq!(result.prefix, "5BAA6");

        let clean_result = service
            .check_credential("super_unbreached_secret_998811")
            .unwrap_or(BreachMatchResult {
                is_breached: false,
                count: 0,
                prefix: String::new(),
            });
        assert!(!clean_result.is_breached);
    }

    #[test]
    fn test_sensitive_clipboard_opt_in_guard() {
        let mock_provider = Arc::new(MockRangeProvider::new());
        let disabled_config = DataBreachConfig::default(); // default: enabled=false, scan_clipboard=false
        let service = BreachService::new(disabled_config, mock_provider.clone());

        let payload = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        // Disabled by default: returns empty findings (zero privacy invasion without opt-in)
        let findings = service.scan_clipboard(payload);
        assert!(findings.is_empty());

        let enabled_config = DataBreachConfig {
            enabled: true,
            scan_clipboard: true,
            scan_uploads: false,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        };
        let active_service = BreachService::new(enabled_config, mock_provider);
        let active_findings = active_service.scan_clipboard(payload);
        assert_eq!(active_findings.len(), 1);
        assert_eq!(active_findings[0].masked_preview, "AKIA****************");
    }
}
