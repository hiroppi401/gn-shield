//! Two-layer Public Suffix List (PSL) engine for GN-Shield.
//!
//! Provides eTLD+1 extraction using:
//! 1. Compiled-in fallback via `psl` crate (always available offline).
//! 2. Dynamic runtime layer via `publicsuffix` crate (updated via Update Service).
//!
//! Matches domain boundaries strictly on label boundaries, never naive string ends_with.

use psl::Psl;
use std::time::{Duration, SystemTime};

pub struct PslEngine {
    dynamic_list: Option<publicsuffix::List>,
    last_refreshed_at: Option<SystemTime>,
    stale_warning_days: u32,
}

impl PslEngine {
    #[must_use]
    pub fn new(stale_warning_days: u32) -> Self {
        Self {
            dynamic_list: None,
            last_refreshed_at: None,
            stale_warning_days,
        }
    }

    /// Loads a dynamic PSL data string (e.g. public_suffix_list.dat from Update Service).
    pub fn load_dynamic_list(&mut self, dat_content: &str) -> Result<(), String> {
        let parsed_list: publicsuffix::List = dat_content
            .parse()
            .map_err(|e| format!("Failed to parse public suffix list: {e}"))?;
        self.dynamic_list = Some(parsed_list);
        self.last_refreshed_at = Some(SystemTime::now());
        Ok(())
    }

    /// Returns the timestamp when the dynamic layer was last refreshed.
    #[must_use]
    pub fn last_refreshed_at(&self) -> Option<SystemTime> {
        self.last_refreshed_at
    }

    /// Checks if the dynamic PSL layer is stale (older than `stale_warning_days`).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        match self.last_refreshed_at {
            Some(time) => {
                let max_age = Duration::from_secs(u64::from(self.stale_warning_days) * 86400);
                match SystemTime::now().duration_since(time) {
                    Ok(age) => age > max_age,
                    Err(_) => false,
                }
            }
            None => true, // No dynamic refresh yet
        }
    }

    /// Extracts the eTLD+1 (registrable root domain) from a given domain string.
    /// Priority:
    /// 1. Dynamic PSL list if available.
    /// 2. Compiled-in fallback list (`psl::List`).
    #[must_use]
    pub fn extract_etld_plus_one(&self, domain: &str) -> Option<String> {
        let domain_trimmed = domain.trim().trim_end_matches('.');
        if domain_trimmed.is_empty() {
            return None;
        }

        // Layer 1: Dynamic layer
        if let Some(dynamic) = &self.dynamic_list {
            use publicsuffix::Psl as _;
            if let Some(domain_obj) = dynamic.domain(domain_trimmed.as_bytes()) {
                if let Ok(root_str) = std::str::from_utf8(domain_obj.as_bytes()) {
                    return Some(root_str.to_string());
                }
            }
        }

        // Layer 2: Compiled-in fallback (psl::List)
        if let Some(domain_obj) = psl::List.domain(domain_trimmed.as_bytes()) {
            if let Ok(root_str) = std::str::from_utf8(domain_obj.as_bytes()) {
                return Some(root_str.to_string());
            }
        }

        // If not found in suffix list (e.g. localhost, internal domains), fallback to last two labels if available
        let labels: Vec<&str> = domain_trimmed.split('.').collect();
        if labels.len() >= 2 {
            Some(format!(
                "{}.{}",
                labels[labels.len() - 2],
                labels[labels.len() - 1]
            ))
        } else {
            Some(domain_trimmed.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psl_compiled_fallback_extraction() {
        let engine = PslEngine::new(45);
        // Note: In PSL, trycloudflare.com is registered as a private suffix for tunnel isolation.
        // Therefore, each user tunnel (e.g. tunnel.trycloudflare.com) is the registrable eTLD+1.
        assert_eq!(
            engine
                .extract_etld_plus_one("sub.tunnel.trycloudflare.com")
                .as_deref(),
            Some("tunnel.trycloudflare.com")
        );
        assert_eq!(
            engine.extract_etld_plus_one("api.service.co.uk").as_deref(),
            Some("service.co.uk")
        );
        assert_eq!(
            engine.extract_etld_plus_one("github.com").as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn test_psl_dynamic_layer_and_staleness() {
        let mut engine = PslEngine::new(45);
        assert!(engine.is_stale()); // None is considered stale/unrefreshed

        // Valid PSL dat requires section header
        let sample_psl_dat = "// ===BEGIN ICANN DOMAINS===\ncustomtld\n*.tokyo.jp\n";
        engine
            .load_dynamic_list(sample_psl_dat)
            .expect("Failed to load dynamic PSL");

        assert!(!engine.is_stale());
        assert_eq!(
            engine.extract_etld_plus_one("app.customtld").as_deref(),
            Some("app.customtld")
        );
    }
}
