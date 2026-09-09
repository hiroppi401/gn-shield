//! DNS domain filtering engine with Tier 4 Allowlist and reputation blocklists.

use crate::psl_engine::PslEngine;
use gn_shield_config::DomainAllowlistEntry;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFilterVerdict {
    Allow { reason: String },
    Block { reason: String, source: String },
}

/// Tier 4 matcher ensuring label-boundary matching on eTLD+1 and subdomains.
#[derive(Debug, Clone)]
pub struct DomainAllowlistRule {
    pub raw_pattern: String,
    pub is_wildcard: bool,
    pub base_domain: String,
    pub reason: String,
}

impl DomainAllowlistRule {
    pub fn parse(entry: &DomainAllowlistEntry) -> Self {
        let pattern = entry.pattern.trim().to_lowercase();
        let pattern_trimmed = pattern.trim_end_matches('.');
        let is_wildcard = pattern_trimmed.starts_with("*.");
        let base_domain = if is_wildcard {
            pattern_trimmed[2..].to_string()
        } else {
            pattern_trimmed.to_string()
        };

        Self {
            raw_pattern: pattern,
            is_wildcard,
            base_domain,
            reason: entry.reason.clone(),
        }
    }

    /// Matches a normalized hostname strictly on dot-separated label boundaries.
    pub fn matches(&self, hostname: &str) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_lowercase();
        if host == self.base_domain {
            return true;
        }
        if self.is_wildcard {
            if let Some(prefix) = host.strip_suffix(&self.base_domain) {
                // Must end with a dot before base_domain to prevent matching "badtrycloudflare.com"
                return prefix.ends_with('.');
            }
        }
        false
    }
}

pub struct DnsFilterEngine {
    psl: PslEngine,
    allowlist_rules: Vec<DomainAllowlistRule>,
    blocklist_domains: HashSet<String>,
    blocklist_metadata: HashMap<String, (String, String)>, // domain -> (source, reason)
}

impl DnsFilterEngine {
    #[must_use]
    pub fn new(allowlist: &[DomainAllowlistEntry], stale_warning_days: u32) -> Self {
        let allowlist_rules = allowlist.iter().map(DomainAllowlistRule::parse).collect();
        Self {
            psl: PslEngine::new(stale_warning_days),
            allowlist_rules,
            blocklist_domains: HashSet::new(),
            blocklist_metadata: HashMap::new(),
        }
    }

    pub fn psl_mut(&mut self) -> &mut PslEngine {
        &mut self.psl
    }

    pub fn psl(&self) -> &PslEngine {
        &self.psl
    }

    /// Adds a domain to the blocklist with source (e.g. "urlhaus", "phishtank", "coinblockerlists")
    pub fn add_blocked_domain(&mut self, domain: &str, source: &str, reason: &str) {
        let d = domain.trim().trim_end_matches('.').to_lowercase();
        self.blocklist_domains.insert(d.clone());
        self.blocklist_metadata
            .insert(d, (source.to_string(), reason.to_string()));
    }

    /// Adds multiple blocked domains from a feed
    pub fn add_blocklist_feed(&mut self, domains: &[String], source: &str, reason: &str) {
        for d in domains {
            self.add_blocked_domain(d, source, reason);
        }
    }

    /// Evaluates a query hostname.
    /// 1. Short-circuit: If matched in Tier 4 allowlist -> Allow.
    /// 2. If exact domain or eTLD+1 in blocklist -> Block.
    /// 3. Default -> Allow.
    #[must_use]
    pub fn evaluate(&self, query_hostname: &str) -> DnsFilterVerdict {
        let hostname = query_hostname.trim().trim_end_matches('.').to_lowercase();
        if hostname.is_empty() {
            return DnsFilterVerdict::Allow {
                reason: "empty_hostname".to_string(),
            };
        }

        // 1. Tier 4 Allowlist check (Short Circuit)
        for rule in &self.allowlist_rules {
            if rule.matches(&hostname) {
                return DnsFilterVerdict::Allow {
                    reason: format!("tier4_allowlist: {}", rule.reason),
                };
            }
        }

        // 2. Exact match in blocklist
        if let Some((source, reason)) = self.blocklist_metadata.get(&hostname) {
            return DnsFilterVerdict::Block {
                reason: reason.clone(),
                source: source.clone(),
            };
        }

        // 3. eTLD+1 boundary match in blocklist
        if let Some(etld_plus_one) = self.psl.extract_etld_plus_one(&hostname) {
            let etld_lower = etld_plus_one.to_lowercase();
            if let Some((source, reason)) = self.blocklist_metadata.get(&etld_lower) {
                return DnsFilterVerdict::Block {
                    reason: format!("{reason} (matched eTLD+1: {etld_lower})"),
                    source: source.clone(),
                };
            }
        }

        // 4. Default Allow
        DnsFilterVerdict::Allow {
            reason: "clean_domain".to_string(),
        }
    }

    #[must_use]
    pub fn get_blocked_domains(&self) -> Vec<String> {
        let mut list: Vec<String> = self.blocklist_domains.iter().cloned().collect();
        list.sort();
        list
    }

    #[must_use]
    pub fn blocklist_count(&self) -> usize {
        self.blocklist_domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier4_domain_allowlist_matching() {
        let entry = DomainAllowlistEntry {
            pattern: "*.trycloudflare.com".to_string(),
            reason: "cloudflare_tunnel_official".to_string(),
        };
        let rule = DomainAllowlistRule::parse(&entry);

        // Valid subdomains
        assert!(rule.matches("tunnel-xyz.trycloudflare.com"));
        assert!(rule.matches("deep.sub.tunnel.trycloudflare.com"));
        assert!(rule.matches("trycloudflare.com"));

        // Must NOT match spoofed domains
        assert!(!rule.matches("eviltrycloudflare.com"));
        assert!(!rule.matches("trycloudflare.com.attacker.com"));
    }

    #[test]
    fn test_filter_engine_allow_and_block() {
        let allowlist = vec![
            DomainAllowlistEntry {
                pattern: "*.trycloudflare.com".to_string(),
                reason: "cloudflare_tunnel_official".to_string(),
            },
            DomainAllowlistEntry {
                pattern: "*.ts.net".to_string(),
                reason: "tailscale".to_string(),
            },
        ];

        let mut engine = DnsFilterEngine::new(&allowlist, 45);

        // Add malicious domains
        engine.add_blocked_domain("phish-target.com", "phishtank", "credential_phishing");
        engine.add_blocked_domain(
            "crypto-pool.mine",
            "coinblockerlists",
            "in_page_cryptomining",
        );

        // 1. Allowed tunnels
        let v1 = engine.evaluate("random-tunnel.trycloudflare.com");
        assert!(matches!(v1, DnsFilterVerdict::Allow { .. }));

        let v2 = engine.evaluate("my-device.ts.net");
        assert!(matches!(v2, DnsFilterVerdict::Allow { .. }));

        // 2. Blocked domains
        let v3 = engine.evaluate("phish-target.com");
        assert!(matches!(v3, DnsFilterVerdict::Block { .. }));

        // Subdomain of blocked root domain should also be blocked via eTLD+1
        let v4 = engine.evaluate("login.secure.phish-target.com");
        assert!(matches!(v4, DnsFilterVerdict::Block { .. }));

        // 3. Normal clean domain
        let v5 = engine.evaluate("docs.rs");
        assert!(matches!(v5, DnsFilterVerdict::Allow { .. }));
    }
}
