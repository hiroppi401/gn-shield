//! Configuration schema definition and parser for GN-Shield.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub telemetry_enabled: bool,
    #[serde(default = "default_update_channel")]
    pub update_channel: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_update_channel() -> String {
    "stable".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            telemetry_enabled: false,
            update_channel: default_update_channel(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    #[serde(default = "default_weight_static")]
    pub weight_static: f32,
    #[serde(default = "default_weight_hash")]
    pub weight_hash_reputation: f32,
    #[serde(default = "default_weight_behavior")]
    pub weight_behavior: f32,
    #[serde(default = "default_threshold_block")]
    pub threshold_block: f32,
    #[serde(default = "default_threshold_prompt")]
    pub threshold_prompt: f32,
}

fn default_weight_static() -> f32 {
    0.4
}
fn default_weight_hash() -> f32 {
    0.4
}
fn default_weight_behavior() -> f32 {
    0.2
}
fn default_threshold_block() -> f32 {
    0.8
}
fn default_threshold_prompt() -> f32 {
    0.4
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weight_static: default_weight_static(),
            weight_hash_reputation: default_weight_hash(),
            weight_behavior: default_weight_behavior(),
            threshold_block: default_threshold_block(),
            threshold_prompt: default_threshold_prompt(),
        }
    }
}

/// Tier 1: Hash Allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashAllowlistEntry {
    pub sha256: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub added_by: String,
    #[serde(default)]
    pub added_at: String,
}

/// Tier 2: Publisher/Package Trust entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublisherAllowlistEntry {
    pub platform: String,
    pub verified_by: String,
    pub package_name: String,
    #[serde(default)]
    pub auto_trust: bool,
    #[serde(default)]
    pub high_fanout_expected: bool,
}

/// Tier 3: Path Allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathAllowlistEntry {
    pub path: String,
    #[serde(default)]
    pub verified_by: String,
    #[serde(default)]
    pub auto_reverify_on_update: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub hash: Vec<HashAllowlistEntry>,
    #[serde(default)]
    pub publisher: Vec<PublisherAllowlistEntry>,
    #[serde(default)]
    pub path: Vec<PathAllowlistEntry>,
}

/// Tier 5: Context-Aware Directory Exception for Ransomware Detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcludedPathEntry {
    pub path_pattern: String,
    pub reason: String,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String, // "reduced"
}

fn default_sensitivity() -> String {
    "reduced".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareConfig {
    #[serde(default = "default_mass_write_threshold")]
    pub mass_write_threshold: usize,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,
    #[serde(default = "default_excluded_paths")]
    pub excluded_paths: Vec<ExcludedPathEntry>,
}

fn default_mass_write_threshold() -> usize {
    10
}

fn default_window_seconds() -> u64 {
    5
}

fn default_entropy_threshold() -> f32 {
    7.2
}

fn default_excluded_paths() -> Vec<ExcludedPathEntry> {
    vec![
        ExcludedPathEntry {
            path_pattern: "**/node_modules/**".to_string(),
            reason: "development_dependencies".to_string(),
            sensitivity: "reduced".to_string(),
        },
        ExcludedPathEntry {
            path_pattern: "**/.git/**".to_string(),
            reason: "version_control_objects".to_string(),
            sensitivity: "reduced".to_string(),
        },
        ExcludedPathEntry {
            path_pattern: "**/target/**".to_string(),
            reason: "rust_build_artifacts".to_string(),
            sensitivity: "reduced".to_string(),
        },
        ExcludedPathEntry {
            path_pattern: "**/dist/**".to_string(),
            reason: "build_output".to_string(),
            sensitivity: "reduced".to_string(),
        },
        ExcludedPathEntry {
            path_pattern: "**/build/**".to_string(),
            reason: "build_output".to_string(),
            sensitivity: "reduced".to_string(),
        },
        ExcludedPathEntry {
            path_pattern: "**/.venv/**".to_string(),
            reason: "python_virtualenv".to_string(),
            sensitivity: "reduced".to_string(),
        },
    ]
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            mass_write_threshold: default_mass_write_threshold(),
            window_seconds: default_window_seconds(),
            entropy_threshold: default_entropy_threshold(),
            excluded_paths: default_excluded_paths(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "default_notification_style")]
    pub style: String,
    #[serde(default = "default_prompt_timeout_seconds")]
    pub prompt_timeout_seconds: u32,
    #[serde(default = "default_action_on_timeout")]
    pub default_action_on_timeout: String,
    #[serde(default = "default_batching_enabled")]
    pub batching_enabled: bool,
    #[serde(default = "default_batch_window_ms")]
    pub batch_window_ms: u64,
    #[serde(default = "default_batch_threshold_count")]
    pub batch_threshold_count: usize,
}

fn default_notification_style() -> String {
    "native".to_string()
}

fn default_prompt_timeout_seconds() -> u32 {
    60
}

fn default_action_on_timeout() -> String {
    "allow_once".to_string()
}

fn default_batching_enabled() -> bool {
    true
}

fn default_batch_window_ms() -> u64 {
    1000
}

fn default_batch_threshold_count() -> usize {
    2
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            style: default_notification_style(),
            prompt_timeout_seconds: default_prompt_timeout_seconds(),
            default_action_on_timeout: default_action_on_timeout(),
            batching_enabled: default_batching_enabled(),
            batch_window_ms: default_batch_window_ms(),
            batch_threshold_count: default_batch_threshold_count(),
        }
    }
}

/// Tier 4: Domain Allowlist entry (tunnel / developer tool domains)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAllowlistEntry {
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

/// Tier 4: IP Allowlist entry (CIDR override)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpAllowlistEntry {
    pub cidr: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_domain_allowlist")]
    pub domain_allowlist: Vec<DomainAllowlistEntry>,
    #[serde(default)]
    pub ip_allowlist: Vec<IpAllowlistEntry>,
}

fn default_domain_allowlist() -> Vec<DomainAllowlistEntry> {
    vec![
        DomainAllowlistEntry {
            pattern: "*.trycloudflare.com".to_string(),
            reason: "cloudflare_tunnel_official".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.cfargotunnel.com".to_string(),
            reason: "cloudflare_tunnel_official".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.ngrok.io".to_string(),
            reason: "ngrok_tunnel".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.ts.net".to_string(),
            reason: "tailscale".to_string(),
        },
    ]
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            domain_allowlist: default_domain_allowlist(),
            ip_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterConfig {
    #[serde(default = "default_dns_filter_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dns_listen_address")]
    pub listen_address: String,
    #[serde(default = "default_dns_listen_address_v6")]
    pub listen_address_v6: String,
    #[serde(default = "default_dns_upstream")]
    pub upstream: Vec<String>,
    #[serde(default = "default_blocklist_sources")]
    pub blocklist_sources: Vec<String>,
    #[serde(default = "default_psl_stale_warning_days")]
    pub psl_stale_warning_days: u32,
    #[serde(default = "default_integration_mode")]
    pub integration_mode: String,
    #[serde(default = "default_chain_upstream_listen_port")]
    pub chain_upstream_listen_port: u16,
}

fn default_dns_filter_enabled() -> bool {
    true
}
fn default_dns_listen_address() -> String {
    "127.0.0.1:53".to_string()
}
fn default_dns_listen_address_v6() -> String {
    "[::1]:53".to_string()
}
fn default_dns_upstream() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]
}
fn default_blocklist_sources() -> Vec<String> {
    vec![
        "urlhaus".to_string(),
        "phishtank".to_string(),
        "coinblockerlists".to_string(),
    ]
}
fn default_psl_stale_warning_days() -> u32 {
    45
}
fn default_integration_mode() -> String {
    "auto".to_string()
}
fn default_chain_upstream_listen_port() -> u16 {
    5353
}

impl Default for DnsFilterConfig {
    fn default() -> Self {
        Self {
            enabled: default_dns_filter_enabled(),
            listen_address: default_dns_listen_address(),
            listen_address_v6: default_dns_listen_address_v6(),
            upstream: default_dns_upstream(),
            blocklist_sources: default_blocklist_sources(),
            psl_stale_warning_days: default_psl_stale_warning_days(),
            integration_mode: default_integration_mode(),
            chain_upstream_listen_port: default_chain_upstream_listen_port(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationConfig {
    #[serde(default = "default_ip_rep_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ip_feed_sources")]
    pub feed_sources: Vec<String>,
    #[serde(default = "default_ip_ttl_days")]
    pub ttl_days: u32,
    #[serde(default = "default_ip_stale_warning_days")]
    pub stale_warning_days: u32,
    #[serde(default = "default_repeated_attempt_threshold_count")]
    pub repeated_attempt_threshold_count: usize,
    #[serde(default = "default_repeated_attempt_threshold_window_seconds")]
    pub repeated_attempt_threshold_window_seconds: u64,
}

fn default_ip_rep_enabled() -> bool {
    true
}
fn default_ip_feed_sources() -> Vec<String> {
    vec![
        "feodotracker".to_string(),
        "spamhaus_drop".to_string(),
        "coinblockerlists".to_string(),
    ]
}
fn default_ip_ttl_days() -> u32 {
    10
}
fn default_ip_stale_warning_days() -> u32 {
    7
}
fn default_repeated_attempt_threshold_count() -> usize {
    3
}
fn default_repeated_attempt_threshold_window_seconds() -> u64 {
    300
}

impl Default for IpReputationConfig {
    fn default() -> Self {
        Self {
            enabled: default_ip_rep_enabled(),
            feed_sources: default_ip_feed_sources(),
            ttl_days: default_ip_ttl_days(),
            stale_warning_days: default_ip_stale_warning_days(),
            repeated_attempt_threshold_count: default_repeated_attempt_threshold_count(),
            repeated_attempt_threshold_window_seconds:
                default_repeated_attempt_threshold_window_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtensionConfig {
    #[serde(default = "default_browser_ext_enabled")]
    pub enabled: bool,
    #[serde(default = "default_enforce_domain_blocklist")]
    pub enforce_domain_blocklist: bool,
    #[serde(default = "default_form_action_mismatch_heuristic")]
    pub form_action_mismatch_heuristic: bool,
    #[serde(default = "default_trusted_identity_providers")]
    pub trusted_identity_providers: Vec<String>,
    #[serde(default = "default_blocklist_refresh_via")]
    pub blocklist_refresh_via: String,
}

fn default_browser_ext_enabled() -> bool {
    true
}

fn default_enforce_domain_blocklist() -> bool {
    true
}

fn default_form_action_mismatch_heuristic() -> bool {
    true
}

fn default_trusted_identity_providers() -> Vec<String> {
    vec![
        "accounts.google.com".to_string(),
        "login.microsoftonline.com".to_string(),
        "github.com".to_string(),
        "appleid.apple.com".to_string(),
        "*.okta.com".to_string(),
        "*.auth0.com".to_string(),
    ]
}

fn default_blocklist_refresh_via() -> String {
    "gn-shield-core".to_string()
}

impl Default for BrowserExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: default_browser_ext_enabled(),
            enforce_domain_blocklist: default_enforce_domain_blocklist(),
            form_action_mismatch_heuristic: default_form_action_mismatch_heuristic(),
            trusted_identity_providers: default_trusted_identity_providers(),
            blocklist_refresh_via: default_blocklist_refresh_via(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBreachConfig {
    #[serde(default = "default_breach_enabled")]
    pub enabled: bool,
    #[serde(default = "default_scan_clipboard")]
    pub scan_clipboard: bool,
    #[serde(default = "default_scan_uploads")]
    pub scan_uploads: bool,
    #[serde(default = "default_k_anonymity_api_url")]
    pub k_anonymity_api_url: String,
    #[serde(default = "default_breach_check_timeout_ms")]
    pub check_timeout_ms: u64,
}

fn default_breach_enabled() -> bool {
    false
}
fn default_scan_clipboard() -> bool {
    false
}
fn default_scan_uploads() -> bool {
    false
}
fn default_k_anonymity_api_url() -> String {
    "https://api.pwnedpasswords.com/range/".to_string()
}
fn default_breach_check_timeout_ms() -> u64 {
    3000
}

impl Default for DataBreachConfig {
    fn default() -> Self {
        Self {
            enabled: default_breach_enabled(),
            scan_clipboard: default_scan_clipboard(),
            scan_uploads: default_scan_uploads(),
            k_anonymity_api_url: default_k_anonymity_api_url(),
            check_timeout_ms: default_breach_check_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnShieldConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub ransomware: RansomwareConfig,
    #[serde(default)]
    pub dns_filter: DnsFilterConfig,
    #[serde(default)]
    pub ip_reputation_filter: IpReputationConfig,
    #[serde(default)]
    pub browser_extension: BrowserExtensionConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub data_breach: DataBreachConfig,
}

impl GnShieldConfig {
    pub fn parse_toml(content: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        let total_weight = self.scoring.weight_static
            + self.scoring.weight_hash_reputation
            + self.scoring.weight_behavior;

        if (total_weight - 1.0).abs() > 0.001 {
            return Err(format!(
                "Scoring weights must sum to 1.0, current sum is {total_weight}"
            ));
        }

        if self.scoring.threshold_block <= self.scoring.threshold_prompt {
            return Err(format!(
                "threshold_block ({}) must be greater than threshold_prompt ({})",
                self.scoring.threshold_block, self.scoring.threshold_prompt
            ));
        }

        if self.notifications.default_action_on_timeout.to_lowercase() == "block" {
            return Err(
                "default_action_on_timeout cannot be set to 'block' (violates AGENTS.md safety rule)"
                    .to_string(),
            );
        }

        let mode = self.dns_filter.integration_mode.to_lowercase();
        if !["auto", "takeover", "chain_upstream", "disabled"].contains(&mode.as_str()) {
            return Err(format!(
                "dns_filter.integration_mode must be one of 'auto', 'takeover', 'chain_upstream', 'disabled', got '{mode}'"
            ));
        }

        if let Some(port_str) = self.dns_filter.listen_address.rsplit(':').next() {
            if let Ok(listen_port) = port_str.parse::<u16>() {
                if listen_port == self.dns_filter.chain_upstream_listen_port {
                    return Err(format!(
                        "dns_filter.chain_upstream_listen_port ({}) cannot be the same as listen_address port ({})",
                        self.dns_filter.chain_upstream_listen_port, listen_port
                    ));
                }
            }
        }

        if self.ip_reputation_filter.ttl_days == 0 {
            return Err("ip_reputation_filter.ttl_days must be positive (> 0)".to_string());
        }

        if self.ip_reputation_filter.stale_warning_days == 0 {
            return Err(
                "ip_reputation_filter.stale_warning_days must be positive (> 0)".to_string(),
            );
        }

        if self.browser_extension.blocklist_refresh_via != "gn-shield-core" {
            return Err(format!(
                "browser_extension.blocklist_refresh_via must be 'gn-shield-core' to protect privacy, got '{}'",
                self.browser_extension.blocklist_refresh_via
            ));
        }

        if self.notifications.batch_window_ms == 0 {
            return Err("notifications.batch_window_ms must be positive (> 0)".to_string());
        }

        if self.data_breach.k_anonymity_api_url.trim().is_empty() {
            return Err("data_breach.k_anonymity_api_url cannot be empty".to_string());
        }

        if self.data_breach.check_timeout_ms == 0 {
            return Err("data_breach.check_timeout_ms must be positive (> 0)".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_config() {
        let toml_str = r#"
        [general]
        log_level = "debug"

        [[allowlist.hash]]
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        name = "cloudflared"

        [[allowlist.publisher]]
        platform = "linux"
        verified_by = "pacman"
        package_name = "firefox"
        auto_trust = true
        high_fanout_expected = true

        [[allowlist.path]]
        path = "/usr/bin/cloudflared"
        verified_by = "pacman"
        auto_reverify_on_update = true

        [[ransomware.excluded_paths]]
        path_pattern = "**/custom_build/**"
        reason = "custom_tool"
        sensitivity = "reduced"
        "#;

        let config = GnShieldConfig::parse_toml(toml_str).expect("failed to parse config");
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.allowlist.hash.len(), 1);
        assert_eq!(config.allowlist.hash[0].name, "cloudflared");
        assert_eq!(config.allowlist.publisher.len(), 1);
        assert_eq!(config.allowlist.publisher[0].package_name, "firefox");
        assert!(config.allowlist.publisher[0].high_fanout_expected);
        assert_eq!(config.allowlist.path.len(), 1);
        assert_eq!(config.allowlist.path[0].path, "/usr/bin/cloudflared");
        assert_eq!(config.ransomware.excluded_paths.len(), 1);
        assert_eq!(
            config.ransomware.excluded_paths[0].path_pattern,
            "**/custom_build/**"
        );
        assert_eq!(config.network.domain_allowlist.len(), 4);
        assert_eq!(config.dns_filter.listen_address, "127.0.0.1:53");
        assert_eq!(config.dns_filter.integration_mode, "auto");
        assert_eq!(config.ip_reputation_filter.ttl_days, 10);
    }

    #[test]
    fn test_invalid_scoring_weights() {
        let toml_str = r#"
        [scoring]
        weight_static = 0.5
        weight_hash_reputation = 0.5
        weight_behavior = 0.5
        "#;
        assert!(GnShieldConfig::parse_toml(toml_str).is_err());
    }

    #[test]
    fn test_invalid_default_action_on_timeout() {
        let toml_str = r#"
        [notifications]
        default_action_on_timeout = "block"
        "#;
        assert!(GnShieldConfig::parse_toml(toml_str).is_err());
    }

    #[test]
    fn test_dns_filter_and_ip_rep_validation() {
        let invalid_mode = r#"
        [dns_filter]
        integration_mode = "invalid_mode"
        "#;
        assert!(GnShieldConfig::parse_toml(invalid_mode).is_err());

        let port_collision = r#"
        [dns_filter]
        listen_address = "127.0.0.1:5353"
        chain_upstream_listen_port = 5353
        "#;
        assert!(GnShieldConfig::parse_toml(port_collision).is_err());

        let invalid_ttl = r#"
        [ip_reputation_filter]
        ttl_days = 0
        "#;
        assert!(GnShieldConfig::parse_toml(invalid_ttl).is_err());
    }

    #[test]
    fn test_browser_extension_config() {
        let toml_str = r#"
        [browser_extension]
        enabled = true
        enforce_domain_blocklist = true
        form_action_mismatch_heuristic = true
        trusted_identity_providers = ["accounts.google.com", "custom-sso.company.com"]
        blocklist_refresh_via = "gn-shield-core"
        "#;
        let config =
            GnShieldConfig::parse_toml(toml_str).expect("failed to parse browser extension config");
        assert!(config.browser_extension.enabled);
        assert_eq!(config.browser_extension.trusted_identity_providers.len(), 2);
        assert_eq!(
            config.browser_extension.blocklist_refresh_via,
            "gn-shield-core"
        );

        // Invalid external refresh via
        let invalid_refresh = r#"
        [browser_extension]
        blocklist_refresh_via = "https://external-tracker.com"
        "#;
        assert!(GnShieldConfig::parse_toml(invalid_refresh).is_err());
    }

    #[test]
    fn test_data_breach_and_notification_batching_config() {
        let toml_str = r#"
        [notifications]
        style = "native"
        prompt_timeout_seconds = 45
        batching_enabled = true
        batch_window_ms = 1500
        batch_threshold_count = 3

        [data_breach]
        enabled = true
        scan_clipboard = true
        scan_uploads = true
        k_anonymity_api_url = "https://api.pwnedpasswords.com/range/"
        check_timeout_ms = 4000
        "#;
        let config = GnShieldConfig::parse_toml(toml_str)
            .expect("failed to parse data breach and batching config");
        assert!(config.notifications.batching_enabled);
        assert_eq!(config.notifications.batch_window_ms, 1500);
        assert_eq!(config.notifications.batch_threshold_count, 3);
        assert!(config.data_breach.enabled);
        assert!(config.data_breach.scan_clipboard);
        assert!(config.data_breach.scan_uploads);
        assert_eq!(config.data_breach.check_timeout_ms, 4000);

        let invalid_breach = r#"
        [data_breach]
        k_anonymity_api_url = "  "
        "#;
        assert!(GnShieldConfig::parse_toml(invalid_breach).is_err());
    }
}
