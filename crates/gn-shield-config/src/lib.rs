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
    pub path: Vec<PathAllowlistEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnShieldConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
}

impl GnShieldConfig {
    pub fn parse_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
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

        [[allowlist.path]]
        path = "/usr/bin/cloudflared"
        verified_by = "pacman"
        auto_reverify_on_update = true
        "#;

        let config = GnShieldConfig::parse_toml(toml_str).expect("failed to parse config");
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.allowlist.hash.len(), 1);
        assert_eq!(config.allowlist.hash[0].name, "cloudflared");
        assert_eq!(config.allowlist.path.len(), 1);
        assert_eq!(config.allowlist.path[0].path, "/usr/bin/cloudflared");
    }
}
