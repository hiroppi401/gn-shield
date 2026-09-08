//! Configuration schema definition and parser for GN-Shield.

#[derive(Debug, Clone)]
pub struct GeneralConfig {
    pub log_level: String,
    pub telemetry_enabled: bool,
    pub update_channel: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            telemetry_enabled: false,
            update_channel: "stable".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScoringConfig {
    pub weight_static: f32,
    pub weight_hash_reputation: f32,
    pub weight_behavior: f32,
    pub threshold_block: f32,
    pub threshold_prompt: f32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weight_static: 0.4,
            weight_hash_reputation: 0.4,
            weight_behavior: 0.2,
            threshold_block: 0.8,
            threshold_prompt: 0.4,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct GnShieldConfig {
    pub general: GeneralConfig,
    pub scoring: ScoringConfig,
}
