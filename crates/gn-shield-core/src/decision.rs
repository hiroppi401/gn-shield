//! Decision Engine implementation for GN-Shield.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    Trusted,
    KnownBad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
    PromptUser,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub static_score: f32,
    pub hash_reputation: f32,
    pub behavior_score: f32,
    pub allowlist_override: Option<TrustLevel>,
}

/// Evaluates a verdict against allowlist overrides, ceiling/veto gates, and weighted scoring.
#[must_use]
pub fn decide(v: &Verdict) -> Action {
    if let Some(TrustLevel::Trusted) = v.allowlist_override {
        return Action::Allow; // Short circuit: trusted override always allows
    }
    if let Some(TrustLevel::KnownBad) = v.allowlist_override {
        return Action::Block; // Known bad signature/hash always blocks
    }

    // Ceiling / Veto Gates: Extreme individual signals cannot be diluted by 0.0 signals
    if v.behavior_score >= 0.9 {
        return Action::Block;
    }
    if v.behavior_score >= 0.7 || v.static_score >= 0.8 || v.hash_reputation >= 0.8 {
        return Action::PromptUser;
    }

    let total = (v.static_score * 0.4) + (v.hash_reputation * 0.4) + (v.behavior_score * 0.2);

    if total > 0.8 {
        Action::Block
    } else if total > 0.4 {
        Action::PromptUser
    } else {
        Action::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_override() {
        let v = Verdict {
            static_score: 1.0,
            hash_reputation: 1.0,
            behavior_score: 1.0,
            allowlist_override: Some(TrustLevel::Trusted),
        };
        assert_eq!(decide(&v), Action::Allow);
    }

    #[test]
    fn test_known_bad_override() {
        let v = Verdict {
            static_score: 0.0,
            hash_reputation: 0.0,
            behavior_score: 0.0,
            allowlist_override: Some(TrustLevel::KnownBad),
        };
        assert_eq!(decide(&v), Action::Block);
    }

    #[test]
    fn test_ceiling_veto_gate_high_behavior() {
        // High behavior score (1.0) must not be diluted by 0.0 static and hash scores
        let v = Verdict {
            static_score: 0.0,
            hash_reputation: 0.0,
            behavior_score: 0.95,
            allowlist_override: None,
        };
        assert_eq!(decide(&v), Action::Block);
    }

    #[test]
    fn test_ceiling_veto_gate_moderate_behavior() {
        let v = Verdict {
            static_score: 0.0,
            hash_reputation: 0.0,
            behavior_score: 0.75,
            allowlist_override: None,
        };
        assert_eq!(decide(&v), Action::PromptUser);
    }

    #[test]
    fn test_ceiling_veto_gate_high_static() {
        let v = Verdict {
            static_score: 0.85,
            hash_reputation: 0.0,
            behavior_score: 0.0,
            allowlist_override: None,
        };
        assert_eq!(decide(&v), Action::PromptUser);
    }

    #[test]
    fn test_ceiling_veto_gate_high_hash_reputation() {
        // Fuzzy/partial hash match (belum cukup exact untuk KnownBad override) tidak boleh
        // "terlarut" jadi Allow hanya karena static_score dan behavior_score kebetulan 0.0.
        // hash_reputation berbobot sama (0.4) dengan static_score, jadi wajib dilindungi
        // ceiling gate yang sama, bukan cuma static_score.
        let v = Verdict {
            static_score: 0.0,
            hash_reputation: 0.85,
            behavior_score: 0.0,
            allowlist_override: None,
        };
        assert_eq!(decide(&v), Action::PromptUser);
    }

    #[test]
    fn test_clean_verdict() {
        let v = Verdict {
            static_score: 0.1,
            hash_reputation: 0.0,
            behavior_score: 0.1,
            allowlist_override: None,
        };
        assert_eq!(decide(&v), Action::Allow);
    }
}
