//! Behavioral Ransomware Detector and Tier 5 Exclusion Pipeline.
//! Implements explicit condition-based ransomware evaluation (honeypot + entropy shift + mass write).
//! Strictly enforces that Tier 5 directory exceptions reduce sensitivity rather than disable detection,
//! while resolving symlinks to prevent evasion.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gn_shield_config::{GnShieldConfig, RansomwareConfig};
use gn_shield_rules::{calculate_file_entropy, HoneypotManager};

use crate::decision::Action;

/// Recorded filesystem modification event within the detection sliding window.
#[derive(Debug, Clone)]
pub struct ModificationEvent {
    pub path: PathBuf,
    pub timestamp: Instant,
    pub entropy: f32,
    pub is_high_entropy: bool,
    pub is_tier5_excluded: bool,
    pub is_honeypot: bool,
}

/// Incident response containment actions for confirmed ransomware attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentAction {
    Allow,
    PromptUser(String),
    ContainAndTerminate {
        reason: String,
        target_paths: Vec<PathBuf>,
    },
}

pub struct RansomwareDetector {
    config: RansomwareConfig,
    honeypot_manager: HoneypotManager,
    history: VecDeque<ModificationEvent>,
    auto_terminations: VecDeque<Instant>,
}

impl RansomwareDetector {
    #[must_use]
    pub fn new(config: &GnShieldConfig, honeypot_manager: HoneypotManager) -> Self {
        Self {
            config: config.ransomware.clone(),
            honeypot_manager,
            history: VecDeque::new(),
            auto_terminations: VecDeque::new(),
        }
    }

    /// Access the honeypot manager.
    pub fn honeypot_manager_mut(&mut self) -> &mut HoneypotManager {
        &mut self.honeypot_manager
    }

    #[must_use]
    pub fn honeypot_manager(&self) -> &HoneypotManager {
        &self.honeypot_manager
    }

    /// Checks if a path matches any Tier 5 excluded directory patterns.
    /// Crucial: symlinks MUST be resolved to their canonical paths first!
    pub fn is_tier5_excluded(&self, path: &Path) -> bool {
        // Resolve symlinks to canonical path to prevent scope-escape evasion
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        for excluded in &self.config.excluded_paths {
            if matches_pattern(&canonical_path, &excluded.path_pattern) {
                return true;
            }
        }
        false
    }

    /// Cleans up events outside the sliding detection window.
    pub fn prune_old_events(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);

        while let Some(front) = self.history.front() {
            if now.duration_since(front.timestamp) > window {
                self.history.pop_front();
            } else {
                break;
            }
        }

        // Prune circuit breaker history (60 seconds window)
        let cb_window = Duration::from_secs(60);
        while let Some(front) = self.auto_terminations.front() {
            if now.duration_since(*front) > cb_window {
                self.auto_terminations.pop_front();
            } else {
                break;
            }
        }
    }

    /// Records a file modification event and evaluates against ransomware behavioral conditions.
    pub fn record_and_evaluate(
        &mut self,
        path: &Path,
        payload_entropy: Option<f32>,
    ) -> (Action, IncidentAction) {
        self.prune_old_events();

        let entropy = match payload_entropy {
            Some(e) => e,
            None => calculate_file_entropy(path).unwrap_or(0.0),
        };

        let high_entropy = entropy >= self.config.entropy_threshold;
        let is_tier5 = self.is_tier5_excluded(path);
        let is_honeypot = self.honeypot_manager.is_canary(path);

        let event = ModificationEvent {
            path: path.to_path_buf(),
            timestamp: Instant::now(),
            entropy,
            is_high_entropy: high_entropy,
            is_tier5_excluded: is_tier5,
            is_honeypot,
        };

        self.history.push_back(event);

        // Check conditions:
        // Condition 1: Honeypot canary file tampered (modified, encrypted, or deleted)
        let honeypot_tampered = self
            .history
            .iter()
            .any(|ev| ev.is_honeypot && self.honeypot_manager.is_tampered(&ev.path));

        // Count high entropy writes in window
        let high_entropy_count = self.history.iter().filter(|ev| ev.is_high_entropy).count();

        // Check if writes occurred in Tier 5 excluded directory (reduced sensitivity)
        let tier5_writes_count = self
            .history
            .iter()
            .filter(|ev| ev.is_tier5_excluded)
            .count();
        let non_tier5_writes_count = self.history.len().saturating_sub(tier5_writes_count);

        // Effective threshold calculation:
        // Tier 5 directories have reduced sensitivity, so normal mass writes without honeypot changes never alert.
        let threshold = if non_tier5_writes_count == 0 && tier5_writes_count > 0 {
            // All writes in tier 5 (e.g. npm install / cargo build): relaxed threshold
            self.config.mass_write_threshold * 10
        } else {
            self.config.mass_write_threshold
        };

        // Strict condition matching as specified in DECISION_ENGINE.md Section 5 item 2:
        // ALL conditions must be met simultaneously for Action::Block:
        // 1. Honeypot file changed/tampered
        // 2. High entropy shift/writes
        // 3. Rate of modifications exceeds threshold
        if honeypot_tampered && high_entropy_count >= self.config.mass_write_threshold {
            // Check mass-kill circuit breaker
            if self.auto_terminations.len() >= 5 {
                let reason = format!(
                    "Ransomware pattern detected (honeypot tampered + {} high-entropy writes), but mass-kill circuit breaker is tripped. Falling back to PromptUser.",
                    high_entropy_count
                );
                return (Action::PromptUser, IncidentAction::PromptUser(reason));
            }

            self.auto_terminations.push_back(Instant::now());

            let affected_paths: Vec<PathBuf> = self
                .history
                .iter()
                .filter(|ev| ev.is_high_entropy || ev.is_honeypot)
                .map(|ev| ev.path.clone())
                .collect();

            let reason = format!(
                "Ransomware activity confirmed: canary decoy tampered and {} high-entropy file writes detected within detection window",
                high_entropy_count
            );

            return (
                Action::Block,
                IncidentAction::ContainAndTerminate {
                    reason,
                    target_paths: affected_paths,
                },
            );
        }

        // Suspicious behavior below auto-block threshold: honeypot touched OR mass writes in non-tier5
        if honeypot_tampered
            || (non_tier5_writes_count >= threshold && high_entropy_count >= threshold / 2)
        {
            let reason = format!(
                "Suspicious mass file modification activity detected (honeypot_tampered={}, high_entropy_writes={})",
                honeypot_tampered, high_entropy_count
            );
            return (Action::PromptUser, IncidentAction::PromptUser(reason));
        }

        // Normal activity
        (Action::Allow, IncidentAction::Allow)
    }
}

/// Matches path against glob-like pattern such as "**/node_modules/**" or "**/target/**".
pub fn matches_pattern(path: &Path, pattern: &str) -> bool {
    let clean_pattern = pattern.trim_matches('*').trim_matches('/');

    for component in path.components() {
        if let std::path::Component::Normal(os_str) = component {
            if let Some(s) = os_str.to_str() {
                if s == clean_pattern {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_matches_pattern_tier5() {
        let p1 = Path::new("/home/user/project/node_modules/package/index.js");
        assert!(matches_pattern(p1, "**/node_modules/**"));

        let p2 = Path::new("/home/user/project/target/debug/app");
        assert!(matches_pattern(p2, "**/target/**"));

        let p3 = Path::new("/home/user/project/.git/objects/12/345");
        assert!(matches_pattern(p3, "**/.git/**"));

        let p4 = Path::new("/home/user/project/src/main.rs");
        assert!(!matches_pattern(p4, "**/node_modules/**"));
    }

    #[test]
    fn test_tier5_symlink_resolution() {
        let temp = tempdir().expect("tempdir failed");
        let real_doc_dir = temp.path().join("Documents");
        fs::create_dir_all(&real_doc_dir).expect("dir create failed");

        let node_modules_dir = temp.path().join("node_modules");
        fs::create_dir_all(&node_modules_dir).expect("dir create failed");

        // Symlink inside node_modules pointing out to Documents/important.txt
        let doc_file = real_doc_dir.join("important.txt");
        fs::write(&doc_file, b"content").expect("write failed");

        let symlink_file = node_modules_dir.join("sneaky_link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&doc_file, &symlink_file).expect("symlink failed");

        let config = GnShieldConfig::default();
        let honeypot = HoneypotManager::new();
        let detector = RansomwareDetector::new(&config, honeypot);

        #[cfg(unix)]
        {
            // The symlink points to Documents, so canonicalize reveals it is NOT in node_modules
            assert!(!detector.is_tier5_excluded(&symlink_file));
        }
    }

    #[test]
    fn test_normal_build_in_node_modules_does_not_block() {
        let temp = tempdir().expect("tempdir failed");
        let config = GnShieldConfig::default();
        let honeypot = HoneypotManager::new();
        let mut detector = RansomwareDetector::new(&config, honeypot);

        let nm_dir = temp.path().join("node_modules");
        fs::create_dir_all(&nm_dir).expect("create dir failed");

        // Simulate npm install writing 20 files
        for i in 0..20 {
            let file_path = nm_dir.join(format!("pkg_{i}.js"));
            let (action, incident) = detector.record_and_evaluate(&file_path, Some(4.0));
            assert_eq!(action, Action::Allow);
            assert_eq!(incident, IncidentAction::Allow);
        }
    }

    #[test]
    fn test_ransomware_attack_detected_and_blocked() {
        let temp = tempdir().expect("tempdir failed");
        let config = GnShieldConfig::default();
        let mut honeypot = HoneypotManager::new();
        let canaries = honeypot
            .deploy_in_dir(temp.path())
            .expect("deploy canaries failed");

        let mut detector = RansomwareDetector::new(&config, honeypot);

        // Tamper with canary file (encrypt it)
        let canary_path = &canaries[0];
        fs::write(canary_path, vec![0xFF; 256]).expect("tamper failed");

        // Ransomware writes 12 encrypted files (high entropy)
        let mut last_action = Action::Allow;
        let mut last_incident = IncidentAction::Allow;

        for i in 0..12 {
            let file_path = temp.path().join(format!("file_{i}.locked"));
            fs::write(&file_path, vec![0xEE; 100]).expect("write failed");
            let (a, inc) = detector.record_and_evaluate(&file_path, Some(7.8));
            last_action = a;
            last_incident = inc;
        }

        // Also evaluate the canary file modification
        let (a_canary, inc_canary) = detector.record_and_evaluate(canary_path, Some(7.9));
        if a_canary == Action::Block {
            last_action = a_canary;
            last_incident = inc_canary;
        }

        assert_eq!(last_action, Action::Block);
        match last_incident {
            IncidentAction::ContainAndTerminate { reason, .. } => {
                assert!(reason.contains("canary decoy tampered"));
            }
            _ => panic!("Expected ContainAndTerminate, got {last_incident:?}"),
        }
    }
}
