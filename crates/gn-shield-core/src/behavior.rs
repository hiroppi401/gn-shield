//! Process behavior monitoring, child fan-out evaluation, and command-line scanning.
//! Integrates Tier 2 Publisher allowlist flags (high_fanout_expected) to eliminate
//! false positive alerts for multi-process developer tools and browsers.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use gn_shield_config::GnShieldConfig;
use gn_shield_rules::YaraEngine;

/// Record of a child process spawn event.
#[derive(Debug, Clone)]
struct SpawnRecord {
    _child_pid: u32,
    timestamp: Instant,
}

/// Record of a network connection attempt to a blocked IP.
#[derive(Debug, Clone)]
struct BlockedAttemptRecord {
    _destination_ip: String,
    timestamp: Instant,
}

pub struct ProcessBehaviorTracker {
    config: GnShieldConfig,
    yara: YaraEngine,
    spawn_history: HashMap<u32, VecDeque<SpawnRecord>>,
    blocked_connections: HashMap<u32, VecDeque<BlockedAttemptRecord>>,
}

impl ProcessBehaviorTracker {
    pub fn new(config: GnShieldConfig) -> Result<Self, String> {
        let yara = YaraEngine::new_with_default_rules()?;
        Ok(Self {
            config,
            yara,
            spawn_history: HashMap::new(),
            blocked_connections: HashMap::new(),
        })
    }

    /// Checks if a package name or executable path is flagged as high_fanout_expected.
    #[must_use]
    pub fn is_high_fanout_expected(&self, exe_path: &Path) -> bool {
        let file_name = match exe_path.file_name().and_then(|f| f.to_str()) {
            Some(name) => name.to_lowercase(),
            None => return false,
        };

        for pub_entry in &self.config.allowlist.publisher {
            if pub_entry.high_fanout_expected
                && (pub_entry.package_name.eq_ignore_ascii_case(&file_name)
                    || file_name.contains(&pub_entry.package_name.to_lowercase()))
            {
                return true;
            }
        }

        // Common defaults if not explicitly configured
        let default_multi_process = ["firefox", "chromium", "chrome", "docker", "podman", "cargo"];
        default_multi_process
            .iter()
            .any(|&tool| file_name.contains(tool))
    }

    /// Records a process spawn event from ppid -> child_pid.
    pub fn record_spawn(&mut self, ppid: u32, child_pid: u32) {
        let now = Instant::now();
        let records = self.spawn_history.entry(ppid).or_default();
        records.push_back(SpawnRecord {
            _child_pid: child_pid,
            timestamp: now,
        });

        // Prune older than 5 seconds
        let window = Duration::from_secs(5);
        while let Some(front) = records.front() {
            if now.duration_since(front.timestamp) > window {
                records.pop_front();
            } else {
                break;
            }
        }
    }

    /// Records an attempted connection to a blocked IP by a PID.
    pub fn record_blocked_ip_attempt(&mut self, pid: u32, ip: &str) {
        let now = Instant::now();
        let records = self.blocked_connections.entry(pid).or_default();
        records.push_back(BlockedAttemptRecord {
            _destination_ip: ip.to_string(),
            timestamp: now,
        });

        // Prune older than 5 minutes (300s)
        let window = Duration::from_secs(300);
        while let Some(front) = records.front() {
            if now.duration_since(front.timestamp) > window {
                records.pop_front();
            } else {
                break;
            }
        }
    }

    /// Evaluates behavior score for a process based on fan-out, command-line, and network signals.
    pub fn evaluate_process_behavior(
        &self,
        pid: u32,
        ppid: u32,
        exe: &Path,
        cmdline: &[String],
    ) -> f32 {
        let mut score: f32 = 0.0;

        // 1. Check repeated blocked IP connection attempts (DECISION_ENGINE.md Section 5 item 5)
        if let Some(records) = self.blocked_connections.get(&pid) {
            let count = records.len();
            if count >= 3 {
                // >= 3 blocked attempts within 5 minutes -> high confidence malicious behavior
                return 0.95;
            } else if count > 0 {
                score += (count as f32) * 0.25;
            }
        }

        // 2. Evaluate fan-out signal (child spawning frequency)
        if let Some(spawn_records) = self.spawn_history.get(&ppid) {
            let child_count = spawn_records.len();
            let is_trusted_fanout = self.is_high_fanout_expected(exe);

            if !is_trusted_fanout {
                if child_count >= 20 {
                    // Rapid untrusted mass child spawning (fork-bomb or malware propagation)
                    score = score.max(0.85);
                } else if child_count >= 10 {
                    score = score.max(0.60);
                } else if child_count >= 5 {
                    score = score.max(0.30);
                }
            } else {
                // Multi-process browser or container tool: fan-out signal is damped
                score = score.max(0.0);
            }
        }

        // 3. Scan command-line text using YARA-X to catch fileless / LOLBins one-liners
        let full_cmdline = cmdline.join(" ");
        if let Ok(scan_res) = self.yara.scan_bytes(full_cmdline.as_bytes()) {
            if !scan_res.matched_rules.is_empty() {
                score = score.max(scan_res.static_score);
            }
        }

        score.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gn_shield_config::PublisherAllowlistEntry;

    #[test]
    fn test_high_fanout_for_firefox_is_damped() {
        let mut config = GnShieldConfig::default();
        config.allowlist.publisher.push(PublisherAllowlistEntry {
            platform: "linux".to_string(),
            verified_by: "pacman".to_string(),
            package_name: "firefox".to_string(),
            auto_trust: true,
            high_fanout_expected: true,
        });

        let mut tracker = ProcessBehaviorTracker::new(config).expect("tracker init failed");

        let parent_pid = 5000;
        let exe = Path::new("/usr/lib/firefox/firefox");

        // Simulate Firefox spawning 30 tab processes
        for i in 1..=30 {
            tracker.record_spawn(parent_pid, parent_pid + i);
        }

        let cmdline = vec![
            "/usr/lib/firefox/firefox".to_string(),
            "--contentproc".to_string(),
        ];
        let score = tracker.evaluate_process_behavior(parent_pid + 1, parent_pid, exe, &cmdline);

        // Score must NOT be high because firefox is high_fanout_expected!
        assert!(
            score < 0.2,
            "Firefox fanout score unexpectedly high: {score}"
        );
    }

    #[test]
    fn test_untrusted_process_mass_fanout_triggers_high_behavior_score() {
        let config = GnShieldConfig::default();
        let mut tracker = ProcessBehaviorTracker::new(config).expect("tracker init failed");

        let parent_pid = 9999;
        let exe = Path::new("/tmp/unknown_malware");

        // Spawn 25 child processes in rapid succession without high_fanout_expected
        for i in 1..=25 {
            tracker.record_spawn(parent_pid, parent_pid + i);
        }

        let cmdline = vec!["/tmp/unknown_malware".to_string()];
        let score = tracker.evaluate_process_behavior(parent_pid + 1, parent_pid, exe, &cmdline);

        assert!(score >= 0.85, "Untrusted fanout score too low: {score}");
    }

    #[test]
    fn test_repeated_blocked_ip_attempts() {
        let config = GnShieldConfig::default();
        let mut tracker = ProcessBehaviorTracker::new(config).expect("tracker init failed");

        let pid = 7777;
        let exe = Path::new("/tmp/bad_bot");
        let cmdline = vec!["bad_bot".to_string()];

        tracker.record_blocked_ip_attempt(pid, "198.51.100.1");
        tracker.record_blocked_ip_attempt(pid, "198.51.100.2");
        assert!(tracker.evaluate_process_behavior(pid, 1, exe, &cmdline) < 0.9);

        // 3rd attempt exceeds threshold -> 0.95 behavior score
        tracker.record_blocked_ip_attempt(pid, "198.51.100.3");
        assert_eq!(
            tracker.evaluate_process_behavior(pid, 1, exe, &cmdline),
            0.95
        );
    }
}
