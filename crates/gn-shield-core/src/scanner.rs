//! Core on-access file scanning pipeline and evaluation service.
//! Follows the multi-tiered scanning strategy (Layer 0 short-circuit -> Layer 1 YARA-X -> Decision Engine).

use std::path::Path;

use gn_shield_config::GnShieldConfig;
use gn_shield_rules::{calculate_sha256_file, HashReputationStore, YaraEngine};

use crate::decision::{decide, Action, TrustLevel, Verdict};

#[derive(Debug, Clone)]
pub struct ScanEvaluation {
    pub path: std::path::PathBuf,
    pub sha256: String,
    pub static_score: f32,
    pub matched_rules: Vec<String>,
    pub action: Action,
    pub reason: String,
}

pub struct FileScanner {
    config: GnShieldConfig,
    yara: YaraEngine,
    hash_store: HashReputationStore,
}

impl FileScanner {
    /// Initializes scanner with active configuration, compiled default rules, and reputation store.
    pub fn new(config: GnShieldConfig, hash_store: HashReputationStore) -> Result<Self, String> {
        let yara = YaraEngine::new_with_default_rules()?;
        Ok(Self {
            config,
            yara,
            hash_store,
        })
    }

    /// Evaluates a filesystem path according to GN-Shield's tiered decision pipeline.
    pub fn evaluate_file(&self, path: &Path) -> Result<ScanEvaluation, String> {
        if !path.exists() || !path.is_file() {
            return Err(format!("Path does not exist or is not a file: {path:?}"));
        }

        // 1. Calculate file SHA-256
        let sha256 = calculate_sha256_file(path)
            .map_err(|e| format!("Failed to hash file {path:?}: {e}"))?;

        // 2. Layer 0: Short-circuit on Tier 1 Hash Allowlist
        for hash_entry in &self.config.allowlist.hash {
            if hash_entry.sha256.eq_ignore_ascii_case(&sha256) {
                let verdict = Verdict {
                    static_score: 0.0,
                    hash_reputation: 0.0,
                    behavior_score: 0.0,
                    allowlist_override: Some(TrustLevel::Trusted),
                };
                return Ok(ScanEvaluation {
                    path: path.to_path_buf(),
                    sha256,
                    static_score: 0.0,
                    matched_rules: Vec::new(),
                    action: decide(&verdict),
                    reason: format!("Allowed by Tier 1 Hash Allowlist ({})", hash_entry.name),
                });
            }
        }

        // 3. Layer 0: Short-circuit on Tier 3 Path Allowlist
        for path_entry in &self.config.allowlist.path {
            let trusted_path = Path::new(&path_entry.path);
            if path == trusted_path || path.starts_with(trusted_path) {
                let verdict = Verdict {
                    static_score: 0.0,
                    hash_reputation: 0.0,
                    behavior_score: 0.0,
                    allowlist_override: Some(TrustLevel::Trusted),
                };
                return Ok(ScanEvaluation {
                    path: path.to_path_buf(),
                    sha256,
                    static_score: 0.0,
                    matched_rules: Vec::new(),
                    action: decide(&verdict),
                    reason: format!("Allowed by Tier 3 Path Allowlist ({})", path_entry.path),
                });
            }
        }

        // 4. Layer 0: Check known bad hash reputation
        if self.hash_store.is_known_bad(&sha256) {
            let verdict = Verdict {
                static_score: 0.0,
                hash_reputation: 1.0,
                behavior_score: 0.0,
                allowlist_override: Some(TrustLevel::KnownBad),
            };
            return Ok(ScanEvaluation {
                path: path.to_path_buf(),
                sha256,
                static_score: 0.0,
                matched_rules: Vec::new(),
                action: decide(&verdict),
                reason: "Blocked by Known-Bad Hash Reputation Database".to_string(),
            });
        }

        // 5. Layer 1 & 2: YARA-X Pattern Matching
        let scan_res = self.yara.scan_file(path)?;
        let hash_reputation = 0.0;
        let behavior_score = 0.0;

        let verdict = Verdict {
            static_score: scan_res.static_score,
            hash_reputation,
            behavior_score,
            allowlist_override: None,
        };

        let action = decide(&verdict);
        let reason = if !scan_res.matched_rules.is_empty() {
            format!("YARA-X signature matched: {:?}", scan_res.matched_rules)
        } else {
            "File passed all checks cleanly".to_string()
        };

        Ok(ScanEvaluation {
            path: path.to_path_buf(),
            sha256,
            static_score: scan_res.static_score,
            matched_rules: scan_res.matched_rules,
            action,
            reason,
        })
    }

    /// Evaluates a filesystem path and immediately executes remediation via ActionExecutor if required.
    pub fn evaluate_and_execute(
        &self,
        path: &Path,
        pid: Option<u32>,
        executor: &mut crate::executor::ActionExecutor,
    ) -> Result<(ScanEvaluation, crate::executor::ExecutionReport), String> {
        let eval = self.evaluate_file(path)?;
        let report = executor.execute_scan_verdict(&eval, pid)?;
        Ok((eval, report))
    }
}

impl gn_shield_sensors_common::ExecPermEvaluator for FileScanner {
    fn evaluate_permission(&self, path: &Path, _pid: u32) -> Result<bool, String> {
        match self.evaluate_file(path) {
            Ok(eval) => {
                // Deny execution only if Action is Block
                Ok(eval.action != Action::Block)
            }
            Err(e) => {
                // Fail-open per docs/ARCHITECTURE.md line 129
                eprintln!("Scanner evaluation failed for {path:?}: {e}. Failing open.");
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gn_shield_config::{HashAllowlistEntry, PathAllowlistEntry};
    use gn_shield_rules::{calculate_sha256, EICAR_PAYLOAD};
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_eicar_scan_evaluation() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let eicar_file = temp_dir.path().join("eicar.com");
        let mut f = fs::File::create(&eicar_file).expect("create file failed");
        f.write_all(EICAR_PAYLOAD).expect("write failed");
        drop(f);

        let config = GnShieldConfig::default();
        let hash_store = HashReputationStore::new();
        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

        let eval = scanner
            .evaluate_file(&eicar_file)
            .expect("evaluation failed");
        assert_eq!(eval.static_score, 1.0);
        assert_eq!(eval.matched_rules, vec!["EICAR_Test_File"]);
        // High static score triggers prompt or block
        assert_ne!(eval.action, Action::Allow);
    }

    #[test]
    fn test_tier1_hash_allowlist_override() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let eicar_file = temp_dir.path().join("trusted_eicar.com");
        let mut f = fs::File::create(&eicar_file).expect("create file failed");
        f.write_all(EICAR_PAYLOAD).expect("write failed");
        drop(f);

        let eicar_hash = calculate_sha256(EICAR_PAYLOAD);

        let mut config = GnShieldConfig::default();
        config.allowlist.hash.push(HashAllowlistEntry {
            sha256: eicar_hash,
            name: "Explicitly Whitelisted EICAR Sample".to_string(),
            scope: vec!["filesystem".to_string()],
            added_by: "user".to_string(),
            added_at: "2026-09-08T19:00:00Z".to_string(),
        });

        let hash_store = HashReputationStore::new();
        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

        let eval = scanner
            .evaluate_file(&eicar_file)
            .expect("evaluation failed");
        // Must short-circuit to Action::Allow because of Tier 1 hash allowlist!
        assert_eq!(eval.action, Action::Allow);
        assert!(eval.reason.contains("Tier 1 Hash Allowlist"));
    }

    #[test]
    fn test_tier3_path_allowlist_override() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let trusted_dir = temp_dir.path().join("trusted_dir");
        fs::create_dir_all(&trusted_dir).expect("create_dir failed");

        let test_file = trusted_dir.join("trusted_app.bin");
        let mut f = fs::File::create(&test_file).expect("create file failed");
        f.write_all(EICAR_PAYLOAD).expect("write failed");
        drop(f);

        let mut config = GnShieldConfig::default();
        config.allowlist.path.push(PathAllowlistEntry {
            path: trusted_dir.to_string_lossy().to_string(),
            verified_by: "user".to_string(),
            auto_reverify_on_update: false,
        });

        let hash_store = HashReputationStore::new();
        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

        let eval = scanner
            .evaluate_file(&test_file)
            .expect("evaluation failed");
        assert_eq!(eval.action, Action::Allow);
        assert!(eval.reason.contains("Tier 3 Path Allowlist"));
    }

    #[test]
    fn test_known_bad_hash_blocked() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let malware_file = temp_dir.path().join("known_bad.exe");
        let mut f = fs::File::create(&malware_file).expect("create file failed");
        let dummy_payload = b"Sample malicious bytes 123456789";
        f.write_all(dummy_payload).expect("write failed");
        drop(f);

        let malware_hash = calculate_sha256(dummy_payload);

        let config = GnShieldConfig::default();
        let mut hash_store = HashReputationStore::new();
        hash_store.add_known_bad(&malware_hash);

        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");
        let eval = scanner
            .evaluate_file(&malware_file)
            .expect("evaluation failed");
        assert_eq!(eval.action, Action::Block);
        assert!(eval.reason.contains("Known-Bad Hash"));
    }

    #[test]
    fn test_scanner_exec_perm_evaluator_trait() {
        use gn_shield_sensors_common::ExecPermEvaluator;

        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let safe_file = temp_dir.path().join("safe.bin");
        fs::write(&safe_file, b"safe binary content").expect("write failed");

        let malware_file = temp_dir.path().join("malware.bin");
        let malware_bytes = b"definitely_malicious_sample_bytes_987";
        fs::write(&malware_file, malware_bytes).expect("write failed");

        let config = GnShieldConfig::default();
        let mut hash_store = HashReputationStore::new();
        hash_store.add_known_bad(&calculate_sha256(malware_bytes));
        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

        // Safe file must evaluate to allowed (true)
        assert!(scanner.evaluate_permission(&safe_file, 1234).unwrap());

        // Malicious file with Action::Block must evaluate to denied (false)
        assert!(!scanner.evaluate_permission(&malware_file, 1234).unwrap());
    }

    #[test]
    fn test_scanner_evaluate_and_execute_quarantine() {
        use crate::executor::{ActionExecutor, ExecutionReport, QuarantineStatus};

        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let malware_file = temp_dir.path().join("malware_to_execute.bin");
        let malware_bytes = b"malicious_execution_bytes_555";
        fs::write(&malware_file, malware_bytes).expect("write failed");

        let config = GnShieldConfig::default();
        let mut hash_store = HashReputationStore::new();
        hash_store.add_known_bad(&calculate_sha256(malware_bytes));
        let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

        let mut executor = ActionExecutor::new(temp_dir.path().join("quarantine"));
        let (eval, report) = scanner
            .evaluate_and_execute(&malware_file, None, &mut executor)
            .expect("evaluate_and_execute failed");

        assert_eq!(eval.action, Action::Block);
        match report {
            ExecutionReport::ContainedAndTerminated {
                quarantined_files, ..
            } => {
                assert_eq!(quarantined_files.len(), 1);
                assert_eq!(quarantined_files[0].status, QuarantineStatus::Quarantined);
                assert!(!malware_file.exists());
            }
            _ => panic!("Expected ContainedAndTerminated, got: {report:?}"),
        }
    }
}
