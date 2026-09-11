//! Incident Response & Remediation Executor Module.
//! Implements strict phased containment (Freeze SIGSTOP -> Observation -> Terminate SIGKILL)
//! and reversible file quarantine (exec bit removal + rename + metadata persistence)
//! as specified in docs/DECISION_ENGINE.md Section 9.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use gn_shield_rules::calculate_sha256_file;
use serde::{Deserialize, Serialize};

use crate::decision::Action;
use crate::ransomware::IncidentAction;
use crate::scanner::ScanEvaluation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Quarantined,
    SelfDeletedOrNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub sha256: String,
    pub quarantined_at: String,
    pub reason: String,
    pub original_mode: u32,
    pub status: QuarantineStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessContainmentReport {
    pub target_pid: u32,
    pub contained_pids: Vec<u32>,
    pub sigstop_sent: bool,
    pub sigkill_sent: bool,
    pub success: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionReport {
    Allowed {
        target: String,
        reason: String,
    },
    PromptRequired {
        target: String,
        reason: String,
    },
    ContainedAndTerminated {
        target_pid: Option<u32>,
        process_report: Option<ProcessContainmentReport>,
        quarantined_files: Vec<QuarantineRecord>,
        reason: String,
    },
    CircuitBreakerTripped {
        target_pid: Option<u32>,
        reason: String,
    },
}

pub struct ActionExecutor {
    quarantine_dir: PathBuf,
    observation_window: Duration,
    max_terminations_in_window: usize,
    circuit_breaker_window: Duration,
    recent_terminations: VecDeque<Instant>,
    quarantine_history: Vec<QuarantineRecord>,
}

impl Default for ActionExecutor {
    fn default() -> Self {
        let default_quarantine = PathBuf::from("/var/lib/gn-shield/quarantine");
        Self::new(default_quarantine)
    }
}

impl ActionExecutor {
    pub fn new(quarantine_dir: PathBuf) -> Self {
        Self {
            quarantine_dir,
            observation_window: Duration::from_millis(150),
            max_terminations_in_window: 5,
            circuit_breaker_window: Duration::from_secs(60),
            recent_terminations: VecDeque::new(),
            quarantine_history: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_observation_window(mut self, window: Duration) -> Self {
        self.observation_window = window;
        self
    }

    #[must_use]
    pub fn with_circuit_breaker(mut self, max_terminations: usize, window: Duration) -> Self {
        self.max_terminations_in_window = max_terminations;
        self.circuit_breaker_window = window;
        self
    }

    #[must_use]
    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    #[must_use]
    pub fn quarantine_history(&self) -> &[QuarantineRecord] {
        &self.quarantine_history
    }

    fn prune_circuit_breaker(&mut self, now: Instant) {
        while let Some(front) = self.recent_terminations.front() {
            if now.duration_since(*front) > self.circuit_breaker_window {
                self.recent_terminations.pop_front();
            } else {
                break;
            }
        }
    }

    /// Quarantines a file by removing executable bits, moving/renaming with safe extension,
    /// and writing restoration metadata. Handles self-deleted files gracefully.
    pub fn quarantine_file(
        &mut self,
        path: &Path,
        reason: &str,
    ) -> Result<QuarantineRecord, String> {
        let now_str = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => format!("unix-epoch-{}", d.as_secs()),
            Err(_) => "unknown-time".to_string(),
        };

        // DECISION_ENGINE.md Section 9 item 8: Self-delete evasion handling
        if !path.exists() {
            let record = QuarantineRecord {
                original_path: path.to_path_buf(),
                quarantined_path: PathBuf::new(),
                sha256: String::new(),
                quarantined_at: now_str,
                reason: format!("{reason} (file self-deleted or not found on disk)"),
                original_mode: 0,
                status: QuarantineStatus::SelfDeletedOrNotFound,
            };
            self.quarantine_history.push(record.clone());
            return Ok(record);
        }

        let sha256 = calculate_sha256_file(path)
            .map_err(|e| format!("Failed to compute sha256 for quarantine of {path:?}: {e}"))?;

        // Read permissions and remove executable bits
        let original_mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::metadata(path)
                    .map_err(|e| format!("Failed to read metadata for {path:?}: {e}"))?;
                let mode = meta.permissions().mode();
                let mut perms = meta.permissions();
                perms.set_mode(mode & !0o111); // Strip all execute bits (user, group, other)
                let _ = fs::set_permissions(path, perms);
                mode
            }
            #[cfg(not(unix))]
            {
                0
            }
        };

        fs::create_dir_all(&self.quarantine_dir).map_err(|e| {
            format!(
                "Failed to create quarantine dir {:?}: {e}",
                self.quarantine_dir
            )
        })?;

        let file_stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("quarantined_file");
        let sha_short = if sha256.len() >= 8 {
            &sha256[..8]
        } else {
            &sha256
        };

        let quarantined_filename = format!("{now_str}_{sha_short}_{file_stem}.quarantined");
        let quarantined_path = self.quarantine_dir.join(quarantined_filename);

        // Move to quarantine location
        if let Err(e) = fs::rename(path, &quarantined_path) {
            // Attempt copy + remove if rename failed across filesystem boundaries
            fs::copy(path, &quarantined_path).map_err(|copy_err| {
                format!("Failed to move file to quarantine (rename: {e}, copy: {copy_err})")
            })?;
            let _ = fs::remove_file(path);
        }

        // Ensure quarantined file has no executable bits
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&quarantined_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600); // Read/write by owner only, zero execute
                let _ = fs::set_permissions(&quarantined_path, perms);
            }
        }

        let record = QuarantineRecord {
            original_path: path.to_path_buf(),
            quarantined_path: quarantined_path.clone(),
            sha256,
            quarantined_at: now_str,
            reason: reason.to_string(),
            original_mode,
            status: QuarantineStatus::Quarantined,
        };

        // Write metadata file for complete reversibility (AGENTS.md principle 1.3 & DECISION_ENGINE.md Section 9 item 7)
        let meta_path = PathBuf::from(format!("{}.meta.json", quarantined_path.display()));
        let meta_json = serde_json::to_string_pretty(&record)
            .map_err(|e| format!("Failed to serialize quarantine metadata: {e}"))?;
        fs::write(&meta_path, meta_json)
            .map_err(|e| format!("Failed to write quarantine metadata file {meta_path:?}: {e}"))?;

        self.quarantine_history.push(record.clone());
        Ok(record)
    }

    /// Restores a quarantined file to its original location with its original permissions.
    pub fn restore_quarantined_file(&mut self, quarantined_path: &Path) -> Result<PathBuf, String> {
        let meta_path = PathBuf::from(format!("{}.meta.json", quarantined_path.display()));
        if !meta_path.exists() {
            return Err(format!(
                "Quarantine metadata not found at {meta_path:?}. Cannot verify original path."
            ));
        }

        let meta_content = fs::read_to_string(&meta_path)
            .map_err(|e| format!("Failed to read metadata file {meta_path:?}: {e}"))?;
        let record: QuarantineRecord = serde_json::from_str(&meta_content)
            .map_err(|e| format!("Failed to parse metadata JSON: {e}"))?;

        if let Some(parent) = record.original_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Err(e) = fs::rename(quarantined_path, &record.original_path) {
            fs::copy(quarantined_path, &record.original_path).map_err(|copy_err| {
                format!("Failed to restore file (rename: {e}, copy: {copy_err})")
            })?;
            let _ = fs::remove_file(quarantined_path);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if record.original_mode != 0 {
                if let Ok(meta) = fs::metadata(&record.original_path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(record.original_mode);
                    let _ = fs::set_permissions(&record.original_path, perms);
                }
            }
        }

        let _ = fs::remove_file(&meta_path);
        Ok(record.original_path)
    }

    /// Executes phased process containment per DECISION_ENGINE.md Section 9:
    /// Phase 1: Freeze with SIGSTOP (target PID + descendant tree)
    /// Observation: brief delay (observation window)
    /// Phase 2: Terminate with SIGKILL (children first, then target PID)
    pub fn contain_and_terminate_process(
        &mut self,
        target_pid: u32,
        reason: &str,
    ) -> Result<ProcessContainmentReport, String> {
        // Safety guard: Never terminate PID 0, PID 1, or GN-Shield's own PID
        let self_pid = std::process::id();
        if target_pid <= 1 || target_pid == self_pid {
            return Err(format!(
                "Safety guard rejected: target PID {target_pid} is critical system process or GN-Shield daemon itself."
            ));
        }

        // Circuit breaker: check mass auto-kill threshold
        let now = Instant::now();
        self.prune_circuit_breaker(now);
        if self.recent_terminations.len() >= self.max_terminations_in_window {
            return Err(format!(
                "Circuit breaker tripped: {} auto-terminations within {}s limit. Halting automated process kill.",
                self.recent_terminations.len(),
                self.circuit_breaker_window.as_secs()
            ));
        }

        // Discover initial descendant processes (strict downward scope)
        let initial_children = find_descendant_pids(target_pid);

        // Tahap 1, Containment: Freeze with SIGSTOP
        // SAFETY: Sending SIGSTOP to pause target process and children without letting them execute code
        unsafe {
            libc::kill(target_pid as libc::pid_t, libc::SIGSTOP);
            for &child in &initial_children {
                libc::kill(child as libc::pid_t, libc::SIGSTOP);
            }
        }

        // Observation window: pause to observe and catch any newly spawned children
        if self.observation_window > Duration::ZERO {
            std::thread::sleep(self.observation_window);
        }

        // Check for any child processes spawned right before freeze
        let updated_children = find_descendant_pids(target_pid);
        for &child in &updated_children {
            if !initial_children.contains(&child) {
                // SAFETY: Freeze late-spawned child
                unsafe {
                    libc::kill(child as libc::pid_t, libc::SIGSTOP);
                }
            }
        }

        // Tahap 2, Terminate: Send SIGKILL to children, then target PID
        // SAFETY: Sending SIGKILL to terminate already-frozen process tree
        unsafe {
            for &child in &updated_children {
                libc::kill(child as libc::pid_t, libc::SIGKILL);
            }
            libc::kill(target_pid as libc::pid_t, libc::SIGKILL);
        }

        self.recent_terminations.push_back(Instant::now());

        Ok(ProcessContainmentReport {
            target_pid,
            contained_pids: updated_children,
            sigstop_sent: true,
            sigkill_sent: true,
            success: true,
            reason: reason.to_string(),
        })
    }

    /// Consumes a scan evaluation from FileScanner and executes the required remediation.
    pub fn execute_scan_verdict(
        &mut self,
        eval: &ScanEvaluation,
        pid: Option<u32>,
    ) -> Result<ExecutionReport, String> {
        match eval.action {
            Action::Block => {
                let process_report = if let Some(p) = pid {
                    match self.contain_and_terminate_process(p, &eval.reason) {
                        Ok(report) => Some(report),
                        Err(e) if e.contains("Circuit breaker tripped") => {
                            return Ok(ExecutionReport::CircuitBreakerTripped {
                                target_pid: Some(p),
                                reason: e,
                            });
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    None
                };

                let q_rec = self.quarantine_file(&eval.path, &eval.reason)?;
                Ok(ExecutionReport::ContainedAndTerminated {
                    target_pid: pid,
                    process_report,
                    quarantined_files: vec![q_rec],
                    reason: eval.reason.clone(),
                })
            }
            Action::PromptUser => Ok(ExecutionReport::PromptRequired {
                target: eval.path.display().to_string(),
                reason: eval.reason.clone(),
            }),
            Action::Allow => Ok(ExecutionReport::Allowed {
                target: eval.path.display().to_string(),
                reason: eval.reason.clone(),
            }),
        }
    }

    /// Consumes an IncidentAction from RansomwareDetector and executes containment.
    pub fn execute_incident_action(
        &mut self,
        incident: &IncidentAction,
        pid: Option<u32>,
    ) -> Result<ExecutionReport, String> {
        match incident {
            IncidentAction::ContainAndTerminate {
                reason,
                target_paths,
            } => {
                let process_report = if let Some(p) = pid {
                    match self.contain_and_terminate_process(p, reason) {
                        Ok(report) => Some(report),
                        Err(e) if e.contains("Circuit breaker tripped") => {
                            return Ok(ExecutionReport::CircuitBreakerTripped {
                                target_pid: Some(p),
                                reason: e,
                            });
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    None
                };

                let mut quarantined = Vec::new();
                for path in target_paths {
                    let rec = self.quarantine_file(path, reason)?;
                    quarantined.push(rec);
                }

                Ok(ExecutionReport::ContainedAndTerminated {
                    target_pid: pid,
                    process_report,
                    quarantined_files: quarantined,
                    reason: reason.clone(),
                })
            }
            IncidentAction::PromptUser(reason) => Ok(ExecutionReport::PromptRequired {
                target: "Ransomware Behavioral Incident".to_string(),
                reason: reason.clone(),
            }),
            IncidentAction::Allow => Ok(ExecutionReport::Allowed {
                target: "Filesystem Modification Activity".to_string(),
                reason: "Normal activity confirmed".to_string(),
            }),
        }
    }
}

/// Discovers descendant process IDs on Linux, scoping strictly downwards.
fn find_descendant_pids(target_pid: u32) -> Vec<u32> {
    let mut descendants = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(target_pid);

    while let Some(parent) = queue.pop_front() {
        let children = get_direct_children(parent);
        for child in children {
            if !descendants.contains(&child) && child != target_pid {
                descendants.push(child);
                queue.push_back(child);
            }
        }
    }

    descendants
}

fn get_direct_children(parent_pid: u32) -> Vec<u32> {
    let mut children = Vec::new();

    // 1. Try reading /proc/{parent_pid}/task/{parent_pid}/children
    let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    if let Ok(content) = fs::read_to_string(&children_path) {
        for pid_str in content.split_whitespace() {
            if let Ok(p) = pid_str.parse::<u32>() {
                children.push(p);
            }
        }
        if !children.is_empty() {
            return children;
        }
    }

    // 2. Scan /proc for PPID matching parent_pid
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if let Some(name_str) = file_name.to_str() {
                if let Ok(pid) = name_str.parse::<u32>() {
                    let stat_path = format!("/proc/{pid}/stat");
                    if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                        if let Some(close_paren) = stat_content.rfind(')') {
                            let rest = &stat_content[close_paren + 1..];
                            let fields: Vec<&str> = rest.split_whitespace().collect();
                            if fields.len() >= 2 {
                                if let Ok(ppid) = fields[1].parse::<u32>() {
                                    if ppid == parent_pid {
                                        children.push(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    children
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_quarantine_file_and_reversibility() {
        let temp = tempdir().expect("tempdir failed");
        let q_dir = temp.path().join("quarantine");
        let mut executor = ActionExecutor::new(q_dir);

        // Create a dummy executable script
        let file_path = temp.path().join("malicious_script.sh");
        let mut f = fs::File::create(&file_path).expect("create file failed");
        f.write_all(b"#!/bin/bash\necho malicious")
            .expect("write failed");
        drop(f);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&file_path).expect("meta").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&file_path, perms).expect("set perms");
        }

        // Execute quarantine
        let record = executor
            .quarantine_file(&file_path, "EICAR / Malicious script detected")
            .expect("quarantine failed");

        assert_eq!(record.status, QuarantineStatus::Quarantined);
        assert!(
            !file_path.exists(),
            "Original file should no longer exist at original path"
        );
        assert!(
            record.quarantined_path.exists(),
            "Quarantined file must exist in quarantine dir"
        );
        assert!(record
            .quarantined_path
            .to_string_lossy()
            .ends_with(".quarantined"));

        // Verify exec bit stripped on quarantined file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let q_meta = fs::metadata(&record.quarantined_path).expect("meta");
            assert_eq!(
                q_meta.permissions().mode() & 0o111,
                0,
                "Exec bits must be stripped!"
            );
        }

        // Verify metadata file exists
        let meta_file = PathBuf::from(format!("{}.meta.json", record.quarantined_path.display()));
        assert!(
            meta_file.exists(),
            "Quarantine metadata file must exist for reversibility"
        );

        // Test reversibility: restore file
        let restored_path = executor
            .restore_quarantined_file(&record.quarantined_path)
            .expect("restore failed");
        assert_eq!(restored_path, file_path);
        assert!(
            file_path.exists(),
            "Restored file must exist at original path"
        );
        assert!(
            !meta_file.exists(),
            "Metadata file should be cleaned up after restore"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let restored_meta = fs::metadata(&file_path).expect("meta");
            assert_eq!(
                restored_meta.permissions().mode() & 0o777,
                0o755,
                "Original permissions must be restored!"
            );
        }
    }

    #[test]
    fn test_quarantine_self_deleted_file() {
        let temp = tempdir().expect("tempdir failed");
        let q_dir = temp.path().join("quarantine");
        let mut executor = ActionExecutor::new(q_dir);

        let non_existent = temp.path().join("already_deleted.exe");
        let record = executor
            .quarantine_file(&non_existent, "Self-deleted malware")
            .expect("should not error on self-deleted file");

        assert_eq!(record.status, QuarantineStatus::SelfDeletedOrNotFound);
        assert!(record.reason.contains("self-deleted or not found"));
    }

    #[test]
    fn test_contain_and_terminate_process_lifecycle() {
        use std::process::Command;

        // Spawn a child process to terminate
        let mut child = Command::new("sleep")
            .arg("100")
            .spawn()
            .expect("failed to spawn sleep");
        let child_pid = child.id();

        let temp = tempdir().expect("tempdir failed");
        let mut executor = ActionExecutor::new(temp.path().join("quarantine"))
            .with_observation_window(Duration::from_millis(50));

        let report = executor
            .contain_and_terminate_process(child_pid, "Suspicious ransomware activity")
            .expect("containment failed");

        assert_eq!(report.target_pid, child_pid);
        assert!(report.sigstop_sent);
        assert!(report.sigkill_sent);
        assert!(report.success);

        // Wait on child process; should have been killed by SIGKILL
        let status = child.wait().expect("wait failed");
        assert!(!status.success());
    }

    #[test]
    fn test_safety_guard_rejects_critical_pids() {
        let temp = tempdir().expect("tempdir failed");
        let mut executor = ActionExecutor::new(temp.path().join("quarantine"));

        // Attempting to kill PID 1 (init) must be rejected
        assert!(executor.contain_and_terminate_process(1, "test").is_err());

        // Attempting to kill self PID must be rejected
        assert!(executor
            .contain_and_terminate_process(std::process::id(), "test")
            .is_err());
    }

    #[test]
    fn test_mass_kill_circuit_breaker() {
        let temp = tempdir().expect("tempdir failed");
        let mut executor = ActionExecutor::new(temp.path().join("quarantine"))
            .with_circuit_breaker(3, Duration::from_secs(60))
            .with_observation_window(Duration::ZERO);

        // Simulate 3 process terminations
        for _ in 0..3 {
            let mut child = std::process::Command::new("sleep")
                .arg("50")
                .spawn()
                .expect("spawn failed");
            let pid = child.id();
            executor
                .contain_and_terminate_process(pid, "test")
                .expect("should succeed");
            let _ = child.wait();
        }

        // 4th termination must trip the circuit breaker!
        let mut child4 = std::process::Command::new("sleep")
            .arg("50")
            .spawn()
            .expect("spawn failed");
        let pid4 = child4.id();

        let err = executor
            .contain_and_terminate_process(pid4, "test")
            .unwrap_err();
        assert!(err.contains("Circuit breaker tripped"));

        // Clean up child4
        let _ = child4.kill();
        let _ = child4.wait();
    }

    #[test]
    fn test_execute_scan_verdict_integration() {
        let temp = tempdir().expect("tempdir failed");
        let test_file = temp.path().join("infected.bin");
        fs::write(&test_file, b"malicious content").expect("write failed");

        let mut executor = ActionExecutor::new(temp.path().join("quarantine"));

        let eval = ScanEvaluation {
            path: test_file.clone(),
            sha256: "dummyhash123".to_string(),
            static_score: 0.95,
            matched_rules: vec!["Win32_Trojan".to_string()],
            action: Action::Block,
            reason: "Known malicious signature matched".to_string(),
        };

        let report = executor
            .execute_scan_verdict(&eval, None)
            .expect("execution failed");
        match report {
            ExecutionReport::ContainedAndTerminated {
                quarantined_files, ..
            } => {
                assert_eq!(quarantined_files.len(), 1);
                assert_eq!(quarantined_files[0].status, QuarantineStatus::Quarantined);
                assert!(!test_file.exists());
            }
            _ => panic!("Expected ContainedAndTerminated, got: {report:?}"),
        }
    }
}
