//! Integration tests for process containment by PID in ransomware and file scanner paths.
//! Verifies:
//! 1. Phased containment (freeze SIGSTOP + terminate SIGKILL) of malicious process PID on ransomware attack.
//! 2. Immediate containment of calling process PID when malicious executable or dropper file is scanned.
//! 3. Critical process safety guards (never terminate PID 0, PID 1, or self PID).
//! 4. Graceful handling when PID is None (quarantining files without attempting process termination).

use gn_shield_config::GnShieldConfig;
use gn_shield_core::executor::{ActionExecutor, ExecutionReport};
use gn_shield_core::ransomware::IncidentAction;
use gn_shield_core::{Action, ExecDenyTracker, FileScanner, RansomwareDetector};
use gn_shield_rules::{calculate_sha256, HashReputationStore, HoneypotManager};
use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::tempdir;

/// Helper to spawn a long-running benign child process (`sleep 300`) to test containment.
fn spawn_test_process() -> std::process::Child {
    Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("failed to spawn test sleep process")
}

/// Helper to check if a process is still alive.
fn is_process_alive(pid: u32) -> bool {
    // kill(pid, 0) returns 0 if process exists, -1 with ESRCH if dead
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[test]
fn test_ransomware_containment_by_pid_stops_and_terminates_attacker() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor =
        ActionExecutor::new(q_dir.clone()).with_observation_window(Duration::from_millis(50));

    let config = GnShieldConfig::default();
    let mut honeypot = HoneypotManager::new();
    let canaries = honeypot
        .deploy_in_dir(temp.path())
        .expect("deploy canaries");
    let mut detector = RansomwareDetector::new(&config, honeypot);

    // Spawn an active process simulating a ransomware encryptor
    let mut encryptor_child = spawn_test_process();
    let attacker_pid = encryptor_child.id();
    assert!(
        is_process_alive(attacker_pid),
        "Spawned attacker process must initially be alive"
    );

    // Simulate mass encryption writes attributed to attacker_pid
    let mut target_files = Vec::new();
    for i in 0..12 {
        let p = temp.path().join(format!("encrypted_file_{i}.locked"));
        fs::write(
            &p,
            format!("encrypted pseudo-random ciphertext content {i}"),
        )
        .expect("write");
        target_files.push(p.clone());
        let _ = detector.record_and_evaluate_with_pid(&p, Some(7.85), Some(attacker_pid));
    }

    // Attacker tampers with honeypot canary
    fs::write(&canaries[0], b"TAMPERED_BY_RANSOMWARE").expect("tamper canary");
    let (action, incident) =
        detector.record_and_evaluate_with_pid(&canaries[0], Some(7.9), Some(attacker_pid));

    assert_eq!(action, Action::Block);
    assert!(matches!(
        incident,
        IncidentAction::ContainAndTerminate { .. }
    ));

    // Execute containment wiring with target PID
    let report = executor
        .execute_incident_action(&incident, Some(attacker_pid))
        .expect("execute containment failed");

    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            quarantined_files,
            ..
        } => {
            assert_eq!(target_pid, Some(attacker_pid));
            let proc_rep = process_report.expect("process containment report must be present");
            assert_eq!(proc_rep.target_pid, attacker_pid);
            assert!(proc_rep.sigstop_sent);
            assert!(proc_rep.sigkill_sent);
            assert!(proc_rep.success);
            assert!(!quarantined_files.is_empty());
        }
        other => panic!("Expected ContainedAndTerminated, got: {other:?}"),
    }

    // EMPIRICAL VERIFICATION: Attacker process MUST NO LONGER BE ALIVE!
    let _ = encryptor_child.wait(); // clean up zombie
    assert!(
        !is_process_alive(attacker_pid),
        "Attacker process PID {attacker_pid} must be terminated by phased containment"
    );
}

#[test]
fn test_file_scanner_threat_containment_by_pid_terminates_dropper() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor =
        ActionExecutor::new(q_dir.clone()).with_observation_window(Duration::from_millis(50));

    let evil_file = temp.path().join("trojan_dropper.bin");
    let evil_bytes = b"evil_malware_c2_sample_payload_bytes";
    fs::write(&evil_file, evil_bytes).expect("write evil file");

    let evil_hash = calculate_sha256(evil_bytes);
    let mut hash_store = HashReputationStore::new();
    hash_store.add_known_bad(&evil_hash);

    let config = GnShieldConfig::default();
    let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

    // Spawn a dropper process that attempted to create/drop the malicious file
    let mut dropper_child = spawn_test_process();
    let dropper_pid = dropper_child.id();
    assert!(
        is_process_alive(dropper_pid),
        "Dropper process must be alive before scan containment"
    );

    let eval = scanner
        .evaluate_file(&evil_file)
        .expect("evaluate file failed");
    assert_eq!(eval.action, Action::Block);

    // Execute scan verdict with dropper PID
    let report = executor
        .execute_scan_verdict(&eval, Some(dropper_pid))
        .expect("execute scan verdict failed");

    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            quarantined_files,
            ..
        } => {
            assert_eq!(target_pid, Some(dropper_pid));
            let p_rep = process_report.expect("process report must be present");
            assert_eq!(p_rep.target_pid, dropper_pid);
            assert!(p_rep.sigstop_sent);
            assert!(p_rep.sigkill_sent);
            assert!(p_rep.success);
            assert_eq!(quarantined_files.len(), 1);
            assert_eq!(quarantined_files[0].original_path, evil_file);
        }
        other => panic!("Expected ContainedAndTerminated, got: {other:?}"),
    }

    // Malicious file must be quarantined
    assert!(
        !evil_file.exists(),
        "Malicious file must be quarantined from disk"
    );

    // EMPIRICAL VERIFICATION: Dropper PID must be terminated
    let _ = dropper_child.wait();
    assert!(
        !is_process_alive(dropper_pid),
        "Dropper PID {dropper_pid} must be terminated"
    );
}

#[test]
fn test_containment_critical_system_pids_protected() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor = ActionExecutor::new(q_dir);

    // Attempting containment on PID 0, PID 1, or self PID must be rejected by safety guards
    assert!(executor.contain_and_terminate_process(0, "test").is_err());
    assert!(executor.contain_and_terminate_process(1, "test").is_err());
    assert!(executor
        .contain_and_terminate_process(std::process::id(), "test")
        .is_err());
}

#[test]
fn test_containment_with_none_pid_quarantines_safely() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor = ActionExecutor::new(q_dir);

    let test_file = temp.path().join("malware_no_pid.bin");
    fs::write(&test_file, b"sample content").expect("write");

    let eval = gn_shield_core::ScanEvaluation {
        path: test_file.clone(),
        sha256: "dummyhash".to_string(),
        static_score: 1.0,
        matched_rules: vec!["EICAR".to_string()],
        action: Action::Block,
        reason: "Test block".to_string(),
    };

    // Passing None for PID should quarantine file without errors or terminating random processes
    let report = executor
        .execute_scan_verdict(&eval, None)
        .expect("execute with None pid must succeed");

    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            quarantined_files,
            ..
        } => {
            assert_eq!(target_pid, None);
            assert!(process_report.is_none());
            assert_eq!(quarantined_files.len(), 1);
            assert!(!test_file.exists());
        }
        other => panic!("Expected ContainedAndTerminated, got: {other:?}"),
    }
}

#[test]
fn test_exec_deny_repeat_offender_gate_containment_escalation() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor =
        ActionExecutor::new(q_dir).with_observation_window(Duration::from_millis(50));
    let mut tracker = ExecDenyTracker::new();

    let evil_file = temp.path().join("suspicious_loader.bin");
    let evil_bytes = b"loader_stub_payload_test_bytes";
    fs::write(&evil_file, evil_bytes).expect("write evil file");

    let evil_hash = calculate_sha256(evil_bytes);
    let mut hash_store = HashReputationStore::new();
    hash_store.add_known_bad(&evil_hash);

    let config = GnShieldConfig::default();
    let scanner = FileScanner::new(config, hash_store).expect("scanner init failed");

    // Spawn caller process attempting execution
    let mut caller_child = spawn_test_process();
    let caller_pid = caller_child.id();
    assert!(is_process_alive(caller_pid), "Caller process must be alive");

    let eval = scanner
        .evaluate_file(&evil_file)
        .expect("evaluate file failed");
    assert_eq!(eval.action, Action::Block);

    // Attempt 1: Exec-deny recorded. Gate must NOT escalate to containment!
    let escalate_1 = tracker.record_deny(caller_pid);
    assert!(
        !escalate_1,
        "1st exec-deny attempt must not escalate to containment"
    );
    assert!(
        is_process_alive(caller_pid),
        "Caller process must still be alive after attempt 1"
    );

    // Attempt 2: Exec-deny recorded. Gate must NOT escalate to containment!
    let escalate_2 = tracker.record_deny(caller_pid);
    assert!(
        !escalate_2,
        "2nd exec-deny attempt must not escalate to containment"
    );
    assert!(
        is_process_alive(caller_pid),
        "Caller process must still be alive after attempt 2"
    );

    // Attempt 3: Exec-deny recorded. Gate MUST escalate to containment!
    let escalate_3 = tracker.record_deny(caller_pid);
    assert!(
        escalate_3,
        "3rd exec-deny attempt within window must escalate to containment"
    );

    // Now execute containment as daemon handler does on attempt 3
    let report = executor
        .execute_scan_verdict(&eval, Some(caller_pid))
        .expect("execute containment on 3rd attempt");

    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            ..
        } => {
            assert_eq!(target_pid, Some(caller_pid));
            let p_rep = process_report.expect("process report must be present");
            assert!(p_rep.success);
        }
        other => panic!("Expected ContainedAndTerminated, got: {other:?}"),
    }

    // Caller process must now be terminated
    let _ = caller_child.wait();
    assert!(
        !is_process_alive(caller_pid),
        "Caller process must be terminated on 3rd attempt"
    );
}

#[test]
fn test_exec_deny_distinct_pids_do_not_escalate_containment() {
    let mut tracker = ExecDenyTracker::new();

    // Spawn 3 distinct processes
    let mut child1 = spawn_test_process();
    let mut child2 = spawn_test_process();
    let mut child3 = spawn_test_process();

    let pid1 = child1.id();
    let pid2 = child2.id();
    let pid3 = child3.id();

    // Each triggers 1 exec-deny
    assert!(!tracker.record_deny(pid1));
    assert!(!tracker.record_deny(pid2));
    assert!(!tracker.record_deny(pid3));

    // All processes must remain alive (no containment)
    assert!(is_process_alive(pid1));
    assert!(is_process_alive(pid2));
    assert!(is_process_alive(pid3));

    // Clean up
    let _ = child1.kill();
    let _ = child1.wait();
    let _ = child2.kill();
    let _ = child2.wait();
    let _ = child3.kill();
    let _ = child3.wait();
}

#[test]
fn test_exec_deny_window_expiry_resets_gate_in_regression() {
    let mut tracker = ExecDenyTracker::new();
    let pid = 88888;
    let t0 = Instant::now();

    assert!(!tracker.record_deny_at(pid, t0));
    assert!(!tracker.record_deny_at(pid, t0 + Duration::from_secs(15)));

    // Attempt 3 occurs after 80s (> 60s window from both t0 and t0+15s)
    let t_expired = t0 + Duration::from_secs(80);
    assert!(
        !tracker.record_deny_at(pid, t_expired),
        "Expired window must reset count, not escalate"
    );
    assert_eq!(tracker.count_for_pid_at(pid, t_expired), 1);
}

#[test]
fn test_ransomware_dominant_pid_ratio_and_floor_gates_containment() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor =
        ActionExecutor::new(q_dir).with_observation_window(Duration::from_millis(50));

    let config = GnShieldConfig::default();
    let mut honeypot = HoneypotManager::new();
    let canaries = honeypot
        .deploy_in_dir(temp.path())
        .expect("deploy canaries");
    let mut detector = RansomwareDetector::new(&config, honeypot);

    let mut attacker_child = spawn_test_process();
    let attacker_pid = attacker_child.id();

    // 9 events from attacker_pid (60% of 15, >= 3 floor)
    for i in 0..9 {
        let p = temp.path().join(format!("enc_atk_reg_{i}.lock"));
        fs::write(&p, b"encrypted ciphertext bytes").expect("write");
        let _ = detector.record_and_evaluate_with_pid(&p, Some(7.8), Some(attacker_pid));
    }

    // 6 events from other benign/secondary PID
    for i in 0..6 {
        let p = temp.path().join(format!("enc_other_reg_{i}.lock"));
        fs::write(&p, b"encrypted ciphertext bytes").expect("write");
        let _ = detector.record_and_evaluate_with_pid(&p, Some(7.8), Some(99999));
    }

    // Canary tampered
    fs::write(&canaries[0], b"TAMPERED").expect("tamper");
    let (action, incident) =
        detector.record_and_evaluate_with_pid(&canaries[0], Some(7.9), Some(attacker_pid));
    assert_eq!(action, Action::Block);
    assert!(matches!(
        incident,
        IncidentAction::ContainAndTerminate { .. }
    ));

    // dominant_pid() must return Some(attacker_pid)
    assert_eq!(detector.dominant_pid(), Some(attacker_pid));

    // Containment executed with attacker_pid
    let report = executor
        .execute_incident_action(&incident, detector.dominant_pid())
        .expect("execute containment");

    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            ..
        } => {
            assert_eq!(target_pid, Some(attacker_pid));
            let p_rep = process_report.expect("process report");
            assert!(p_rep.success);
        }
        other => panic!("Expected ContainedAndTerminated, got {other:?}"),
    }

    let _ = attacker_child.wait();
    assert!(!is_process_alive(attacker_pid));
}

#[test]
fn test_ransomware_dominant_pid_spread_skips_process_kill_quarantines_files() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    let mut executor =
        ActionExecutor::new(q_dir).with_observation_window(Duration::from_millis(50));

    let config = GnShieldConfig::default();
    let mut honeypot = HoneypotManager::new();
    let canaries = honeypot
        .deploy_in_dir(temp.path())
        .expect("deploy canaries");
    let mut detector = RansomwareDetector::new(&config, honeypot);

    // Spawn a benign process that should NOT be terminated
    let mut safe_child = spawn_test_process();
    let safe_pid = safe_child.id();

    // 15 events spread across 5 distinct PIDs (3 events each = 20% each < 50%)
    for i in 0..15 {
        let p = temp.path().join(format!("enc_spread_{i}.lock"));
        fs::write(&p, b"ciphertext").expect("write");
        let pid = if i < 3 { safe_pid } else { 70000 + (i as u32) };
        let _ = detector.record_and_evaluate_with_pid(&p, Some(7.8), Some(pid));
    }

    // Tamper canary
    fs::write(&canaries[0], b"TAMPERED").expect("tamper");
    let canary_file = canaries[0].clone();

    // In this scenario, caller does not have an explicit PID (pid is None),
    // and dominant_pid() must return None because no PID has >= 50% ratio
    assert_eq!(
        detector.dominant_pid(),
        None,
        "dominant_pid must be None when no PID reaches 50% ratio"
    );

    // Execute through record_evaluate_and_execute with pid = None
    let (action, incident, exec_report) =
        detector.record_evaluate_and_execute(&canary_file, Some(7.9), None, &mut executor);

    assert_eq!(action, Action::Block);
    assert!(matches!(
        incident,
        IncidentAction::ContainAndTerminate { .. }
    ));

    let report = exec_report.expect("execution report must be generated");
    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            quarantined_files,
            ..
        } => {
            // Target PID must be None
            assert_eq!(target_pid, None);
            // Process containment report must be None (no process killed)
            assert!(process_report.is_none());
            // But files must still be quarantined!
            assert!(!quarantined_files.is_empty());
        }
        other => panic!("Expected ContainedAndTerminated, got {other:?}"),
    }

    // The safe child process must still be alive!
    assert!(
        is_process_alive(safe_pid),
        "Safe process must not be terminated when dominant_pid is None"
    );

    let _ = safe_child.kill();
    let _ = safe_child.wait();
}
