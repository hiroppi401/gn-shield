use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use gn_shield_config::GnShieldConfig;
use gn_shield_core::executor::{ActionExecutor, ExecutionReport, QuarantineStatus};
use gn_shield_core::ransomware::IncidentAction;
use gn_shield_core::{FileScanner, RansomwareDetector};
use gn_shield_rules::{calculate_sha256, HashReputationStore, HoneypotManager};
use gn_shield_sensors_linux::LinuxFsSensor;

#[test]
fn test_fanotify_sensor_wired_to_file_scanner_evaluator() {
    let temp = tempdir().expect("tempdir failed");
    let safe_binary = temp.path().join("safe_tool");
    fs::write(&safe_binary, b"echo safe tool execution").expect("write safe binary");

    let evil_binary = temp.path().join("evil_trojan");
    let evil_bytes = b"evil_malicious_signature_test_sample";
    fs::write(&evil_binary, evil_bytes).expect("write evil binary");

    let evil_hash = calculate_sha256(evil_bytes);

    let config = GnShieldConfig::default();
    let mut hash_store = HashReputationStore::new();
    hash_store.add_known_bad(&evil_hash);

    let scanner = Arc::new(FileScanner::new(config, hash_store).expect("scanner init failed"));

    // Instantiate LinuxFsSensor wired with FileScanner as ExecPermEvaluator
    let sensor = LinuxFsSensor::new()
        .with_evaluator(scanner)
        .with_watchdog_timeout(Duration::from_millis(200));

    // 1. Safe binary: evaluates cleanly and gives permission (FAN_ALLOW)
    let safe_allowed = sensor.evaluate_and_decide_exec(&safe_binary, 2001);
    assert!(
        safe_allowed,
        "Safe binary must receive execution permission"
    );

    // 2. Malicious binary: evaluates to Block and denies execution (FAN_DENY)
    let evil_allowed = sensor.evaluate_and_decide_exec(&evil_binary, 2002);
    assert!(!evil_allowed, "Known-bad binary must be denied execution");

    // 3. Self-PID deadlock bypass: even if evaluating known bad binary, self PID must receive allow
    let self_allowed = sensor.evaluate_and_decide_exec(&evil_binary, std::process::id());
    assert!(
        self_allowed,
        "Daemon's own PID must bypass to prevent recursive deadlock"
    );
}

#[test]
fn test_executor_quarantine_reversibility_and_exec_strip() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("gn_shield_quarantine");
    let mut executor = ActionExecutor::new(q_dir.clone());

    // Create an executable script with 0o755 permissions
    let script_path = temp.path().join("dropper.sh");
    fs::write(&script_path, b"#!/bin/sh\nrm -rf /tmp/victim\n").expect("write script");
    let mut perms = fs::metadata(&script_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("set 0o755");

    // Verify initial executable bit
    let initial_mode = fs::metadata(&script_path)
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(
        initial_mode & 0o111,
        0o111,
        "Must have executable bits initially"
    );

    // Execute quarantine
    let record = executor
        .quarantine_file(&script_path, "Exploit dropper detected")
        .expect("quarantine failed");

    assert_eq!(record.status, QuarantineStatus::Quarantined);
    assert!(
        !script_path.exists(),
        "Original file must be removed from original path"
    );
    assert!(
        record.quarantined_path.exists(),
        "Quarantined file must exist"
    );
    assert!(record
        .quarantined_path
        .to_string_lossy()
        .ends_with(".quarantined"));

    // Verify all exec bits are stripped on quarantined file (mode & 0o111 == 0)
    let q_mode = fs::metadata(&record.quarantined_path)
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(
        q_mode & 0o111,
        0,
        "All executable bits must be stripped in quarantine!"
    );

    // Verify metadata JSON exists
    let meta_json_path = PathBuf::from(format!("{}.meta.json", record.quarantined_path.display()));
    assert!(
        meta_json_path.exists(),
        "Restoration metadata file must exist"
    );

    // Test reversibility: restore file
    let restored = executor
        .restore_quarantined_file(&record.quarantined_path)
        .expect("restore failed");
    assert_eq!(restored, script_path);
    assert!(script_path.exists(), "File must be back at original path");
    assert!(!record.quarantined_path.exists());
    assert!(!meta_json_path.exists());

    // Verify original permissions 0o755 are restored
    let restored_mode = fs::metadata(&script_path)
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(
        restored_mode & 0o777,
        0o755,
        "Original executable permissions must be restored"
    );
}

#[test]
fn test_executor_phased_containment_sequence() {
    use std::process::Command;

    // Spawn dummy process
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target_pid = child.id();

    let temp = tempdir().expect("tempdir failed");
    let mut executor = ActionExecutor::new(temp.path().join("quarantine"))
        .with_observation_window(Duration::from_millis(50));

    // Execute containment: SIGSTOP -> observation -> SIGKILL
    let report = executor
        .contain_and_terminate_process(target_pid, "Confirmed ransomware process")
        .expect("containment failed");

    assert_eq!(report.target_pid, target_pid);
    assert!(report.sigstop_sent, "SIGSTOP freeze must be sent first");
    assert!(report.sigkill_sent, "SIGKILL terminate must follow");
    assert!(report.success);

    // Verify process is terminated
    let exit_status = child.wait().expect("wait failed");
    assert!(!exit_status.success(), "Process must have been killed");
}

#[test]
fn test_ransomware_wiring_incident_action_to_executor() {
    let temp = tempdir().expect("tempdir failed");
    let config = GnShieldConfig::default();
    let mut honeypot = HoneypotManager::new();
    let canaries = honeypot
        .deploy_in_dir(temp.path())
        .expect("deploy canaries");

    let mut detector = RansomwareDetector::new(&config, honeypot);
    let mut executor = ActionExecutor::new(temp.path().join("quarantine"));

    // Tamper with canary decoy
    let canary = &canaries[0];
    fs::write(canary, vec![0xFF; 256]).expect("tamper canary");
    let _ = detector.record_and_evaluate(canary, Some(7.9));

    // Mass writes of encrypted files
    for i in 0..11 {
        let p = temp.path().join(format!("data_{i}.locked"));
        fs::write(&p, vec![0xCC; 128]).expect("write data");
        let _ = detector.record_and_evaluate(&p, Some(7.8));
    }

    // 12th write trips ransomware threshold
    let trigger_file = temp.path().join("data_11.locked");
    fs::write(&trigger_file, vec![0xCC; 128]).expect("write trigger data");

    // Spawn a dummy process to simulate the ransomware process being contained
    let mut dummy_proc = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn dummy");
    let proc_pid = dummy_proc.id();

    // Call record_evaluate_and_execute
    let (action, incident, report_opt) = detector.record_evaluate_and_execute(
        &trigger_file,
        Some(7.9),
        Some(proc_pid),
        &mut executor,
    );

    assert_eq!(action, gn_shield_core::Action::Block);
    assert!(matches!(
        incident,
        IncidentAction::ContainAndTerminate { .. }
    ));

    let report = report_opt.expect("ExecutionReport must be returned");
    match report {
        ExecutionReport::ContainedAndTerminated {
            target_pid,
            process_report,
            quarantined_files,
            reason,
        } => {
            assert_eq!(target_pid, Some(proc_pid));
            let proc_rep = process_report.expect("process report should exist");
            assert!(proc_rep.sigstop_sent);
            assert!(proc_rep.sigkill_sent);
            assert!(!quarantined_files.is_empty());
            assert!(reason.contains("canary decoy tampered"));
        }
        _ => panic!("Expected ContainedAndTerminated, got: {report:?}"),
    }

    let _ = dummy_proc.wait();
}
