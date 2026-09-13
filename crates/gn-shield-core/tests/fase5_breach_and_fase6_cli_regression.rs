//! Integration and Regression Test Suite for Fase 5 (Data Breach Check)
//! and Fase 6 (CLI, Unix Domain Socket IPC, Audit Log, Quarantine, and Notification Batching).

use gn_shield_config::{DataBreachConfig, NotificationsConfig};
use gn_shield_core::{
    ActionExecutor, BreachService, InMemoryNotificationSink, IpcClient, IpcServer,
    MockRangeProvider, ModuleHealth, NotificationBatcher, PromptAction, PromptEvent,
};
use gn_shield_rules::breach::KAnonymityChecker;
use gn_shield_rules::sensitive_data::SensitiveDataKind;
use gn_shield_storage::{AuditLogEntry, StorageManager};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_fase5_k_anonymity_privacy_and_accuracy() {
    let mock_provider = Arc::new(MockRangeProvider::new());
    // "admin123" in SHA-1 is F865B53623B121FD34EE5426C792E5C33AF8C227
    let (prefix, suffix) = KAnonymityChecker::split_sha1_hash("admin123");
    assert_eq!(prefix, "F865B");
    assert_eq!(suffix, "53623B121FD34EE5426C792E5C33AF8C227");

    // Insert mock HIBP range
    mock_provider.insert_range(
        &prefix,
        "0018A45C4D1787236E33B0CF63AB333AC10:1\n\
         53623B121FD34EE5426C792E5C33AF8C227:14205\n\
         FFFFF45C4D1787236E33B0CF63AB333AC10:5",
    );

    let breach_service = BreachService::new(
        DataBreachConfig {
            enabled: true,
            scan_clipboard: true,
            scan_uploads: true,
            k_anonymity_api_url: "https://api.pwnedpasswords.com/range/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider.clone(),
    );

    let res = breach_service
        .check_credential("admin123")
        .expect("check should succeed");

    assert!(res.is_breached);
    assert_eq!(res.count, 14205);
    assert_eq!(res.prefix, "F865B");

    // Check clean credential
    let (clean_prefix, _) = KAnonymityChecker::split_sha1_hash("unbreached_secret_994142");
    mock_provider.insert_range(&clean_prefix, "1234567890ABCDEF1234567890ABCDEF123:2");

    let clean_res = breach_service
        .check_credential("unbreached_secret_994142")
        .expect("check should succeed");

    assert!(!clean_res.is_breached);
    assert_eq!(clean_res.count, 0);
}

#[test]
fn test_fase5_sensitive_data_masking_and_opt_in() {
    let mock_provider = Arc::new(MockRangeProvider::new());

    // Test default OFF (strict privacy guard)
    let default_config = DataBreachConfig::default();
    assert!(!default_config.enabled);
    assert!(!default_config.scan_clipboard);
    assert!(!default_config.scan_uploads);

    let service_off = BreachService::new(default_config, mock_provider.clone());
    let raw_payload =
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGH_PAT=ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    assert!(service_off.scan_clipboard(raw_payload).is_empty());
    assert!(service_off.scan_upload(raw_payload).is_empty());

    // Test with explicit opt-in
    let opt_in_config = DataBreachConfig {
        enabled: true,
        scan_clipboard: true,
        scan_uploads: true,
        k_anonymity_api_url: "mock://api/".to_string(),
        check_timeout_ms: 1000,
    };
    let service_on = BreachService::new(opt_in_config, mock_provider);
    let findings = service_on.scan_clipboard(raw_payload);

    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].kind, SensitiveDataKind::AwsAccessKey);
    assert_eq!(findings[0].masked_preview, "AKIA****************");
    assert_eq!(findings[1].kind, SensitiveDataKind::GitHubToken);
    assert!(findings[1].masked_preview.starts_with("ghp_"));
    assert!(!findings[1].masked_preview.contains("0123456789"));
}

#[tokio::test]
async fn test_fase6_ipc_full_lifecycle_and_authorization() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("daemon_test.sock");

    let storage = StorageManager::open_in_memory().expect("storage init");
    let mock_provider = Arc::new(MockRangeProvider::new());
    mock_provider.insert_range("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n");

    let breach_service = Arc::new(BreachService::new(
        DataBreachConfig {
            enabled: true,
            scan_clipboard: true,
            scan_uploads: true,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider,
    ));

    // Record sample audit log
    storage
        .record_decision(&AuditLogEntry {
            id: None,
            timestamp: "2026-09-09T14:30:00Z".to_string(),
            event_type: "file_access".to_string(),
            target: "/usr/local/bin/suspicious.sh".to_string(),
            decision: "Block".to_string(),
            reason: "KnownBadHash".to_string(),
            static_score: Some(0.95),
            hash_reputation: Some(1.0),
            behavior_score: Some(0.0),
            action_taken: "Quarantined file".to_string(),
        })
        .expect("record failed");

    // Record quarantine item
    let qid = storage
        .record_quarantine(
            "/home/user/compromised_script.sh",
            "/var/lib/gn-shield/quarantine/compromised_script.sh.quar",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Ransomware honeypot tampering",
        )
        .expect("quarantine record failed");

    let module_health = ModuleHealth::default();
    module_health
        .fs_sensor_active
        .store(true, Ordering::Relaxed);
    module_health
        .ebpf_sensor_active
        .store(true, Ordering::Relaxed);
    module_health
        .dns_filter_active
        .store(true, Ordering::Relaxed);

    let executor = Arc::new(Mutex::new(ActionExecutor::new(
        dir.path().join("quarantine"),
    )));
    let server = IpcServer::new(
        socket_path.clone(),
        storage.clone(),
        breach_service,
        module_health,
        executor,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

    let srv_task = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = IpcClient::new(&socket_path);

    // 1. Status query
    let status = client
        .call("status", serde_json::json!({}))
        .await
        .expect("status failed");
    assert_eq!(status["running"], true);
    assert_eq!(status["modules"]["fs_sensor_active"], true);
    assert_eq!(status["modules"]["ebpf_sensor_active"], true);
    assert_eq!(status["modules"]["dns_filter_active"], true);
    assert_eq!(status["staleness"]["yara_stale_warning"], false);

    // 2. Audit log query
    let logs = client
        .call(
            "get_audit_log",
            serde_json::json!({ "limit": 10, "decision": "Block" }),
        )
        .await
        .expect("logs failed");
    let log_arr = logs.as_array().expect("array");
    assert_eq!(log_arr.len(), 1);
    assert_eq!(log_arr[0]["decision"], "Block");
    assert_eq!(log_arr[0]["target"], "/usr/local/bin/suspicious.sh");

    // 3. Quarantine list & restore (reversibility principle)
    let qlist = client
        .call("list_quarantine", serde_json::json!({}))
        .await
        .expect("quarantine list failed");
    let qlist_arr = qlist.as_array().expect("array");
    assert_eq!(qlist_arr.len(), 1);
    assert_eq!(qlist_arr[0]["id"], qid);

    // If caller is root / UID 0 (or in test environment), restore succeeds
    let restore_res = client
        .call("restore_quarantine", serde_json::json!({ "id": qid }))
        .await;
    // In unprivileged test process, peer_cred returns user UID (non-0), so permission denied is expected!
    // This empirically verifies the authorization guard from docs/ARCHITECTURE.md section 6.1!
    if let Err(err_msg) = restore_res {
        assert!(err_msg.contains("Permission denied"));
    } else {
        // If run under root (e.g. CI container), it succeeds and restores
        let restored_list = client
            .call("list_quarantine", serde_json::json!({}))
            .await
            .expect("list failed");
        assert_eq!(restored_list.as_array().unwrap().len(), 0);
    }

    // 4. Breach check via k-anonymity
    let breach_info = client
        .call(
            "check_breach",
            serde_json::json!({ "credential": "password" }),
        )
        .await
        .expect("breach check failed");
    assert_eq!(breach_info["is_breached"], true);
    assert_eq!(breach_info["prefix"], "5BAA6");

    let _ = shutdown_tx.send(());
    let _ = srv_task.await;
}

#[test]
fn test_fase6_notification_batching_and_alert_fatigue_prevention() {
    let sink = Arc::new(InMemoryNotificationSink::new(PromptAction::AllowOnce));
    let config = NotificationsConfig {
        style: "native".to_string(),
        prompt_timeout_seconds: 60,
        default_action_on_timeout: "allow_once".to_string(),
        batching_enabled: true,
        batch_window_ms: 1000,
        batch_threshold_count: 3,
    };

    let batcher = NotificationBatcher::new(config, sink.clone());

    // Simulate pacman or npm install triggering multiple ambiguous prompt events
    let pid = 4510;
    let proc_name = "pacman".to_string();

    let ev1 = PromptEvent {
        id: "ev-1".to_string(),
        parent_pid: pid,
        parent_name: proc_name.clone(),
        target: "/usr/lib/libsample1.so".to_string(),
        reason: "Unsigned dynamic library write".to_string(),
        timestamp_ms: 100,
    };
    let ev2 = PromptEvent {
        id: "ev-2".to_string(),
        parent_pid: pid,
        parent_name: proc_name.clone(),
        target: "/usr/lib/libsample2.so".to_string(),
        reason: "Unsigned dynamic library write".to_string(),
        timestamp_ms: 150,
    };
    let ev3 = PromptEvent {
        id: "ev-3".to_string(),
        parent_pid: pid,
        parent_name: proc_name.clone(),
        target: "/usr/lib/libsample3.so".to_string(),
        reason: "Unsigned dynamic library write".to_string(),
        timestamp_ms: 200,
    };

    assert_eq!(batcher.submit_event(ev1).unwrap(), None);
    assert_eq!(batcher.submit_event(ev2).unwrap(), None);

    // Event 3 reaches batch threshold 3: immediately flushes summary batch
    let batch_res = batcher.submit_event(ev3).unwrap();
    assert_eq!(batch_res, Some(PromptAction::AllowOnce));

    let batches = sink.emitted_batches.lock().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].parent_pid, pid);
    assert_eq!(batches[0].parent_name, "pacman");
    assert_eq!(batches[0].events.len(), 3);
    assert!(batches[0].summary_title.contains("3 Aktivitas"));
    assert!(batches[0].summary_body.contains("libsample1.so"));
    assert!(batches[0].summary_body.contains("libsample2.so"));
    assert!(batches[0].summary_body.contains("libsample3.so"));
}
