//! Integration tests for IPC physical quarantine restoration and reversibility.
//! Verifies:
//! 1. Physical restoration of quarantined file and preservation of original Unix permissions.
//! 2. Proper cleanup of .quarantined and .meta.json files on restoration.
//! 3. Database status updated to restored = 1 ONLY on successful physical disk restoration.
//! 4. Physical failure (e.g. missing quarantine file/metadata) returns error and leaves DB untouched (restored = 0).
//! 5. Administrative authorization enforcement (UID=0 required, unprivileged callers rejected).
//! 6. Prevention of double-restoring already restored entries.

use gn_shield_config::DataBreachConfig;
use gn_shield_core::{
    ActionExecutor, BreachService, IpcRequest, IpcServer, MockRangeProvider, ModuleHealth,
    QuarantineStatus,
};
use gn_shield_storage::StorageManager;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_ipc_restore_quarantine_physical_file_and_permissions() {
    let dir = tempdir().expect("tempdir failed");
    let files_dir = dir.path().join("files");
    let quarantine_dir = dir.path().join("quarantine");
    fs::create_dir_all(&files_dir).expect("create files dir");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");

    // 1. Create a script with 0o755 permissions
    let test_file = files_dir.join("critical_tool.sh");
    let original_bytes = b"#!/bin/bash\necho 'hello from developer tool'\n";
    fs::write(&test_file, original_bytes).expect("write original file");

    let mut perms = fs::metadata(&test_file).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&test_file, perms).expect("set 0o755");

    let initial_mode = fs::metadata(&test_file).expect("meta").permissions().mode() & 0o777;
    assert_eq!(initial_mode, 0o755);

    // 2. Quarantine file via ActionExecutor
    let mut raw_executor = ActionExecutor::new(quarantine_dir.clone());
    let q_record = raw_executor
        .quarantine_file(&test_file, "Suspicious behavior flagged")
        .expect("quarantine failed");

    assert_eq!(q_record.status, QuarantineStatus::Quarantined);
    assert!(
        !test_file.exists(),
        "Original file must be removed from original path"
    );
    assert!(
        q_record.quarantined_path.exists(),
        "Quarantined file must exist in quarantine folder"
    );
    let meta_file = q_record.quarantined_path.with_file_name(format!(
        "{}.meta.json",
        q_record
            .quarantined_path
            .file_name()
            .unwrap()
            .to_string_lossy()
    ));
    assert!(meta_file.exists(), "Metadata file must exist");

    // 3. Record in storage
    let storage = StorageManager::open_in_memory().expect("storage open failed");
    let qid = storage
        .record_quarantine(
            &test_file.to_string_lossy(),
            &q_record.quarantined_path.to_string_lossy(),
            &q_record.sha256,
            &q_record.reason,
        )
        .expect("record quarantine in db failed");

    // Verify initial storage state: restored == 0
    let entry_before = storage
        .get_quarantined_file(qid)
        .expect("get quarantined failed")
        .expect("entry should exist");
    assert!(!entry_before.restored);

    // 4. Setup IpcServer dependencies and call dispatch_request with peer_uid = 0
    let executor = Arc::new(Mutex::new(raw_executor));
    let mock_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        DataBreachConfig {
            enabled: false,
            scan_clipboard: false,
            scan_uploads: false,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider,
    ));
    let module_health = ModuleHealth::default();

    let req = IpcRequest {
        id: 42,
        method: "restore_quarantine".to_string(),
        params: serde_json::json!({ "id": qid }),
    };

    let resp = IpcServer::dispatch_request(
        req,
        &storage,
        &breach_service,
        &module_health,
        &executor,
        Instant::now(),
        0, // Admin UID = 0
    );

    assert_eq!(resp.id, 42);
    assert!(
        resp.error.is_none(),
        "IPC response must not return error: {:?}",
        resp.error
    );

    let result = resp.result.expect("result must be present");
    assert_eq!(result["id"], qid);
    assert_eq!(result["restored"], true);
    assert_eq!(
        result["restored_to"].as_str().unwrap(),
        test_file.to_string_lossy()
    );

    // 5. EMPIRICAL VERIFICATION OF DISK STATE
    // The file MUST physically exist again at original path
    assert!(
        test_file.exists(),
        "File must physically exist at original path after IPC restore"
    );
    let restored_bytes = fs::read(&test_file).expect("read restored file");
    assert_eq!(restored_bytes, original_bytes);

    // Original permissions (0o755) MUST be restored
    let restored_mode = fs::metadata(&test_file).expect("meta").permissions().mode() & 0o777;
    assert_eq!(
        restored_mode, 0o755,
        "Original mode 0o755 must be completely restored, got {restored_mode:o}"
    );

    // Quarantine files must be cleaned up
    assert!(
        !q_record.quarantined_path.exists(),
        "Quarantined file must be deleted after restore"
    );
    assert!(
        !meta_file.exists(),
        "Metadata file must be deleted after restore"
    );

    // DB state must now be restored == true
    let entry_after = storage
        .get_quarantined_file(qid)
        .expect("get quarantined failed")
        .expect("entry should exist");
    assert!(entry_after.restored);

    let unquarantined = storage.list_quarantined_files().expect("list failed");
    assert_eq!(unquarantined.len(), 0);
}

#[test]
fn test_ipc_restore_quarantine_physical_failure_does_not_mark_db() {
    let dir = tempdir().expect("tempdir failed");
    let files_dir = dir.path().join("files");
    let quarantine_dir = dir.path().join("quarantine");
    fs::create_dir_all(&files_dir).expect("create files dir");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");

    let test_file = files_dir.join("sample.bin");
    fs::write(&test_file, b"data payload").expect("write file");

    let mut raw_executor = ActionExecutor::new(quarantine_dir);
    let q_record = raw_executor
        .quarantine_file(&test_file, "Suspicious payload")
        .expect("quarantine failed");

    let storage = StorageManager::open_in_memory().expect("storage open failed");
    let qid = storage
        .record_quarantine(
            &test_file.to_string_lossy(),
            &q_record.quarantined_path.to_string_lossy(),
            &q_record.sha256,
            &q_record.reason,
        )
        .expect("record quarantine failed");

    // SIMULATE DISK CORRUPTION / MISSING QUARANTINE FILE:
    // Delete the quarantined file before calling restore
    fs::remove_file(&q_record.quarantined_path).expect("delete quarantine file");

    let executor = Arc::new(Mutex::new(raw_executor));
    let mock_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        DataBreachConfig {
            enabled: false,
            scan_clipboard: false,
            scan_uploads: false,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider,
    ));
    let module_health = ModuleHealth::default();

    let req = IpcRequest {
        id: 101,
        method: "restore_quarantine".to_string(),
        params: serde_json::json!({ "id": qid }),
    };

    let resp = IpcServer::dispatch_request(
        req,
        &storage,
        &breach_service,
        &module_health,
        &executor,
        Instant::now(),
        0, // Admin UID
    );

    // Assert: response MUST be an error
    assert!(
        resp.error.is_some(),
        "Physical failure must return an explicit error"
    );
    let err_msg = resp.error.unwrap();
    assert!(
        err_msg.contains("Failed to physically restore file"),
        "Error message must indicate physical restore failure: {err_msg}"
    );

    // CRITICAL: DB MUST NOT BE MARKED RESTORED
    let entry = storage
        .get_quarantined_file(qid)
        .expect("get quarantined failed")
        .expect("entry should exist");
    assert!(
        !entry.restored,
        "Storage record MUST remain unrestored when physical restoration fails!"
    );

    let active_list = storage.list_quarantined_files().expect("list failed");
    assert_eq!(
        active_list.len(),
        1,
        "File must still be in active quarantine list"
    );
}

#[test]
fn test_ipc_restore_quarantine_authorization_enforced() {
    let dir = tempdir().expect("tempdir failed");
    let storage = StorageManager::open_in_memory().expect("storage open failed");
    let qid = storage
        .record_quarantine(
            "/opt/app/bin",
            "/var/lib/gn-shield/quarantine/mock.quarantined",
            "fakehash",
            "Test",
        )
        .expect("record quarantine failed");

    let executor = Arc::new(Mutex::new(ActionExecutor::new(
        dir.path().join("quarantine"),
    )));
    let mock_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        DataBreachConfig {
            enabled: false,
            scan_clipboard: false,
            scan_uploads: false,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider,
    ));
    let module_health = ModuleHealth::default();

    let req = IpcRequest {
        id: 77,
        method: "restore_quarantine".to_string(),
        params: serde_json::json!({ "id": qid }),
    };

    // Call with unprivileged UID = 1000
    let resp = IpcServer::dispatch_request(
        req,
        &storage,
        &breach_service,
        &module_health,
        &executor,
        Instant::now(),
        1000,
    );

    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert!(err.contains("Permission denied"));

    // Verify DB still unrestored
    let entry = storage.get_quarantined_file(qid).unwrap().unwrap();
    assert!(!entry.restored);
}

#[test]
fn test_ipc_restore_quarantine_already_restored_rejection() {
    let dir = tempdir().expect("tempdir failed");
    let storage = StorageManager::open_in_memory().expect("storage open failed");
    let qid = storage
        .record_quarantine(
            "/opt/app/bin",
            "/var/lib/gn-shield/quarantine/mock.quarantined",
            "fakehash",
            "Test",
        )
        .expect("record quarantine failed");

    // Manually mark restored in DB
    storage
        .mark_quarantine_restored(qid)
        .expect("mark restored");

    let executor = Arc::new(Mutex::new(ActionExecutor::new(
        dir.path().join("quarantine"),
    )));
    let mock_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        DataBreachConfig {
            enabled: false,
            scan_clipboard: false,
            scan_uploads: false,
            k_anonymity_api_url: "mock://api/".to_string(),
            check_timeout_ms: 1000,
        },
        mock_provider,
    ));
    let module_health = ModuleHealth::default();

    let req = IpcRequest {
        id: 88,
        method: "restore_quarantine".to_string(),
        params: serde_json::json!({ "id": qid }),
    };

    let resp = IpcServer::dispatch_request(
        req,
        &storage,
        &breach_service,
        &module_health,
        &executor,
        Instant::now(),
        0,
    );

    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert!(err.contains("already marked as restored"));
}
