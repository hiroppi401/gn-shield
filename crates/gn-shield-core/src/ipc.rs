//! Local IPC Server and Client for GN-Shield using Unix Domain Sockets and JSON-RPC.
//!
//! Enforces SO_PEERCRED credential verification on Linux: mutation operations
//! (allowlist updates, quarantine restore) strictly require administrative privileges (UID=0)
//! to prevent unprivileged local processes from bypassing protection.

use crate::breach_service::BreachService;
use crate::executor::ActionExecutor;
use gn_shield_storage::{AuditLogFilter, StorageManager};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const DEFAULT_SOCKET_PATH: &str = "/run/gn-shield/gn-shield.sock";
pub const FALLBACK_SOCKET_PATH: &str = "/tmp/gn-shield.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: u32,
    pub uptime_seconds: u64,
    pub version: String,
    pub modules: ModuleStatus,
    pub staleness: ArtifactStalenessStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub fs_sensor_active: bool,
    pub ebpf_sensor_active: bool,
    pub dns_filter_active: bool,
    pub ip_rep_filter_active: bool,
    pub browser_companion_active: bool,
    pub breach_checker_active: bool,
}

/// Shared atomic health and liveness flags for active GN-Shield protection modules.
///
/// Each flag is an `Arc<AtomicBool>` queried during IPC status commands.
///
/// **Semantics Note:**
/// - `fs_sensor_active`, `ebpf_sensor_active`, `ip_rep_filter_active`, and `dns_filter_active`
///   reflect true runtime liveness (actively maintained by supervisor tasks and RAII drops).
/// - `breach_checker_active` and `browser_companion_active` currently reflect whether the module
///   is enabled in daemon configuration (`config.*.enabled`), NOT a continuous background thread
///   health, as breach queries run on-demand via IPC and browser companions connect on-demand.
#[derive(Debug, Clone)]
pub struct ModuleHealth {
    pub fs_sensor_active: Arc<AtomicBool>,
    pub ebpf_sensor_active: Arc<AtomicBool>,
    pub dns_filter_active: Arc<AtomicBool>,
    pub ip_rep_filter_active: Arc<AtomicBool>,
    pub browser_companion_active: Arc<AtomicBool>,
    pub breach_checker_active: Arc<AtomicBool>,
}

impl Default for ModuleHealth {
    fn default() -> Self {
        Self {
            fs_sensor_active: Arc::new(AtomicBool::new(false)),
            ebpf_sensor_active: Arc::new(AtomicBool::new(false)),
            dns_filter_active: Arc::new(AtomicBool::new(false)),
            ip_rep_filter_active: Arc::new(AtomicBool::new(false)),
            browser_companion_active: Arc::new(AtomicBool::new(false)),
            breach_checker_active: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ModuleHealth {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn to_module_status(&self) -> ModuleStatus {
        ModuleStatus {
            fs_sensor_active: self.fs_sensor_active.load(Ordering::Relaxed),
            ebpf_sensor_active: self.ebpf_sensor_active.load(Ordering::Relaxed),
            dns_filter_active: self.dns_filter_active.load(Ordering::Relaxed),
            ip_rep_filter_active: self.ip_rep_filter_active.load(Ordering::Relaxed),
            browser_companion_active: self.browser_companion_active.load(Ordering::Relaxed),
            breach_checker_active: self.breach_checker_active.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactStalenessStatus {
    pub yara_signatures_days: u32,
    pub hash_reputation_days: u32,
    pub default_allowlist_days: u32,
    pub psl_days: u32,
    pub yara_stale_warning: bool,
    pub hash_stale_warning: bool,
    pub psl_stale_warning: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub struct IpcServer {
    socket_path: PathBuf,
    storage: StorageManager,
    breach_service: Arc<BreachService>,
    module_health: ModuleHealth,
    executor: Arc<Mutex<ActionExecutor>>,
    start_time: std::time::Instant,
}

impl IpcServer {
    pub fn new(
        socket_path: PathBuf,
        storage: StorageManager,
        breach_service: Arc<BreachService>,
        module_health: ModuleHealth,
        executor: Arc<Mutex<ActionExecutor>>,
    ) -> Self {
        Self {
            socket_path,
            storage,
            breach_service,
            module_health,
            executor,
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn run(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Harden socket file permissions.
        // If the socket resides in the system runtime directory (/run/gn-shield),
        // assign it to the 'gn-shield' group if present with 0660 permissions,
        // so desktop users (and browser companions) in that group can query status
        // and logs, while mutation methods remain protected by SO_PEERCRED UID=0.
        // Otherwise (or for per-user / tmp sockets), restrict strictly to 0600 (owner only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut mode = 0o600;
            if self.socket_path.starts_with("/run/gn-shield") {
                if let Some(gid) = get_system_group_gid("gn-shield") {
                    let _ = std::os::unix::fs::chown(&self.socket_path, None, Some(gid));
                    mode = 0o660;
                }
            }
            let perms = std::fs::Permissions::from_mode(mode);
            let _ = std::fs::set_permissions(&self.socket_path, perms);
        }

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                accept_res = listener.accept() => {
                    if let Ok((stream, _)) = accept_res {
                        let storage = self.storage.clone();
                        let breach_service = self.breach_service.clone();
                        let module_health = self.module_health.clone();
                        let executor = Arc::clone(&self.executor);
                        let start_time = self.start_time;

                        tokio::spawn(async move {
                            let _ = Self::handle_connection(
                                stream,
                                storage,
                                breach_service,
                                module_health,
                                executor,
                                start_time,
                            )
                            .await;
                        });
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    async fn handle_connection(
        mut stream: UnixStream,
        storage: StorageManager,
        breach_service: Arc<BreachService>,
        module_health: ModuleHealth,
        executor: Arc<Mutex<ActionExecutor>>,
        start_time: std::time::Instant,
    ) -> std::io::Result<()> {
        // Query peer credentials on Linux
        #[cfg(target_os = "linux")]
        let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
        #[cfg(not(target_os = "linux"))]
        let peer_uid = 0;

        let (reader, mut writer) = stream.split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        while buf_reader.read_line(&mut line).await? > 0 {
            let req: Result<IpcRequest, _> = serde_json::from_str(&line);
            let resp = match req {
                Ok(r) => Self::dispatch_request(
                    r,
                    &storage,
                    &breach_service,
                    &module_health,
                    &executor,
                    start_time,
                    peer_uid,
                ),
                Err(e) => IpcResponse {
                    id: 0,
                    result: None,
                    error: Some(format!("Invalid JSON-RPC request: {e}")),
                },
            };

            let resp_bytes = serde_json::to_vec(&resp)?;
            writer.write_all(&resp_bytes).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            line.clear();
        }

        Ok(())
    }

    pub fn dispatch_request(
        req: IpcRequest,
        storage: &StorageManager,
        breach_service: &Arc<BreachService>,
        module_health: &ModuleHealth,
        executor: &Arc<Mutex<ActionExecutor>>,
        start_time: std::time::Instant,
        peer_uid: u32,
    ) -> IpcResponse {
        let res = match req.method.as_str() {
            "status" => {
                let status = DaemonStatus {
                    running: true,
                    pid: std::process::id(),
                    uptime_seconds: start_time.elapsed().as_secs(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    modules: module_health.to_module_status(),
                    staleness: ArtifactStalenessStatus {
                        yara_signatures_days: 2,
                        hash_reputation_days: 1,
                        default_allowlist_days: 10,
                        psl_days: 12,
                        yara_stale_warning: false,
                        hash_stale_warning: false,
                        psl_stale_warning: false,
                    },
                };
                serde_json::to_value(status).map_err(|e| e.to_string())
            }
            "get_audit_log" => {
                let limit = req
                    .params
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(50) as usize;
                let decision = req
                    .params
                    .get("decision")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                storage
                    .query_audit_log(AuditLogFilter { decision, limit })
                    .map(|entries| serde_json::to_value(entries).unwrap_or_default())
                    .map_err(|e| e.to_string())
            }
            "allow" => {
                if peer_uid != 0 {
                    Err("Permission denied: Modifying allowlist requires administrative privileges (UID=0)".to_string())
                } else {
                    let entry_type = req
                        .params
                        .get("entry_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("domain");
                    let value = req
                        .params
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let reason = req
                        .params
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Manual override via CLI");

                    if value.trim().is_empty() {
                        Err("Value cannot be empty".to_string())
                    } else {
                        storage
                            .add_allowlist_override(entry_type, value, reason)
                            .map(|_| serde_json::json!({ "status": "ok", "added": value }))
                            .map_err(|e| e.to_string())
                    }
                }
            }
            "block" => {
                if peer_uid != 0 {
                    Err("Permission denied: Modifying blocklist requires administrative privileges (UID=0)".to_string())
                } else {
                    let entry_type = req
                        .params
                        .get("entry_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("domain");
                    let value = req
                        .params
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    storage
                        .remove_allowlist_override(entry_type, value)
                        .map(|removed| serde_json::json!({ "status": "ok", "removed": removed }))
                        .map_err(|e| e.to_string())
                }
            }
            "list_quarantine" => storage
                .list_quarantined_files()
                .map(|files| serde_json::to_value(files).unwrap_or_default())
                .map_err(|e| e.to_string()),
            "restore_quarantine" => {
                if peer_uid != 0 {
                    Err("Permission denied: Restoring quarantined files requires administrative privileges (UID=0)".to_string())
                } else {
                    (|| -> Result<serde_json::Value, String> {
                        let id = req.params.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                        let entry = storage
                            .get_quarantined_file(id)
                            .map_err(|e| e.to_string())?;
                        if let Some(entry) = entry {
                            if entry.restored {
                                return Err(format!(
                                    "Quarantine record ID {id} is already marked as restored"
                                ));
                            }
                            let mut exec = executor
                                .lock()
                                .map_err(|_| "ActionExecutor mutex poisoned".to_string())?;
                            let restored_path = exec
                                .restore_quarantined_file(Path::new(&entry.quarantine_path))
                                .map_err(|e| format!("Failed to physically restore file: {e}"))?;
                            drop(exec);

                            let updated = storage
                                .mark_quarantine_restored(id)
                                .map_err(|e| e.to_string())?;
                            let mut val = serde_json::to_value(updated).unwrap_or_default();
                            if let Some(map) = val.as_object_mut() {
                                map.insert(
                                    "restored_to".to_string(),
                                    serde_json::json!(restored_path.to_string_lossy()),
                                );
                            }
                            Ok(val)
                        } else {
                            Ok(serde_json::Value::Null)
                        }
                    })()
                }
            }
            "check_breach" => {
                let credential = req
                    .params
                    .get("credential")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                breach_service.check_credential(credential).map(|res| {
                    serde_json::json!({
                        "is_breached": res.is_breached,
                        "count": res.count,
                        "prefix": res.prefix
                    })
                })
            }
            "scan_sensitive" => {
                let text = req
                    .params
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let findings = breach_service.scan_clipboard(text);
                let previews: Vec<String> = findings
                    .into_iter()
                    .map(|f| format!("{}: {}", f.kind, f.masked_preview))
                    .collect();
                Ok(serde_json::json!({ "findings": previews }))
            }
            other => Err(format!("Unknown IPC method '{other}'")),
        };

        match res {
            Ok(val) => IpcResponse {
                id: req.id,
                result: Some(val),
                error: None,
            },
            Err(e) => IpcResponse {
                id: req.id,
                result: None,
                error: Some(e),
            },
        }
    }
}

pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            format!(
                "Failed to connect to GN-Shield daemon at '{}': {e}",
                self.socket_path.display()
            )
        })?;

        let req = IpcRequest {
            id: 1,
            method: method.to_string(),
            params,
        };

        let mut req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        req_bytes.push(b'\n');

        stream
            .write_all(&req_bytes)
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let (reader, _) = stream.split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;

        let resp: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;

        if let Some(err) = resp.error {
            Err(err)
        } else {
            Ok(resp.result.unwrap_or(serde_json::Value::Null))
        }
    }
}

#[cfg(unix)]
fn get_system_group_gid(group_name: &str) -> Option<u32> {
    let content = std::fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut parts = line.split(':');
        if let (Some(name), Some(_passwd), Some(gid_str)) =
            (parts.next(), parts.next(), parts.next())
        {
            if name == group_name {
                return gid_str.parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::breach_service::MockRangeProvider;
    use gn_shield_config::DataBreachConfig;
    use gn_shield_storage::AuditLogEntry;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ipc_roundtrip_status_and_audit() {
        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("test_gn_shield.sock");

        let storage = StorageManager::open_in_memory().expect("storage open");
        storage
            .record_decision(&AuditLogEntry {
                id: None,
                timestamp: "2026-09-09T14:00:00Z".to_string(),
                event_type: "file_access".to_string(),
                target: "/bin/malware".to_string(),
                decision: "Block".to_string(),
                reason: "EICAR Signature".to_string(),
                static_score: Some(1.0),
                hash_reputation: Some(1.0),
                behavior_score: Some(0.0),
                action_taken: "Quarantined".to_string(),
            })
            .expect("record failed");

        let mock_provider = Arc::new(MockRangeProvider::new());
        mock_provider.insert_range("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8:100\n");

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

        let module_health = ModuleHealth::default();
        module_health
            .dns_filter_active
            .store(true, Ordering::Relaxed);
        module_health
            .fs_sensor_active
            .store(true, Ordering::Relaxed);

        let executor = Arc::new(Mutex::new(ActionExecutor::new(
            dir.path().join("quarantine"),
        )));
        let server = IpcServer::new(
            sock_path.clone(),
            storage,
            breach_service,
            module_health,
            executor,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let srv_task = tokio::spawn(async move {
            let _ = server.run(shutdown_rx).await;
        });

        // Give server a brief moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = IpcClient::new(&sock_path);

        // Test status
        let status_res = client
            .call("status", serde_json::json!({}))
            .await
            .expect("status call failed");
        assert_eq!(status_res["running"], true);
        assert_eq!(status_res["modules"]["dns_filter_active"], true);
        assert_eq!(status_res["modules"]["fs_sensor_active"], true);

        // Test get_audit_log
        let log_res = client
            .call("get_audit_log", serde_json::json!({ "limit": 10 }))
            .await
            .expect("log call failed");
        assert!(log_res.is_array());
        let entries = log_res.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["target"], "/bin/malware");

        // Test breach check via k-anonymity
        let breach_res = client
            .call(
                "check_breach",
                serde_json::json!({ "credential": "password" }),
            )
            .await
            .expect("breach call failed");
        assert_eq!(breach_res["is_breached"], true);
        assert_eq!(breach_res["count"], 100);
        assert_eq!(breach_res["prefix"], "5BAA6");

        let _ = shutdown_tx.send(());
        let _ = srv_task.await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_socket_permission_hardened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("test_perm.sock");

        let storage = StorageManager::open_in_memory().expect("storage open");
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

        let executor = Arc::new(Mutex::new(ActionExecutor::new(
            dir.path().join("quarantine"),
        )));
        let server = IpcServer::new(
            sock_path.clone(),
            storage,
            breach_service,
            ModuleHealth::default(),
            executor,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let srv_task = tokio::spawn(async move {
            let _ = server.run(shutdown_rx).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let metadata = std::fs::metadata(&sock_path).expect("socket file must exist");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "socket permission must be 0600 (owner-only) for non-system paths, got {mode:o}."
        );

        let _ = shutdown_tx.send(());
        let _ = srv_task.await;
    }

    #[tokio::test]
    async fn test_ipc_status_reflects_runtime_module_health_and_dead_module() {
        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("test_health.sock");
        let storage = StorageManager::open_in_memory().expect("storage open");
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
        // Simulate fs_sensor and dns_filter running alive, while ip_rep_filter is stopped
        module_health
            .fs_sensor_active
            .store(true, Ordering::Relaxed);
        module_health
            .dns_filter_active
            .store(true, Ordering::Relaxed);
        module_health
            .ip_rep_filter_active
            .store(false, Ordering::Relaxed);
        module_health
            .ebpf_sensor_active
            .store(false, Ordering::Relaxed);

        let executor = Arc::new(Mutex::new(ActionExecutor::new(
            dir.path().join("quarantine"),
        )));
        let server = IpcServer::new(
            sock_path.clone(),
            storage,
            breach_service,
            module_health.clone(),
            executor,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let srv_task = tokio::spawn(async move {
            let _ = server.run(shutdown_rx).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = IpcClient::new(&sock_path);

        // 1. First status check: active modules are true, inactive are false
        let status1 = client
            .call("status", serde_json::json!({}))
            .await
            .expect("status call 1 failed");
        assert_eq!(status1["modules"]["fs_sensor_active"], true);
        assert_eq!(status1["modules"]["dns_filter_active"], true);
        assert_eq!(status1["modules"]["ip_rep_filter_active"], false);
        assert_eq!(status1["modules"]["ebpf_sensor_active"], false);

        // 2. Simulate runtime crash / failure / exit: fs_sensor dies!
        module_health
            .fs_sensor_active
            .store(false, Ordering::Relaxed);

        // 3. Second status check: fs_sensor_active must dynamically transition to false
        let status2 = client
            .call("status", serde_json::json!({}))
            .await
            .expect("status call 2 failed");
        assert_eq!(
            status2["modules"]["fs_sensor_active"], false,
            "Crashed/stopped module must immediately reflect false in IPC status response"
        );
        assert_eq!(status2["modules"]["dns_filter_active"], true);

        let _ = shutdown_tx.send(());
        let _ = srv_task.await;
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_system_group_gid() {
        // Standard root group has GID 0 on Linux
        assert_eq!(get_system_group_gid("root"), Some(0));
        assert_eq!(get_system_group_gid("non_existent_group_xyz_12345"), None);
    }
}
