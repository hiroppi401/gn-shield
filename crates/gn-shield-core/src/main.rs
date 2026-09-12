//! GN-Shield Core Daemon Binary Entrypoint.
//!
//! Starts the GN-Shield core daemon, initializes storage, loads configuration,
//! runs the Unix domain socket IPC server, and sets up background protection sensors:
//! LinuxFsSensor, FileScanner, RansomwareDetector, ActionExecutor, DnsProxyServer,
//! and EbpfIpReputationFilter as active live loops.
//! Enforces fail-closed configuration validation prior to executing any initialization.

use gn_shield_config::GnShieldConfig;
use gn_shield_core::breach_service::{BreachService, MockRangeProvider};
use gn_shield_core::executor::ActionExecutor;
use gn_shield_core::ipc::{IpcServer, DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH};
use gn_shield_core::ransomware::{IncidentAction, RansomwareDetector};
use gn_shield_core::{Action, FileScanner};
use gn_shield_dns::{DnsFilterEngine, DnsProxyServer};
use gn_shield_rules::{HashReputationStore, HoneypotManager};
use gn_shield_sensors_common::{FileSystemSensor, FsEvent, NetworkEvent, NetworkSensor};
use gn_shield_sensors_linux::{EbpfIpReputationFilter, IpVerdict, LinuxFsSensor};
use gn_shield_storage::StorageManager;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::signal;

fn get_config_path() -> PathBuf {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return PathBuf::from(&args[i + 1]);
        }
        i += 1;
    }
    PathBuf::from("/etc/gn-shield/config.toml")
}

fn get_socket_path() -> PathBuf {
    let run_dir = Path::new("/run/gn-shield");
    if run_dir.exists() || std::fs::create_dir_all(run_dir).is_ok() {
        PathBuf::from(DEFAULT_SOCKET_PATH)
    } else {
        PathBuf::from(FALLBACK_SOCKET_PATH)
    }
}

fn get_storage_path() -> PathBuf {
    let var_dir = Path::new("/var/lib/gn-shield");
    if var_dir.exists() || std::fs::create_dir_all(var_dir).is_ok() {
        var_dir.join("gn-shield.db")
    } else {
        PathBuf::from("/tmp/gn-shield.db")
    }
}

fn get_quarantine_path() -> PathBuf {
    let var_dir = Path::new("/var/lib/gn-shield");
    if var_dir.exists() || std::fs::create_dir_all(var_dir).is_ok() {
        var_dir.join("quarantine")
    } else {
        PathBuf::from("/tmp/gn-shield-quarantine")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("gn-shield-core v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("GN-Shield Core Daemon v{}", env!("CARGO_PKG_VERSION"));
        println!();
        println!("Usage:");
        println!("  gn-shield-core [--config <path>] [--socket <path>]");
        println!();
        println!("Options:");
        println!("  --config <path>   Path to configuration TOML file (default: /etc/gn-shield/config.toml)");
        println!("  --socket <path>   Path to IPC Unix domain socket (default: /run/gn-shield/gn-shield.sock)");
        println!("  --version, -v     Print version and exit");
        println!("  --help, -h        Print this help message");
        return Ok(());
    }

    println!("============================================================");
    println!("🛡️  GN-Shield Core Daemon v{}", env!("CARGO_PKG_VERSION"));
    println!("Process ID: {}", std::process::id());
    println!("============================================================");

    // 1. Load and validate configuration with strict fail-closed policy.
    // If config file is specified or exists, it MUST parse and pass validation;
    // failure terminates execution immediately before any side effects occur.
    let config_path = get_config_path();
    let config = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            format!(
                "Fail-closed: could not read configuration file at {}: {e}",
                config_path.display()
            )
        })?;
        let cfg = GnShieldConfig::parse_toml(&content).map_err(|e| {
            format!(
                "Fail-closed: configuration parsing/validation failed for {}: {e}",
                config_path.display()
            )
        })?;
        println!("Loaded configuration from: {}", config_path.display());
        cfg
    } else {
        println!(
            "No configuration file found at {}. Loading default configuration.",
            config_path.display()
        );
        let cfg = GnShieldConfig::default();
        cfg.validate()
            .map_err(|e| format!("Fail-closed: default configuration validation failed: {e}"))?;
        cfg
    };

    // Explicit fail-closed validation check before proceeding to any subsequent step
    config
        .validate()
        .map_err(|e| format!("Fail-closed: configuration validation check failed: {e}"))?;
    println!("Configuration validated successfully (fail-closed checks passed).");

    // 2. Initialize storage
    let storage_path = get_storage_path();
    let storage = match StorageManager::open(&storage_path) {
        Ok(s) => {
            println!("Storage initialized (WAL mode): {}", storage_path.display());
            s
        }
        Err(e) => {
            eprintln!(
                "Warning: could not open storage at {}: {e}. Using in-memory database.",
                storage_path.display()
            );
            StorageManager::open_in_memory()?
        }
    };

    // 3. Initialize ActionExecutor (quarantine management & phased containment)
    let quarantine_path = get_quarantine_path();
    if let Err(e) = std::fs::create_dir_all(&quarantine_path) {
        eprintln!(
            "Warning: could not create quarantine directory at {}: {e}",
            quarantine_path.display()
        );
    }
    let executor = Arc::new(Mutex::new(ActionExecutor::new(quarantine_path.clone())));
    println!(
        "ActionExecutor initialized (quarantine dir: {}).",
        quarantine_path.display()
    );

    // 4. Initialize FileScanner (hash reputation store + YARA-X rule engine)
    let hash_store = HashReputationStore::new();
    let file_scanner = Arc::new(
        FileScanner::new(config.clone(), hash_store)
            .map_err(|e| format!("Failed to initialize FileScanner: {e}"))?,
    );
    println!("FileScanner initialized (YARA-X rules compiled and hash store ready).");

    // 5. Initialize RansomwareDetector and deploy honeypot canaries
    let mut honeypot_manager = HoneypotManager::new();
    let canary_dir = PathBuf::from("/tmp/gn-shield-canaries");
    if let Err(e) = std::fs::create_dir_all(&canary_dir) {
        eprintln!(
            "Warning: could not create canary directory {}: {e}",
            canary_dir.display()
        );
    } else {
        match honeypot_manager.deploy_in_dir(&canary_dir) {
            Ok(canaries) => {
                println!(
                    "Honeypot canary decoys deployed ({} canaries in {}).",
                    canaries.len(),
                    canary_dir.display()
                );
            }
            Err(e) => {
                eprintln!("Warning: failed to deploy honeypot canaries: {e}");
            }
        }
    }
    let ransomware_detector = Arc::new(Mutex::new(RansomwareDetector::new(
        &config,
        honeypot_manager,
    )));
    println!("RansomwareDetector initialized (sliding window and entropy tracker).");

    // 6. Initialize and run LinuxFsSensor wired with FileScanner as ExecPermEvaluator
    let mut fs_sensor = LinuxFsSensor::new().with_evaluator(file_scanner.clone());

    if let Err(e) = fs_sensor.try_init_fanotify() {
        println!(
            "Info: fanotify initialization deferred ({e}); running in notify filesystem watcher mode."
        );
    } else {
        println!("fanotify kernel sensor initialized with FAN_CLASS_CONTENT execution protection.");
    }

    if canary_dir.exists() {
        if let Err(e) = fs_sensor.watch(&canary_dir) {
            eprintln!(
                "Warning: could not watch canary directory {}: {e}",
                canary_dir.display()
            );
        }
    }
    let tmp_dir = Path::new("/tmp");
    if tmp_dir.exists() {
        if let Err(e) = fs_sensor.watch(tmp_dir) {
            eprintln!("Warning: could not watch {}: {e}", tmp_dir.display());
        }
    }

    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let fs_scanner_ref = Arc::clone(&file_scanner);
    let fs_ransomware_ref = Arc::clone(&ransomware_detector);
    let fs_executor_ref = Arc::clone(&executor);
    let fs_shutdown = Arc::clone(&shutdown_signal);
    let fs_tx = fs_sensor.event_sender();

    let fs_thread = std::thread::Builder::new()
        .name("gn-shield-fs-sensor".to_string())
        .spawn(move || {
            while !fs_shutdown.load(Ordering::Relaxed) {
                match fs_sensor.next_event() {
                    Ok(event) => match event {
                        FsEvent::Created(path) | FsEvent::Modified(path) => {
                            if path.is_file() {
                                // Evaluate file with FileScanner
                                if let Ok(eval) = fs_scanner_ref.evaluate_file(&path) {
                                    if eval.action == Action::Block {
                                        eprintln!(
                                            "🛡️ [Threat Detected] Malicious file: {} - {}",
                                            path.display(),
                                            eval.reason
                                        );
                                        if let Ok(mut exec) = fs_executor_ref.lock() {
                                            if let Err(e) = exec.execute_scan_verdict(&eval, None) {
                                                eprintln!("Error executing scan verdict remediation: {e}");
                                            }
                                        }
                                    }
                                }

                                // Evaluate file modification with RansomwareDetector
                                let (action, incident) = {
                                    if let Ok(mut detector) = fs_ransomware_ref.lock() {
                                        detector.record_and_evaluate(&path, None)
                                    } else {
                                        (Action::Allow, IncidentAction::Allow)
                                    }
                                };
                                if action == Action::Block {
                                    eprintln!(
                                        "🚨 [Ransomware Incident] Detected on {}",
                                        path.display()
                                    );
                                    if let Ok(mut exec) = fs_executor_ref.lock() {
                                        if let Err(e) =
                                            exec.execute_incident_action(&incident, None)
                                        {
                                            eprintln!(
                                                "Error executing ransomware remediation: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        FsEvent::Deleted(path) => {
                            let (action, incident) = {
                                if let Ok(mut detector) = fs_ransomware_ref.lock() {
                                    detector.record_and_evaluate(&path, None)
                                } else {
                                    (Action::Allow, IncidentAction::Allow)
                                }
                            };
                            if action == Action::Block {
                                eprintln!(
                                    "🚨 [Ransomware Tampering Incident] Honeypot canary deleted: {}",
                                    path.display()
                                );
                                if let Ok(mut exec) = fs_executor_ref.lock() {
                                    let _ = exec.execute_incident_action(&incident, None);
                                }
                            }
                        }
                        FsEvent::ExecPermRequested { .. } => {
                            // Execution permission evaluated synchronously via watchdog in fanotify worker
                        }
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("Failed to spawn LinuxFsSensor thread: {e}"))?;
    println!("LinuxFsSensor active loop running.");

    // 7. Initialize and run EbpfIpReputationFilter loop
    let mut ip_filter =
        EbpfIpReputationFilter::new(&config.ip_reputation_filter, &config.network.ip_allowlist);
    if let Err(e) = ip_filter.subscribe() {
        eprintln!("Warning: IP reputation filter subscription failed: {e}");
    }

    let ip_executor_ref = Arc::clone(&executor);
    let ip_shutdown = Arc::clone(&shutdown_signal);
    let ip_tx = ip_filter.event_sender();

    let ip_thread = std::thread::Builder::new()
        .name("gn-shield-ip-filter".to_string())
        .spawn(move || {
            while !ip_shutdown.load(Ordering::Relaxed) {
                match ip_filter.next_event() {
                    Ok(NetworkEvent::ConnectionAttempt {
                        pid,
                        destination_ip,
                        destination_port,
                    }) => {
                        let verdict =
                            ip_filter.evaluate_connection(destination_ip, SystemTime::now());
                        match verdict {
                            IpVerdict::Block {
                                reason,
                                feed_source,
                            } => {
                                eprintln!(
                                    "🛡️ [Network Threat Blocked] PID {pid} connecting to {destination_ip}:{destination_port} - reason: {reason} (feed: {feed_source})"
                                );
                                if let Ok(mut exec) = ip_executor_ref.lock() {
                                    let _ = exec.contain_and_terminate_process(
                                        pid,
                                        &format!(
                                            "Blocked C2 connection to {destination_ip} ({feed_source})"
                                        ),
                                    );
                                }
                            }
                            IpVerdict::Allow { .. } => {}
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("Failed to spawn EbpfIpReputationFilter thread: {e}"))?;
    println!("EbpfIpReputationFilter active loop running.");

    // 8. Initialize and run DnsProxyServer
    let dns_engine = Arc::new(tokio::sync::RwLock::new(DnsFilterEngine::new(
        &config.network.domain_allowlist,
        config.dns_filter.psl_stale_warning_days,
    )));

    let dns_port = if config.dns_filter.integration_mode == "chain_upstream" {
        config.dns_filter.chain_upstream_listen_port
    } else {
        config
            .dns_filter
            .listen_address
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(53)
    };

    let dns_listen_v4: SocketAddr = format!("127.0.0.1:{dns_port}")
        .parse()
        .map_err(|e| format!("Invalid DNS IPv4 listen address: {e}"))?;
    let dns_listen_v6: SocketAddr = format!("[::1]:{dns_port}")
        .parse()
        .map_err(|e| format!("Invalid DNS IPv6 listen address: {e}"))?;

    let upstream_addr: SocketAddr = config
        .dns_filter
        .upstream
        .first()
        .map(|s| {
            if s.contains(':') {
                s.clone()
            } else {
                format!("{s}:53")
            }
        })
        .unwrap_or_else(|| "1.1.1.1:53".to_string())
        .parse()
        .unwrap_or_else(|_| "1.1.1.1:53".parse().unwrap());

    let dns_server = Arc::new(DnsProxyServer::new(
        dns_engine,
        dns_listen_v4,
        dns_listen_v6,
        upstream_addr,
    ));

    if config.dns_filter.enabled && config.dns_filter.integration_mode != "disabled" {
        let dns_clone = Arc::clone(&dns_server);
        tokio::spawn(async move {
            if let Err(e) = dns_clone.run_udp_listeners().await {
                eprintln!("Warning: DNS proxy server listener failed on port {dns_port}: {e}");
            }
        });
        println!("DnsProxyServer active on port {dns_port} (dual-stack IPv4/IPv6).");
    } else {
        println!("DnsProxyServer disabled in configuration.");
    }

    // 9. Initialize Breach Service
    let breach_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        config.data_breach.clone(),
        breach_provider,
    ));
    println!("Breach detection service initialized (k-anonymity).");

    // 10. Determine socket path and spawn IPC Server
    let mut custom_sock = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" && i + 1 < args.len() {
            custom_sock = Some(PathBuf::from(&args[i + 1]));
            break;
        }
        i += 1;
    }
    let socket_path = custom_sock.unwrap_or_else(get_socket_path);

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let ipc_server = IpcServer::new(socket_path.clone(), storage.clone(), breach_service.clone());
    let sock_display = socket_path.display().to_string();

    tokio::spawn(async move {
        if let Err(e) = ipc_server.run(shutdown_rx).await {
            eprintln!("IPC Server error on {sock_display}: {e}");
        }
    });
    println!("IPC Server listening at: {}", socket_path.display());

    println!("All active protection modules running as live loops.");
    println!("Ready for connections from gn-shield-cli and native companions.");

    // 11. Graceful shutdown handler
    signal::ctrl_c().await?;
    println!("\nReceived shutdown signal. Stopping GN-Shield daemon cleanly...");
    shutdown_signal.store(true, Ordering::Relaxed);
    let _ = fs_tx.send(Err(gn_shield_sensors_common::SensorError::InitError(
        "Shutdown".to_string(),
    )));
    drop(ip_tx);
    let _ = shutdown_tx.send(());
    let _ = fs_thread.join();
    let _ = ip_thread.join();
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    println!("GN-Shield daemon terminated cleanly.");
    Ok(())
}
