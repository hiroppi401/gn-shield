use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

use gn_shield_config::GnShieldConfig;
use gn_shield_core::executor::ActionExecutor;
use gn_shield_core::ransomware::{IncidentAction, RansomwareDetector};
use gn_shield_core::{Action, FileScanner};
use gn_shield_dns::{DnsFilterEngine, DnsProxyServer};
use gn_shield_rules::{calculate_sha256, HashReputationStore, HoneypotManager};
use gn_shield_sensors_common::{FileSystemSensor, FsEvent, NetworkEvent, NetworkSensor};
use gn_shield_sensors_linux::{EbpfIpReputationFilter, IpVerdict, LinuxFsSensor};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};

#[test]
fn test_config_validation_fail_closed_invalid_weights() {
    let invalid_toml = r#"
[scoring]
weight_static = 0.5
weight_hash_reputation = 0.5
weight_behavior = 0.5
"#;
    let res = GnShieldConfig::parse_toml(invalid_toml);
    assert!(res.is_err(), "Invalid scoring weights sum must fail-closed");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Scoring weights must sum to 1.0"),
        "Error message should explain weights mismatch: {err_msg}"
    );
}

#[test]
fn test_config_validation_fail_closed_threshold_inversion() {
    let invalid_toml = r#"
[scoring]
weight_static = 0.4
weight_hash_reputation = 0.4
weight_behavior = 0.2
threshold_block = 0.3
threshold_prompt = 0.7
"#;
    let res = GnShieldConfig::parse_toml(invalid_toml);
    assert!(
        res.is_err(),
        "threshold_block <= threshold_prompt must fail-closed"
    );
}

#[test]
fn test_config_validation_fail_closed_block_on_timeout_violation() {
    let invalid_toml = r#"
[notifications]
default_action_on_timeout = "block"
"#;
    let res = GnShieldConfig::parse_toml(invalid_toml);
    assert!(
        res.is_err(),
        "default_action_on_timeout = 'block' violates AGENTS.md safety rule and must fail-closed"
    );
}

#[tokio::test]
async fn test_integrated_live_daemon_components_loop() {
    let temp = tempdir().expect("tempdir failed");
    let q_dir = temp.path().join("quarantine");
    fs::create_dir_all(&q_dir).expect("create q_dir");

    // 1. Config validation (fail-closed check)
    let config = GnShieldConfig::default();
    assert!(
        config.validate().is_ok(),
        "Default config must pass validation"
    );

    // 2. ActionExecutor
    let executor = Arc::new(Mutex::new(ActionExecutor::new(q_dir.clone())));

    // 3. FileScanner with a known-bad hash
    let evil_bytes = b"trojan_payload_binary_data";
    let evil_hash = calculate_sha256(evil_bytes);
    let mut hash_store = HashReputationStore::new();
    hash_store.add_known_bad(&evil_hash);
    let file_scanner =
        Arc::new(FileScanner::new(config.clone(), hash_store).expect("scanner init"));

    // 4. RansomwareDetector & HoneypotManager
    let mut honeypot_manager = HoneypotManager::new();
    let canary_dir = temp.path().join("canaries");
    fs::create_dir_all(&canary_dir).expect("create canary_dir");
    let canaries = honeypot_manager
        .deploy_in_dir(&canary_dir)
        .expect("deploy canaries");
    assert!(!canaries.is_empty());
    let canary_file = canaries[0].clone();

    let ransomware_detector = Arc::new(Mutex::new(RansomwareDetector::new(
        &config,
        honeypot_manager,
    )));

    // 5. LinuxFsSensor wired to FileScanner
    let mut fs_sensor = LinuxFsSensor::new().with_evaluator(file_scanner.clone());
    let _ = fs_sensor.watch(&canary_dir);

    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let fs_tx = fs_sensor.event_sender();

    let fs_scanner_ref = Arc::clone(&file_scanner);
    let fs_ransomware_ref = Arc::clone(&ransomware_detector);
    let fs_executor_ref = Arc::clone(&executor);
    let fs_shutdown = Arc::clone(&shutdown_signal);

    let fs_thread = std::thread::Builder::new()
        .name("test-fs-sensor".to_string())
        .spawn(move || {
            while !fs_shutdown.load(Ordering::Relaxed) {
                match fs_sensor.next_event() {
                    Ok(event) => match event {
                        FsEvent::Created { path, pid } | FsEvent::Modified { path, pid } => {
                            if path.is_file() {
                                if let Ok(eval) = fs_scanner_ref.evaluate_file(&path) {
                                    if eval.action == Action::Block {
                                        if let Ok(mut exec) = fs_executor_ref.lock() {
                                            let _ = exec.execute_scan_verdict(&eval, pid);
                                        }
                                    }
                                }

                                let (action, incident) = {
                                    if let Ok(mut detector) = fs_ransomware_ref.lock() {
                                        detector.record_and_evaluate_with_pid(&path, None, pid)
                                    } else {
                                        (Action::Allow, IncidentAction::Allow)
                                    }
                                };
                                if action == Action::Block {
                                    if let Ok(mut exec) = fs_executor_ref.lock() {
                                        let _ = exec.execute_incident_action(&incident, pid);
                                    }
                                }
                            }
                        }
                        FsEvent::Deleted { path, pid } => {
                            let (action, incident) = {
                                if let Ok(mut detector) = fs_ransomware_ref.lock() {
                                    detector.record_and_evaluate_with_pid(&path, None, pid)
                                } else {
                                    (Action::Allow, IncidentAction::Allow)
                                }
                            };
                            if action == Action::Block {
                                if let Ok(mut exec) = fs_executor_ref.lock() {
                                    let _ = exec.execute_incident_action(&incident, pid);
                                }
                            }
                        }
                        FsEvent::ExecPermRequested { .. } => {}
                    },
                    Err(_) => break,
                }
            }
        })
        .expect("spawn fs_thread");

    // 6. EbpfIpReputationFilter
    let mut ip_filter =
        EbpfIpReputationFilter::new(&config.ip_reputation_filter, &config.network.ip_allowlist);
    let bad_c2_ip: std::net::IpAddr = "198.51.100.99".parse().unwrap();
    ip_filter.add_ip_entry(bad_c2_ip, "test_feed", "active_c2", Some(3600));
    ip_filter.subscribe().expect("subscribe ip filter");

    let ip_executor_ref = Arc::clone(&executor);
    let ip_shutdown = Arc::clone(&shutdown_signal);
    let ip_tx = ip_filter.event_sender();

    let ip_thread = std::thread::Builder::new()
        .name("test-ip-filter".to_string())
        .spawn(move || {
            while !ip_shutdown.load(Ordering::Relaxed) {
                match ip_filter.next_event() {
                    Ok(NetworkEvent::ConnectionAttempt {
                        pid,
                        destination_ip,
                        ..
                    }) => {
                        let verdict =
                            ip_filter.evaluate_connection(destination_ip, SystemTime::now());
                        match verdict {
                            IpVerdict::Block {
                                reason,
                                feed_source,
                            } => {
                                if let Ok(mut exec) = ip_executor_ref.lock() {
                                    let _ = exec.contain_and_terminate_process(
                                        pid,
                                        &format!("Blocked C2 connection to {destination_ip} ({feed_source}: {reason})"),
                                    );
                                }
                            }
                            IpVerdict::Allow { .. } => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("spawn ip_thread");

    // 7. DnsProxyServer
    let mut dns_filter_engine = DnsFilterEngine::new(
        &config.network.domain_allowlist,
        config.dns_filter.psl_stale_warning_days,
    );
    dns_filter_engine.add_blocked_domain("phishing-crypto-scam.com", "phishtank", "phishing");
    let dns_engine = Arc::new(tokio::sync::RwLock::new(dns_filter_engine));
    let dns_listen_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let dns_listen_v6: SocketAddr = "[::1]:0".parse().unwrap();
    let upstream_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

    let dns_server = Arc::new(DnsProxyServer::new(
        dns_engine,
        dns_listen_v4,
        dns_listen_v6,
        upstream_addr,
    ));

    // Test A: FileScanner in live loop via FsEvent
    let evil_file_path = temp.path().join("evil_trojan.bin");
    fs::write(&evil_file_path, evil_bytes).expect("write evil file");
    fs_tx
        .send(Ok(FsEvent::created(evil_file_path.clone())))
        .expect("send evil created event");

    // Give the thread a moment to process and quarantine
    tokio::time::sleep(Duration::from_millis(50)).await;
    {
        let exec = executor.lock().unwrap();
        assert!(
            exec.quarantine_history()
                .iter()
                .any(|r| r.original_path == evil_file_path),
            "Malicious file must be quarantined by ActionExecutor via FileScanner loop"
        );
    }

    // Test B: Ransomware tampering in live loop via honeypot deletion
    fs::remove_file(&canary_file).expect("tamper canary");
    fs_tx
        .send(Ok(FsEvent::deleted(canary_file.clone())))
        .expect("send canary deleted event");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test C: EbpfIpReputationFilter connection attempt
    ip_tx
        .send(NetworkEvent::ConnectionAttempt {
            pid: 999999, // Unused non-critical PID
            destination_ip: bad_c2_ip,
            destination_port: 443,
        })
        .expect("send ip connection attempt");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test D: DnsProxyServer evaluation
    let mut query_msg = Message::new();
    let query_name = Name::from_ascii("phishing-crypto-scam.com.").unwrap();
    let mut query = Query::new();
    query.set_name(query_name);
    query.set_query_type(RecordType::A);
    query_msg.add_query(query);
    let wire_bytes = query_msg.to_vec().unwrap();

    let resp_bytes = dns_server
        .process_query_bytes(&wire_bytes)
        .await
        .expect("dns process query");
    let resp_msg = Message::from_vec(&resp_bytes).expect("parse dns response");
    assert_eq!(
        resp_msg.response_code(),
        hickory_proto::op::ResponseCode::NXDomain,
        "Malicious domain should receive NXDomain from DnsProxyServer"
    );

    // Shutdown cleanly
    shutdown_signal.store(true, Ordering::Relaxed);
    let _ = fs_tx.send(Err(gn_shield_sensors_common::SensorError::InitError(
        "shutdown".into(),
    )));
    drop(ip_tx);

    let _ = fs_thread.join();
    let _ = ip_thread.join();
}

#[tokio::test]
async fn test_dns_proxy_supervisor_liveness_transitions_and_shutdown() {
    let dns_engine = Arc::new(tokio::sync::RwLock::new(DnsFilterEngine::new(&[], 45)));
    let dns_server = Arc::new(DnsProxyServer::new(
        dns_engine,
        "127.0.0.1:0".parse().unwrap(),
        "[::1]:0".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
    ));

    let dns_alive = Arc::new(AtomicBool::new(false));
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let dns_alive_clone = Arc::clone(&dns_alive);
    let shutdown_clone = Arc::clone(&shutdown_signal);
    let cancel_clone = cancel_token.clone();
    let dns_clone = Arc::clone(&dns_server);

    let supervisor = tokio::spawn(async move {
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _guard = Guard(Arc::clone(&dns_alive_clone));

        match dns_clone.run_udp_listeners(cancel_clone.clone()).await {
            Ok((mut v4_handle, mut v6_handle)) => {
                dns_alive_clone.store(true, Ordering::Relaxed);

                tokio::select! {
                    res = &mut v4_handle => {
                        if let Err(e) = res {
                            eprintln!("Warning: DNS IPv4 listener task panicked: {e}");
                        } else {
                            eprintln!("Warning: DNS IPv4 listener task exited unexpectedly.");
                        }
                        cancel_clone.cancel();
                        let _ = v6_handle.await;
                    }
                    res = &mut v6_handle => {
                        if let Err(e) = res {
                            eprintln!("Warning: DNS IPv6 listener task panicked: {e}");
                        } else {
                            eprintln!("Warning: DNS IPv6 listener task exited unexpectedly.");
                        }
                        cancel_clone.cancel();
                        let _ = v4_handle.await;
                    }
                    _ = cancel_clone.cancelled() => {
                        let _ = v4_handle.await;
                        let _ = v6_handle.await;
                    }
                    _ = async {
                        while !shutdown_clone.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    } => {
                        cancel_clone.cancel();
                        let _ = v4_handle.await;
                        let _ = v6_handle.await;
                    }
                }
                dns_alive_clone.store(false, Ordering::Relaxed);
            }
            Err(e) => {
                dns_alive_clone.store(false, Ordering::Relaxed);
                eprintln!("Warning: DNS proxy server listener failed: {e}");
            }
        }
    });

    // 1. Give supervisor time to initialize
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        dns_alive.load(Ordering::Relaxed),
        "dns_alive must be true while listeners run"
    );

    // 2. Test graceful shutdown path
    cancel_token.cancel();
    let res = tokio::time::timeout(Duration::from_secs(1), supervisor).await;
    assert!(res.is_ok(), "Supervisor task must complete on cancellation");
    assert!(
        !dns_alive.load(Ordering::Relaxed),
        "dns_alive must transition to false after shutdown"
    );
}
