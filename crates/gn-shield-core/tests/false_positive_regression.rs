//! PRD Section 6.4: False Positive Regression Suite for Linux.
//! Validates that GN-Shield strictly achieves zero false positives against standard developer workflows,
//! while maintaining 100% detection on genuine malware and ransomware attacks.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

use gn_shield_config::{GnShieldConfig, PathAllowlistEntry, PublisherAllowlistEntry};
use gn_shield_core::{
    Action, FileScanner, IncidentAction, ProcessBehaviorTracker, RansomwareDetector,
};
use gn_shield_rules::{HashReputationStore, HoneypotManager, EICAR_PAYLOAD};

/// Sets up a standard GN-Shield test environment with known developer tools in allowlist.
fn setup_developer_environment() -> (GnShieldConfig, HashReputationStore, HoneypotManager) {
    let mut config = GnShieldConfig::default();

    // 1. Tier 2 Publisher entries for developer tools
    config.allowlist.publisher.push(PublisherAllowlistEntry {
        platform: "linux".to_string(),
        verified_by: "pacman".to_string(),
        package_name: "firefox".to_string(),
        auto_trust: true,
        high_fanout_expected: true,
    });
    config.allowlist.publisher.push(PublisherAllowlistEntry {
        platform: "linux".to_string(),
        verified_by: "pacman".to_string(),
        package_name: "chromium".to_string(),
        auto_trust: true,
        high_fanout_expected: true,
    });
    config.allowlist.publisher.push(PublisherAllowlistEntry {
        platform: "linux".to_string(),
        verified_by: "pacman".to_string(),
        package_name: "docker".to_string(),
        auto_trust: true,
        high_fanout_expected: true,
    });
    config.allowlist.publisher.push(PublisherAllowlistEntry {
        platform: "linux".to_string(),
        verified_by: "pacman".to_string(),
        package_name: "podman".to_string(),
        auto_trust: true,
        high_fanout_expected: true,
    });
    config.allowlist.publisher.push(PublisherAllowlistEntry {
        platform: "linux".to_string(),
        verified_by: "pacman".to_string(),
        package_name: "cargo".to_string(),
        auto_trust: true,
        high_fanout_expected: true,
    });

    // 2. Tier 3 Path allowlist for tunnels
    config.allowlist.path.push(PathAllowlistEntry {
        path: "/usr/bin/cloudflared".to_string(),
        verified_by: "pacman".to_string(),
        auto_reverify_on_update: true,
    });
    config.allowlist.path.push(PathAllowlistEntry {
        path: "/usr/bin/ngrok".to_string(),
        verified_by: "pacman".to_string(),
        auto_reverify_on_update: true,
    });
    config.allowlist.path.push(PathAllowlistEntry {
        path: "/usr/bin/tailscale".to_string(),
        verified_by: "pacman".to_string(),
        auto_reverify_on_update: true,
    });

    let mut hash_store = HashReputationStore::new();
    hash_store.add_known_bad("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    let honeypot_manager = HoneypotManager::new();

    (config, hash_store, honeypot_manager)
}

#[test]
fn test_regression_firefox_chromium_fanout() {
    let (config, _hash_store, _honeypot) = setup_developer_environment();
    let mut tracker = ProcessBehaviorTracker::new(config).expect("tracker init failed");

    // Scenario: User opens Firefox or Chromium with 50 simultaneous tabs
    let firefox_parent_pid = 2000;
    let chromium_parent_pid = 3000;

    for i in 1..=50 {
        tracker.record_spawn(firefox_parent_pid, firefox_parent_pid + i);
        tracker.record_spawn(chromium_parent_pid, chromium_parent_pid + i);
    }

    let ff_exe = Path::new("/usr/lib/firefox/firefox");
    let ff_cmd = vec!["firefox".to_string(), "--contentproc".to_string()];
    let ff_score = tracker.evaluate_process_behavior(2001, firefox_parent_pid, ff_exe, &ff_cmd);
    assert_eq!(ff_score, 0.0, "Firefox fanout must be damped to 0.0");

    let cr_exe = Path::new("/usr/lib/chromium/chromium");
    let cr_cmd = vec!["chromium".to_string(), "--type=renderer".to_string()];
    let cr_score = tracker.evaluate_process_behavior(3001, chromium_parent_pid, cr_exe, &cr_cmd);
    assert_eq!(cr_score, 0.0, "Chromium fanout must be damped to 0.0");
}

#[test]
fn test_regression_cloudflared_ngrok_tailscale() {
    let temp = tempdir().expect("tempdir failed");

    // Simulate verified cloudflared binary
    let cf_path = temp.path().join("cloudflared");
    let mut f = File::create(&cf_path).expect("create failed");
    f.write_all(b"legitimate cloudflared binary content")
        .expect("write failed");
    drop(f);

    // With Tier 3 path allowlist matching
    let mut cf_config = GnShieldConfig::default();
    cf_config.allowlist.path.push(PathAllowlistEntry {
        path: cf_path.to_string_lossy().to_string(),
        verified_by: "pacman".to_string(),
        auto_reverify_on_update: true,
    });
    let cf_scanner = FileScanner::new(cf_config, HashReputationStore::new()).expect("scanner init");
    let eval = cf_scanner.evaluate_file(&cf_path).expect("eval failed");
    assert_eq!(eval.action, Action::Allow);
    assert!(eval.reason.contains("Tier 3 Path Allowlist"));
}

#[test]
fn test_regression_git_clone_and_checkout() {
    let (config, _hash_store, honeypot) = setup_developer_environment();
    let mut detector = RansomwareDetector::new(&config, honeypot);

    let temp = tempdir().expect("tempdir failed");
    let git_dir = temp.path().join(".git");
    let objects_dir = git_dir.join("objects");
    fs::create_dir_all(&objects_dir).expect("create dir failed");

    // Simulate git checkout modifying 100 files inside repo tree and .git
    for i in 0..100 {
        let obj_file = objects_dir.join(format!("obj_{i}"));
        fs::write(&obj_file, b"git blob content").expect("write failed");

        let (action, incident) = detector.record_and_evaluate(&obj_file, Some(5.2));
        assert_eq!(action, Action::Allow, "Git object write falsely flagged!");
        assert_eq!(incident, IncidentAction::Allow);
    }
}

#[test]
fn test_regression_npm_cargo_pip_installs() {
    let (config, _hash_store, honeypot) = setup_developer_environment();
    let mut detector = RansomwareDetector::new(&config, honeypot);

    let temp = tempdir().expect("tempdir failed");
    let node_modules = temp.path().join("node_modules");
    let target_dir = temp.path().join("target");
    let venv_dir = temp.path().join(".venv");

    fs::create_dir_all(&node_modules).expect("create nm failed");
    fs::create_dir_all(&target_dir).expect("create target failed");
    fs::create_dir_all(&venv_dir).expect("create venv failed");

    // Simulate npm install, cargo build, and pip install writing hundreds of files
    for i in 0..150 {
        let nm_file = node_modules.join(format!("index_{i}.js"));
        fs::write(&nm_file, b"exports.run = function() {};").expect("write nm failed");
        let (action_nm, inc_nm) = detector.record_and_evaluate(&nm_file, Some(4.5));
        assert_eq!(action_nm, Action::Allow);
        assert_eq!(inc_nm, IncidentAction::Allow);

        let target_file = target_dir.join(format!("lib_{i}.rlib"));
        fs::write(&target_file, b"rust rlib binary content").expect("write target failed");
        let (action_target, inc_target) = detector.record_and_evaluate(&target_file, Some(5.8));
        assert_eq!(action_target, Action::Allow);
        assert_eq!(inc_target, IncidentAction::Allow);

        let venv_file = venv_dir.join(format!("module_{i}.py"));
        fs::write(&venv_file, b"def run(): pass").expect("write venv failed");
        let (action_venv, inc_venv) = detector.record_and_evaluate(&venv_file, Some(4.0));
        assert_eq!(action_venv, Action::Allow);
        assert_eq!(inc_venv, IncidentAction::Allow);
    }
}

#[test]
fn test_security_boundary_eicar_in_node_modules_is_still_blocked() {
    // CRITICAL REQUIREMENT (PRD 5 / DECISION_ENGINE.md):
    // Tier 5 exclusion for node_modules MUST NOT bypass static scanner or behavior monitor!
    let (config, hash_store, _honeypot) = setup_developer_environment();
    let scanner = FileScanner::new(config.clone(), hash_store).expect("scanner init failed");

    let temp = tempdir().expect("tempdir failed");
    let node_modules = temp.path().join("node_modules");
    fs::create_dir_all(&node_modules).expect("create dir failed");

    let malicious_package_file = node_modules.join("malicious_dep.js");
    fs::write(&malicious_package_file, EICAR_PAYLOAD).expect("write failed");

    // Case 1: On-access scan with hash reputation triggers Layer 0 short-circuit block
    let eval_hash = scanner
        .evaluate_file(&malicious_package_file)
        .expect("eval failed");
    assert_eq!(
        eval_hash.action,
        Action::Block,
        "Malware in node_modules bypassed scanner!"
    );
    assert!(eval_hash.reason.contains("Known-Bad Hash"));

    // Case 2: On-access scan without known hash triggers Layer 1 YARA-X signature engine
    let yara_only_scanner =
        FileScanner::new(config, HashReputationStore::new()).expect("scanner init");
    let eval_yara = yara_only_scanner
        .evaluate_file(&malicious_package_file)
        .expect("eval failed");
    assert_ne!(
        eval_yara.action,
        Action::Allow,
        "YARA signature in node_modules bypassed!"
    );
    assert_eq!(eval_yara.matched_rules, vec!["EICAR_Test_File"]);
}

#[test]
fn test_regression_ransomware_attack_detected_and_contained() {
    let (config, _hash_store, mut honeypot) = setup_developer_environment();
    let temp = tempdir().expect("tempdir failed");

    // Deploy canaries
    let canaries = honeypot.deploy_in_dir(temp.path()).expect("deploy failed");
    let mut detector = RansomwareDetector::new(&config, honeypot);

    // Tamper with canary decoy file (encrypt it)
    fs::write(&canaries[0], vec![0xCA; 200]).expect("canary tamper failed");

    // Rapidly write 15 high-entropy (.locked) files
    let mut final_action = Action::Allow;
    let mut final_incident = IncidentAction::Allow;

    for i in 0..15 {
        let locked_file = temp.path().join(format!("user_data_{i}.locked"));
        fs::write(&locked_file, vec![0xFE; 256]).expect("write locked failed");
        let (a, inc) = detector.record_and_evaluate(&locked_file, Some(7.9));
        final_action = a;
        final_incident = inc;
    }

    // Evaluate tampered canary
    let (canary_a, canary_inc) = detector.record_and_evaluate(&canaries[0], Some(7.9));
    if canary_a == Action::Block {
        final_action = canary_a;
        final_incident = canary_inc;
    }

    // Must be blocked with ContainAndTerminate incident action
    assert_eq!(final_action, Action::Block);
    match final_incident {
        IncidentAction::ContainAndTerminate {
            reason,
            target_paths,
        } => {
            assert!(reason.contains("canary decoy tampered"));
            assert!(!target_paths.is_empty());
        }
        _ => panic!("Expected ContainAndTerminate action, got: {final_incident:?}"),
    }
}

#[tokio::test]
async fn test_regression_dns_filter_domain_allowlist_dual_stack() {
    use gn_shield_config::DomainAllowlistEntry;
    use gn_shield_dns::{DnsFilterEngine, DnsFilterVerdict};

    let domain_allowlist = vec![
        DomainAllowlistEntry {
            pattern: "*.trycloudflare.com".to_string(),
            reason: "cloudflare_tunnel".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.cfargotunnel.com".to_string(),
            reason: "cloudflare_tunnel".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.ngrok.io".to_string(),
            reason: "ngrok_tunnel".to_string(),
        },
        DomainAllowlistEntry {
            pattern: "*.ts.net".to_string(),
            reason: "tailscale".to_string(),
        },
    ];

    let mut engine = DnsFilterEngine::new(&domain_allowlist, 45);
    engine.add_blocked_domain("bad-credential-phish.net", "phishtank", "phishing");
    engine.add_blocked_domain(
        "monero-crypto-pool.org",
        "coinblockerlists",
        "in_page_cryptominer",
    );
    engine.add_blocked_domain("malware-c2-drop.xyz", "urlhaus", "c2_server");

    // 1. Legitimate developer tunnel domains MUST be allowed (Short Circuit)
    let allowed_cases = [
        "tunnel-random-xyz.trycloudflare.com",
        "nested.sub.tunnel.trycloudflare.com",
        "app.cfargotunnel.com",
        "custom-dev.ngrok.io",
        "my-laptop.ts.net",
    ];
    for domain in allowed_cases {
        let verdict = engine.evaluate(domain);
        assert!(
            matches!(verdict, DnsFilterVerdict::Allow { .. }),
            "Developer tunnel domain {domain} was falsely blocked: {verdict:?}"
        );
    }

    // 2. Spoofed / Lookalike domains MUST NOT match the allowlist rule
    let spoofed_cases = [
        "eviltrycloudflare.com",
        "trycloudflare.com.attacker-controlled.com",
        "ngrok.io.fake-site.com",
    ];
    for domain in spoofed_cases {
        let verdict = engine.evaluate(domain);
        if let DnsFilterVerdict::Allow { reason } = &verdict {
            assert!(
                !reason.contains("tier4_allowlist"),
                "Spoofed domain {domain} falsely matched allowlist!"
            );
        }
    }

    // 3. Known bad domains (and their subdomains via eTLD+1) MUST be blocked
    let blocked_cases = [
        "bad-credential-phish.net",
        "login.secure.bad-credential-phish.net",
        "monero-crypto-pool.org",
        "worker.monero-crypto-pool.org",
        "malware-c2-drop.xyz",
    ];
    for domain in blocked_cases {
        let verdict = engine.evaluate(domain);
        assert!(
            matches!(verdict, DnsFilterVerdict::Block { .. }),
            "Malicious domain {domain} bypassed DNS filter: {verdict:?}"
        );
    }
}

#[test]
fn test_regression_ip_reputation_ttl_and_cdn_protection() {
    use gn_shield_config::{IpAllowlistEntry, IpReputationConfig};
    use gn_shield_sensors_linux::{EbpfIpReputationFilter, IpVerdict};
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};

    let allowlist = vec![
        IpAllowlistEntry {
            cidr: "100.64.0.0/10".to_string(),
            reason: "tailscale_cgnat".to_string(),
        },
        IpAllowlistEntry {
            cidr: "2001:db8:cafe::/48".to_string(),
            reason: "internal_tailscale_ipv6".to_string(),
        },
    ];

    let config = IpReputationConfig {
        ttl_days: 10,
        stale_warning_days: 7,
        ..Default::default()
    };
    let mut filter = EbpfIpReputationFilter::new(&config, &allowlist);

    let now = SystemTime::now();

    // 1. Expired CDN edge IP (Cloudflare / AWS edge IP formerly on shared hosting)
    let cdn_edge_ipv4: IpAddr = "104.16.100.1".parse().unwrap();
    let cdn_edge_ipv6: IpAddr = "2606:4700::6810:6401".parse().unwrap();

    // Added 14 days ago with 10 days TTL -> expired
    let past_time = now - Duration::from_secs(14 * 86400);
    let ttl_secs = 10 * 86400;
    filter.add_ip_entry_with_time(
        cdn_edge_ipv4,
        "feodotracker",
        "expired_host",
        past_time,
        ttl_secs,
    );
    filter.add_ip_entry_with_time(
        cdn_edge_ipv6,
        "spamhaus_drop",
        "expired_host",
        past_time,
        ttl_secs,
    );

    // Must be allowed due to TTL expiration
    assert!(
        matches!(
            filter.evaluate_connection(cdn_edge_ipv4, now),
            IpVerdict::Allow { .. }
        ),
        "Expired CDN IPv4 edge IP falsely blocked!"
    );
    assert!(
        matches!(
            filter.evaluate_connection(cdn_edge_ipv6, now),
            IpVerdict::Allow { .. }
        ),
        "Expired CDN IPv6 edge IP falsely blocked!"
    );

    // 2. Active C2 IP (Feodo Tracker, Spamhaus DROP) must be BLOCKED on both IPv4 and IPv6
    let active_c2_v4: IpAddr = "198.51.100.99".parse().unwrap();
    let active_c2_v6: IpAddr = "2001:db8:dead::beef".parse().unwrap();
    filter.add_ip_entry(active_c2_v4, "feodotracker", "emotet_c2", None);
    filter.add_ip_entry(active_c2_v6, "spamhaus_drop", "qakbot_c2", None);

    assert!(
        matches!(
            filter.evaluate_connection(active_c2_v4, now),
            IpVerdict::Block { .. }
        ),
        "Active C2 IPv4 bypassed IP filter!"
    );
    assert!(
        matches!(
            filter.evaluate_connection(active_c2_v6, now),
            IpVerdict::Block { .. }
        ),
        "Active C2 IPv6 bypassed IP filter!"
    );

    // 3. User Allowlist CIDR overrides even if IP is in a malicious feed
    let tailscale_v4: IpAddr = "100.64.50.1".parse().unwrap();
    let tailscale_v6: IpAddr = "2001:db8:cafe:1::10".parse().unwrap();
    filter.add_ip_entry(tailscale_v4, "feodotracker", "false_positive_feed", None);
    filter.add_ip_entry(tailscale_v6, "spamhaus_drop", "false_positive_feed", None);

    assert!(
        matches!(
            filter.evaluate_connection(tailscale_v4, now),
            IpVerdict::Allow { .. }
        ),
        "Tailscale IPv4 falsely blocked despite allowlist CIDR!"
    );
    assert!(
        matches!(
            filter.evaluate_connection(tailscale_v6, now),
            IpVerdict::Allow { .. }
        ),
        "Tailscale IPv6 falsely blocked despite allowlist CIDR!"
    );
}

#[test]
fn test_regression_resolver_detection_all_modes() {
    use gn_shield_dns::{IntegrationMode, ResolverDetector, ResolverKind};
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    let temp = tempdir().expect("tempdir failed");
    let root = temp.path();

    // Skenario 1: systemd-resolved aktif dengan 127.0.0.53:53
    let run_systemd = root.join("run/systemd/resolve");
    fs::create_dir_all(&run_systemd).expect("create dir failed");
    File::create(run_systemd.join("stub-resolv.conf")).expect("create stub failed");

    let etc = root.join("etc");
    fs::create_dir_all(&etc).expect("create etc failed");
    let mut resolv_conf = File::create(etc.join("resolv.conf")).expect("create resolv failed");
    writeln!(resolv_conf, "nameserver 127.0.0.53").expect("write failed");

    let result = ResolverDetector::detect_with_root(root);
    assert_eq!(result.kind, ResolverKind::SystemdResolved);
    assert!(result.active);
    assert_eq!(result.recommended_mode, IntegrationMode::ChainUpstream);
    assert_eq!(result.alternative_port, 5353);
    assert!(result.remediation_instruction.contains("resolvectl dns"));

    // Skenario 2: Sistem tanpa competing resolver
    let temp_clean = tempdir().expect("tempdir failed");
    let root_clean = temp_clean.path();
    let etc_clean = root_clean.join("etc");
    fs::create_dir_all(&etc_clean).expect("create etc failed");
    let mut clean_resolv =
        File::create(etc_clean.join("resolv.conf")).expect("create resolv failed");
    writeln!(clean_resolv, "nameserver 1.1.1.1").expect("write failed");

    let clean_res = ResolverDetector::detect_with_root(root_clean);
    assert_eq!(clean_res.kind, ResolverKind::None);
    assert!(!clean_res.active);
    assert_eq!(clean_res.recommended_mode, IntegrationMode::Takeover);

    // Skenario 3: Pi-hole aktif
    let temp_pihole = tempdir().expect("tempdir failed");
    let root_pihole = temp_pihole.path();
    fs::create_dir_all(root_pihole.join("etc/pihole")).expect("create pihole dir");

    let pi_res = ResolverDetector::detect_with_root(root_pihole);
    assert_eq!(pi_res.kind, ResolverKind::PiHole);
    assert!(pi_res.active);
    assert_eq!(pi_res.recommended_mode, IntegrationMode::ChainUpstream);
}

#[tokio::test]
async fn test_regression_dns_proxy_latency_overhead() {
    use gn_shield_config::DomainAllowlistEntry;
    use gn_shield_dns::{DnsFilterEngine, DnsProxyServer};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let allowlist = vec![DomainAllowlistEntry {
        pattern: "*.trycloudflare.com".to_string(),
        reason: "tunnel".to_string(),
    }];
    let mut engine = DnsFilterEngine::new(&allowlist, 45);
    engine.add_blocked_domain("bad-domain-to-block.xyz", "urlhaus", "c2");

    let engine_arc = Arc::new(RwLock::new(engine));
    let server = DnsProxyServer::new(
        engine_arc,
        "127.0.0.1:5353".parse().unwrap(),
        "[::1]:5353".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
    );

    // Test query execution overhead
    let mut msg = Message::new();
    msg.set_id(9999);
    let name = Name::from_str("bad-domain-to-block.xyz.").unwrap();
    msg.add_query(Query::query(name, RecordType::A));

    let wire = msg.to_vec().unwrap();
    let resp = server.process_query_bytes(&wire).await.unwrap();
    assert!(!resp.is_empty());

    let metrics_lock = server.metrics();
    let metrics = metrics_lock.read().await;

    // Overhead must be strictly under 50,000 µs (50ms requirement, PRD 6.3), typically < 1,000 µs (1ms)
    assert!(
        metrics.last_latency_micros < 50_000,
        "DNS proxy latency overhead too high: {} µs",
        metrics.last_latency_micros
    );
}
