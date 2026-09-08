//! GN-Shield Core Daemon Binary Entrypoint.

use gn_shield_config::GnShieldConfig;
use gn_shield_core::FileScanner;
use gn_shield_rules::HashReputationStore;
use gn_shield_sensors_common::{FileSystemSensor, FsEvent};
use gn_shield_sensors_linux::LinuxFsSensor;
use std::path::Path;

fn main() {
    println!("🛡️  GN-Shield Core Daemon (Phase 1)");
    println!("Initializing configuration and signature database...");

    let config = GnShieldConfig::default();
    let mut hash_store = HashReputationStore::new();

    // Seed sample known-bad hashes (e.g. EICAR hash standard)
    hash_store.add_known_bad("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    let scanner = match FileScanner::new(config, hash_store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize file scanner: {e}");
            std::process::exit(1);
        }
    };

    println!("YARA-X signature engine loaded successfully.");

    let watch_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/gn-shield-watch".to_string());
    let path = Path::new(&watch_path);

    if !path.exists() {
        let _ = std::fs::create_dir_all(path);
    }

    let mut sensor = LinuxFsSensor::new();
    if let Err(e) = sensor.watch(path) {
        eprintln!("Warning: failed to watch {path:?}: {e}");
    } else {
        println!("Filesystem sensor watching: {path:?}");
    }

    println!("Daemon running. Monitoring events (press Ctrl+C to stop)...");

    // In a full daemon, this runs inside a Tokio task or background thread
    // For Phase 1 CLI demo, process 1 event if available or exit cleanly
    if let Ok(event) = sensor.next_event() {
        match event {
            FsEvent::Created(p) | FsEvent::Modified(p) => {
                if p.is_file() {
                    println!("Event detected on file: {p:?}");
                    if let Ok(eval) = scanner.evaluate_file(&p) {
                        println!("Verdict: {:?} | Reason: {}", eval.action, eval.reason);
                    }
                }
            }
            FsEvent::Deleted(p) => {
                println!("File deleted: {p:?}");
            }
            FsEvent::ExecPermRequested { path, pid } => {
                println!("Exec permission requested for PID {pid}: {path:?}");
            }
        }
    }
}
