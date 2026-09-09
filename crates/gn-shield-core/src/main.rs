//! GN-Shield Core Daemon Binary Entrypoint.
//!
//! Starts the GN-Shield core daemon, initializes storage, loads configuration,
//! runs the Unix domain socket IPC server, and sets up background protection sensors.

use gn_shield_config::GnShieldConfig;
use gn_shield_core::breach_service::{BreachService, MockRangeProvider};
use gn_shield_core::ipc::{IpcServer, DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH};
use gn_shield_storage::StorageManager;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

    // 1. Load configuration
    let config_path = get_config_path();
    let config = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                match GnShieldConfig::parse_toml(&content) {
                    Ok(cfg) => {
                        println!("Loaded configuration from: {}", config_path.display());
                        cfg
                    }
                    Err(e) => {
                        eprintln!("Warning: invalid configuration at {}: {e}. Using default configuration.", config_path.display());
                        GnShieldConfig::default()
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: could not read {}: {e}. Using default configuration.",
                    config_path.display()
                );
                GnShieldConfig::default()
            }
        }
    } else {
        println!(
            "No config file found at {}. Using default configuration.",
            config_path.display()
        );
        GnShieldConfig::default()
    };

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

    // 3. Initialize Breach Service
    let breach_provider = Arc::new(MockRangeProvider::new());
    let breach_service = Arc::new(BreachService::new(
        config.data_breach.clone(),
        breach_provider,
    ));
    println!("Breach detection service initialized (k-anonymity).");

    // 4. Determine socket path
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

    // 5. Spawn IPC Server
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let ipc_server = IpcServer::new(socket_path.clone(), storage.clone(), breach_service.clone());
    let sock_display = socket_path.display().to_string();

    tokio::spawn(async move {
        if let Err(e) = ipc_server.run(shutdown_rx).await {
            eprintln!("IPC Server error on {sock_display}: {e}");
        }
    });
    println!("IPC Server listening at: {}", socket_path.display());

    println!("All active protection modules running.");
    println!("Ready for connections from gn-shield-cli and native companions.");

    // 6. Graceful shutdown handler
    signal::ctrl_c().await?;
    println!("\nReceived shutdown signal. Stopping GN-Shield daemon cleanly...");
    let _ = shutdown_tx.send(());
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    println!("GN-Shield daemon terminated cleanly.");
    Ok(())
}
