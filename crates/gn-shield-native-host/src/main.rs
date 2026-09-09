//! GN-Shield Native Messaging Host Executable.

use gn_shield_config::GnShieldConfig;
use gn_shield_native_host::{
    generate_chrome_manifest, generate_firefox_manifest, install_manifest_file,
    standard_manifest_paths, HostHandler, CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID,
    NATIVE_HOST_NAME,
};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

fn default_blocked_domains() -> Vec<String> {
    vec![
        // Phishing feed samples
        "phish-paypal-update.com".to_string(),
        "secure-bank-login.xyz".to_string(),
        "account-verification-alert.top".to_string(),
        // Cryptomining pool feeds (coinblockerlists)
        "moneroocean.stream".to_string(),
        "supportxmr.com".to_string(),
        "pool.minexmr.com".to_string(),
        "coinhive.com".to_string(),
        "cryptoloot.pro".to_string(),
    ]
}

fn load_config() -> GnShieldConfig {
    let config_paths = [
        PathBuf::from("/etc/gn-shield/gn-shield.toml"),
        env::var("HOME")
            .map(|h| PathBuf::from(h).join(".config/gn-shield/gn-shield.toml"))
            .unwrap_or_default(),
    ];

    for path in &config_paths {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(cfg) = GnShieldConfig::parse_toml(&content) {
                    return cfg;
                }
            }
        }
    }

    GnShieldConfig::default()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--version" | "-v" => {
                println!("gn-shield-native-host {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!("GN-Shield Native Messaging Companion Host");
                println!();
                println!("Usage:");
                println!("  gn-shield-native-host [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --generate-chrome-manifest [BIN_PATH]   Print Chrome native messaging manifest");
                println!("  --generate-firefox-manifest [BIN_PATH]  Print Firefox native messaging manifest");
                println!("  --install-manifests [--system]          Install manifests to standard browser paths");
                println!("  --help, -h                              Show this help message");
                println!("  --version, -v                           Show version");
                println!();
                println!(
                    "When invoked without options, runs the stdio native messaging protocol loop."
                );
                return;
            }
            "--generate-chrome-manifest" => {
                let current_exe = env::current_exe()
                    .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/gn-shield-native-host"));
                let bin_path = args.get(2).map(Path::new).unwrap_or(&current_exe);
                let manifest = generate_chrome_manifest(bin_path);
                println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
                return;
            }
            "--generate-firefox-manifest" => {
                let current_exe = env::current_exe()
                    .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/gn-shield-native-host"));
                let bin_path = args.get(2).map(Path::new).unwrap_or(&current_exe);
                let manifest = generate_firefox_manifest(bin_path);
                println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
                return;
            }
            "--install-manifests" => {
                let is_system = args.iter().any(|a| a == "--system");
                let current_exe = env::current_exe()
                    .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/gn-shield-native-host"));
                let (chrome_paths, ff_paths) = standard_manifest_paths(is_system);

                let chrome_manifest = generate_chrome_manifest(&current_exe);
                let ff_manifest = generate_firefox_manifest(&current_exe);

                println!("Installing GN-Shield native messaging manifests...");
                for dir in &chrome_paths {
                    match install_manifest_file(dir, &chrome_manifest) {
                        Ok(p) => println!("  Installed Chromium/Chrome manifest: {}", p.display()),
                        Err(e) => {
                            eprintln!("  Warning: could not install to {}: {e}", dir.display())
                        }
                    }
                }
                for dir in &ff_paths {
                    match install_manifest_file(dir, &ff_manifest) {
                        Ok(p) => println!("  Installed Firefox manifest: {}", p.display()),
                        Err(e) => {
                            eprintln!("  Warning: could not install to {}: {e}", dir.display())
                        }
                    }
                }
                println!("Registered Chrome Extension ID: {CHROME_EXTENSION_ID}");
                println!("Registered Firefox Extension ID: {FIREFOX_EXTENSION_ID}");
                println!("Native Host Identifier: {NATIVE_HOST_NAME}");
                return;
            }
            _ => {
                // Unknown CLI argument, log to stderr and proceed to stdio loop or exit
                eprintln!(
                    "Unknown argument '{}', starting in stdio native messaging mode.",
                    args[1]
                );
            }
        }
    }

    let config = load_config();
    let blocked_domains = default_blocked_domains();
    let handler = HostHandler::new(config, blocked_domains);

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    if let Err(e) = handler.run_loop(&mut stdin, &mut stdout) {
        eprintln!("GN-Shield native host error: {e}");
        process::exit(1);
    }
}
