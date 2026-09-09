//! GN-Shield Command Line Interface (CLI).
//!
//! Connects to `gn-shield-core` daemon via Unix Domain Socket IPC (JSON-RPC)
//! to inspect daemon status, review audit logs, modify allowlists/blocklists,
//! manage quarantined files, and perform k-anonymity credential breach checks.

use gn_shield_core::{IpcClient, DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH};
use std::env;
use std::path::{Path, PathBuf};

fn print_usage() {
    println!(
        "GN-Shield Security Daemon CLI v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("Usage:");
    println!("  gn-shield-cli status [--socket <path>]");
    println!(
        "  gn-shield-cli log [--limit <n>] [--decision <allow|block|prompt>] [--socket <path>]"
    );
    println!(
        "  gn-shield-cli allow <hash|path|domain> <value> [--reason <reason>] [--socket <path>]"
    );
    println!("  gn-shield-cli block <hash|path|domain> <value> [--socket <path>]");
    println!("  gn-shield-cli quarantine list [--socket <path>]");
    println!("  gn-shield-cli quarantine restore <id> [--socket <path>]");
    println!("  gn-shield-cli check-breach <credential> [--socket <path>]");
    println!("  gn-shield-cli scan-sensitive <text> [--socket <path>]");
    println!("  gn-shield-cli version");
    println!("  gn-shield-cli help");
}

fn resolve_socket_path(custom: Option<String>) -> PathBuf {
    if let Some(c) = custom {
        return PathBuf::from(c);
    }
    if Path::new(DEFAULT_SOCKET_PATH).exists() {
        PathBuf::from(DEFAULT_SOCKET_PATH)
    } else {
        PathBuf::from(FALLBACK_SOCKET_PATH)
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = args[1].to_lowercase();
    if command == "help" || command == "--help" || command == "-h" {
        print_usage();
        return;
    }

    if command == "version" || command == "--version" || command == "-v" {
        println!("gn-shield-cli v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Extract optional --socket argument
    let mut custom_socket = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--socket" && i + 1 < args.len() {
            custom_socket = Some(args[i + 1].clone());
            break;
        }
        i += 1;
    }

    let socket_path = resolve_socket_path(custom_socket);
    let client = IpcClient::new(&socket_path);

    match command.as_str() {
        "status" => cmd_status(&client).await,
        "log" | "history" => cmd_log(&client, &args[2..]).await,
        "allow" => cmd_allow(&client, &args[2..]).await,
        "block" => cmd_block(&client, &args[2..]).await,
        "quarantine" => cmd_quarantine(&client, &args[2..]).await,
        "check-breach" => cmd_check_breach(&client, &args[2..]).await,
        "scan-sensitive" => cmd_scan_sensitive(&client, &args[2..]).await,
        other => {
            eprintln!("Unknown command: '{other}'");
            print_usage();
            std::process::exit(1);
        }
    }
}

async fn cmd_status(client: &IpcClient) {
    match client.call("status", serde_json::json!({})).await {
        Ok(status) => {
            let pid = status["pid"].as_u64().unwrap_or(0);
            let uptime = status["uptime_seconds"].as_u64().unwrap_or(0);
            let version = status["version"].as_str().unwrap_or("unknown");

            println!("============================================================");
            println!("GN-Shield Daemon v{version}");
            println!("PID: {pid} | Uptime: {uptime}s | Status: RUNNING");
            println!("============================================================");
            println!();

            println!("[Active Protection Modules]");
            let modules = &status["modules"];
            print_mod(
                "Filesystem Sensor (inotify/fanotify)",
                modules["fs_sensor_active"].as_bool().unwrap_or(false),
            );
            print_mod(
                "eBPF Process Sensor",
                modules["ebpf_sensor_active"].as_bool().unwrap_or(false),
            );
            print_mod(
                "DNS Proxy & Domain Filter",
                modules["dns_filter_active"].as_bool().unwrap_or(false),
            );
            print_mod(
                "IP Reputation Filter",
                modules["ip_rep_filter_active"].as_bool().unwrap_or(false),
            );
            print_mod(
                "Browser Companion",
                modules["browser_companion_active"]
                    .as_bool()
                    .unwrap_or(false),
            );
            print_mod(
                "Breach Checker (k-anonymity)",
                modules["breach_checker_active"].as_bool().unwrap_or(false),
            );
            println!();

            println!("[Artifact Freshness & Staleness]");
            let staleness = &status["staleness"];
            print_stale(
                "YARA Signatures",
                staleness["yara_signatures_days"].as_u64().unwrap_or(0),
                staleness["yara_stale_warning"].as_bool().unwrap_or(false),
            );
            print_stale(
                "Hash Reputation Feed",
                staleness["hash_reputation_days"].as_u64().unwrap_or(0),
                staleness["hash_stale_warning"].as_bool().unwrap_or(false),
            );
            print_stale(
                "Default Allowlist",
                staleness["default_allowlist_days"].as_u64().unwrap_or(0),
                false,
            );
            print_stale(
                "Public Suffix List",
                staleness["psl_days"].as_u64().unwrap_or(0),
                staleness["psl_stale_warning"].as_bool().unwrap_or(false),
            );
        }
        Err(e) => {
            eprintln!("Error connecting to GN-Shield daemon: {e}");
            std::process::exit(1);
        }
    }
}

fn print_mod(name: &str, active: bool) {
    if active {
        println!("  • {:<36} \x1b[32mACTIVE\x1b[0m", name);
    } else {
        println!("  • {:<36} \x1b[33mINACTIVE\x1b[0m", name);
    }
}

fn print_stale(name: &str, days: u64, stale_warning: bool) {
    if stale_warning {
        println!(
            "  • {:<24} {days} days old \x1b[31m[STALE WARNING]\x1b[0m",
            name
        );
    } else {
        println!("  • {:<24} {days} days old \x1b[32m(OK)\x1b[0m", name);
    }
}

async fn cmd_log(client: &IpcClient, args: &[String]) {
    let mut limit = 20;
    let mut decision = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" && i + 1 < args.len() {
            limit = args[i + 1].parse().unwrap_or(20);
            i += 1;
        } else if args[i] == "--decision" && i + 1 < args.len() {
            decision = Some(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }

    let mut params = serde_json::json!({ "limit": limit });
    if let Some(d) = decision {
        params["decision"] = serde_json::Value::String(d);
    }

    match client.call("get_audit_log", params).await {
        Ok(res) => {
            let entries = res.as_array().cloned().unwrap_or_default();
            if entries.is_empty() {
                println!("No audit log entries found.");
                return;
            }

            println!(
                "{:<6} {:<20} {:<10} {:<30} {:<30}",
                "ID", "TIMESTAMP", "DECISION", "TARGET", "REASON"
            );
            println!("{}", "-".repeat(100));

            for e in entries {
                let id = e["id"].as_i64().unwrap_or(0);
                let ts = e["timestamp"].as_str().unwrap_or("-");
                let dec = e["decision"].as_str().unwrap_or("-");
                let target = e["target"].as_str().unwrap_or("-");
                let reason = e["reason"].as_str().unwrap_or("-");

                let dec_colored = match dec {
                    "Allow" => format!("\x1b[32m{dec:<10}\x1b[0m"),
                    "Block" => format!("\x1b[31m{dec:<10}\x1b[0m"),
                    "PromptUser" => format!("\x1b[33m{dec:<10}\x1b[0m"),
                    _ => format!("{dec:<10}"),
                };

                let target_short = if target.len() > 28 {
                    &target[..28]
                } else {
                    target
                };
                let reason_short = if reason.len() > 28 {
                    &reason[..28]
                } else {
                    reason
                };

                println!(
                    "{:<6} {:<20} {} {:<30} {:<30}",
                    id, ts, dec_colored, target_short, reason_short
                );
            }
        }
        Err(e) => {
            eprintln!("Error fetching audit log: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_allow(client: &IpcClient, args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: gn-shield-cli allow <hash|path|domain> <value> [--reason <reason>]");
        std::process::exit(1);
    }

    let entry_type = &args[0];
    let value = &args[1];
    let mut reason = "Manual allow override via CLI";

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--reason" && i + 1 < args.len() {
            reason = &args[i + 1];
            break;
        }
        i += 1;
    }

    let params = serde_json::json!({
        "entry_type": entry_type,
        "value": value,
        "reason": reason
    });

    match client.call("allow", params).await {
        Ok(_) => println!("Successfully added '{value}' ({entry_type}) to allowlist."),
        Err(e) => {
            eprintln!("Failed to add allowlist entry: {e}");
            if e.contains("Permission denied") {
                eprintln!("Hint: Modifying security allowlists requires administrator access. Run with 'sudo'.");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_block(client: &IpcClient, args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: gn-shield-cli block <hash|path|domain> <value>");
        std::process::exit(1);
    }

    let entry_type = &args[0];
    let value = &args[1];

    let params = serde_json::json!({
        "entry_type": entry_type,
        "value": value,
    });

    match client.call("block", params).await {
        Ok(_) => println!("Successfully removed/blocked '{value}' ({entry_type})."),
        Err(e) => {
            eprintln!("Failed to block entry: {e}");
            if e.contains("Permission denied") {
                eprintln!("Hint: Modifying security rules requires administrator access. Run with 'sudo'.");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_quarantine(client: &IpcClient, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gn-shield-cli quarantine <list|restore <id>>");
        std::process::exit(1);
    }

    let subcmd = args[0].to_lowercase();
    match subcmd.as_str() {
        "list" => match client.call("list_quarantine", serde_json::json!({})).await {
            Ok(res) => {
                let files = res.as_array().cloned().unwrap_or_default();
                if files.is_empty() {
                    println!("No quarantined files currently held.");
                    return;
                }
                println!(
                    "{:<6} {:<30} {:<30} {:<24}",
                    "ID", "ORIGINAL PATH", "REASON", "QUARANTINED AT"
                );
                println!("{}", "-".repeat(95));
                for f in files {
                    let id = f["id"].as_i64().unwrap_or(0);
                    let orig = f["original_path"].as_str().unwrap_or("-");
                    let reason = f["reason"].as_str().unwrap_or("-");
                    let at = f["quarantined_at"].as_str().unwrap_or("-");
                    println!("{:<6} {:<30} {:<30} {:<24}", id, orig, reason, at);
                }
            }
            Err(e) => {
                eprintln!("Error fetching quarantine list: {e}");
                std::process::exit(1);
            }
        },
        "restore" => {
            if args.len() < 2 {
                eprintln!("Usage: gn-shield-cli quarantine restore <id>");
                std::process::exit(1);
            }
            let id: i64 = args[1].parse().unwrap_or(0);
            match client
                .call("restore_quarantine", serde_json::json!({ "id": id }))
                .await
            {
                Ok(res) => {
                    if res.is_null() {
                        eprintln!("Quarantine record ID {id} not found.");
                    } else {
                        println!(
                            "Successfully restored quarantined file ID {id}. Original path: {}",
                            res["original_path"].as_str().unwrap_or("")
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error restoring quarantine file: {e}");
                    if e.contains("Permission denied") {
                        eprintln!(
                            "Hint: Restoring files requires administrator access. Run with 'sudo'."
                        );
                    }
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown quarantine command '{other}'. Usage: gn-shield-cli quarantine <list|restore <id>>");
            std::process::exit(1);
        }
    }
}

async fn cmd_check_breach(client: &IpcClient, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gn-shield-cli check-breach <credential>");
        std::process::exit(1);
    }

    let credential = &args[0];
    let params = serde_json::json!({ "credential": credential });

    match client.call("check_breach", params).await {
        Ok(res) => {
            let is_breached = res["is_breached"].as_bool().unwrap_or(false);
            let count = res["count"].as_u64().unwrap_or(0);
            let prefix = res["prefix"].as_str().unwrap_or("");

            println!("K-Anonymity Credential Check Result:");
            println!(
                "  • Hash Prefix Queried: {prefix} (only 5 chars sent, raw secret never exposed)"
            );
            if is_breached {
                println!("  • \x1b[31mBREACH DETECTED\x1b[0m: This password appeared {count} times in known data breaches!");
                println!("    Recommendation: Change this password immediately on all accounts.");
            } else {
                println!("  • \x1b[32mCLEAN\x1b[0m: No known breach occurrences found for this credential.");
            }
        }
        Err(e) => {
            eprintln!("Breach check error: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_scan_sensitive(client: &IpcClient, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gn-shield-cli scan-sensitive <text>");
        std::process::exit(1);
    }

    let text = args.join(" ");
    let params = serde_json::json!({ "text": text });

    match client.call("scan_sensitive", params).await {
        Ok(res) => {
            let findings = res["findings"].as_array().cloned().unwrap_or_default();
            if findings.is_empty() {
                println!("No sensitive keys or secrets detected.");
            } else {
                println!("\x1b[33mSensitive Patterns Detected (Masked Previews):\x1b[0m");
                for f in findings {
                    println!("  • {}", f.as_str().unwrap_or(""));
                }
            }
        }
        Err(e) => {
            eprintln!("Scan error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_socket_path() {
        let custom = resolve_socket_path(Some("/tmp/custom.sock".to_string()));
        assert_eq!(custom, PathBuf::from("/tmp/custom.sock"));

        let default = resolve_socket_path(None);
        assert!(default.to_string_lossy().contains(".sock"));
    }
}
