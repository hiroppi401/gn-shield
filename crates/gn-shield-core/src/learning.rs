//! Learning mode for GN-Shield first-time setup and installation.
//! Scans installed packages via the system package manager (e.g. pacman on Arch/CachyOS, dpkg on Debian/Ubuntu),
//! matches against known developer tools, and produces a batch approval recommendation for Tier 2 Publisher Trust.

use gn_shield_config::{GnShieldConfig, PublisherAllowlistEntry};
use std::collections::HashSet;
use std::path::Path;

/// Information on a package installed on the host system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub publisher_manager: String, // e.g. "pacman", "dpkg"
}

/// Known developer and system tools definition.
#[derive(Debug, Clone)]
pub struct KnownToolSpec {
    pub package_pattern: &'static str,
    pub name: &'static str,
    pub high_fanout_expected: bool,
}

pub const KNOWN_DEVELOPER_TOOLS: &[KnownToolSpec] = &[
    KnownToolSpec {
        package_pattern: "cloudflared",
        name: "Cloudflare Tunnel Client",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "ngrok",
        name: "ngrok Secure Introspectable Tunnel",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "tailscale",
        name: "Tailscale Mesh VPN",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "docker",
        name: "Docker Container Engine",
        high_fanout_expected: true,
    },
    KnownToolSpec {
        package_pattern: "podman",
        name: "Podman Container Tool",
        high_fanout_expected: true,
    },
    KnownToolSpec {
        package_pattern: "git",
        name: "Git Version Control",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "nodejs",
        name: "Node.js JavaScript Runtime",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "npm",
        name: "Node Package Manager",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "rust",
        name: "Rust Toolchain",
        high_fanout_expected: true,
    },
    KnownToolSpec {
        package_pattern: "cargo",
        name: "Cargo Package Manager",
        high_fanout_expected: true,
    },
    KnownToolSpec {
        package_pattern: "python",
        name: "Python Interpreter",
        high_fanout_expected: false,
    },
    KnownToolSpec {
        package_pattern: "firefox",
        name: "Mozilla Firefox Web Browser",
        high_fanout_expected: true,
    },
    KnownToolSpec {
        package_pattern: "chromium",
        name: "Chromium Web Browser",
        high_fanout_expected: true,
    },
];

pub struct LearningModeScanner;

impl LearningModeScanner {
    /// Scans installed packages from local system package manager databases.
    /// Prefers inspecting `/var/lib/pacman/local` on Arch/CachyOS systems.
    pub fn scan_system_packages() -> Vec<InstalledPackage> {
        let mut packages = Vec::new();

        // 1. Check pacman local DB
        let pacman_dir = Path::new("/var/lib/pacman/local");
        if pacman_dir.exists() && pacman_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(pacman_dir) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_dir() {
                            let dir_name = entry.file_name().to_string_lossy().to_string();
                            if let Some((pkg_name, pkg_ver)) = split_pacman_pkg_dir(&dir_name) {
                                packages.push(InstalledPackage {
                                    name: pkg_name.to_string(),
                                    version: pkg_ver.to_string(),
                                    publisher_manager: "pacman".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        packages
    }

    /// Evaluates discovered installed packages against known developer tools and
    /// generates batch approval recommendations for Tier 2 Publisher Trust.
    #[must_use]
    pub fn generate_batch_recommendations(
        packages: &[InstalledPackage],
    ) -> Vec<PublisherAllowlistEntry> {
        let mut recommendations = Vec::new();
        let mut matched_tools = HashSet::new();

        for pkg in packages {
            for spec in KNOWN_DEVELOPER_TOOLS {
                if pkg.name.contains(spec.package_pattern)
                    && !matched_tools.contains(spec.package_pattern)
                {
                    matched_tools.insert(spec.package_pattern);
                    recommendations.push(PublisherAllowlistEntry {
                        platform: "linux".to_string(),
                        verified_by: pkg.publisher_manager.clone(),
                        package_name: pkg.name.clone(),
                        auto_trust: true,
                        high_fanout_expected: spec.high_fanout_expected,
                    });
                }
            }
        }

        recommendations
    }

    /// Batch approves recommendations and applies them directly into configuration.
    pub fn apply_batch_approval(
        config: &mut GnShieldConfig,
        approved_entries: Vec<PublisherAllowlistEntry>,
    ) {
        for entry in approved_entries {
            if !config
                .allowlist
                .publisher
                .iter()
                .any(|p| p.package_name == entry.package_name && p.platform == entry.platform)
            {
                config.allowlist.publisher.push(entry);
            }
        }
    }
}

fn split_pacman_pkg_dir(dir_name: &str) -> Option<(&str, &str)> {
    // Format: name-version-pkgrel (e.g. "firefox-130.0-1")
    let mut parts: Vec<&str> = dir_name.split('-').collect();
    if parts.len() < 3 {
        return None;
    }
    let pkgrel = parts.pop()?;
    let version = parts.pop()?;
    let name = parts.join("-");
    if name.is_empty() || version.is_empty() || pkgrel.is_empty() {
        None
    } else {
        // Return reconstructed references
        let prefix_len = name.len();
        let ver_start = prefix_len + 1;
        let ver_end = ver_start + version.len();
        Some((&dir_name[..prefix_len], &dir_name[ver_start..ver_end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_pacman_pkg_dir() {
        assert_eq!(
            split_pacman_pkg_dir("firefox-130.0-1"),
            Some(("firefox", "130.0"))
        );
        assert_eq!(
            split_pacman_pkg_dir("cloudflared-2024.8.3-1"),
            Some(("cloudflared", "2024.8.3"))
        );
        assert_eq!(
            split_pacman_pkg_dir("docker-1:27.1.1-1"),
            Some(("docker", "1:27.1.1"))
        );
    }

    #[test]
    fn test_generate_and_apply_batch_recommendations() {
        let sample_packages = vec![
            InstalledPackage {
                name: "firefox".to_string(),
                version: "130.0".to_string(),
                publisher_manager: "pacman".to_string(),
            },
            InstalledPackage {
                name: "docker".to_string(),
                version: "27.1.1".to_string(),
                publisher_manager: "pacman".to_string(),
            },
            InstalledPackage {
                name: "cloudflared".to_string(),
                version: "2024.8.3".to_string(),
                publisher_manager: "pacman".to_string(),
            },
            InstalledPackage {
                name: "unrelated-app".to_string(),
                version: "1.0.0".to_string(),
                publisher_manager: "pacman".to_string(),
            },
        ];

        let recommendations = LearningModeScanner::generate_batch_recommendations(&sample_packages);

        assert_eq!(recommendations.len(), 3);

        let firefox_entry = recommendations
            .iter()
            .find(|e| e.package_name == "firefox")
            .expect("firefox not found");
        assert!(firefox_entry.high_fanout_expected);
        assert!(firefox_entry.auto_trust);

        let cf_entry = recommendations
            .iter()
            .find(|e| e.package_name == "cloudflared")
            .expect("cloudflared not found");
        assert!(!cf_entry.high_fanout_expected);
        assert!(cf_entry.auto_trust);

        let mut config = GnShieldConfig::default();
        LearningModeScanner::apply_batch_approval(&mut config, recommendations);

        assert_eq!(config.allowlist.publisher.len(), 3);
    }
}
