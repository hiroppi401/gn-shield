//! Active DNS resolver and proxy detector for Linux installation.
//!
//! Detects active resolvers (`systemd-resolved`, `dnsmasq`, `pihole`, `dnscrypt-proxy`)
//! and determines the appropriate integration mode (`takeover`, `chain_upstream`, `disabled`).

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverKind {
    None,
    SystemdResolved,
    Dnsmasq,
    PiHole,
    DnscryptProxy,
    Other(SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationMode {
    Takeover,
    ChainUpstream,
    Disabled,
}

impl IntegrationMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Takeover => "takeover",
            Self::ChainUpstream => "chain_upstream",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverDetectionResult {
    pub kind: ResolverKind,
    pub active: bool,
    pub recommended_mode: IntegrationMode,
    pub alternative_port: u16,
    pub details: String,
    pub remediation_instruction: String,
}

pub struct ResolverDetector;

impl ResolverDetector {
    /// Detects active resolvers starting from given root (for testing, pass custom root).
    #[must_use]
    pub fn detect_with_root(root: &Path) -> ResolverDetectionResult {
        let resolv_conf_path = root.join("etc/resolv.conf");
        let systemd_stub_path = root.join("run/systemd/resolve/stub-resolv.conf");
        let systemd_resolv_path = root.join("run/systemd/resolve/resolv.conf");
        let dnsmasq_conf_path = root.join("etc/dnsmasq.conf");
        let pihole_dir = root.join("etc/pihole");
        let dnscrypt_dir = root.join("etc/dnscrypt-proxy");

        // 1. Check systemd-resolved
        let is_systemd_stub = systemd_stub_path.exists() || systemd_resolv_path.exists();
        let mut has_127_0_0_53 = false;

        if let Ok(content) = fs::read_to_string(&resolv_conf_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") && trimmed.contains("127.0.0.53") {
                    has_127_0_0_53 = true;
                    break;
                }
            }
        }

        if is_systemd_stub || has_127_0_0_53 {
            return ResolverDetectionResult {
                kind: ResolverKind::SystemdResolved,
                active: true,
                recommended_mode: IntegrationMode::ChainUpstream,
                alternative_port: 5353,
                details: "Detected active systemd-resolved (listening on 127.0.0.53:53)."
                    .to_string(),
                remediation_instruction:
                    "GN-Shield will listen on 127.0.0.1:5353. Configure upstream via: \
                     `resolvectl dns <interface> 127.0.0.1:5353` to preserve mDNS/LLMNR."
                        .to_string(),
            };
        }

        // 2. Check Pi-hole
        if pihole_dir.exists() {
            return ResolverDetectionResult {
                kind: ResolverKind::PiHole,
                active: true,
                recommended_mode: IntegrationMode::ChainUpstream,
                alternative_port: 5353,
                details: "Detected Pi-hole installation in /etc/pihole.".to_string(),
                remediation_instruction:
                    "Configure Pi-hole custom upstream DNS server to point to 127.0.0.1:5353."
                        .to_string(),
            };
        }

        // 3. Check dnsmasq
        if dnsmasq_conf_path.exists() {
            return ResolverDetectionResult {
                kind: ResolverKind::Dnsmasq,
                active: true,
                recommended_mode: IntegrationMode::ChainUpstream,
                alternative_port: 5353,
                details: "Detected dnsmasq configuration in /etc/dnsmasq.conf.".to_string(),
                remediation_instruction:
                    "Set `server=127.0.0.1#5353` in dnsmasq.conf to chain GN-Shield upstream."
                        .to_string(),
            };
        }

        // 4. Check dnscrypt-proxy
        if dnscrypt_dir.exists() {
            return ResolverDetectionResult {
                kind: ResolverKind::DnscryptProxy,
                active: true,
                recommended_mode: IntegrationMode::ChainUpstream,
                alternative_port: 5353,
                details: "Detected dnscrypt-proxy in /etc/dnscrypt-proxy.".to_string(),
                remediation_instruction:
                    "Chain dnscrypt-proxy or configure GN-Shield on alternative port 5353."
                        .to_string(),
            };
        }

        // 5. Default: No conflict detected, recommend Takeover
        ResolverDetectionResult {
            kind: ResolverKind::None,
            active: false,
            recommended_mode: IntegrationMode::Takeover,
            alternative_port: 5353,
            details: "No active competing DNS resolver or proxy detected.".to_string(),
            remediation_instruction:
                "GN-Shield will bind to 127.0.0.1:53 and [::1]:53 and manage /etc/resolv.conf."
                    .to_string(),
        }
    }

    /// Detects using the host system's root ("/").
    #[must_use]
    pub fn detect() -> ResolverDetectionResult {
        Self::detect_with_root(Path::new("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_detect_systemd_resolved() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let root = temp_dir.path();

        let run_systemd = root.join("run/systemd/resolve");
        fs::create_dir_all(&run_systemd).expect("dir failed");
        File::create(run_systemd.join("stub-resolv.conf")).expect("file failed");

        let etc = root.join("etc");
        fs::create_dir_all(&etc).expect("dir failed");
        let mut f = File::create(etc.join("resolv.conf")).expect("file failed");
        writeln!(f, "nameserver 127.0.0.53").expect("write failed");

        let result = ResolverDetector::detect_with_root(root);
        assert_eq!(result.kind, ResolverKind::SystemdResolved);
        assert!(result.active);
        assert_eq!(result.recommended_mode, IntegrationMode::ChainUpstream);
        assert_eq!(result.alternative_port, 5353);
        assert!(result.details.contains("systemd-resolved"));
    }

    #[test]
    fn test_detect_no_resolver_recommends_takeover() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let root = temp_dir.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).expect("dir failed");
        let mut f = File::create(etc.join("resolv.conf")).expect("file failed");
        writeln!(f, "nameserver 1.1.1.1").expect("write failed");

        let result = ResolverDetector::detect_with_root(root);
        assert_eq!(result.kind, ResolverKind::None);
        assert!(!result.active);
        assert_eq!(result.recommended_mode, IntegrationMode::Takeover);
    }

    #[test]
    fn test_detect_pihole() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let root = temp_dir.path();

        let pihole_dir = root.join("etc/pihole");
        fs::create_dir_all(&pihole_dir).expect("dir failed");

        let result = ResolverDetector::detect_with_root(root);
        assert_eq!(result.kind, ResolverKind::PiHole);
        assert!(result.active);
        assert_eq!(result.recommended_mode, IntegrationMode::ChainUpstream);
    }
}
