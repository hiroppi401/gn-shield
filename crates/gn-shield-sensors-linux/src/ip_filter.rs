//! Linux IP Reputation Filter with eBPF (aya) integration, dual-stack AF_INET / AF_INET6,
//! TTL auto-expiration, and CIDR allowlist overrides.

use aya::Ebpf;
use gn_shield_config::{IpAllowlistEntry, IpReputationConfig};
use gn_shield_sensors_common::{NetworkEvent, NetworkSensor, SensorError};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVerdict {
    Allow { reason: String },
    Block { reason: String, feed_source: String },
}

#[derive(Debug, Clone)]
pub struct IpReputationEntry {
    pub ip: IpAddr,
    pub feed_source: String,
    pub reason: String,
    pub added_at: SystemTime,
    pub ttl_seconds: u64,
}

impl IpReputationEntry {
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.added_at) {
            Ok(age) => age > Duration::from_secs(self.ttl_seconds),
            Err(_) => false,
        }
    }
}

pub struct EbpfIpReputationFilter {
    bpf: Option<Ebpf>,
    entries: HashMap<IpAddr, IpReputationEntry>,
    allowlist_cidrs: Vec<(IpNet, String)>,
    default_ttl_seconds: u64,
    tx: Sender<NetworkEvent>,
    rx: Receiver<NetworkEvent>,
    subscribed: bool,
}

impl Default for EbpfIpReputationFilter {
    fn default() -> Self {
        Self::new(&IpReputationConfig::default(), &[])
    }
}

impl EbpfIpReputationFilter {
    #[must_use]
    pub fn new(config: &IpReputationConfig, ip_allowlist: &[IpAllowlistEntry]) -> Self {
        let (tx, rx) = channel();
        let default_ttl_seconds = u64::from(config.ttl_days) * 86400;

        let allowlist_cidrs = ip_allowlist
            .iter()
            .filter_map(|entry| {
                IpNet::from_str(&entry.cidr)
                    .ok()
                    .map(|net| (net, entry.reason.clone()))
            })
            .collect();

        Self {
            bpf: None,
            entries: HashMap::new(),
            allowlist_cidrs,
            default_ttl_seconds,
            tx,
            rx,
            subscribed: false,
        }
    }

    /// Loads eBPF bytecode for egress network hook using aya loader.
    pub fn with_bpf_bytecode(
        config: &IpReputationConfig,
        ip_allowlist: &[IpAllowlistEntry],
        bytecode: &[u8],
    ) -> Result<Self, SensorError> {
        let bpf = Ebpf::load(bytecode).map_err(|e| SensorError::InitError(e.to_string()))?;
        let mut filter = Self::new(config, ip_allowlist);
        filter.bpf = Some(bpf);
        Ok(filter)
    }

    #[must_use]
    pub fn has_bpf_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Adds an IP to reputation feed with specific TTL.
    pub fn add_ip_entry(
        &mut self,
        ip: IpAddr,
        feed_source: &str,
        reason: &str,
        ttl_seconds: Option<u64>,
    ) {
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);
        self.entries.insert(
            ip,
            IpReputationEntry {
                ip,
                feed_source: feed_source.to_string(),
                reason: reason.to_string(),
                added_at: SystemTime::now(),
                ttl_seconds: ttl,
            },
        );
    }

    /// Adds an IP entry with a specific added_at time (useful for simulating expired entries).
    pub fn add_ip_entry_with_time(
        &mut self,
        ip: IpAddr,
        feed_source: &str,
        reason: &str,
        added_at: SystemTime,
        ttl_seconds: u64,
    ) {
        self.entries.insert(
            ip,
            IpReputationEntry {
                ip,
                feed_source: feed_source.to_string(),
                reason: reason.to_string(),
                added_at,
                ttl_seconds,
            },
        );
    }

    /// Adds an allowed CIDR subnet (IPv4 or IPv6).
    pub fn add_allowlist_cidr(&mut self, cidr: &str, reason: &str) -> Result<(), String> {
        let net =
            IpNet::from_str(cidr).map_err(|e| format!("Invalid CIDR format '{cidr}': {e}"))?;
        self.allowlist_cidrs.push((net, reason.to_string()));
        Ok(())
    }

    /// Evaluates an outbound connection attempt.
    /// 1. CIDR Allowlist override (IPv4/IPv6): Always Allow.
    /// 2. If IP in feed and NOT expired: Block.
    /// 3. If IP in feed but expired (e.g. former CDN/cloud edge IP): Allow.
    /// 4. Otherwise: Allow.
    #[must_use]
    pub fn evaluate_connection(&self, destination_ip: IpAddr, now: SystemTime) -> IpVerdict {
        // 1. Check Allowlist CIDR overrides
        for (net, reason) in &self.allowlist_cidrs {
            if net.contains(&destination_ip) {
                return IpVerdict::Allow {
                    reason: format!("allowlist_cidr_override: {reason} ({net})"),
                };
            }
        }

        // 2. Check IP reputation feed
        if let Some(entry) = self.entries.get(&destination_ip) {
            if entry.is_expired(now) {
                // TTL expired: IP was recycled or clean again (e.g. Cloudflare / AWS edge IP)
                return IpVerdict::Allow {
                    reason: format!(
                        "reputation_entry_expired (feed: {}, ttl: {}s)",
                        entry.feed_source, entry.ttl_seconds
                    ),
                };
            }

            return IpVerdict::Block {
                reason: entry.reason.clone(),
                feed_source: entry.feed_source.clone(),
            };
        }

        IpVerdict::Allow {
            reason: "clean_ip".to_string(),
        }
    }

    pub fn emit_connection_attempt(
        &self,
        pid: u32,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Result<(), SensorError> {
        self.tx
            .send(NetworkEvent::ConnectionAttempt {
                pid,
                destination_ip,
                destination_port,
            })
            .map_err(|e| SensorError::InitError(e.to_string()))
    }

    /// Returns a clone of the network event sender.
    #[must_use]
    pub fn event_sender(&self) -> Sender<NetworkEvent> {
        self.tx.clone()
    }
}

impl NetworkSensor for EbpfIpReputationFilter {
    fn subscribe(&mut self) -> Result<(), SensorError> {
        self.subscribed = true;
        Ok(())
    }

    fn next_event(&mut self) -> Result<NetworkEvent, SensorError> {
        if !self.subscribed {
            return Err(SensorError::InitError(
                "Network sensor not subscribed".to_string(),
            ));
        }
        self.rx
            .recv()
            .map_err(|_| SensorError::InitError("Network event channel closed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gn_shield_config::IpAllowlistEntry;

    #[test]
    fn test_active_malware_c2_ip_blocked_v4_and_v6() {
        let config = IpReputationConfig::default();
        let mut filter = EbpfIpReputationFilter::new(&config, &[]);

        let now = SystemTime::now();
        let bad_c2_v4: IpAddr = "198.51.100.55".parse().unwrap();
        let bad_c2_v6: IpAddr = "2001:db8:ffff::1".parse().unwrap();

        filter.add_ip_entry(bad_c2_v4, "feodotracker", "dridex_c2", Some(86400));
        filter.add_ip_entry(bad_c2_v6, "spamhaus_drop", "botnet_c2", Some(86400));

        let v4_verdict = filter.evaluate_connection(bad_c2_v4, now);
        assert!(matches!(v4_verdict, IpVerdict::Block { .. }));

        let v6_verdict = filter.evaluate_connection(bad_c2_v6, now);
        assert!(matches!(v6_verdict, IpVerdict::Block { .. }));
    }

    #[test]
    fn test_expired_cdn_edge_ip_is_allowed() {
        let config = IpReputationConfig::default();
        let mut filter = EbpfIpReputationFilter::new(&config, &[]);

        let now = SystemTime::now();
        let cdn_edge_ip: IpAddr = "104.16.123.99".parse().unwrap(); // Cloudflare edge IP

        // Added 15 days ago with 10 days TTL -> expired
        let added_at = now - Duration::from_secs(15 * 86400);
        let ttl_seconds = 10 * 86400;

        filter.add_ip_entry_with_time(
            cdn_edge_ip,
            "feodotracker",
            "stale_shared_host",
            added_at,
            ttl_seconds,
        );

        let verdict = filter.evaluate_connection(cdn_edge_ip, now);
        assert!(
            matches!(verdict, IpVerdict::Allow { .. }),
            "Expired CDN edge IP must be allowed, got: {verdict:?}"
        );
    }

    #[test]
    fn test_ip_allowlist_cidr_override() {
        let allowlist = vec![
            IpAllowlistEntry {
                cidr: "100.64.0.0/10".to_string(),
                reason: "tailscale_cgnat".to_string(),
            },
            IpAllowlistEntry {
                cidr: "2001:db8:cafe::/48".to_string(),
                reason: "internal_ipv6_vpn".to_string(),
            },
        ];

        let config = IpReputationConfig::default();
        let mut filter = EbpfIpReputationFilter::new(&config, &allowlist);

        let tailscale_ip: IpAddr = "100.64.1.2".parse().unwrap();
        let vpn_ipv6: IpAddr = "2001:db8:cafe:1::5".parse().unwrap();

        // Add both to malicious feed
        let now = SystemTime::now();
        filter.add_ip_entry(
            tailscale_ip,
            "spamhaus_drop",
            "false_positive_feed",
            Some(86400),
        );
        filter.add_ip_entry(
            vpn_ipv6,
            "spamhaus_drop",
            "false_positive_feed",
            Some(86400),
        );

        // CIDR override must win!
        let v1 = filter.evaluate_connection(tailscale_ip, now);
        assert!(matches!(v1, IpVerdict::Allow { .. }));

        let v2 = filter.evaluate_connection(vpn_ipv6, now);
        assert!(matches!(v2, IpVerdict::Allow { .. }));
    }
}
