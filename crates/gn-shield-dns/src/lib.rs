//! DNS Proxy and filtering module for GN-Shield.
//!
//! Provides:
//! - Dual-stack DNS proxy server (IPv4 & IPv6).
//! - Tier 4 domain allowlist matcher for developer tools and tunnels.
//! - Anti-phishing and cryptomining pool domain blocklists.
//! - Two-layer PSL (Public Suffix List) support with staleness tracking.
//! - Resolver and proxy detector for Linux installation.

pub mod detector;
pub mod filter;
pub mod psl_engine;
pub mod server;

pub use detector::{IntegrationMode, ResolverDetectionResult, ResolverDetector, ResolverKind};
pub use filter::{DnsFilterEngine, DnsFilterVerdict, DomainAllowlistRule};
pub use psl_engine::PslEngine;
pub use server::{DnsProxyMetrics, DnsProxyServer};

use gn_shield_config::DnsFilterConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct DnsFilterService {
    pub is_running: bool,
    pub server: Option<Arc<DnsProxyServer>>,
    pub engine: Arc<RwLock<DnsFilterEngine>>,
}

impl DnsFilterService {
    #[must_use]
    pub fn new(
        config: &DnsFilterConfig,
        domain_allowlist: &[gn_shield_config::DomainAllowlistEntry],
    ) -> Self {
        let engine = Arc::new(RwLock::new(DnsFilterEngine::new(
            domain_allowlist,
            config.psl_stale_warning_days,
        )));

        Self {
            is_running: false,
            server: None,
            engine,
        }
    }

    /// Starts the DNS proxy service if enabled in config.
    pub async fn start(&mut self, config: &DnsFilterConfig) -> Result<(), String> {
        if !config.enabled || config.integration_mode == "disabled" {
            self.is_running = false;
            return Ok(());
        }

        let listen_port = if config.integration_mode == "chain_upstream" {
            config.chain_upstream_listen_port
        } else {
            config
                .listen_address
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(53)
        };

        let ipv4: SocketAddr = format!("127.0.0.1:{listen_port}")
            .parse()
            .map_err(|e| format!("Invalid IPv4 listen address: {e}"))?;
        let ipv6: SocketAddr = format!("[::1]:{listen_port}")
            .parse()
            .map_err(|e| format!("Invalid IPv6 listen address: {e}"))?;
        let upstream_addr: SocketAddr = config
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

        let server = Arc::new(DnsProxyServer::new(
            self.engine.clone(),
            ipv4,
            ipv6,
            upstream_addr,
        ));

        self.server = Some(server);
        self.is_running = true;
        Ok(())
    }
}
