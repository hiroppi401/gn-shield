//! DNS Proxy and filtering module for GN-Shield.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFilterVerdict {
    Allow,
    Block,
}

#[derive(Debug, Default)]
pub struct DnsFilterService {
    pub is_running: bool,
}

impl DnsFilterService {
    #[must_use]
    pub fn new() -> Self {
        Self { is_running: false }
    }
}
