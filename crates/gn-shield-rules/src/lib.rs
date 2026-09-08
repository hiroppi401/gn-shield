//! Rule and signature matching engine for GN-Shield.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Default)]
pub struct RuleStore {
    pub ruleset_version: u64,
}

impl RuleStore {
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self {
            ruleset_version: version,
        }
    }
}
