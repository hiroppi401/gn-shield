//! GN-Shield Core Daemon and Decision Engine.

pub mod decision;
pub mod scanner;

pub use decision::{decide, Action, TrustLevel, Verdict};
pub use scanner::{FileScanner, ScanEvaluation};
