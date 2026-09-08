//! GN-Shield Core Daemon and Decision Engine.

pub mod decision;

pub use decision::{decide, Action, TrustLevel, Verdict};
