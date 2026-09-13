//! GN-Shield Core Daemon, Decision Engine, Behavior Tracking, and Ransomware Protection.

pub mod behavior;
pub mod breach_service;
pub mod decision;
pub mod exec_deny;
pub mod executor;
pub mod ipc;
pub mod learning;
pub mod notification;
pub mod ransomware;
pub mod scanner;

pub use behavior::ProcessBehaviorTracker;
pub use breach_service::{BreachService, MockRangeProvider, RangeProvider};
pub use decision::{decide, Action, TrustLevel, Verdict};
pub use exec_deny::ExecDenyTracker;
pub use executor::{
    ActionExecutor, ExecutionReport, ProcessContainmentReport, QuarantineRecord, QuarantineStatus,
};
pub use ipc::{
    ArtifactStalenessStatus, DaemonStatus, IpcClient, IpcRequest, IpcResponse, IpcServer,
    ModuleHealth, ModuleStatus, DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH,
};
pub use learning::{InstalledPackage, LearningModeScanner};
pub use notification::{
    BatchedNotification, InMemoryNotificationSink, NotificationBatcher, NotificationSink,
    PromptAction, PromptEvent,
};
pub use ransomware::{
    IncidentAction, RansomwareDetector, DOMINANT_PID_MIN_COUNT, DOMINANT_PID_MIN_RATIO,
};
pub use scanner::{FileScanner, ScanEvaluation};
