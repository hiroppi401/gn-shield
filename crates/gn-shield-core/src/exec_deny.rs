//! Tracker for repeated execution denial events (repeat offender gate).
//!
//! Enforces that calling processes triggering kernel-level execution denials (FAN_DENY)
//! are not immediately subjected to process containment on their first attempt.
//! Escalates to process containment only when the same caller PID repeatedly
//! triggers exec-deny verdicts within a sliding time window (repeat offender).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Sliding-window tracker for repeated execution denial events.
#[derive(Debug, Clone)]
pub struct ExecDenyTracker {
    window: Duration,
    threshold: usize,
    history: VecDeque<(u32, Instant)>,
    counts: BTreeMap<u32, usize>,
}

impl Default for ExecDenyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecDenyTracker {
    /// Baseline sliding window: 60 seconds.
    pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
    /// Baseline threshold: 3 execution denials within window.
    pub const DEFAULT_THRESHOLD: usize = 3;

    /// Creates a new `ExecDenyTracker` with default parameters (60s window, threshold 3).
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(Self::DEFAULT_WINDOW, Self::DEFAULT_THRESHOLD)
    }

    /// Creates a new `ExecDenyTracker` with custom window duration and threshold.
    #[must_use]
    pub fn with_params(window: Duration, threshold: usize) -> Self {
        Self {
            window,
            threshold,
            history: VecDeque::new(),
            counts: BTreeMap::new(),
        }
    }

    /// Prunes events outside the active sliding window.
    pub fn prune(&mut self, now: Instant) {
        while let Some(&(pid, timestamp)) = self.history.front() {
            if now.saturating_duration_since(timestamp) > self.window {
                self.history.pop_front();
                if let Some(entry) = self.counts.get_mut(&pid) {
                    *entry = entry.saturating_sub(1);
                    if *entry == 0 {
                        self.counts.remove(&pid);
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Records an execution denial for a caller PID at a specific timestamp.
    ///
    /// Returns `true` if this PID has reached or exceeded the repeat offender threshold (>= 3)
    /// within the sliding window, indicating that process containment should be escalated.
    pub fn record_deny_at(&mut self, pid: u32, now: Instant) -> bool {
        self.prune(now);
        self.history.push_back((pid, now));
        let count = self.counts.entry(pid).or_insert(0);
        *count += 1;
        *count >= self.threshold
    }

    /// Records an execution denial for a caller PID at current time (`Instant::now()`).
    ///
    /// Returns `true` if this PID has reached or exceeded the repeat offender threshold.
    pub fn record_deny(&mut self, pid: u32) -> bool {
        self.record_deny_at(pid, Instant::now())
    }

    /// Returns the current count of exec-deny events for `pid` within the active window at `now`.
    pub fn count_for_pid_at(&mut self, pid: u32, now: Instant) -> usize {
        self.prune(now);
        self.counts.get(&pid).copied().unwrap_or(0)
    }

    /// Returns the current count of exec-deny events for `pid` at current time.
    pub fn count_for_pid(&mut self, pid: u32) -> usize {
        self.count_for_pid_at(pid, Instant::now())
    }

    /// Returns configured observation window duration.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Returns configured repeat offender threshold count.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_deny_first_and_second_do_not_escalate() {
        let mut tracker = ExecDenyTracker::new();
        let pid = 12345;
        let t0 = Instant::now();

        // 1st attempt: count = 1, should return false (no containment)
        assert!(
            !tracker.record_deny_at(pid, t0),
            "1st attempt must not escalate to containment"
        );
        assert_eq!(tracker.count_for_pid_at(pid, t0), 1);

        // 2nd attempt: count = 2, should return false (no containment)
        let t1 = t0 + Duration::from_secs(10);
        assert!(
            !tracker.record_deny_at(pid, t1),
            "2nd attempt must not escalate to containment"
        );
        assert_eq!(tracker.count_for_pid_at(pid, t1), 2);
    }

    #[test]
    fn test_exec_deny_third_attempt_escalates_to_containment() {
        let mut tracker = ExecDenyTracker::new();
        let pid = 12345;
        let t0 = Instant::now();

        assert!(!tracker.record_deny_at(pid, t0));
        assert!(!tracker.record_deny_at(pid, t0 + Duration::from_secs(5)));

        // 3rd attempt within 60s window: count = 3, must return true (escalate to containment)
        let t2 = t0 + Duration::from_secs(15);
        assert!(
            tracker.record_deny_at(pid, t2),
            "3rd attempt within window must escalate to containment"
        );
        assert_eq!(tracker.count_for_pid_at(pid, t2), 3);
    }

    #[test]
    fn test_exec_deny_different_pids_do_not_trigger_containment() {
        let mut tracker = ExecDenyTracker::new();
        let t0 = Instant::now();

        // 3 exec-denies but each from a distinct PID
        assert!(!tracker.record_deny_at(101, t0));
        assert!(!tracker.record_deny_at(102, t0 + Duration::from_secs(1)));
        assert!(!tracker.record_deny_at(103, t0 + Duration::from_secs(2)));

        assert_eq!(
            tracker.count_for_pid_at(101, t0 + Duration::from_secs(2)),
            1
        );
        assert_eq!(
            tracker.count_for_pid_at(102, t0 + Duration::from_secs(2)),
            1
        );
        assert_eq!(
            tracker.count_for_pid_at(103, t0 + Duration::from_secs(2)),
            1
        );
    }

    #[test]
    fn test_exec_deny_window_expiration_resets_counter() {
        let mut tracker = ExecDenyTracker::new();
        let pid = 5555;
        let t0 = Instant::now();

        // 1st attempt at t0
        assert!(!tracker.record_deny_at(pid, t0));
        // 2nd attempt at t0 + 10s
        assert!(!tracker.record_deny_at(pid, t0 + Duration::from_secs(10)));
        assert_eq!(
            tracker.count_for_pid_at(pid, t0 + Duration::from_secs(10)),
            2
        );

        // 3rd attempt occurs at t0 + 75s (more than 60s after t0 and t0+10s)
        let t_expired = t0 + Duration::from_secs(75);
        // Previous attempts have expired from the 60s window! Count resets to 1.
        assert!(
            !tracker.record_deny_at(pid, t_expired),
            "Attempt after window expiration must not escalate"
        );
        assert_eq!(tracker.count_for_pid_at(pid, t_expired), 1);
    }
}
