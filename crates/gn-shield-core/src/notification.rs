//! Notification manager and batching engine.
//!
//! Enforces desktop notification formatting, reversibility rules, and sliding-window
//! notification batching to prevent alert fatigue when multiple ambiguous PromptUser
//! events occur within related activities.

use gn_shield_config::NotificationsConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PromptAction {
    #[default]
    AllowOnce,
    AlwaysAllow,
    Block,
    ReviewIndividually,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptEvent {
    pub id: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub target: String,
    pub reason: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedNotification {
    pub batch_id: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub events: Vec<PromptEvent>,
    pub summary_title: String,
    pub summary_body: String,
    pub available_actions: Vec<PromptAction>,
}

pub trait NotificationSink: Send + Sync {
    fn emit_single(&self, event: &PromptEvent) -> Result<PromptAction, String>;
    fn emit_batch(&self, batch: &BatchedNotification) -> Result<PromptAction, String>;
}

/// In-memory notification sink for headless environments, tests, and CLI listener.
#[derive(Default)]
pub struct InMemoryNotificationSink {
    pub emitted_singles: Arc<Mutex<Vec<PromptEvent>>>,
    pub emitted_batches: Arc<Mutex<Vec<BatchedNotification>>>,
    default_response: Arc<Mutex<PromptAction>>,
}

impl InMemoryNotificationSink {
    #[must_use]
    pub fn new(default_response: PromptAction) -> Self {
        Self {
            emitted_singles: Arc::new(Mutex::new(Vec::new())),
            emitted_batches: Arc::new(Mutex::new(Vec::new())),
            default_response: Arc::new(Mutex::new(default_response)),
        }
    }

    pub fn set_default_response(&self, response: PromptAction) {
        if let Ok(mut resp) = self.default_response.lock() {
            *resp = response;
        }
    }
}

impl NotificationSink for InMemoryNotificationSink {
    fn emit_single(&self, event: &PromptEvent) -> Result<PromptAction, String> {
        if let Ok(mut singles) = self.emitted_singles.lock() {
            singles.push(event.clone());
        }
        let resp = self
            .default_response
            .lock()
            .map(|r| r.clone())
            .unwrap_or(PromptAction::AllowOnce);
        Ok(resp)
    }

    fn emit_batch(&self, batch: &BatchedNotification) -> Result<PromptAction, String> {
        if let Ok(mut batches) = self.emitted_batches.lock() {
            batches.push(batch.clone());
        }
        let resp = self
            .default_response
            .lock()
            .map(|r| r.clone())
            .unwrap_or(PromptAction::AllowOnce);
        Ok(resp)
    }
}

struct PendingBatchGroup {
    parent_pid: u32,
    parent_name: String,
    events: Vec<PromptEvent>,
    created_at: Instant,
}

pub struct NotificationBatcher {
    config: NotificationsConfig,
    sink: Arc<dyn NotificationSink>,
    pending_groups: Mutex<HashMap<u32, PendingBatchGroup>>,
}

impl NotificationBatcher {
    #[must_use]
    pub fn new(config: NotificationsConfig, sink: Arc<dyn NotificationSink>) -> Self {
        Self {
            config,
            sink,
            pending_groups: Mutex::new(HashMap::new()),
        }
    }

    /// Submits a PromptUser event. If batching is disabled, dispatches immediately.
    /// If batching is enabled, groups with events from the same parent process.
    pub fn submit_event(&self, event: PromptEvent) -> Result<Option<PromptAction>, String> {
        if !self.config.batching_enabled {
            let action = self.sink.emit_single(&event)?;
            return Ok(Some(action));
        }

        let parent_pid = event.parent_pid;
        let mut groups = self.pending_groups.lock().map_err(|e| e.to_string())?;
        let entry = groups
            .entry(parent_pid)
            .or_insert_with(|| PendingBatchGroup {
                parent_pid,
                parent_name: event.parent_name.clone(),
                events: Vec::new(),
                created_at: Instant::now(),
            });

        entry.events.push(event);
        let should_flush = entry.events.len() >= self.config.batch_threshold_count;

        if should_flush {
            // Threshold reached, flush immediately into a batched notification
            let group = groups.remove(&parent_pid).unwrap();
            let batch = Self::format_batch(&group);
            let action = self.sink.emit_batch(&batch)?;
            return Ok(Some(action));
        }

        // Held in buffer waiting for window expiry or subsequent events
        Ok(None)
    }

    /// Flushes any pending groups whose batch window has elapsed.
    pub fn flush_expired_groups(&self) -> Result<Vec<(u32, PromptAction)>, String> {
        let mut expired = Vec::new();
        let window = Duration::from_millis(self.config.batch_window_ms);
        let now = Instant::now();

        let mut groups = self.pending_groups.lock().map_err(|e| e.to_string())?;
        let expired_pids: Vec<u32> = groups
            .iter()
            .filter(|(_, g)| now.duration_since(g.created_at) >= window)
            .map(|(pid, _)| *pid)
            .collect();

        for pid in expired_pids {
            if let Some(group) = groups.remove(&pid) {
                if group.events.len() == 1 {
                    let action = self.sink.emit_single(&group.events[0])?;
                    expired.push((pid, action));
                } else if !group.events.is_empty() {
                    let batch = Self::format_batch(&group);
                    let action = self.sink.emit_batch(&batch)?;
                    expired.push((pid, action));
                }
            }
        }

        Ok(expired)
    }

    fn format_batch(group: &PendingBatchGroup) -> BatchedNotification {
        let count = group.events.len();
        let title = format!("GN-Shield: {count} Aktivitas Membutuhkan Izin");

        let targets: Vec<String> = group
            .events
            .iter()
            .take(5)
            .map(|e| format!("• {} ({})", e.target, e.reason))
            .collect();

        let mut body = format!(
            "Proses '{}' (PID {}) memicu sejumlah event ambigu:\n{}",
            group.parent_name,
            group.parent_pid,
            targets.join("\n")
        );

        if count > 5 {
            body.push_str(&format!("\n...dan {} aktivitas lainnya", count - 5));
        }

        BatchedNotification {
            batch_id: format!("batch-{}-{}", group.parent_pid, group.events.len()),
            parent_pid: group.parent_pid,
            parent_name: group.parent_name.clone(),
            events: group.events.clone(),
            summary_title: title,
            summary_body: body,
            available_actions: vec![
                PromptAction::AllowOnce,
                PromptAction::AlwaysAllow,
                PromptAction::Block,
                PromptAction::ReviewIndividually,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batching_threshold_trigger() {
        let sink = Arc::new(InMemoryNotificationSink::new(PromptAction::AllowOnce));
        let config = NotificationsConfig {
            style: "native".to_string(),
            prompt_timeout_seconds: 30,
            default_action_on_timeout: "allow_once".to_string(),
            batching_enabled: true,
            batch_window_ms: 500,
            batch_threshold_count: 2,
        };

        let batcher = NotificationBatcher::new(config, sink.clone());

        // Event 1 from PID 1001: held in buffer
        let action1 = batcher
            .submit_event(PromptEvent {
                id: "evt-1".to_string(),
                parent_pid: 1001,
                parent_name: "cargo".to_string(),
                target: "temp_build_probe.bin".to_string(),
                reason: "Suspicious binary write".to_string(),
                timestamp_ms: 1000,
            })
            .expect("submit failed");
        assert!(action1.is_none());

        // Event 2 from PID 1001: hits threshold 2, flushes batch
        let action2 = batcher
            .submit_event(PromptEvent {
                id: "evt-2".to_string(),
                parent_pid: 1001,
                parent_name: "cargo".to_string(),
                target: "temp_linker_probe.so".to_string(),
                reason: "Ambiguous shared object link".to_string(),
                timestamp_ms: 1050,
            })
            .expect("submit failed");

        assert_eq!(action2, Some(PromptAction::AllowOnce));

        let batches = sink.emitted_batches.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].parent_pid, 1001);
        assert_eq!(batches[0].events.len(), 2);
        assert!(batches[0].summary_title.contains("2 Aktivitas"));
    }

    #[test]
    fn test_single_event_flushed_after_window_expiry() {
        let sink = Arc::new(InMemoryNotificationSink::new(PromptAction::AlwaysAllow));
        let config = NotificationsConfig {
            style: "native".to_string(),
            prompt_timeout_seconds: 30,
            default_action_on_timeout: "allow_once".to_string(),
            batching_enabled: true,
            batch_window_ms: 10, // fast window for test
            batch_threshold_count: 5,
        };

        let batcher = NotificationBatcher::new(config, sink.clone());
        let _ = batcher.submit_event(PromptEvent {
            id: "evt-solo".to_string(),
            parent_pid: 2002,
            parent_name: "npm".to_string(),
            target: "install_script.js".to_string(),
            reason: "Postinstall hook".to_string(),
            timestamp_ms: 500,
        });

        std::thread::sleep(Duration::from_millis(20));

        let flushed = batcher.flush_expired_groups().expect("flush failed");
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0], (2002, PromptAction::AlwaysAllow));

        let singles = sink.emitted_singles.lock().unwrap();
        assert_eq!(singles.len(), 1);
        assert_eq!(singles[0].parent_name, "npm");
    }
}
