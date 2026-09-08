//! Linux specific sensors implementation (fanotify/inotify, eBPF via aya).

use gn_shield_sensors_common::{FileSystemSensor, FsEvent, SensorError};
use std::path::Path;

#[derive(Debug, Default)]
pub struct LinuxFsSensor {
    is_watching: bool,
}

impl LinuxFsSensor {
    #[must_use]
    pub fn new() -> Self {
        Self { is_watching: false }
    }
}

impl FileSystemSensor for LinuxFsSensor {
    fn watch(&mut self, _path: &Path) -> Result<(), SensorError> {
        self.is_watching = true;
        Ok(())
    }

    fn next_event(&mut self) -> Result<FsEvent, SensorError> {
        // Will be connected to fanotify / inotify in Phase 1
        Err(SensorError::InitError("Sensor not initialized".to_string()))
    }
}
