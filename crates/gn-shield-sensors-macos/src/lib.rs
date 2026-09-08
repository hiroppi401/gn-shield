//! macOS specific sensors implementation (FSEvents, EndpointSecurity).

use gn_shield_sensors_common::{FileSystemSensor, FsEvent, SensorError};
use std::path::Path;

#[derive(Debug, Default)]
pub struct MacOsFsSensor;

impl FileSystemSensor for MacOsFsSensor {
    fn watch(&mut self, _path: &Path) -> Result<(), SensorError> {
        Ok(())
    }

    fn next_event(&mut self) -> Result<FsEvent, SensorError> {
        Err(SensorError::InitError(
            "macOS sensor not supported on current platform".to_string(),
        ))
    }
}
