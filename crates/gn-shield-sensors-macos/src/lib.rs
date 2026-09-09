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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_fs_sensor_stub() {
        let mut sensor = MacOsFsSensor;
        assert!(sensor.watch(Path::new("/tmp")).is_ok());

        let result = sensor.next_event();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("macOS sensor not supported"));
    }
}
