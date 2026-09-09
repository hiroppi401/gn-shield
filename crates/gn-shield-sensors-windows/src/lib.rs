//! Windows specific sensors implementation (ReadDirectoryChangesW, ETW).

use gn_shield_sensors_common::{FileSystemSensor, FsEvent, SensorError};
use std::path::Path;

#[derive(Debug, Default)]
pub struct WindowsFsSensor;

impl FileSystemSensor for WindowsFsSensor {
    fn watch(&mut self, _path: &Path) -> Result<(), SensorError> {
        Ok(())
    }

    fn next_event(&mut self) -> Result<FsEvent, SensorError> {
        Err(SensorError::InitError(
            "Windows sensor not supported on current platform".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_fs_sensor_stub() {
        let mut sensor = WindowsFsSensor;
        assert!(sensor.watch(Path::new("C:\\temp")).is_ok());

        let result = sensor.next_event();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Windows sensor not supported"));
    }
}
