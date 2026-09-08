//! Linux specific sensors implementation (inotify via notify, fanotify target, eBPF via aya).

use gn_shield_sensors_common::{FileSystemSensor, FsEvent, SensorError};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};

pub struct LinuxFsSensor {
    watcher: Option<RecommendedWatcher>,
    rx: Receiver<notify::Result<Event>>,
    tx: Sender<notify::Result<Event>>,
}

impl Default for LinuxFsSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxFsSensor {
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            watcher: None,
            rx,
            tx,
        }
    }

    fn ensure_watcher(&mut self) -> Result<&mut RecommendedWatcher, SensorError> {
        if self.watcher.is_none() {
            let tx = self.tx.clone();
            let watcher = RecommendedWatcher::new(
                move |res| {
                    let _ = tx.send(res);
                },
                Config::default(),
            )
            .map_err(|e| SensorError::InitError(e.to_string()))?;
            self.watcher = Some(watcher);
        }
        Ok(self.watcher.as_mut().expect("watcher must be set"))
    }
}

impl FileSystemSensor for LinuxFsSensor {
    fn watch(&mut self, path: &Path) -> Result<(), SensorError> {
        let watcher = self.ensure_watcher()?;
        watcher
            .watch(path, RecursiveMode::Recursive)
            .map_err(|e| SensorError::InitError(format!("Failed to watch {path:?}: {e}")))?;
        Ok(())
    }

    fn next_event(&mut self) -> Result<FsEvent, SensorError> {
        loop {
            match self.rx.recv() {
                Ok(Ok(event)) => {
                    let path = event.paths.into_iter().next().unwrap_or_default();
                    match event.kind {
                        EventKind::Create(_) => return Ok(FsEvent::Created(path)),
                        EventKind::Modify(_) => return Ok(FsEvent::Modified(path)),
                        EventKind::Remove(_) => return Ok(FsEvent::Deleted(path)),
                        _ => continue,
                    }
                }
                Ok(Err(e)) => return Err(SensorError::InitError(e.to_string())),
                Err(_) => {
                    return Err(SensorError::InitError(
                        "Filesystem sensor channel disconnected".to_string(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_linux_fs_sensor_watch_tempdir() {
        let temp_dir = tempfile::tempdir().expect("tempdir creation failed");
        let mut sensor = LinuxFsSensor::new();
        sensor.watch(temp_dir.path()).expect("watch failed");

        let file_path = temp_dir.path().join("test_file.txt");
        let mut f = fs::File::create(&file_path).expect("file create failed");
        f.write_all(b"sample data").expect("write failed");
        drop(f);

        // Receive event from sensor
        let event = sensor.next_event().expect("next_event failed");
        match event {
            FsEvent::Created(p) | FsEvent::Modified(p) => {
                assert_eq!(p.file_name(), file_path.file_name());
            }
            _ => panic!("Unexpected event: {event:?}"),
        }
    }
}
