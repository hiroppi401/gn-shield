//! Linux specific sensors implementation (inotify via notify, fanotify target, eBPF via aya).

pub mod ip_filter;
pub use ip_filter::{EbpfIpReputationFilter, IpReputationEntry, IpVerdict};

use aya::Ebpf;
use gn_shield_sensors_common::{
    FileSystemSensor, FsEvent, ProcessEvent, ProcessSensor, SensorError,
};
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

/// Linux eBPF process monitoring sensor using aya.
pub struct EbpfProcessSensor {
    bpf: Option<Ebpf>,
    tx: Sender<ProcessEvent>,
    rx: Receiver<ProcessEvent>,
    subscribed: bool,
}

impl Default for EbpfProcessSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfProcessSensor {
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            bpf: None,
            tx,
            rx,
            subscribed: false,
        }
    }

    /// Loads eBPF bytecode using aya loader.
    pub fn with_bpf_bytecode(bytecode: &[u8]) -> Result<Self, SensorError> {
        let bpf = Ebpf::load(bytecode).map_err(|e| SensorError::InitError(e.to_string()))?;
        let (tx, rx) = channel();
        Ok(Self {
            bpf: Some(bpf),
            tx,
            rx,
            subscribed: false,
        })
    }

    #[must_use]
    pub fn has_bpf_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    #[must_use]
    pub fn event_sender(&self) -> Sender<ProcessEvent> {
        self.tx.clone()
    }

    pub fn emit_event(&self, event: ProcessEvent) -> Result<(), SensorError> {
        self.tx
            .send(event)
            .map_err(|e| SensorError::InitError(e.to_string()))
    }
}

impl ProcessSensor for EbpfProcessSensor {
    fn subscribe(&mut self) -> Result<(), SensorError> {
        self.subscribed = true;
        Ok(())
    }

    fn next_event(&mut self) -> Result<ProcessEvent, SensorError> {
        if !self.subscribed {
            return Err(SensorError::InitError(
                "Process sensor not subscribed".to_string(),
            ));
        }
        self.rx
            .recv()
            .map_err(|_| SensorError::InitError("Process event channel closed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

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

    #[test]
    fn test_ebpf_process_sensor_lifecycle() {
        let mut sensor = EbpfProcessSensor::new();
        assert!(!sensor.has_bpf_loaded());

        // Calling next_event before subscribe should error
        assert!(sensor.next_event().is_err());

        sensor.subscribe().expect("subscribe failed");

        let event = ProcessEvent::Started {
            pid: 1234,
            ppid: 1000,
            exe: PathBuf::from("/usr/bin/cargo"),
            cmdline: vec!["cargo".to_string(), "build".to_string()],
        };

        sensor.emit_event(event.clone()).expect("emit failed");

        let received = sensor.next_event().expect("next_event failed");
        match received {
            ProcessEvent::Started { pid, exe, .. } => {
                assert_eq!(pid, 1234);
                assert_eq!(exe, PathBuf::from("/usr/bin/cargo"));
            }
            _ => panic!("Unexpected event received: {received:?}"),
        }
    }
}
