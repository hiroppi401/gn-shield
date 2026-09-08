use std::path::Path;

#[derive(Debug)]
pub enum SensorError {
    Io(std::io::Error),
    PermissionDenied,
    InitError(String),
}

impl std::fmt::Display for SensorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::InitError(msg) => write!(f, "Sensor initialization error: {msg}"),
        }
    }
}

impl std::error::Error for SensorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SensorError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug, Clone)]
pub enum FsEvent {
    Created(std::path::PathBuf),
    Modified(std::path::PathBuf),
    Deleted(std::path::PathBuf),
    ExecPermRequested { path: std::path::PathBuf, pid: u32 },
}

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    Started {
        pid: u32,
        ppid: u32,
        exe: std::path::PathBuf,
        cmdline: Vec<String>,
    },
    Terminated {
        pid: u32,
    },
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    ConnectionAttempt {
        pid: u32,
        destination_ip: std::net::IpAddr,
        destination_port: u16,
    },
}

pub trait FileSystemSensor {
    fn watch(&mut self, path: &Path) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<FsEvent, SensorError>;
}

pub trait ProcessSensor {
    fn subscribe(&mut self) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<ProcessEvent, SensorError>;
}

pub trait NetworkSensor {
    fn subscribe(&mut self) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<NetworkEvent, SensorError>;
}
