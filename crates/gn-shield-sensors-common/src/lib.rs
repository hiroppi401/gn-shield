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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    #[test]
    fn test_sensor_error_display_and_source() {
        let io_err = IoError::new(ErrorKind::NotFound, "file not found");
        let sensor_io = SensorError::from(io_err);
        assert!(sensor_io.to_string().contains("I/O error"));
        use std::error::Error;
        assert!(sensor_io.source().is_some());

        let perm = SensorError::PermissionDenied;
        assert_eq!(perm.to_string(), "Permission denied");
        assert!(perm.source().is_none());

        let init = SensorError::InitError("failed to attach probe".to_string());
        assert!(init.to_string().contains("Sensor initialization error"));
        assert!(init.source().is_none());
    }

    #[test]
    fn test_sensor_event_instantiation() {
        let path = PathBuf::from("/tmp/test.txt");

        let fs_created = FsEvent::Created(path.clone());
        let fs_modified = FsEvent::Modified(path.clone());
        let fs_deleted = FsEvent::Deleted(path.clone());
        let fs_exec = FsEvent::ExecPermRequested {
            path: path.clone(),
            pid: 1234,
        };

        match fs_created {
            FsEvent::Created(p) => assert_eq!(p, path),
            _ => panic!("unexpected event"),
        }
        assert!(matches!(fs_modified, FsEvent::Modified(_)));
        assert!(matches!(fs_deleted, FsEvent::Deleted(_)));
        assert!(matches!(
            fs_exec,
            FsEvent::ExecPermRequested { pid: 1234, .. }
        ));

        let proc_event = ProcessEvent::Started {
            pid: 4321,
            ppid: 1000,
            exe: path.clone(),
            cmdline: vec!["app".into(), "--arg".into()],
        };
        assert!(matches!(
            proc_event,
            ProcessEvent::Started { pid: 4321, .. }
        ));

        let proc_term = ProcessEvent::Terminated { pid: 4321 };
        assert!(matches!(proc_term, ProcessEvent::Terminated { pid: 4321 }));

        let net_event = NetworkEvent::ConnectionAttempt {
            pid: 4321,
            destination_ip: std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            destination_port: 443,
        };
        assert!(matches!(
            net_event,
            NetworkEvent::ConnectionAttempt {
                destination_port: 443,
                ..
            }
        ));
    }
}
