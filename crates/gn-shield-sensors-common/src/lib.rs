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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    Created {
        path: std::path::PathBuf,
        pid: Option<u32>,
    },
    Modified {
        path: std::path::PathBuf,
        pid: Option<u32>,
    },
    Deleted {
        path: std::path::PathBuf,
        pid: Option<u32>,
    },
    ExecPermRequested {
        path: std::path::PathBuf,
        pid: u32,
    },
}

impl FsEvent {
    #[must_use]
    pub fn created(path: std::path::PathBuf) -> Self {
        Self::Created { path, pid: None }
    }

    #[must_use]
    pub fn created_with_pid(path: std::path::PathBuf, pid: u32) -> Self {
        Self::Created {
            path,
            pid: Some(pid),
        }
    }

    #[must_use]
    pub fn modified(path: std::path::PathBuf) -> Self {
        Self::Modified { path, pid: None }
    }

    #[must_use]
    pub fn modified_with_pid(path: std::path::PathBuf, pid: u32) -> Self {
        Self::Modified {
            path,
            pid: Some(pid),
        }
    }

    #[must_use]
    pub fn deleted(path: std::path::PathBuf) -> Self {
        Self::Deleted { path, pid: None }
    }

    #[must_use]
    pub fn deleted_with_pid(path: std::path::PathBuf, pid: u32) -> Self {
        Self::Deleted {
            path,
            pid: Some(pid),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Created { path, .. }
            | Self::Modified { path, .. }
            | Self::Deleted { path, .. }
            | Self::ExecPermRequested { path, .. } => path,
        }
    }

    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Created { pid, .. } | Self::Modified { pid, .. } | Self::Deleted { pid, .. } => {
                *pid
            }
            Self::ExecPermRequested { pid, .. } => Some(*pid),
        }
    }
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

/// Evaluator trait for fanotify / endpoint execution permission requests.
pub trait ExecPermEvaluator: Send + Sync {
    /// Evaluates whether an executable at `path` is allowed to run for process `pid`.
    /// Returns Ok(true) if allowed, Ok(false) if blocked/denied, or Err if evaluation failed.
    fn evaluate_permission(&self, path: &Path, pid: u32) -> Result<bool, String>;
}

impl<F> ExecPermEvaluator for F
where
    F: Fn(&Path, u32) -> Result<bool, String> + Send + Sync,
{
    fn evaluate_permission(&self, path: &Path, pid: u32) -> Result<bool, String> {
        (self)(path, pid)
    }
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

        let fs_created = FsEvent::created(path.clone());
        let fs_modified = FsEvent::modified_with_pid(path.clone(), 9999);
        let fs_deleted = FsEvent::deleted(path.clone());
        let fs_exec = FsEvent::ExecPermRequested {
            path: path.clone(),
            pid: 1234,
        };

        match fs_created {
            FsEvent::Created { path: p, pid } => {
                assert_eq!(p, path);
                assert_eq!(pid, None);
            }
            _ => panic!("unexpected event"),
        }
        assert_eq!(fs_modified.pid(), Some(9999));
        assert!(matches!(fs_modified, FsEvent::Modified { .. }));
        assert!(matches!(fs_deleted, FsEvent::Deleted { .. }));
        assert_eq!(fs_deleted.pid(), None);
        assert!(matches!(
            fs_exec,
            FsEvent::ExecPermRequested { pid: 1234, .. }
        ));
        assert_eq!(fs_exec.path(), path.as_path());
        assert_eq!(fs_exec.pid(), Some(1234));

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

    #[test]
    fn test_exec_perm_evaluator_closure() {
        let evaluator = |_path: &Path, pid: u32| {
            if pid == 9999 {
                Ok(false)
            } else {
                Ok(true)
            }
        };

        assert!(evaluator
            .evaluate_permission(Path::new("/bin/ls"), 1234)
            .unwrap());
        assert!(!evaluator
            .evaluate_permission(Path::new("/bin/malware"), 9999)
            .unwrap());
    }
}
