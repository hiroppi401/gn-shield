//! Linux specific sensors implementation (inotify via notify, fanotify target, eBPF via aya).

pub mod ip_filter;
pub use ip_filter::{EbpfIpReputationFilter, IpReputationEntry, IpVerdict};

use aya::Ebpf;
use gn_shield_sensors_common::{
    ExecPermEvaluator, FileSystemSensor, FsEvent, ProcessEvent, ProcessSensor, SensorError,
};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

pub struct LinuxFsSensor {
    watcher: Option<RecommendedWatcher>,
    rx: Receiver<Result<FsEvent, SensorError>>,
    tx: Sender<Result<FsEvent, SensorError>>,
    evaluator: Option<Arc<dyn ExecPermEvaluator>>,
    fanotify_fd: Option<i32>,
    stop_signal: Arc<AtomicBool>,
    watchdog_timeout: Duration,
    fanotify_thread: Option<std::thread::JoinHandle<()>>,
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
            evaluator: None,
            fanotify_fd: None,
            stop_signal: Arc::new(AtomicBool::new(false)),
            watchdog_timeout: Duration::from_millis(250),
            fanotify_thread: None,
        }
    }

    /// Attaches an executable permission evaluator to the sensor.
    #[must_use]
    pub fn with_evaluator(mut self, evaluator: Arc<dyn ExecPermEvaluator>) -> Self {
        self.evaluator = Some(evaluator);
        self
    }

    /// Configures the watchdog timeout for execution evaluation (default: 250ms).
    #[must_use]
    pub fn with_watchdog_timeout(mut self, timeout: Duration) -> Self {
        self.watchdog_timeout = timeout;
        self
    }

    /// Returns a clone of the filesystem event sender.
    #[must_use]
    pub fn event_sender(&self) -> Sender<Result<FsEvent, SensorError>> {
        self.tx.clone()
    }

    /// Attempts to initialize fanotify with `FAN_CLASS_CONTENT` and permission mode.
    /// Returns `Ok(())` if privileged, or `Err(SensorError::PermissionDenied)` if unprivileged.
    pub fn try_init_fanotify(&mut self) -> Result<(), SensorError> {
        if self.fanotify_fd.is_some() {
            return Ok(());
        }

        // SAFETY: fanotify_init syscall to initialize fanotify content engine with non-blocking mode
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };

        if fd < 0 {
            let io_err = std::io::Error::last_os_error();
            if io_err.raw_os_error() == Some(libc::EPERM)
                || io_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(SensorError::PermissionDenied);
            }
            return Err(SensorError::InitError(format!(
                "fanotify_init failed: {io_err}"
            )));
        }

        self.fanotify_fd = Some(fd);
        self.start_fanotify_worker(fd);
        Ok(())
    }

    fn start_fanotify_worker(&mut self, fd: i32) {
        let stop_signal = Arc::clone(&self.stop_signal);
        let evaluator = self.evaluator.clone();
        let watchdog_timeout = self.watchdog_timeout;
        let tx = self.tx.clone();

        let handle = std::thread::spawn(move || {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };

            while !stop_signal.load(Ordering::Relaxed) {
                // SAFETY: poll fanotify descriptor with 100ms timeout
                let poll_res = unsafe { libc::poll(&mut pfd, 1, 100) };
                if poll_res <= 0 || (pfd.revents & libc::POLLIN) == 0 {
                    continue;
                }

                let mut buf = [0u8; 4096];
                // SAFETY: read fanotify_event_metadata from fanotify fd
                let len =
                    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if len <= 0 {
                    continue;
                }

                let mut offset = 0usize;
                while offset < len as usize {
                    let meta_ptr =
                        unsafe { buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata };
                    let meta = unsafe { &*meta_ptr };
                    if meta.event_len == 0 || meta.vers != libc::FANOTIFY_METADATA_VERSION {
                        break;
                    }

                    if (meta.mask & libc::FAN_OPEN_EXEC_PERM) != 0 {
                        let calling_pid = meta.pid as u32;
                        let event_fd = meta.fd;
                        let self_pid = std::process::id();

                        // 1. Recursive deadlock bypass: always allow GN-Shield's own PID
                        if calling_pid == self_pid {
                            let resp = libc::fanotify_response {
                                fd: event_fd,
                                response: libc::FAN_ALLOW,
                            };
                            // SAFETY: write fanotify_response and close event_fd
                            unsafe {
                                libc::write(
                                    fd,
                                    &resp as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::fanotify_response>(),
                                );
                                libc::close(event_fd);
                            }
                            offset += meta.event_len as usize;
                            continue;
                        }

                        // 2. Resolve executable path from /proc/self/fd/<event_fd>
                        let link_target = format!("/proc/self/fd/{event_fd}");
                        let target_path = std::fs::read_link(&link_target)
                            .unwrap_or_else(|_| PathBuf::from("unknown"));

                        // 3. Evaluate file with watchdog timeout
                        let allowed = if let Some(ref eval) = evaluator {
                            evaluate_with_watchdog(
                                eval,
                                &target_path,
                                calling_pid,
                                watchdog_timeout,
                            )
                        } else {
                            true // fail-open
                        };

                        let response_code = if allowed {
                            libc::FAN_ALLOW
                        } else {
                            libc::FAN_DENY
                        };
                        let resp = libc::fanotify_response {
                            fd: event_fd,
                            response: response_code,
                        };

                        // SAFETY: write response back to kernel and close event file descriptor
                        unsafe {
                            libc::write(
                                fd,
                                &resp as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::fanotify_response>(),
                            );
                            libc::close(event_fd);
                        }

                        let _ = tx.send(Ok(FsEvent::ExecPermRequested {
                            path: target_path,
                            pid: calling_pid,
                        }));
                    }
                    offset += meta.event_len as usize;
                }
            }
        });

        self.fanotify_thread = Some(handle);
    }

    /// Evaluates execution permission for a file (synchronous simulation & test hook).
    /// Holds execution until evaluator completes, adhering to fast-path self bypass and watchdog timeout.
    pub fn evaluate_and_decide_exec(&self, path: &Path, pid: u32) -> bool {
        // Fast-path bypass for self PID to prevent recursive deadlocks
        if pid == std::process::id() {
            return true;
        }

        let allowed = if let Some(ref eval) = self.evaluator {
            evaluate_with_watchdog(eval, path, pid, self.watchdog_timeout)
        } else {
            true // fail-open
        };

        let _ = self.tx.send(Ok(FsEvent::ExecPermRequested {
            path: path.to_path_buf(),
            pid,
        }));

        allowed
    }

    fn ensure_watcher(&mut self) -> Result<&mut RecommendedWatcher, SensorError> {
        if self.watcher.is_none() {
            let tx = self.tx.clone();
            let watcher = RecommendedWatcher::new(
                move |res: notify::Result<Event>| match res {
                    Ok(event) => {
                        let path = event.paths.into_iter().next().unwrap_or_default();
                        match event.kind {
                            EventKind::Create(_) => {
                                let _ = tx.send(Ok(FsEvent::Created(path)));
                            }
                            EventKind::Modify(_) => {
                                let _ = tx.send(Ok(FsEvent::Modified(path)));
                            }
                            EventKind::Remove(_) => {
                                let _ = tx.send(Ok(FsEvent::Deleted(path)));
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(SensorError::InitError(e.to_string())));
                    }
                },
                Config::default(),
            )
            .map_err(|e| SensorError::InitError(e.to_string()))?;
            self.watcher = Some(watcher);
        }
        Ok(self.watcher.as_mut().expect("watcher must be set"))
    }
}

impl Drop for LinuxFsSensor {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(fd) = self.fanotify_fd {
            // SAFETY: close fanotify descriptor upon sensor termination
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(handle) = self.fanotify_thread.take() {
            let _ = handle.join();
        }
    }
}

fn evaluate_with_watchdog(
    evaluator: &Arc<dyn ExecPermEvaluator>,
    path: &Path,
    pid: u32,
    timeout: Duration,
) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    let eval = Arc::clone(evaluator);
    let p = path.to_path_buf();

    std::thread::spawn(move || {
        let res = eval.evaluate_permission(&p, pid);
        let _ = tx.send(res);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(allowed)) => allowed,
        Ok(Err(err)) => {
            eprintln!(
                "Warning: permission evaluation failed for {path:?} (PID {pid}): {err}. Failing open."
            );
            true // fail-open per ARCHITECTURE.md line 129
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "Warning: permission evaluation timed out for {path:?} (PID {pid}). Failing open."
            );
            true // fail-open per ARCHITECTURE.md line 129 & 309
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
    }
}

impl FileSystemSensor for LinuxFsSensor {
    fn watch(&mut self, path: &Path) -> Result<(), SensorError> {
        let watcher = self.ensure_watcher()?;
        watcher
            .watch(path, RecursiveMode::Recursive)
            .map_err(|e| SensorError::InitError(format!("Failed to watch {path:?}: {e}")))?;

        if let Some(fd) = self.fanotify_fd {
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|e| SensorError::InitError(e.to_string()))?;
            // SAFETY: fanotify_mark on specified directory for execution permission events
            let res = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD,
                    libc::FAN_OPEN_EXEC_PERM | libc::FAN_EVENT_ON_CHILD,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                )
            };
            if res < 0 {
                return Err(SensorError::InitError(format!(
                    "fanotify_mark failed for {path:?}: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(())
    }

    fn next_event(&mut self) -> Result<FsEvent, SensorError> {
        match self.rx.recv() {
            Ok(Ok(event)) => Ok(event),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(SensorError::InitError(
                "Filesystem sensor channel disconnected".to_string(),
            )),
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

    #[test]
    fn test_linux_fs_sensor_fanotify_permission_allow_and_deny() {
        let evaluator: Arc<dyn ExecPermEvaluator> = Arc::new(|path: &Path, _pid: u32| {
            if path.to_string_lossy().contains("malware") {
                Ok(false) // Block
            } else {
                Ok(true) // Allow
            }
        });

        let mut sensor = LinuxFsSensor::new().with_evaluator(evaluator);

        // Safe executable allowed
        assert!(sensor.evaluate_and_decide_exec(Path::new("/usr/bin/safe_app"), 4321));
        let ev1 = sensor.next_event().expect("should receive exec event");
        match ev1 {
            FsEvent::ExecPermRequested { path, pid } => {
                assert_eq!(path, Path::new("/usr/bin/safe_app"));
                assert_eq!(pid, 4321);
            }
            _ => panic!("Unexpected event: {ev1:?}"),
        }

        // Malicious executable denied
        assert!(!sensor.evaluate_and_decide_exec(Path::new("/tmp/malware.bin"), 4321));
        let ev2 = sensor.next_event().expect("should receive exec event");
        match ev2 {
            FsEvent::ExecPermRequested { path, pid } => {
                assert_eq!(path, Path::new("/tmp/malware.bin"));
                assert_eq!(pid, 4321);
            }
            _ => panic!("Unexpected event: {ev2:?}"),
        }
    }

    #[test]
    fn test_linux_fs_sensor_self_pid_deadlock_bypass() {
        // Evaluator that blocks everything
        let blocking_evaluator: Arc<dyn ExecPermEvaluator> =
            Arc::new(|_path: &Path, _pid: u32| Ok(false));

        let sensor = LinuxFsSensor::new().with_evaluator(blocking_evaluator);

        // Self-PID bypass must return true to prevent recursive deadlock
        assert!(sensor
            .evaluate_and_decide_exec(Path::new("/usr/bin/gn-shield-core"), std::process::id()));
    }

    #[test]
    fn test_linux_fs_sensor_watchdog_timeout_fail_open() {
        // Evaluator that hangs / sleeps 500ms
        let hanging_evaluator: Arc<dyn ExecPermEvaluator> = Arc::new(|_path: &Path, _pid: u32| {
            std::thread::sleep(Duration::from_millis(500));
            Ok(false)
        });

        // Watchdog timeout set to 50ms
        let sensor = LinuxFsSensor::new()
            .with_evaluator(hanging_evaluator)
            .with_watchdog_timeout(Duration::from_millis(50));

        // Must fail-open to prevent freezing system
        assert!(sensor.evaluate_and_decide_exec(Path::new("/usr/bin/slow_app"), 5678));
    }

    #[test]
    fn test_linux_fs_sensor_try_init_fanotify() {
        let mut sensor = LinuxFsSensor::new();
        let res = sensor.try_init_fanotify();
        // If run without CAP_SYS_ADMIN (unprivileged), must return PermissionDenied
        // If run with root, it returns Ok(())
        match res {
            Ok(()) => println!("fanotify initialized successfully (running privileged)"),
            Err(SensorError::PermissionDenied) => {
                println!("fanotify correctly reported PermissionDenied in unprivileged test")
            }
            Err(e) => panic!("Unexpected error from try_init_fanotify: {e}"),
        }
    }
}
