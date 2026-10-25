// debug-only local controls for native allocation and fetch-gate experiments.
#![allow(clippy::disallowed_methods)]

use anyhow::{anyhow, ensure, Result};
use serde::Deserialize;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use crate::container::{AllocationRequest, AllocationView, CellContainer, ContainerEngine};

const ENV: &str = "CELLD_TEST_ALLOCATION_CONTROL_DIR";
const LIMIT: u64 = 8192;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    version: u8,
    nonce: String,
    scope: String,
    mode: String,
    allocation_id: Option<String>,
    timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signal {
    version: u8,
    nonce: String,
}

pub(crate) struct Control {
    directory: File,
    config: Config,
    epoch: u64,
    op: Option<u64>,
    deadline: Instant,
    entered: AtomicBool,
}

// pin the directory descriptor so renaming a path cannot redirect a live experiment.
fn open_at(directory: &File, name: &str, flags: i32) -> std::io::Result<File> {
    let name = CString::new(name).expect("fixed control filename");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_json(directory: &File, name: &str) -> Result<Option<Vec<u8>>> {
    let file = match open_at(directory, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(anyhow!("debug control file unavailable")),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() <= LIMIT,
        "invalid debug control file"
    );
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "oversized debug control file"
    );
    Ok(Some(bytes))
}

impl Control {
    pub(crate) fn claim(
        path: &Path,
        scope: &str,
        mode: &str,
        allocation_id: Option<&str>,
        epoch: u64,
        op: Option<u64>,
    ) -> Result<Option<Arc<Self>>> {
        ensure!(
            path.is_absolute(),
            "debug control directory must be absolute"
        );
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| anyhow!("debug control directory unavailable"))?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.mode() & 0o777 == 0o700
                && metadata.uid() == unsafe { libc::geteuid() },
            "invalid debug control directory"
        );
        let bytes = read_json(&directory, "control.json")?
            .ok_or_else(|| anyhow!("debug control configuration missing"))?;
        let config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("invalid debug control configuration"))?;
        ensure!(
            config.version == 1
                && config.nonce.len() == 32
                && config
                    .nonce
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && !config.scope.is_empty()
                && config.scope.len() <= 4096
                && config.scope.bytes().all(|c| c.is_ascii_graphic())
                && (100..=30_000).contains(&config.timeout_ms),
            "invalid debug control bounds"
        );
        ensure!(
            match config.mode.as_str() {
                "cancel-startup" | "fetch-gate" => config.allocation_id.is_none(),
                "delay-destroy" => config.allocation_id.as_ref().is_some_and(|id| {
                    !id.is_empty()
                        && id.len() <= 64
                        && id.as_bytes()[0].is_ascii_alphanumeric()
                        && id
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                }),
                _ => false,
            },
            "invalid debug control selection"
        );
        if config.scope != scope
            || config.mode != mode
            || config.allocation_id.as_deref() != allocation_id
        {
            return Ok(None);
        }
        // a durable claim prevents recapture on retry, including after process restart.
        if read_json(&directory, "claimed.json")?.is_some() {
            return Ok(None);
        }
        for name in [
            "entered.json",
            "settled.json",
            "cancel.json",
            "release.json",
        ] {
            ensure!(
                read_json(&directory, name)?.is_none(),
                "debug control directory is not fresh"
            );
        }
        let control = Arc::new(Self {
            deadline: Instant::now() + Duration::from_millis(config.timeout_ms),
            directory,
            config,
            epoch,
            op,
            entered: AtomicBool::new(false),
        });
        if !control.ack("claimed.json", "claimed", false, None, None)? {
            return Ok(None);
        }
        Ok(Some(control))
    }

    fn from_env(
        scope: &str,
        mode: &str,
        id: Option<&str>,
        epoch: u64,
        op: Option<u64>,
    ) -> Result<Option<Arc<Self>>> {
        let Some(path) = std::env::var_os(ENV) else {
            return Ok(None);
        };
        Self::claim(Path::new(&path), scope, mode, id, epoch, op)
    }

    fn ack(
        &self,
        name: &str,
        status: &str,
        admitted: bool,
        reason: Option<&str>,
        view: Option<&AllocationView>,
    ) -> Result<bool> {
        let bytes = serde_json::to_vec(&json!({
            "version": 1, "nonce": self.config.nonce, "mode": self.config.mode,
            "scope": self.config.scope, "epoch": self.epoch, "op": self.op,
            "allocationId": self.config.allocation_id, "status": status,
            "admitted": admitted, "reason": reason,
            "allocationStatus": view.map(|view| view.status.as_str()),
            "containerId": view.and_then(|view| view.container_id.as_deref()),
        }))?;
        // exclusive temporary files and linkat publish complete acknowledgements without overwrites.
        let temporary = format!("{name}.tmp");
        let mut file = match open_at(
            &self.directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && name == "claimed.json" =>
            {
                return Ok(false)
            }
            Err(_) => return Err(anyhow!("debug acknowledgement unavailable")),
        };
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            let temporary = CString::new(temporary.as_str())?;
            let name = CString::new(name)?;
            let linked = unsafe {
                libc::linkat(
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Ok(false);
                }
                return Err(anyhow!("debug acknowledgement publication failed"));
            }
            Ok(true)
        })();
        let temporary = CString::new(temporary)?;
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
        result
    }

    pub(crate) fn enter(&self) -> Result<()> {
        ensure!(
            self.ack(
                "entered.json",
                "entered",
                false,
                (self.config.mode == "fetch-gate").then_some("output-gate-passed"),
                None
            )?,
            "debug entry already exists"
        );
        self.entered.store(true, Ordering::Release);
        Ok(())
    }

    async fn signal(&self, name: &str) -> Result<()> {
        loop {
            ensure!(Instant::now() < self.deadline, "debug control timed out");
            if self.entered.load(Ordering::Acquire) {
                if let Some(bytes) = read_json(&self.directory, name)? {
                    let signal: Signal = serde_json::from_slice(&bytes)
                        .map_err(|_| anyhow!("invalid debug control signal"))?;
                    ensure!(
                        signal.version == 1 && signal.nonce == self.config.nonce,
                        "invalid debug control signal"
                    );
                    ensure!(Instant::now() < self.deadline, "debug control timed out");
                    return Ok(());
                }
            }
            tokio::time::sleep_until(
                self.deadline
                    .min(Instant::now() + Duration::from_millis(10)),
            )
            .await;
        }
    }

    fn settle(
        &self,
        status: &str,
        admitted: bool,
        reason: Option<&str>,
        view: Option<&AllocationView>,
    ) -> Result<()> {
        ensure!(
            self.ack("settled.json", status, admitted, reason, view)?,
            "debug settlement already exists"
        );
        Ok(())
    }
}

pub(crate) struct FetchGate {
    control: Arc<Control>,
    settled: bool,
    admitted: bool,
}

impl FetchGate {
    pub(crate) fn claim(scope: &str, epoch: u64) -> Result<Option<Self>> {
        Ok(Control::from_env(scope, "fetch-gate", None, epoch, None)?.map(Self::new))
    }

    pub(crate) fn new(control: Arc<Control>) -> Self {
        Self {
            control,
            settled: false,
            admitted: false,
        }
    }

    pub(crate) async fn wait(
        &mut self,
        gated: bool,
        verdict: impl Future<Output = std::result::Result<(), String>>,
    ) -> std::result::Result<(), String> {
        if !gated {
            self.finish("failed", false, "fetch-has-no-output-gate")?;
            return Err("debug fetch requires an output gate".to_string());
        }
        match tokio::time::timeout_at(self.control.deadline, verdict).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.finish("failed", false, "output-gate-refused")?;
                return Err(error);
            }
            Err(_) => {
                self.finish("timed-out", false, "output-gate-pending")?;
                return Err("debug fetch gate timed out".to_string());
            }
        }
        self.control.enter().map_err(|error| error.to_string())?;
        if self.control.signal("release.json").await.is_err() {
            let status = if Instant::now() >= self.control.deadline {
                "timed-out"
            } else {
                "failed"
            };
            self.finish(status, false, "fetch-not-admitted")?;
            return Err(format!("debug fetch gate {status}"));
        }
        Ok(())
    }

    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.control.deadline
    }

    pub(crate) fn timed_out(&mut self) -> std::result::Result<(), String> {
        self.finish("timed-out", false, "fetch-not-admitted")
    }

    pub(crate) fn admission(&mut self, admitted: bool) -> std::result::Result<(), String> {
        self.finish(
            if admitted { "admitted" } else { "refused" },
            admitted,
            if admitted {
                "dispatch-admitted-not-completed"
            } else {
                "stale-owner"
            },
        )
    }

    fn finish(
        &mut self,
        status: &str,
        admitted: bool,
        reason: &str,
    ) -> std::result::Result<(), String> {
        self.admitted = admitted;
        self.control
            .settle(status, admitted, Some(reason), None)
            .map_err(|error| error.to_string())?;
        self.settled = true;
        Ok(())
    }
}

impl Drop for FetchGate {
    fn drop(&mut self) {
        if !self.settled
            && self
                .control
                .settle("dropped", self.admitted, Some("fetch-future-dropped"), None)
                .is_err()
        {
            tracing::error!(
                event = "fetch_debug_control_failed",
                "debug fetch settlement unavailable"
            );
        }
    }
}

tokio::task_local! { static STARTUP: Arc<Control>; }

pub(crate) async fn post_attach(scope: &str, epoch: u64) -> Result<()> {
    if let Ok(control) = STARTUP.try_with(Arc::clone) {
        ensure!(
            control.config.scope == scope && control.epoch == epoch,
            "debug startup identity mismatch"
        );
        control.enter()?;
        std::future::pending::<()>().await;
    }
    Ok(())
}

pub(crate) async fn startup<T>(
    scope: &str,
    epoch: u64,
    op: u64,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    let control = Control::from_env(scope, "cancel-startup", None, epoch, Some(op))?;
    startup_control(control, future).await
}

pub(crate) async fn startup_control<T>(
    control: Option<Arc<Control>>,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    let Some(control) = control else {
        return future.await;
    };
    let outcome = {
        let mut startup = Box::pin(STARTUP.scope(control.clone(), future));
        match futures_util::future::select(
            startup.as_mut(),
            Box::pin(control.signal("cancel.json")),
        )
        .await
        {
            futures_util::future::Either::Left((result, _)) => Ok(result),
            futures_util::future::Either::Right((signal, _)) => Err(signal),
        }
        // the actual startup future and its pending guards drop before settlement.
    };
    match outcome {
        Ok(result) => {
            control.settle(
                "failed",
                false,
                Some("startup-ended-before-cancellation"),
                None,
            )?;
            result
        }
        Err(signal) => {
            let status = match &signal {
                Ok(()) => "cancelled",
                Err(_) if Instant::now() >= control.deadline => "timed-out",
                Err(_) => "failed",
            };
            control.settle(status, false, Some("startup-future-dropped"), None)?;
            Err(anyhow!("debug allocation startup {status}"))
        }
    }
}

pub(crate) fn capture_destroy(
    engine: &Arc<ContainerEngine>,
    cell: &Arc<CellContainer>,
    scope: &str,
    request: &AllocationRequest,
    epoch: Option<u64>,
) -> Result<bool> {
    let AllocationRequest::Destroy(id) = request else {
        return Ok(false);
    };
    let Some(epoch) = epoch else {
        return Ok(false);
    };
    let Some(control) = Control::from_env(scope, "delay-destroy", Some(id), epoch, None)? else {
        return Ok(false);
    };
    control.enter()?;
    let engine = engine.clone();
    let cell = cell.clone();
    let id = id.clone();
    crate::asyncrt::spawn(async move {
        if delayed_destroy(control, engine, cell, AllocationRequest::Destroy(id))
            .await
            .is_err()
        {
            tracing::error!(
                event = "allocation_debug_control_failed",
                "debug allocation acknowledgement failed"
            );
        }
    })
    .detach();
    Ok(true)
}

pub(crate) async fn delayed_destroy(
    control: Arc<Control>,
    engine: Arc<ContainerEngine>,
    cell: Arc<CellContainer>,
    request: AllocationRequest,
) -> Result<()> {
    if control.signal("release.json").await.is_err() {
        let status = if Instant::now() >= control.deadline {
            "timed-out"
        } else {
            "failed"
        };
        return control.settle(status, false, Some("not-admitted"), None);
    }
    // never substitute the current epoch and never use the epoch-less internal api.
    let receiver = match engine.allocation_request_from_event(cell, request, Some(control.epoch)) {
        Ok(receiver) => receiver,
        Err(error) => {
            let reason =
                if error.to_string() == "allocation event epoch is stale, missing or pending" {
                    "stale-owner"
                } else {
                    "admission-error"
                };
            return control.settle("refused", false, Some(reason), None);
        }
    };
    match tokio::time::timeout_at(control.deadline, receiver).await {
        Ok(Ok(Ok(view))) => control.settle("completed", true, None, Some(&view)),
        Ok(_) => control.settle("failed", true, Some("native-operation-error"), None),
        // the engine still owns admitted work. dropping its receiver does not cancel docker.
        Err(_) => control.settle("timed-out", true, Some("outcome-unknown"), None),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn directory(
        scope: &str,
        mode: &str,
        id: Option<&str>,
        timeout: u64,
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        write(
            dir.path(),
            "control.json",
            json!({"version":1,"nonce":"0123456789abcdef0123456789abcdef","scope":scope,"mode":mode,"allocationId":id,"timeoutMs":timeout}),
        );
        dir
    }

    pub(crate) fn write(dir: &Path, name: &str, value: Value) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))
            .unwrap();
        file.write_all(serde_json::to_string(&value).unwrap().as_bytes())
            .unwrap();
    }

    pub(crate) fn signal(dir: &Path, name: &str) {
        write(
            dir,
            name,
            json!({"version":1,"nonce":"0123456789abcdef0123456789abcdef"}),
        );
    }

    pub(crate) async fn ack(dir: &Path, name: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = std::fs::read(dir.join(name)) {
                    return serde_json::from_slice(&bytes).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn native_effect_debug_fetch_gate_failures_never_claim_admission() {
        for outcome in [
            "timeout",
            "wrong-nonce",
            "dropped",
            "gate-refused",
            "ungated",
        ] {
            let dir = directory("fetch-scope", "fetch-gate", None, 100);
            assert!(
                Control::claim(dir.path(), "foreign", "fetch-gate", None, 9, None)
                    .unwrap()
                    .is_none()
            );
            assert!(!dir.path().join("claimed.json").exists());
            let control = Control::claim(dir.path(), "fetch-scope", "fetch-gate", None, 9, None)
                .unwrap()
                .unwrap();
            let mut gate = FetchGate::new(control);
            if outcome == "wrong-nonce" {
                let mut waiting = Box::pin(gate.wait(true, async { Ok(()) }));
                assert!(futures_util::poll!(&mut waiting).is_pending());
                write(
                    dir.path(),
                    "release.json",
                    json!({"version": 1, "nonce": "ffffffffffffffffffffffffffffffff"}),
                );
                assert!(waiting.await.is_err());
            } else if outcome == "dropped" {
                let mut waiting = Box::pin(gate.wait(true, std::future::pending()));
                assert!(futures_util::poll!(&mut waiting).is_pending());
                drop(waiting);
                drop(gate);
            } else {
                let result = gate
                    .wait(outcome != "ungated", async {
                        if outcome == "gate-refused" {
                            Err("unproven".to_string())
                        } else {
                            Ok(())
                        }
                    })
                    .await;
                assert!(result.is_err());
            }
            let settled = ack(dir.path(), "settled.json").await;
            assert_eq!(settled["admitted"], false);
            assert_eq!(
                settled["status"],
                match outcome {
                    "timeout" => "timed-out",
                    "dropped" => "dropped",
                    _ => "failed",
                }
            );
            assert_eq!(settled["epoch"], 9);
        }
    }

    #[tokio::test]
    async fn native_allocation_debug_controls_selection_bounds_and_signals() {
        let dir = directory("scope", "cancel-startup", None, 100);
        assert!(
            Control::claim(dir.path(), "other", "cancel-startup", None, 8, Some(9))
                .unwrap()
                .is_none()
        );
        assert!(!dir.path().join("claimed.json").exists());
        let control = Control::claim(dir.path(), "scope", "cancel-startup", None, 8, Some(9))
            .unwrap()
            .unwrap();
        control.enter().unwrap();
        assert!(control.signal("cancel.json").await.is_err());
        assert!(
            Control::claim(dir.path(), "scope", "cancel-startup", None, 9, Some(10))
                .unwrap()
                .is_none()
        );
        let dir = directory("scope", "delay-destroy", Some("a"), 1000);
        assert!(
            Control::claim(dir.path(), "scope", "delay-destroy", Some("b"), 1, None)
                .unwrap()
                .is_none()
        );
        let control = Control::claim(dir.path(), "scope", "delay-destroy", Some("a"), 1, None)
            .unwrap()
            .unwrap();
        control.enter().unwrap();
        write(
            dir.path(),
            "release.json",
            json!({"version":1,"nonce":"wrong"}),
        );
        assert!(control.signal("release.json").await.is_err());
        let dir = directory("scope", "cancel-startup", None, 1000);
        let control =
            Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).unwrap();
        startup_control(control, async { Ok(()) }).await.unwrap();
        assert_eq!(ack(dir.path(), "settled.json").await["status"], "failed");
        assert!(!dir.path().join("entered.json").exists());
        for timeout in [0, 99, 30001] {
            let dir = directory("scope", "cancel-startup", None, timeout);
            assert!(
                Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err()
            );
        }
    }

    #[test]
    fn native_allocation_debug_controls_refuse_unsafe_or_ambiguous_files() {
        let dir = directory("scope", "cancel-startup", None, 1000);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dir.path().join("control.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err());
        let dir = directory("scope", "cancel-startup", None, 1000);
        signal(dir.path(), "cancel.json");
        assert!(Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err());
        let dir = directory("scope", "cancel-startup", None, 1000);
        std::os::unix::fs::symlink("control.json", dir.path().join("release.json")).unwrap();
        assert!(Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err());
        for contents in ["{".to_string(), " ".repeat(LIMIT as usize + 1)] {
            let dir = directory("scope", "cancel-startup", None, 1000);
            std::fs::write(dir.path().join("control.json"), contents).unwrap();
            assert!(
                Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err()
            );
        }
        let dir = directory("scope", "cancel-startup", None, 1000);
        let mut config: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("control.json")).unwrap())
                .unwrap();
        config["unexpected"] = json!(true);
        std::fs::write(
            dir.path().join("control.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        assert!(Control::claim(dir.path(), "scope", "cancel-startup", None, 1, Some(1)).is_err());
    }
}
