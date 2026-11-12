#![allow(clippy::disallowed_methods)]

use super::ContainerEngine;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    ApprovalCommit,
    ReleaseWrite,
    ReleaseSync,
    FinalCommit,
    GateUnlink,
    ReleaseUnlink,
    DirectorySync,
    DirectoryRemove,
    ParentSync,
    TombstoneCommit,
}

type Hook = Arc<dyn Fn(Point, bool) -> anyhow::Result<()> + Send + Sync>;

pub(super) struct Control {
    pub(super) source: PathBuf,
    pub(super) host_allowed: AtomicBool,
    pub(super) host_checks: AtomicUsize,
    hook: Mutex<Option<Hook>>,
}

impl Control {
    pub(super) fn new(source: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            source,
            host_allowed: AtomicBool::new(true),
            host_checks: AtomicUsize::new(0),
            hook: Mutex::new(None),
        })
    }

    pub(super) fn set_hook(&self, hook: Option<Hook>) {
        *self.hook.lock().unwrap() = hook;
    }

    pub(super) fn verify_host(&self) -> anyhow::Result<()> {
        self.host_checks.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            self.host_allowed.load(Ordering::SeqCst),
            "simulated host verifier refused admission"
        );
        Ok(())
    }

    pub(super) fn checkpoint(&self, point: Point, after: bool) -> anyhow::Result<()> {
        let hook = self.hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(point, after)?;
        }
        Ok(())
    }
}

static CONTROLS: LazyLock<Mutex<HashMap<PathBuf, Arc<Control>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) struct Registration(PathBuf);

impl Registration {
    pub(super) fn new(journal_directory: &Path, control: Arc<Control>) -> Self {
        let key = std::fs::canonicalize(journal_directory).unwrap();
        assert!(CONTROLS
            .lock()
            .unwrap()
            .insert(key.clone(), control)
            .is_none());
        Self(key)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        CONTROLS.lock().unwrap().remove(&self.0);
    }
}

pub(super) fn for_engine(engine: &ContainerEngine) -> Option<Arc<Control>> {
    lookup(engine.allocations.path.parent()?)
}

pub(super) fn for_directory(directory: &Path) -> Option<Arc<Control>> {
    lookup(directory.parent()?.parent()?)
}

fn lookup(directory: &Path) -> Option<Arc<Control>> {
    let key = std::fs::canonicalize(directory).ok()?;
    CONTROLS.lock().unwrap().get(&key).cloned()
}

pub(super) fn checkpoint(
    engine: &ContainerEngine,
    point: Point,
    after: bool,
) -> anyhow::Result<()> {
    if let Some(control) = for_engine(engine) {
        control.checkpoint(point, after)?;
    }
    Ok(())
}
