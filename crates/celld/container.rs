// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Containers attached to Durable Objects: the engine side of
//! `ctx.container`.
//!
//! A cell of a class named in the deployment's `containers` config owns at
//! most one container, named after the cell, on the node that owns the
//! cell. The Durable Object supervises it through the ops in
//! `js/container.rs`; this module performs the effects against the
//! container engine, which is the Docker Engine API on a unix socket
//! (Podman serves the same API).
//!
//! The container is bound to the cell's ownership on this node, not to its
//! residency: an idle eviction leaves it running under an inactivity timer
//! and the next activation of the same cell reconnects to it by name, which
//! is what Cloudflare does and what the `@cloudflare/containers` class's
//! `sleepAfter` alarm relies on. Every other stop destroys it. The
//! container's disk is ephemeral on Cloudflare too, so a takeover that
//! starts fresh is conformant.
//!
//! Images travel through the bucket. `celld deploy` saves the image the
//! config names as a tar at `deploy/images/<id>.tar`, and a node loads it
//! into its engine the first time a cell of that class starts, so a node
//! never talks to a registry.

#[path = "container_allocation.rs"]
mod allocation;
pub use allocation::{AllocationOptions, AllocationRequest, AllocationView};

use crate::asyncrt;
use crate::docker::{frame_header, Docker, Stream};
use anyhow::{anyhow, Context};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// One `containers[]` entry of a deployment, as the node sees it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub class_name: String,
    /// The image reference the engine starts, `celld-image:<content key>`,
    /// so two deployments of one image share one tar and one load.
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    /// The OCI runtime this class runs under, such as `runsc` (gVisor) for
    /// untrusted code. Overrides the node's `CELLD_CONTAINER_RUNTIME` for
    /// this class; `None` takes the node default. A node whose daemon does
    /// not have the runtime fails every start of the class, so the class
    /// runs only where its isolation is available. celld extends the
    /// Cloudflare config here, which has no per-class runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// The reference every engine holds an image under, from its content key.
/// The key hashes the layer digests and the image config, so an engine
/// that rebuilds identical content under a new id still resolves it.
pub fn image_reference(key: &str) -> String {
    format!("celld-image:{key}")
}

/// The bucket key of one saved image, from its reference.
pub fn image_key(image: &str) -> String {
    format!(
        "deploy/images/{}.tar",
        image.trim_start_matches("celld-image:")
    )
}

/// The resources an instance type reserves. Cloudflare's published table;
/// a name outside it is refused at deploy.
pub fn instance_resources(instance_type: &str) -> Option<(f64, u64)> {
    let gib = 1024 * 1024 * 1024;
    Some(match instance_type {
        "lite" | "dev" => (1.0 / 16.0, 256 * 1024 * 1024),
        "basic" => (0.25, gib),
        "standard-1" | "standard" => (0.5, 4 * gib),
        "standard-2" => (1.0, 6 * gib),
        "standard-3" => (2.0, 8 * gib),
        "standard-4" => (4.0, 12 * gib),
        _ => return None,
    })
}

/// The instance type of a class that declares none, as on Cloudflare.
const DEFAULT_INSTANCE_TYPE: &str = "dev";

/// The resolvers a container gets when it runs under a non-default runtime
/// and the operator set none. gVisor's network stack does not reach
/// Docker's embedded resolver at `127.0.0.11`, so a container under it
/// cannot resolve a hostname though it reaches the Internet by address; a
/// public resolver, which the fence permits, restores name resolution.
/// `CELLD_CONTAINER_DNS` overrides this.
const DEFAULT_CONTAINER_DNS: &[&str] = &["1.1.1.1", "1.0.0.1"];

/// The memory a container of this instance type reserves on the node. A
/// class that declares none gets the default type, as `create_and_start`
/// does. An unknown name is refused at deploy, so a running container
/// always maps; this returns 0 for a name that somehow does not, which
/// undercounts rather than blocks a sample.
pub fn instance_memory_bytes(instance_type: Option<&str>) -> u64 {
    instance_resources(instance_type.unwrap_or(DEFAULT_INSTANCE_TYPE))
        .map(|(_, memory)| memory)
        .unwrap_or(0)
}

/// The memory this node commits to its running containers, for the node's
/// capacity accounting. Zero when no engine has connected. See
/// `celld_logic::pressure::Load::container_reserved_bytes` for why the node
/// counts the cap rather than the container's live usage.
pub fn reserved_memory_bytes() -> u64 {
    engine_if_ready().map_or(0, |engine| engine.reserved_memory_bytes())
}

/// This node's running containers per class, published in the node lease so
/// peers can sum a class's instances across the fleet for `max_instances`.
/// Empty when no engine has connected.
pub fn running_instances_by_class() -> std::collections::BTreeMap<String, u64> {
    engine_if_ready().map_or_else(Default::default, |engine| {
        engine.running_instances_by_class()
    })
}
/// Processes one container can hold. Cloudflare publishes no number; this
/// is room for a build tool's process tree and far short of a fork bomb.
const PIDS_LIMIT: u64 = 1024;
/// The host interfaces of the two bridges, named so the fence can address
/// them; Docker's default `br-<id>` changes with every recreation.
const OPEN_BRIDGE: &str = "celld0";
const INTERNAL_BRIDGE: &str = "celld1";
const BRIDGE_NAME_OPTION: &str = "com.docker.network.bridge.name";
/// The fence, installed on the node from a one-shot privileged container of
/// the `celld-fence` image: a container may reach the Internet and nothing
/// of the node's own. Hooks before Docker's own chains (priority filter -
/// 10) so a verdict here is final. Input: no new connection from a bridge
/// to the node itself, which is where the internal listener and the public
/// listener bind; replies to connections the node opened still pass.
/// Forward: nothing to the private ranges, where the fleet, the VPC, and
/// the metadata service live. Rules on the host side of the bridge cover
/// every runtime, gVisor included, and no process inside a container can
/// see them, let alone remove them.
const FENCE_RULES: &str = r#"table inet celld
delete table inet celld
table inet celld {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname { "celld0", "celld1" } ct state established,related accept
    iifname { "celld0", "celld1" } reject
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname { "celld0", "celld1" } ip daddr { 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } reject
    iifname { "celld0", "celld1" } ip6 daddr { fe80::/10, fc00::/7 } reject
  }
}
"#;

/// Docker's bridge option that forbids traffic between two containers on
/// the same bridge. The node still reaches every container, because it
/// speaks from the host side of the bridge.
const ICC_OPTION: &str = "com.docker.network.bridge.enable_icc";

/// How a cell stop treats its container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// An idle eviction: keep the container under its inactivity timer.
    Keep,
    /// Ownership leaves this node, or the cell is reset: destroy it.
    Destroy,
}

/// The default inactivity window after an idle eviction when the object
/// never set one. The `@cloudflare/containers` alarm wakes the object well
/// inside this to enforce `sleepAfter`, so this is the backstop for an
/// object that never wakes, not the policy.
const DEFAULT_INACTIVITY: Duration = Duration::from_secs(10 * 60);

/// Environment every container sees. The values mirror workerd's local
/// engine: applications read the names, never the values.
const DEFAULT_ENV: &[&str] = &[
    "CLOUDFLARE_COUNTRY_A2=XX",
    "CLOUDFLARE_DEPLOYMENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "CLOUDFLARE_LOCATION=loc01",
    "CLOUDFLARE_REGION=REGN",
    "CLOUDFLARE_APPLICATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
];

pub struct StartParams {
    pub entrypoint: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
    pub enable_internet: bool,
    pub labels: Vec<(String, String)>,
}

#[derive(Default)]
struct CellState {
    running: bool,
    /// Where the node dials the container: the bridge address on Linux,
    /// the published loopback ports elsewhere.
    address: Address,
    inactivity: Option<Duration>,
    /// The pending destroy after an idle eviction. Dropping it cancels.
    sweeper: Option<asyncrt::TaskHandle<()>>,
    /// Bumped per start so a wait from a previous run cannot report for
    /// this one.
    run: u64,
    allocation_container: Option<String>,
    allocation_admitted: bool,
    activation_epoch: u64,
    activation_serial: u64,
    activation_pending: bool,
    startup: Option<StartupOwnership>,
    legacy_start: Option<LegacyStart>,
    inactivity_epoch: u64,
    allocation_sweeper: Option<tokio_util::sync::CancellationToken>,
}

#[derive(Clone, Debug, Default)]
enum Address {
    #[default]
    None,
    Ip(String),
    Published(HashMap<u16, u16>),
}

pub struct CellContainer {
    scope: String,
    name: String,
    spec: Arc<ContainerSpec>,
    state: Mutex<CellState>,
    legacy_lifecycle: Arc<tokio::sync::Mutex<()>>,
    /// Processes `exec()` started in this container. An object drops one
    /// after `output()`; the rest go with the container.
    processes: Mutex<Vec<u64>>,
    /// The exit of the current run, `None` while it runs. `Some(Err)` is
    /// an engine failure the wait could not attribute to the process.
    /// Written with `send_replace`: a plain `send` discards the value
    /// while nobody subscribes, and `monitor()` usually subscribes late.
    exit: watch::Sender<Option<(u64, Result<i64, String>)>>,
}

impl CellContainer {
    pub fn running(&self) -> bool {
        self.state.lock().unwrap().running
    }

    /// `host:port` for `getTcpPort(port)`.
    pub fn address(&self, port: u16) -> Result<String, String> {
        let state = self.state.lock().unwrap();
        if !state.running {
            return Err("the container is not running".to_string());
        }
        match &state.address {
            Address::Ip(ip) => Ok(format!("{ip}:{port}")),
            Address::Published(ports) => ports
                .get(&port)
                .map(|host| format!("127.0.0.1:{host}"))
                .ok_or_else(|| {
                    format!(
                        "The container is not listening on port {port}: on this platform a port \
                         must be declared with EXPOSE in the image"
                    )
                }),
            Address::None => Err(format!("The container is not listening on port {port}")),
        }
    }

    pub fn set_inactivity(&self, duration: Duration) {
        self.state.lock().unwrap().inactivity = Some(duration);
    }

    /// Open the next run, synchronously, before the start is even queued.
    /// The object's `start()` returns at once and its `monitor()` follows
    /// immediately, so the run they both mean must exist before either
    /// effect runs, or the monitor would find the previous run's exit and
    /// report the new container dead on arrival.
    pub fn begin_run(&self) -> u64 {
        let mut state = self.state.lock().unwrap();
        state.run += 1;
        state.running = true;
        state.address = Address::None;
        let run = state.run;
        drop(state);
        self.exit.send_replace(None);
        run
    }

    /// The run `monitor()` waits on: the newest one.
    pub fn current_run(&self) -> u64 {
        self.state.lock().unwrap().run
    }
}

#[derive(Clone)]
pub struct ContainerActivation {
    cell: Arc<CellContainer>,
    epoch: u64,
    serial: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LegacyStart {
    serial: u64,
    run: u64,
}

#[derive(Clone)]
struct StartupOwnership {
    epoch: u64,
    serial: u64,
    native: bool,
    allocation: Option<String>,
    legacy_target: Option<String>,
    legacy_start: Option<LegacyStart>,
    legacy_start_pending: bool,
}

pub struct PendingContainerActivation {
    engine: Arc<ContainerEngine>,
    activation: ContainerActivation,
    legacy_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    inserted: bool,
    committed: bool,
}

impl PendingContainerActivation {
    pub fn commit(mut self) -> ContainerActivation {
        let activation = self.activation.clone();
        let _cells = self.engine.cells.lock().unwrap();
        let mut state = activation.cell.state.lock().unwrap();
        // startup runs no container handler. authority transfers only with the runtime handle.
        state.activation_epoch = activation.epoch;
        state.activation_serial = activation.serial;
        state.activation_pending = false;
        state.startup = None;
        state.allocation_admitted = true;
        state.sweeper = None;
        if let Some(cancel) = state.allocation_sweeper.take() {
            cancel.cancel();
        }
        state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
        drop(state);
        self.committed = true;
        activation
    }
}

impl Drop for PendingContainerActivation {
    fn drop(&mut self) {
        let cell = &self.activation.cell;
        let mut cells = self.engine.cells.lock().unwrap();
        if !self.committed {
            cell.state.lock().unwrap().activation_pending = false;
        }
        // observation owns no workload. retain prior authority, timers and journalled cleanup.
        // keep recovered handles and their exit observers, even when startup did not commit.
        // discard only a new handle with no journalled responsibility.
        if !self.committed
            && self.inserted
            && self
                .engine
                .allocations
                .native_scope(&cell.scope)
                .is_ok_and(|native| !native)
            && self
                .engine
                .allocations
                .legacy_record(&cell.scope)
                .is_ok_and(|record| record.is_none())
            && cells
                .get(&cell.scope)
                .is_some_and(|current| Arc::ptr_eq(current, cell))
        {
            cells.remove(&cell.scope);
        }
        // a timer or fence may already own cleanup while attachment holds the guard.
        // transfer that guard to the executor, never invent destruction on startup failure.
        let cleanup = self.engine.allocations.legacy_record(&cell.scope);
        if matches!(cleanup, Ok(Some(ref record)) if record.cleanup.is_some() && record.phase != "idle")
        {
            if let Some(guard) = self.legacy_guard.take() {
                self.engine.resume_legacy_cleanup(cell.clone(), guard);
            }
        }
    }
}

pub struct ContainerRelease {
    activation: ContainerActivation,
    run: u64,
    mode: Release,
    native: bool,
    allocation: Option<String>,
}

fn verify_legacy_identity(
    info: &Value,
    record: &allocation::LegacyRecord,
    node: &str,
) -> anyhow::Result<()> {
    let labels = &info["Config"]["Labels"];
    anyhow::ensure!(
        record.target.is_some()
            && info["Id"].as_str() == record.target.as_deref()
            && info["Name"].as_str()
                == Some(format!("/{}", container_name(node, &record.scope)).as_str())
            && labels["celld.node"].as_str() == Some(node)
            && labels["celld.cell"].as_str() == Some(record.scope.as_str())
            && labels["celld.class"].as_str() == Some(record.spec.class_name.as_str())
            && labels.get("celld.allocation.attempt").is_none()
            && labels.get("celld.allocation.id").is_none(),
        "legacy target ownership mismatch"
    );
    Ok(())
}

enum LegacyOperation {
    Start {
        run: u64,
        params: StartParams,
    },
    Destroy {
        owner: Option<allocation::LegacyCleanup>,
    },
}

pub struct ContainerEngine {
    /// See `Config::runtime`.
    runtime: Option<String>,
    /// See `Config::dns`.
    dns: Vec<String>,
    /// The absolute path of the container resolv.conf this engine wrote and
    /// bind-mounts; `None` when it could not be written.
    resolv_conf: Option<PathBuf>,
    docker: Docker,
    node: String,
    bucket: Option<crate::bucket::Bucket>,
    /// Per-image load lock, so two cells of one class starting together
    /// load the tar once.
    images: Mutex<HashMap<String, Arc<tokio::sync::Mutex<bool>>>>,
    cells: Mutex<HashMap<String, Arc<CellContainer>>>,
    networks: tokio::sync::Mutex<Option<(String, String)>>,
    /// Whether this process has installed the fence on the node's bridges.
    fenced: tokio::sync::Mutex<bool>,
    lifecycle: tokio::sync::Mutex<()>,
    allocations: allocation::Journal,
    allocation_slots: Arc<tokio::sync::Semaphore>,
    legacy_slots: Arc<tokio::sync::Semaphore>,
    allocation_wait: Duration,
    #[cfg(test)]
    native_ownership_for_test: Mutex<Option<Arc<crate::ownership_store::BucketOwnership>>>,
}

/// What the runtime told this module about the node: set once at start.
struct Config {
    node: String,
    bucket: Option<crate::bucket::Bucket>,
    /// `CELLD_CONTAINER_RUNTIME`: the OCI runtime every container starts
    /// under, such as `runsc` (gVisor) or `kata` (a VM). `None` is the
    /// daemon's default, which is `runc` unless the operator changed it. A
    /// class can override it, see `ContainerSpec::runtime`.
    runtime: Option<String>,
    /// `CELLD_CONTAINER_DNS`: the resolvers a container gets, overriding
    /// `DEFAULT_CONTAINER_DNS`. Empty takes the default when a runtime is in
    /// use and the daemon's otherwise.
    dns: Vec<String>,
    /// The node's state directory. celld writes the container resolv.conf
    /// here and bind-mounts it, so the path must be the same on the host as
    /// celld sees it; a self-hosted node runs celld as a host process, and
    /// the lab mounts the directory one-to-one.
    data_dir: PathBuf,
}

static CONFIG: RwLock<Option<Config>> = RwLock::new(None);
/// The deployment's container classes. Replaced on every generation swap;
/// a running container keeps the spec it started with.
static SPECS: RwLock<Vec<Arc<ContainerSpec>>> = RwLock::new(Vec::new());
/// The deployment's `celld-fence` image; see `Manifest::fence_image`.
static FENCE_IMAGE: RwLock<Option<String>> = RwLock::new(None);
/// The engine, connected on first use. A node whose deployment declares no
/// container class never opens the socket.
static ENGINE: tokio::sync::OnceCell<Arc<ContainerEngine>> = tokio::sync::OnceCell::const_new();

pub fn configure(node: String, bucket: Option<crate::bucket::Bucket>, data_dir: PathBuf) {
    let runtime = std::env::var("CELLD_CONTAINER_RUNTIME")
        .ok()
        .filter(|runtime| !runtime.is_empty());
    let dns = std::env::var("CELLD_CONTAINER_DNS")
        .unwrap_or_default()
        .split(',')
        .map(|resolver| resolver.trim().to_string())
        .filter(|resolver| !resolver.is_empty())
        .collect();
    *CONFIG.write().unwrap() = Some(Config {
        node,
        bucket,
        runtime,
        dns,
        data_dir,
    });
}

pub fn install_specs(specs: Vec<ContainerSpec>, fence_image: Option<String>) {
    *SPECS.write().unwrap() = specs.into_iter().map(Arc::new).collect();
    *FENCE_IMAGE.write().unwrap() = fence_image;
}

pub fn spec(class: &str) -> Option<Arc<ContainerSpec>> {
    SPECS
        .read()
        .unwrap()
        .iter()
        .find(|spec| spec.class_name == class)
        .cloned()
}

/// The engine, connecting on the first call. A failure is returned rather
/// than cached, so a daemon that comes up later is found by the next call.
pub async fn engine() -> anyhow::Result<Arc<ContainerEngine>> {
    ENGINE
        .get_or_try_init(|| async {
            let (node, bucket, runtime, dns, data_dir) = {
                let config = CONFIG.read().unwrap();
                let config = config.as_ref().ok_or_else(|| {
                    anyhow!("the container engine is not configured on this node")
                })?;
                (
                    config.node.clone(),
                    config.bucket.clone(),
                    config.runtime.clone(),
                    config.dns.clone(),
                    config.data_dir.clone(),
                )
            };
            let docker = Docker::discover().ok_or_else(|| {
                anyhow!(
                    "no container engine: set DOCKER_HOST to a unix socket, or run a Docker or \
                     Podman daemon on this node"
                )
            })?;
            Ok(Arc::new(
                ContainerEngine::connect(docker, node, bucket, runtime, dns, data_dir).await?,
            ))
        })
        .await
        .cloned()
}

/// The engine only if a previous call connected it.
pub fn engine_if_ready() -> Option<Arc<ContainerEngine>> {
    ENGINE.get().cloned()
}

/// Destroy every container of this node at process exit. A preserve
/// shutdown (`celld dev` on Ctrl-C) keeps its cells resident and stops
/// none of them, and a handoff cut by the deadline leaves cells behind
/// too; without this their containers ran on until the next start of the
/// same node reaped them, invisible to the object that owned them.
pub async fn shutdown() {
    let Some(engine) = engine_if_ready() else {
        return;
    };
    if let Err(error) = engine.reap().await {
        tracing::warn!(
            event = "container_shutdown_reap_failed",
            error = %format!("{error:#}"),
            "containers of this node may still be running"
        );
    }
}

/// Connect and load every image of the installed specs, ahead of the
/// first cell that needs one. Failures are logged: a node without an
/// engine still serves every other class, and the container class fails
/// at its first `start()` with the same message.
pub async fn prewarm() {
    let engine = match engine().await {
        Ok(engine) => engine,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "containers are unavailable on this node");
            return;
        }
    };
    if let Err(error) = engine.ensure_fence().await {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the container bridges are not fenced; no container starts on this node"
        );
    }
    let specs = SPECS.read().unwrap().clone();
    for spec in specs {
        if let Err(error) = engine.ensure_image(&spec.image).await {
            tracing::warn!(
                class = %spec.class_name,
                image = %spec.image,
                error = %format!("{error:#}"),
                "container image is unavailable"
            );
        }
    }
}

impl ContainerEngine {
    /// Connect to the engine and reap every container a previous process
    /// of this node left behind. A restarted node cannot know which of its
    /// containers still belong to cells it will own again, and a container
    /// whose object has lost track of it is a leak, so a restart starts
    /// clean. The next `start()` of each object creates a fresh one.
    pub async fn connect(
        docker: Docker,
        node: String,
        bucket: Option<crate::bucket::Bucket>,
        runtime: Option<String>,
        dns: Vec<String>,
        data_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        // Write the resolv.conf once, to bind into every container that runs
        // under a non-default runtime. gVisor cannot reach Docker's embedded
        // resolver, so a bind-mounted file with a public resolver, which the
        // fence permits, is the only resolv.conf the container can use.
        let resolvers: Vec<String> = if dns.is_empty() {
            DEFAULT_CONTAINER_DNS
                .iter()
                .map(|r| r.to_string())
                .collect()
        } else {
            dns.clone()
        };
        let resolv_conf = {
            let path = data_dir.join("container-resolv.conf");
            let body: String = resolvers
                .iter()
                .map(|resolver| format!("nameserver {resolver}\n"))
                .collect();
            let fs = asyncrt::fs();
            match fs
                .create_dir_all(&data_dir)
                .and_then(|()| fs.write(&path, body.as_bytes()))
            {
                Ok(()) => Some(path),
                Err(error) => {
                    tracing::warn!(event = "container_resolv_write_failed", %error);
                    None
                }
            }
        };
        let allocations = allocation::Journal::open(&data_dir, &node)?;
        let docker = docker.with_response_limit(1024 * 1024);
        let engine = Self {
            docker,
            node,
            bucket,
            runtime,
            dns,
            resolv_conf,
            images: Mutex::new(HashMap::new()),
            cells: Mutex::new(HashMap::new()),
            networks: tokio::sync::Mutex::new(None),
            fenced: tokio::sync::Mutex::new(false),
            lifecycle: tokio::sync::Mutex::new(()),
            allocations,
            allocation_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            legacy_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            allocation_wait: allocation::DEADLINE,
            #[cfg(test)]
            native_ownership_for_test: Mutex::new(None),
        };
        engine.reap().await?;
        Ok(engine)
    }

    pub fn socket(&self) -> &std::path::Path {
        self.docker.socket()
    }

    async fn reap(&self) -> anyhow::Result<()> {
        // connect calls this before publishing the engine. attached scopes are never reaped.
        self.allocations.check()?;
        let filters = json!({ "label": [format!("celld.node={}", self.node)] }).to_string();
        let reply = self
            .allocation_call(
                "GET",
                &format!(
                    "/containers/json?all=true&filters={}",
                    percent_encoding::utf8_percent_encode(
                        &filters,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                None,
            )
            .await?;
        anyhow::ensure!(reply.status.is_success(), "container inventory unavailable");
        let list = reply.json()?;
        anyhow::ensure!(list.is_array(), "invalid container inventory");
        for entry in list.as_array().into_iter().flatten() {
            // allocation attempts are reconciled only by their durable journal.
            if entry.pointer("/Labels/celld.allocation.attempt").is_some() {
                self.allocations.validate_inventory(entry)?;
                continue;
            }
            if entry
                .pointer("/Labels/celld.cell")
                .and_then(Value::as_str)
                .map(|scope| self.allocations.native_scope(scope))
                .transpose()?
                .unwrap_or(false)
            {
                continue;
            }
            let (Some(id), Some(scope), Some(class)) = (
                entry["Id"].as_str(),
                entry["Labels"]["celld.cell"].as_str(),
                entry["Labels"]["celld.class"].as_str(),
            ) else {
                continue;
            };
            if entry["Labels"]["celld.node"].as_str() != Some(self.node.as_str())
                || !self.allocations.owns_legacy(scope, class, id)?
            {
                continue;
            }
            if self.cell(scope).is_some() {
                continue;
            }
            let Some(mut record) = self.allocations.legacy_record(scope)? else {
                continue;
            };
            let observed = match self.owned_legacy(&record).await {
                Ok(observed) => observed,
                Err(_) => continue,
            };
            record.phase = "deleting".to_string();
            self.allocations.save_legacy(&mut record)?;
            if observed.is_some() {
                let removed = self
                    .allocation_call("DELETE", &format!("/containers/{id}?force=true"), None)
                    .await;
                if !removed
                    .is_ok_and(|reply| reply.status.is_success() || reply.status.as_u16() == 404)
                {
                    tracing::warn!(
                        event = "legacy_reaper_cleanup_unresolved",
                        "exact-target cleanup intent retained"
                    );
                    continue;
                }
            }
            record.phase = "idle".to_string();
            record.target = None;
            self.allocations.save_legacy(&mut record)?;
        }
        Ok(())
    }

    /// Make the class's image present in the engine, loading it from the
    /// bucket when it is not. Idempotent and serialized per image.
    pub async fn ensure_image(&self, image: &str) -> anyhow::Result<()> {
        let lock = self
            .images
            .lock()
            .unwrap()
            .entry(image.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(false)))
            .clone();
        let mut loaded = lock.lock().await;
        if *loaded {
            return Ok(());
        }
        let reply = self
            .docker
            .call("GET", &format!("/images/{image}/json"), None)
            .await?;
        if reply.status.is_success() {
            tracing::info!(image, "container image present in the engine");
            *loaded = true;
            return Ok(());
        }
        let bucket = self
            .bucket
            .as_ref()
            .ok_or_else(|| anyhow!("image {image} is not present in the container engine"))?;
        let key = image_key(image);
        let (tar, _) = bucket.get(&key).await?.ok_or_else(|| {
            anyhow!("image {image} is not in the bucket at {key}; run `celld deploy`")
        })?;
        let bytes = tar.len();
        let reply = self
            .docker
            .post_octets("/images/load?quiet=true", tar, "load image")
            .await?;
        tracing::info!(
            image,
            bytes,
            answer = %String::from_utf8_lossy(&reply.body).trim_end(),
            "container image loaded from the bucket"
        );
        *loaded = true;
        Ok(())
    }

    /// The two bridges every container joins: one with egress, one
    /// without. Docker implements an internal network by omitting the
    /// masquerade rule and the default route; the node still reaches the
    /// bridge address, which is all ingress needs.
    async fn networks(&self) -> anyhow::Result<(String, String)> {
        let mut guard = self.networks.lock().await;
        if let Some(names) = guard.as_ref() {
            return Ok(names.clone());
        }
        for (name, internal) in [("celld", false), ("celld-internal", true)] {
            // A bridge keeps the options it was created with, so one from
            // before containers were isolated from each other is replaced.
            // The replacement fails while a container is attached, which a
            // node start after its reap never has; a failure keeps the old
            // bridge and says so rather than refusing every container.
            let current = self
                .docker
                .call("GET", &format!("/networks/{name}"), None)
                .await?;
            if current.status.is_success() {
                let bridge = if internal {
                    INTERNAL_BRIDGE
                } else {
                    OPEN_BRIDGE
                };
                let current_options = current
                    .json()
                    .ok()
                    .and_then(|network| network.get("Options").cloned())
                    .unwrap_or(Value::Null);
                let option = |key: &str| current_options.get(key).and_then(Value::as_str);
                if option(ICC_OPTION) == Some("false") && option(BRIDGE_NAME_OPTION) == Some(bridge)
                {
                    continue;
                }
                let removed = self
                    .docker
                    .call("DELETE", &format!("/networks/{name}"), None)
                    .await?;
                if !removed.status.is_success() {
                    tracing::warn!(
                        network = name,
                        error = %removed.message(),
                        "the container bridge predates container isolation and is in use; \
                         containers on it can reach each other until the node restarts idle"
                    );
                    continue;
                }
            }
            let reply = self
                .docker
                .call(
                    "POST",
                    "/networks/create",
                    Some(json!({
                        "Name": name,
                        "Driver": "bridge",
                        "Internal": internal,
                        "Options": {
                            ICC_OPTION: "false",
                            BRIDGE_NAME_OPTION: if internal { INTERNAL_BRIDGE } else { OPEN_BRIDGE },
                        },
                    })),
                )
                .await?;
            // 409: it exists, which is the steady state.
            if !reply.status.is_success() && reply.status.as_u16() != 409 {
                return Err(anyhow!(
                    "create network {name} failed with [{}] {}",
                    reply.status.as_u16(),
                    reply.message()
                ));
            }
        }
        let names = ("celld".to_string(), "celld-internal".to_string());
        *guard = Some(names.clone());
        Ok(names)
    }

    /// Install the fence on the node's bridges, once per process. Every
    /// container start waits on this and fails when it fails: a node that
    /// cannot fence its bridges runs no container, because an unfenced
    /// container can reach the node's internal listener and the cloud's
    /// metadata service. The rules live in the kernel and outlive this
    /// process; a restart re-applies them, which is idempotent.
    fn require_verified_fence(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.fenced.try_lock().is_ok_and(|fenced| *fenced),
            "container fence is not already verified"
        );
        Ok(())
    }

    pub async fn ensure_fence(&self) -> anyhow::Result<()> {
        let mut fenced = self.fenced.lock().await;
        if *fenced {
            return Ok(());
        }
        let image = FENCE_IMAGE.read().unwrap().clone().ok_or_else(|| {
            anyhow!(
                "this deployment has no fence image; deploy it again with this celld, which \
                 saves the celld-fence image beside the container images"
            )
        })?;
        self.ensure_image(&image).await?;
        self.networks().await?;
        let body = json!({
            "Image": image,
            "Env": [format!("CELLD_NFT={FENCE_RULES}")],
            "Cmd": ["sh", "-c", "printf '%s' \"$CELLD_NFT\" | nft -f -"],
            "Labels": { "celld.node": self.node, "celld.fence": "1" },
            "HostConfig": { "NetworkMode": "host", "CapAdd": ["NET_ADMIN"] },
        });
        let created = self
            .docker
            .expect(
                "POST",
                "/containers/create",
                Some(body),
                "create fence container",
            )
            .await?
            .json()?;
        let id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("create fence container answered without an id"))?
            .to_string();
        let outcome = async {
            self.docker
                .expect(
                    "POST",
                    &format!("/containers/{id}/start"),
                    None,
                    "start fence container",
                )
                .await?;
            let waited = self
                .docker
                .expect(
                    "POST",
                    &format!("/containers/{id}/wait"),
                    None,
                    "wait fence container",
                )
                .await?
                .json()?;
            let code = waited
                .get("StatusCode")
                .and_then(Value::as_i64)
                .unwrap_or(-1);
            if code != 0 {
                let logs = self.logs(&id).await.unwrap_or_default();
                return Err(anyhow!(
                    "the fence container exited with {code}: {}",
                    logs.trim()
                ));
            }
            Ok(())
        }
        .await;
        let _ = self
            .docker
            .call("DELETE", &format!("/containers/{id}?force=true"), None)
            .await;
        outcome.context("fence the container bridges")?;
        tracing::info!(
            event = "container_bridges_fenced",
            bridges = format!("{OPEN_BRIDGE},{INTERNAL_BRIDGE}"),
            "containers can reach the Internet and nothing of the node's own"
        );
        *fenced = true;
        Ok(())
    }

    /// Both output streams of a stopped container, for an error message.
    async fn logs(&self, id: &str) -> anyhow::Result<String> {
        let reply = self
            .docker
            .expect(
                "GET",
                &format!("/containers/{id}/logs?stdout=true&stderr=true"),
                None,
                "container logs",
            )
            .await?;
        let mut text = Vec::new();
        let mut rest: &[u8] = &reply.body;
        while rest.len() >= 8 {
            let (_, length) = frame_header(rest[..8].try_into().unwrap());
            let end = (8 + length).min(rest.len());
            text.extend_from_slice(&rest[8..end]);
            rest = &rest[end..];
        }
        Ok(String::from_utf8_lossy(&text).into_owned())
    }

    /// The cell's container handle, adopting a container a previous
    /// activation on this node left running. Called at cell start for a
    /// class with a spec; the object's `running` reads the answer.
    pub async fn attach(
        self: &Arc<Self>,
        scope: &str,
        class: &str,
    ) -> anyhow::Result<Arc<CellContainer>> {
        Ok(self.attach_activation(scope, class, 0).await?.cell)
    }

    pub async fn attach_activation(
        self: &Arc<Self>,
        scope: &str,
        class: &str,
        epoch: u64,
    ) -> anyhow::Result<ContainerActivation> {
        Ok(self.attach_pending(scope, class, epoch).await?.commit())
    }

    pub async fn attach_pending(
        self: &Arc<Self>,
        scope: &str,
        class: &str,
        epoch: u64,
    ) -> anyhow::Result<PendingContainerActivation> {
        self.allocations.check()?;
        let spec = spec(class).ok_or_else(|| anyhow!("class {class} has no container"))?;
        let (cell, inserted, serial) = {
            let mut cells = self.cells.lock().unwrap();
            let inserted = !cells.contains_key(scope);
            let cell = cells.entry(scope.to_string()).or_insert_with(|| {
                Arc::new(CellContainer {
                    scope: scope.to_string(),
                    name: container_name(&self.node, scope),
                    spec,
                    state: Mutex::new(CellState::default()),
                    legacy_lifecycle: Arc::new(tokio::sync::Mutex::new(())),
                    processes: Mutex::new(Vec::new()),
                    exit: watch::channel(None).0,
                })
            });
            let mut state = cell.state.lock().unwrap();
            anyhow::ensure!(
                !state.activation_pending,
                "container attachment is still pending"
            );
            anyhow::ensure!(
                epoch >= state.activation_epoch
                    && state
                        .startup
                        .as_ref()
                        .is_none_or(|owner| epoch >= owner.epoch),
                "stale container attachment epoch"
            );
            let serial = state
                .activation_serial
                .checked_add(1)
                .expect("container activation counter exhausted");
            let legacy = self.allocations.legacy_record(scope)?;
            // retain exact cleanup responsibility before admission can fail or be cancelled.
            state.startup = Some(StartupOwnership {
                epoch,
                serial: state.activation_serial,
                native: self.allocations.native_scope(scope)?,
                allocation: self.allocations.active(scope)?.map(|record| record.id),
                legacy_target: legacy.as_ref().and_then(|record| record.target.clone()),
                legacy_start: state.legacy_start,
                legacy_start_pending: state.legacy_start.is_some()
                    && legacy.as_ref().is_some_and(|record| {
                        matches!(
                            record.phase.as_str(),
                            "preparing" | "creating" | "starting" | "deleting"
                        )
                    }),
            });
            state.activation_pending = true;
            (cell.clone(), inserted, serial)
        };
        let activation = ContainerActivation {
            cell: cell.clone(),
            epoch,
            serial,
        };
        let mut pending = PendingContainerActivation {
            engine: self.clone(),
            activation,
            legacy_guard: None,
            inserted,
            committed: false,
        };
        pending.legacy_guard = Some(
            cell.legacy_lifecycle
                .clone()
                .try_lock_owned()
                .map_err(|_| anyhow!("legacy lifecycle operation is still pending"))?,
        );
        anyhow::ensure!(
            self.allocations
                .legacy_record(scope)?
                .is_none_or(|record| record.phase != "creating"),
            "legacy create outcome remains unresolved"
        );
        let _guard = asyncrt::timeout(self.allocation_wait, self.lifecycle.lock())
            .await
            .map_err(|_| anyhow!("container attachment deadline exceeded"))?;
        if self.allocations.native_scope(scope)? {
            if let Some(record) = self.allocations.active(scope)? {
                self.observe_allocation(&cell, record).await?;
            }
            return Ok(pending);
        }
        // legacy observation owns only this cell, never the global native lifecycle lock.
        drop(_guard);
        let running = self.inspect_running(&cell).await?;
        // A container this handle did not start, left running by an
        // earlier owner of the name: give it a run so `monitor()` has an
        // exit to wait for. The run opens before the address lands, because
        // opening one clears it.
        let adopted = running.is_some() && !cell.running();
        if adopted {
            let run = cell.begin_run();
            self.watch_exit(&cell, run);
        }
        let mut state = cell.state.lock().unwrap();
        state.running = running.is_some();
        state.address = running.unwrap_or_default();
        drop(state);
        Ok(pending)
    }

    /// The cell's handle, if the cell started on this node.
    pub fn cell(&self, scope: &str) -> Option<Arc<CellContainer>> {
        self.cells.lock().unwrap().get(scope).cloned()
    }

    /// The memory the node's running containers reserve, summed over their
    /// instance-type caps. A cell whose container is not running reserves
    /// nothing: a stopped container holds no memory, and an idle eviction
    /// stops it before the sample would count it.
    // experimental accounting retains commitments until exact teardown, even after process exit.
    pub fn reserved_memory_bytes(&self) -> u64 {
        let Ok(commitments) = self.allocations.commitments() else {
            return u64::MAX;
        };
        commitments
            .iter()
            .map(|spec| instance_memory_bytes(spec.instance_type.as_deref()))
            .fold(0u64, u64::saturating_add)
    }

    /// This node's running containers per class.
    fn running_instances_by_class(&self) -> std::collections::BTreeMap<String, u64> {
        let mut counts = std::collections::BTreeMap::new();
        match self.allocations.commitments() {
            Ok(commitments) => {
                for spec in commitments {
                    *counts.entry(spec.class_name).or_insert(0) += 1;
                }
            }
            Err(_) => {
                for spec in SPECS.read().unwrap().iter() {
                    counts.insert(spec.class_name.clone(), u64::MAX);
                }
            }
        }
        counts
    }

    /// Refuse a start that would put the class over its fleet-wide
    /// `max_instances`. The fleet count is this node's own running
    /// containers of the class, read live, plus every peer's count from the
    /// shared capacity sample; `begin_run` already marked the starting cell
    /// running, so the live count includes it. A class with no
    /// `max_instances`, or a node with no bucket to read the sample from as
    /// under `celld dev`, has no fleet ceiling. See
    /// [`crate::ownership_store::fleet_class_instances`] for the staleness
    /// the sample admits.
    async fn enforce_instance_ceiling(&self, cell: &CellContainer) -> anyhow::Result<()> {
        let Some(max) = cell.spec.max_instances else {
            return Ok(());
        };
        let class = &cell.spec.class_name;
        self.allocations.check()?;
        let here = self
            .running_instances_by_class()
            .get(class)
            .copied()
            .unwrap_or(0);
        let elsewhere = match &self.bucket {
            Some(bucket) => {
                crate::ownership_store::fleet_class_instances(bucket, class, &self.node).await
            }
            None => 0,
        };
        anyhow::ensure!(
            here.saturating_add(elsewhere) <= max,
            "container class {class} is at its max_instances limit of {max}: \
             {here} on this node and {elsewhere} on other nodes",
        );
        Ok(())
    }

    async fn owned_legacy(
        &self,
        record: &allocation::LegacyRecord,
    ) -> anyhow::Result<Option<Value>> {
        let id = record
            .target
            .as_deref()
            .ok_or_else(|| anyhow!("legacy target is not recorded"))?;
        let reply = self
            .allocation_call("GET", &format!("/containers/{id}/json"), None)
            .await?;
        if reply.status.as_u16() == 404 {
            return Ok(None);
        }
        anyhow::ensure!(
            reply.status.is_success(),
            "legacy target inspection unavailable"
        );
        let info = reply.json()?;
        verify_legacy_identity(&info, record, &self.node)?;
        Ok(Some(info))
    }

    async fn inspect_running(&self, cell: &CellContainer) -> anyhow::Result<Option<Address>> {
        let Some(record) = self.allocations.legacy_record(&cell.scope)? else {
            return Ok(None);
        };
        anyhow::ensure!(
            record.spec.class_name == cell.spec.class_name,
            "legacy class mismatch"
        );
        if record.phase != "running" || record.cleanup.is_some() {
            return Ok(None);
        }
        let Some(info) = self.owned_legacy(&record).await? else {
            return Ok(None);
        };
        let running = info
            .pointer("/State/Running")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("legacy state is unverified"))?;
        cell.state.lock().unwrap().allocation_container = record.target;
        Ok(running.then(|| address_of(&info)))
    }

    /// Start the cell's container. The object's `start()` returns before
    /// this completes, as on Cloudflare; a failure surfaces through
    /// `monitor()`.
    /// Start the cell's container for the run `begin_run` opened. The
    /// object's `start()` returns before this completes, as on Cloudflare;
    /// a failure surfaces through `monitor()`.
    pub async fn start(
        self: &Arc<Self>,
        cell: &Arc<CellContainer>,
        run: u64,
        params: StartParams,
    ) -> anyhow::Result<()> {
        let result = self
            .legacy_request(cell, LegacyOperation::Start { run, params })
            .await;
        if let Err(error) = &result {
            let mut state = cell.state.lock().unwrap();
            if state.run == run {
                state.running = false;
                state.address = Address::None;
                cell.exit
                    .send_replace(Some((run, Err(format!("{error:#}")))));
            }
        }
        result
    }

    async fn legacy_request(
        self: &Arc<Self>,
        cell: &Arc<CellContainer>,
        operation: LegacyOperation,
    ) -> anyhow::Result<()> {
        let mut permit = if matches!(&operation, LegacyOperation::Start { .. }) {
            Some(
                self.legacy_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow!("legacy operation admission is full"))?,
            )
        } else {
            None
        };
        let guard = {
            let cells = self.cells.lock().unwrap();
            anyhow::ensure!(
                cells
                    .get(&cell.scope)
                    .is_some_and(|current| Arc::ptr_eq(current, cell)),
                "legacy cell is detached"
            );
            if let LegacyOperation::Destroy { owner } = &operation {
                let state = cell.state.lock().unwrap();
                let current = allocation::LegacyCleanup {
                    epoch: state.activation_epoch,
                    serial: state.activation_serial,
                    run: state.run,
                };
                anyhow::ensure!(
                    owner.as_ref().is_none_or(|owner| owner == &current),
                    "stale legacy release"
                );
                // this is independent of the operation lock and never erases create uncertainty.
                self.allocations
                    .request_legacy_cleanup(&cell.scope, current)?;
            }
            let guard = cell
                .legacy_lifecycle
                .clone()
                .try_lock_owned()
                .map_err(|_| {
                    anyhow!("legacy operation is already pending; cleanup intent retained")
                })?;
            if matches!(&operation, LegacyOperation::Start { .. }) {
                let mut state = cell.state.lock().unwrap();
                anyhow::ensure!(
                    state.allocation_admitted && !state.activation_pending,
                    "legacy admission closed by ownership release or pending activation"
                );
                if let Some(cancel) = state.allocation_sweeper.take() {
                    cancel.cancel();
                }
                state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
            }
            let name = match &operation {
                LegacyOperation::Start { .. } => "start",
                LegacyOperation::Destroy { .. } => "destroy",
            };
            self.allocations.begin_legacy_operation(cell, name)?;
            if let LegacyOperation::Start { run, .. } = &operation {
                let mut state = cell.state.lock().unwrap();
                let serial = state
                    .legacy_start
                    .map_or(0, |start| start.serial)
                    .checked_add(1)
                    .expect("legacy start counter exhausted");
                state.legacy_start = Some(LegacyStart { serial, run: *run });
            }
            guard
        };
        // deletion intent survives aggregate admission refusal and is retryable by exact target.
        if permit.is_none() {
            permit = Some(
                self.legacy_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow!("legacy cleanup admission is full; intent retained"))?,
            );
        }
        let engine = self.clone();
        let cell = cell.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // the task and durable intent outlive an interrupted javascript or runtime waiter.
        asyncrt::spawn(async move {
            let mut guard = Some(guard);
            let _permit = permit;
            let start_run = match &operation {
                LegacyOperation::Start { run, .. } => Some(*run),
                LegacyOperation::Destroy { .. } => None,
            };
            let starting = start_run.is_some();
            let result = match operation {
                LegacyOperation::Start { run, params } => {
                    engine.start_legacy_owned(&cell, run, params).await
                }
                LegacyOperation::Destroy { .. } => engine.destroy_legacy_locked(&cell).await,
            };
            let mut result = match result {
                Err(error) => engine
                    .allocations
                    .finish_legacy_preparation(&cell.scope)
                    .and(Err(error)),
                Ok(()) => Ok(()),
            };
            let cleanup = {
                // closing the task and reserving cleanup share this short admission lock.
                let _cells = engine.cells.lock().unwrap();
                let cleanup = engine.allocations.legacy_record(&cell.scope).map(|record| {
                    starting && record.is_some_and(|record| record.cleanup.is_some())
                });
                if !matches!(&cleanup, Ok(true)) {
                    drop(guard.take());
                }
                cleanup
            };
            match cleanup {
                Ok(true) => {
                    result = match engine.destroy_legacy_locked(&cell).await {
                        Ok(()) if starting => {
                            Err(anyhow!("legacy start cancelled by retained cleanup"))
                        }
                        Ok(()) => result,
                        Err(error) => Err(error),
                    };
                    let _cells = engine.cells.lock().unwrap();
                    drop(guard.take());
                }
                Err(error) => result = Err(error),
                Ok(false) => {}
            }
            if let (Some(run), Err(error)) = (start_run, &result) {
                let mut state = cell.state.lock().unwrap();
                if state.run == run {
                    state.running = false;
                    state.address = Address::None;
                    cell.exit
                        .send_replace(Some((run, Err(format!("{error:#}")))));
                }
            }
            let _ = sender.send(result);
        })
        .detach();
        asyncrt::timeout(self.allocation_wait, receiver)
            .await
            .map_err(|_| anyhow!("legacy operation deadline exceeded; outcome remains owned"))?
            .map_err(|_| anyhow!("legacy operation owner stopped; intent retained"))?
    }

    async fn start_legacy_owned(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        params: StartParams,
    ) -> anyhow::Result<()> {
        let started = self.create_and_start(cell, params).await;
        let address = match started {
            Ok(address) => address,
            Err(error) => {
                // `start()` is fire-and-forget for the object, and its
                // `monitor()` sees this error only if it was already
                // waiting; say it here too, or a start that fails fast
                // leaves no trace anywhere.
                tracing::warn!(
                    event = "container_start_failed",
                    cell = %cell.scope,
                    error = %format!("{error:#}"),
                    "the container did not start"
                );
                let mut state = cell.state.lock().unwrap();
                state.running = false;
                drop(state);
                cell.exit
                    .send_replace(Some((run, Err(format!("{error:#}")))));
                return Err(error);
            }
        };
        {
            let mut state = cell.state.lock().unwrap();
            state.running = false;
            state.address = Address::None;
            anyhow::ensure!(
                self.allocations
                    .legacy_record(&cell.scope)?
                    .is_some_and(|record| record.cleanup.is_none()),
                "legacy cleanup requested before publication"
            );
            state.running = true;
            state.address = address;
        }
        self.watch_exit(cell, run);
        Ok(())
    }

    /// Wait for the container's root process to end and publish the exit
    /// for `run`; a later run's start has already replaced the state.
    fn watch_exit(&self, cell: &Arc<CellContainer>, run: u64) {
        let docker = self.docker.clone();
        let cell_ = cell.clone();
        let Some(target) = cell.state.lock().unwrap().allocation_container.clone() else {
            return;
        };
        asyncrt::spawn(async move {
            let result = docker
                .call("POST", &format!("/containers/{target}/wait"), None)
                .await
                .and_then(|reply| {
                    if !reply.status.is_success() {
                        return Err(anyhow!(
                            "wait failed with [{}] {}",
                            reply.status.as_u16(),
                            reply.message()
                        ));
                    }
                    reply
                        .json()?
                        .get("StatusCode")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| anyhow!("wait answered without a status code"))
                })
                .map_err(|error| format!("{error:#}"));
            let mut state = cell_.state.lock().unwrap();
            if state.run == run {
                state.running = false;
                state.address = Address::None;
            }
            drop(state);
            cell_.exit.send_replace(Some((run, result)));
        })
        .detach();
    }

    async fn create_and_start(
        &self,
        cell: &CellContainer,
        params: StartParams,
    ) -> anyhow::Result<Address> {
        // this experimental path never launches helpers, imports images or changes networks.
        self.require_verified_fence()?;
        let (open, internal) = self
            .networks
            .try_lock()
            .map_err(|_| anyhow!("legacy network preparation is unavailable"))?
            .clone()
            .ok_or_else(|| anyhow!("legacy networks must already be prepared"))?;
        let image = asyncrt::timeout(self.allocation_wait, async {
            self.enforce_instance_ceiling(cell).await?;
            let reply = self
                .allocation_call("GET", &format!("/images/{}/json", cell.spec.image), None)
                .await?;
            anyhow::ensure!(
                reply.status.is_success(),
                "legacy image must already be prepared"
            );
            let body = reply.json()?;
            let image = body["Id"]
                .as_str()
                .ok_or_else(|| anyhow!("legacy image id missing"))?;
            anyhow::ensure!(
                image
                    .strip_prefix("sha256:")
                    .is_some_and(|hex| hex.len() == 64
                        && hex
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))),
                "legacy image id invalid"
            );
            Ok::<_, anyhow::Error>(image.to_string())
        })
        .await
        .map_err(|_| anyhow!("legacy preparation deadline exceeded"))??;
        // A previous run's container may still be named: the wait task
        // observed its exit but nothing removed it, or a restart adopted a
        // stopped one. The name is the cell's, so it is ours to remove.
        // a matching name is not ownership. replacement only removes the recorded id.
        if self
            .allocations
            .legacy_record(&cell.scope)?
            .is_some_and(|record| record.target.is_some())
        {
            self.delete_legacy_target(cell, true).await?;
        }
        let body = self.create_body(cell, params, &image, &open, &internal);
        self.legacy_create_and_start(cell, body).await
    }

    fn create_body(
        &self,
        cell: &CellContainer,
        params: StartParams,
        image: &str,
        open: &str,
        internal: &str,
    ) -> Value {
        let mut env: Vec<String> = DEFAULT_ENV.iter().map(|entry| entry.to_string()).collect();
        env.push(format!("CLOUDFLARE_DURABLE_OBJECT_ID={}", cell.scope));
        env.extend(
            params
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}")),
        );
        let mut labels = serde_json::Map::new();
        labels.insert("celld.node".into(), json!(self.node));
        labels.insert("celld.cell".into(), json!(cell.scope));
        labels.insert("celld.class".into(), json!(cell.spec.class_name));
        for (name, value) in &params.labels {
            labels.insert(format!("celld.user.{name}"), json!(value));
        }
        // Off Linux the node reaches a container only through published
        // ports, and Docker publishes nothing on an internal network, so
        // `enableInternet: false` would make the container unreachable.
        // Development there keeps egress; the compat page says so.
        let offline = !params.enable_internet && cfg!(target_os = "linux");
        if !params.enable_internet && !offline {
            tracing::warn!(
                cell = %cell.scope,
                "enableInternet: false is not enforced on this platform; the container keeps egress"
            );
        }
        // A container is a tenant's process tree, not the operator's: no
        // capability, no privilege gain through setuid binaries, the
        // daemon's seccomp profile, and a process ceiling. What a class
        // legitimately needs beyond this is a config question for later,
        // not a default. The kernel boundary itself is the runtime's.
        let mut host_config = json!({
            "NetworkMode": if offline { &internal } else { &open },
            "PublishAllPorts": !cfg!(target_os = "linux"),
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": PIDS_LIMIT,
            // An init as PID 1 reaps orphaned children. Without it a process
            // whose parent exits becomes a zombie the container holds until
            // it stops, and enough of them exhaust the PID ceiling; a fleet
            // fork bomb left exactly these behind.
            "Init": true,
        });
        // A class can name its own runtime, else the node default. A class
        // that needs isolation names `runsc`, and the node's daemon must
        // have it or the start fails, so the class runs only where its
        // isolation is real.
        let runtime = cell
            .spec
            .runtime
            .as_deref()
            .or(self.runtime.as_deref())
            .filter(|runtime| !runtime.is_empty());
        if let Some(runtime) = runtime {
            host_config["Runtime"] = json!(runtime);
        }
        // A container under a non-default runtime gets an explicit resolver
        // through a bind-mounted resolv.conf: gVisor cannot reach Docker's
        // embedded resolver at `127.0.0.11`, and on a user bridge Docker
        // keeps that address in resolv.conf whatever `--dns` says, so the
        // file itself must name a reachable resolver. An operator who set
        // `CELLD_CONTAINER_DNS` gets it for every container.
        let wants_resolver = runtime.is_some() || !self.dns.is_empty();
        if wants_resolver {
            if let Some(resolv) = &self.resolv_conf {
                let bind = format!("{}:/etc/resolv.conf:ro", resolv.display());
                host_config["Binds"] = json!([bind]);
            }
        }
        // Every container has a limit: a class without an instance type
        // gets Cloudflare's default type rather than the node.
        let instance_type = cell
            .spec
            .instance_type
            .as_deref()
            .unwrap_or(DEFAULT_INSTANCE_TYPE);
        let (vcpu, memory) =
            instance_resources(instance_type).expect("the deploy refused this instance type");
        host_config["NanoCpus"] = json!((vcpu * 1e9) as u64);
        host_config["Memory"] = json!(memory);
        host_config["MemorySwap"] = json!(memory);
        let mut body = json!({
            "Image": image,
            "Env": env,
            "Labels": labels,
            "HostConfig": host_config,
        });
        if let Some(entrypoint) = params.entrypoint {
            body["Cmd"] = json!(entrypoint);
        }
        body
    }

    async fn legacy_create_and_start(
        &self,
        cell: &CellContainer,
        body: Value,
    ) -> anyhow::Result<Address> {
        // The daemon can answer 409 for a name whose previous container is
        // still being removed, so a fresh start after `destroy()` retries
        // briefly, as workerd's engine does.
        // unlike the inherited retry policy, a conflict never authorises name deletion.
        let mut record = {
            // serialize the pre-dispatch transition with synchronous cleanup reservation.
            let _state = cell.state.lock().unwrap();
            let mut record = self
                .allocations
                .legacy_record(&cell.scope)?
                .ok_or_else(|| anyhow!("legacy intent missing"))?;
            anyhow::ensure!(
                record.phase == "preparing" && record.target.is_none() && record.cleanup.is_none(),
                "legacy create is not admitted or cleanup requested"
            );
            record.phase = "creating".to_string();
            self.allocations.save_legacy(&mut record)?;
            record
        };
        let reply = self
            .allocation_call(
                "POST",
                &format!("/containers/create?name={}", cell.name),
                Some(body),
            )
            .await?;
        if matches!(reply.status.as_u16(), 400 | 404 | 409)
            && reply
                .json()
                .ok()
                .is_some_and(|body| body["message"].is_string())
        {
            record.phase = "idle".to_string();
            self.allocations.save_legacy(&mut record)?;
            return Err(anyhow!("legacy create was definitively rejected"));
        }
        anyhow::ensure!(
            reply.status.is_success(),
            "legacy create outcome is unknown"
        );
        let created = reply.json()?;
        let id = created["Id"]
            .as_str()
            .ok_or_else(|| anyhow!("legacy create returned no id"))?;
        {
            // acknowledge this admitted operation under the startup cleanup selection lock.
            let _state = cell.state.lock().unwrap();
            self.allocations
                .record_legacy(&cell.scope, &cell.spec.class_name, id)?;
        }
        let mut record = self
            .allocations
            .legacy_record(&cell.scope)?
            .ok_or_else(|| anyhow!("legacy target record missing"))?;
        anyhow::ensure!(
            self.owned_legacy(&record).await?.is_some(),
            "legacy created target is absent"
        );
        {
            let _state = cell.state.lock().unwrap();
            record = self
                .allocations
                .legacy_record(&cell.scope)?
                .ok_or_else(|| anyhow!("legacy target record missing"))?;
            anyhow::ensure!(
                record.cleanup.is_none(),
                "legacy cleanup requested before start"
            );
        }
        let started = self
            .allocation_call("POST", &format!("/containers/{id}/start"), None)
            .await?;
        anyhow::ensure!(started.status.is_success(), "legacy start is unresolved");
        let info = self
            .owned_legacy(&record)
            .await?
            .ok_or_else(|| anyhow!("legacy started target is absent"))?;
        record.phase = "running".to_string();
        self.allocations.save_legacy(&mut record)?;
        cell.state.lock().unwrap().allocation_container = record.target;
        Ok(address_of(&info))
    }

    /// Wait for the current run to end. `Ok(code)` is the root process's
    /// exit code; a destroyed container reports 137.
    pub async fn monitor(&self, cell: &Arc<CellContainer>, run: u64) -> Result<i64, String> {
        let mut receiver = cell.exit.subscribe();
        loop {
            if let Some((ended, result)) = receiver.borrow_and_update().clone() {
                if ended >= run {
                    return result;
                }
            }
            if receiver.changed().await.is_err() {
                return Err("the container engine went away".to_string());
            }
        }
    }

    pub async fn destroy(self: &Arc<Self>, cell: &Arc<CellContainer>) -> anyhow::Result<()> {
        self.refuse_native_legacy(cell)?;
        self.legacy_request(cell, LegacyOperation::Destroy { owner: None })
            .await
    }

    async fn destroy_legacy_locked(&self, cell: &Arc<CellContainer>) -> anyhow::Result<()> {
        self.delete_legacy_target(cell, false).await
    }

    async fn delete_legacy_target(
        &self,
        cell: &CellContainer,
        replacing: bool,
    ) -> anyhow::Result<()> {
        let mut record = self
            .allocations
            .legacy_record(&cell.scope)?
            .ok_or_else(|| anyhow!("legacy intent missing"))?;
        anyhow::ensure!(
            record.phase != "creating",
            "legacy create outcome remains unknown"
        );
        if let Some(id) = record.target.clone() {
            record.phase = "deleting".to_string();
            self.allocations.save_legacy(&mut record)?;
            // Kill first so the wait task reports 137 before the removal makes
            // the name disappear under it.
            if self.owned_legacy(&record).await?.is_some() {
                let killed = self
                    .allocation_call(
                        "POST",
                        &format!("/containers/{id}/kill?signal=SIGKILL"),
                        None,
                    )
                    .await?;
                anyhow::ensure!(
                    killed.status.is_success() || matches!(killed.status.as_u16(), 404 | 409),
                    "legacy kill is unresolved"
                );
                if self.owned_legacy(&record).await?.is_some() {
                    let deleted = self
                        .allocation_call("DELETE", &format!("/containers/{id}?force=true"), None)
                        .await?;
                    anyhow::ensure!(
                        deleted.status.is_success() || deleted.status.as_u16() == 404,
                        "legacy deletion is unresolved"
                    );
                }
            }
        }
        record.target = None;
        record.phase = if replacing { "preparing" } else { "idle" }.to_string();
        if replacing {
            record.spec = (*cell.spec).clone();
        }
        self.allocations.save_legacy(&mut record)?;
        let mut state = cell.state.lock().unwrap();
        state.running = false;
        state.address = Address::None;
        state.allocation_container = None;
        Ok(())
    }

    async fn legacy_running_target(
        &self,
        cell: &CellContainer,
    ) -> anyhow::Result<allocation::LegacyRecord> {
        self.refuse_native_legacy(cell)?;
        {
            let cells = self.cells.lock().unwrap();
            anyhow::ensure!(
                cells
                    .get(&cell.scope)
                    .is_some_and(|current| std::ptr::eq(&**current, cell)),
                "legacy cell is detached"
            );
            anyhow::ensure!(
                cell.state.lock().unwrap().allocation_admitted,
                "legacy admission closed"
            );
        }
        let record = self
            .allocations
            .legacy_record(&cell.scope)?
            .ok_or_else(|| anyhow!("legacy ownership is not recorded"))?;
        anyhow::ensure!(
            record.phase == "running"
                && record.cleanup.is_none()
                && record.spec.class_name == cell.spec.class_name,
            "legacy target is unresolved"
        );
        anyhow::ensure!(
            self.owned_legacy(&record).await?.is_some(),
            "legacy target is absent"
        );
        Ok(record)
    }

    pub async fn signal(&self, cell: &Arc<CellContainer>, signal: u32) -> anyhow::Result<()> {
        let _permit = self
            .legacy_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("legacy operation admission is full"))?;
        let _guard = cell
            .legacy_lifecycle
            .clone()
            .try_lock_owned()
            .map_err(|_| anyhow!("legacy lifecycle is pending"))?;
        let record = self.legacy_running_target(cell).await?;
        let id = record
            .target
            .as_deref()
            .ok_or_else(|| anyhow!("legacy target missing"))?;
        let reply = self
            .allocation_call(
                "POST",
                &format!("/containers/{id}/kill?signal={signal}"),
                None,
            )
            .await?;
        anyhow::ensure!(
            reply.status.is_success(),
            "legacy signal outcome is unresolved"
        );
        Ok(())
    }

    /// The cell left this node's runtime. An idle eviction keeps the
    /// container for its inactivity window; anything else destroys it, and
    /// the stop waits for that: a drain ends the process right after its
    /// last stop, and a destroy left to a detached task did not always get
    /// its two daemon calls in before the exit.
    pub fn prepare_release(
        &self,
        activation: &ContainerActivation,
        mode: Release,
    ) -> anyhow::Result<ContainerRelease> {
        self.prepare_release_inner(activation, mode, false)
    }

    pub(crate) fn prepare_runtime_release(
        &self,
        activation: &ContainerActivation,
        mode: Release,
    ) -> anyhow::Result<ContainerRelease> {
        self.prepare_release_inner(activation, mode, true)
    }

    fn prepare_release_inner(
        &self,
        activation: &ContainerActivation,
        mode: Release,
        retiring: bool,
    ) -> anyhow::Result<ContainerRelease> {
        let cell = &activation.cell;
        let cells = self.cells.lock().unwrap();
        anyhow::ensure!(
            cells
                .get(&cell.scope)
                .is_some_and(|current| Arc::ptr_eq(current, cell)),
            "container activation is detached"
        );
        let mut state = cell.state.lock().unwrap();
        anyhow::ensure!(
            state.activation_serial == activation.serial
                && state.activation_epoch == activation.epoch,
            "stale container activation release"
        );
        // runtime retirement closes shared admission even when keeping the container.
        // capturing an idle ticket alone does not retire a still-running actor.
        if retiring || mode == Release::Destroy {
            state.allocation_admitted = false;
        }
        if mode == Release::Destroy {
            state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
            if let Some(cancel) = state.allocation_sweeper.take() {
                cancel.cancel();
            }
        }
        let native = self.allocations.native_scope(&cell.scope)?;
        let allocation = self
            .allocations
            .active(&cell.scope)?
            .map(|record| record.id);
        if mode == Release::Destroy {
            if let Some(id) = &allocation {
                self.request_allocation_cleanup(cell, id)?;
            } else if !native {
                self.allocations.request_legacy_cleanup(
                    &cell.scope,
                    allocation::LegacyCleanup {
                        epoch: activation.epoch,
                        serial: activation.serial,
                        run: state.run,
                    },
                )?;
            }
        }
        Ok(ContainerRelease {
            activation: activation.clone(),
            run: state.run,
            mode,
            native,
            allocation,
        })
    }

    /// Bind an older retained native attachment to a verified current owner
    /// before retiring it. Never use this fallback for an unverified scope,
    /// foreign journal, pending attachment, or newer local responsibility.
    pub(crate) fn prepare_dormant_native_release(
        &self,
        scope: &str,
        epoch: u64,
        journal: &str,
    ) -> anyhow::Result<Option<ContainerRelease>> {
        anyhow::ensure!(
            self.native_journal_identity()? == journal,
            "dormant native retirement journal changed"
        );
        {
            let cells = self.cells.lock().unwrap();
            let Some(cell) = cells.get(scope) else {
                return Ok(None);
            };
            let mut state = cell.state.lock().unwrap();
            anyhow::ensure!(
                !state.activation_pending
                    && state.activation_epoch <= epoch
                    && state
                        .startup
                        .as_ref()
                        .is_none_or(|owner| owner.epoch <= epoch),
                "dormant native retirement attachment changed"
            );
            anyhow::ensure!(
                self.allocations.native_scope(scope)?,
                "dormant attachment is not native"
            );
            state.startup = Some(StartupOwnership {
                epoch,
                serial: state.activation_serial,
                native: true,
                allocation: self.allocations.active(scope)?.map(|record| record.id),
                legacy_target: None,
                legacy_start: None,
                legacy_start_pending: false,
            });
            state.allocation_admitted = false;
        }
        self.prepare_startup_release(scope, epoch)
    }

    // failed startup retains an exact target but never gains actor authority. a fence
    // can retire that responsibility after the runtime reports a definite failure.
    pub fn prepare_startup_release(
        &self,
        scope: &str,
        epoch: u64,
    ) -> anyhow::Result<Option<ContainerRelease>> {
        let cells = self.cells.lock().unwrap();
        let Some(cell) = cells.get(scope) else {
            return Ok(None);
        };
        let mut state = cell.state.lock().unwrap();
        let Some(owner) = state.startup.clone() else {
            return Ok(None);
        };
        if owner.epoch != epoch || owner.serial != state.activation_serial {
            return Ok(None);
        }
        if self.allocations.native_scope(scope)? != owner.native
            || self.allocations.active(scope)?.map(|record| record.id) != owner.allocation
        {
            return Ok(None);
        }
        if !owner.native {
            let legacy = self.allocations.legacy_record(scope)?;
            let target = legacy.as_ref().and_then(|record| record.target.as_ref());
            // only the captured admitted start may advance or replace its journalled target.
            // a later start, even for the same run or target, has a different serial.
            if state.legacy_start != owner.legacy_start
                || (target != owner.legacy_target.as_ref() && !owner.legacy_start_pending)
            {
                return Ok(None);
            }
        }
        state.allocation_admitted = false;
        let activation = ContainerActivation {
            cell: cell.clone(),
            epoch: state.activation_epoch,
            serial: state.activation_serial,
        };
        if let Some(id) = &owner.allocation {
            self.request_allocation_cleanup(cell, id)?;
        } else if !owner.native {
            self.allocations.request_legacy_cleanup(
                scope,
                allocation::LegacyCleanup {
                    epoch: activation.epoch,
                    serial: activation.serial,
                    run: state.run,
                },
            )?;
        }
        Ok(Some(ContainerRelease {
            activation,
            run: state.run,
            mode: Release::Destroy,
            native: owner.native,
            allocation: owner.allocation,
        }))
    }

    fn resume_legacy_cleanup(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) {
        let engine = self.clone();
        asyncrt::spawn(async move {
            let _guard = guard;
            let result = async {
                let _permit = asyncrt::timeout(
                    engine.allocation_wait,
                    engine.legacy_slots.clone().acquire_owned(),
                )
                .await
                .map_err(|_| anyhow!("legacy cleanup admission deadline exceeded"))??;
                engine.destroy_legacy_locked(&cell).await
            }
            .await;
            if result.is_err() {
                tracing::warn!(
                    event = "container_pending_cleanup_unresolved",
                    "journalled legacy cleanup remains retryable"
                );
            }
        })
        .detach();
    }

    pub(crate) async fn close_native_handoff(
        self: &Arc<Self>,
        scope: &str,
        epoch: u64,
    ) -> anyhow::Result<Vec<crate::native_handoff::DestroyedAttempt>> {
        let activation = {
            let cells = self.cells.lock().unwrap();
            match cells.get(scope) {
                Some(cell) => {
                    let state = cell.state.lock().unwrap();
                    anyhow::ensure!(
                        state
                            .startup
                            .as_ref()
                            .is_none_or(|owner| owner.epoch == epoch),
                        "native handoff startup epoch changed"
                    );
                    // Failed attachment never commits activation_epoch. Accept
                    // its exact retired startup only with terminal evidence;
                    // never retarget deletion to the requested newer epoch.
                    if !state.activation_pending
                        && !state.allocation_admitted
                        && state.activation_epoch < epoch
                        && state.startup.as_ref().is_some_and(|owner| {
                            owner.native
                                && owner.epoch == epoch
                                && owner.serial == state.activation_serial
                        })
                    {
                        return self.allocations.closed_attempts(scope);
                    }
                    anyhow::ensure!(
                        !state.activation_pending && state.activation_epoch == epoch,
                        "native handoff activation changed or remains pending"
                    );
                    Some(ContainerActivation {
                        cell: cell.clone(),
                        epoch,
                        serial: state.activation_serial,
                    })
                }
                None => None,
            }
        };
        if let Some(activation) = activation {
            let ticket = self.prepare_release(&activation, Release::Destroy)?;
            self.release(ticket).await?;
        }
        // no scope-based deletion fallback: every remaining record must already be terminal.
        self.allocations.closed_attempts(scope)
    }

    pub async fn release(self: &Arc<Self>, ticket: ContainerRelease) -> anyhow::Result<()> {
        let cell = ticket.activation.cell.clone();
        if ticket.mode == Release::Destroy {
            if ticket.native {
                if let Some(id) = ticket.allocation {
                    let receiver = self.allocation_request(cell, AllocationRequest::Destroy(id))?;
                    let result = receiver
                        .await
                        .map_err(|_| anyhow!("allocation cleanup owner stopped"))??;
                    anyhow::ensure!(
                        result.status == "destroyed",
                        "allocation cleanup remains unresolved"
                    );
                }
            } else {
                self.forget(&ticket.activation, ticket.run).await?;
            }
            return Ok(());
        }
        let cancel = tokio_util::sync::CancellationToken::new();
        let (window, epoch) = {
            let mut state = cell.state.lock().unwrap();
            anyhow::ensure!(
                state.activation_serial == ticket.activation.serial
                    && (ticket.native || state.run == ticket.run),
                "stale idle release"
            );
            anyhow::ensure!(
                self.allocations.native_scope(&cell.scope)? == ticket.native
                    && self
                        .allocations
                        .active(&cell.scope)?
                        .map(|record| record.id)
                        == ticket.allocation,
                "idle release no longer owns the selected attempt"
            );
            if let Some(old) = state.allocation_sweeper.replace(cancel.clone()) {
                old.cancel();
            }
            state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
            (
                state.inactivity.unwrap_or(DEFAULT_INACTIVITY),
                state.inactivity_epoch,
            )
        };
        let engine = self.clone();
        asyncrt::spawn(async move {
            let elapsed = futures_util::future::select(
                Box::pin(asyncrt::sleep(window)),
                Box::pin(cancel.cancelled()),
            )
            .await;
            if !matches!(elapsed, futures_util::future::Either::Left(_)) {
                return;
            }
            let result = async {
                {
                    let state = cell.state.lock().unwrap();
                    if state.inactivity_epoch != epoch
                        || state.activation_serial != ticket.activation.serial
                    {
                        return Ok(());
                    }
                    if let Some(id) = &ticket.allocation {
                        // persist before queue admission or any await that can time out.
                        engine.request_allocation_cleanup(&cell, id)?;
                    }
                }
                if ticket.native {
                    if let Some(id) = ticket.allocation {
                        let receiver =
                            engine.allocation_request(cell, AllocationRequest::Destroy(id))?;
                        let result = receiver
                            .await
                            .map_err(|_| anyhow!("idle cleanup owner stopped"))??;
                        anyhow::ensure!(
                            result.status == "destroyed",
                            "idle allocation cleanup remains unresolved"
                        );
                    }
                } else {
                    engine.forget(&ticket.activation, ticket.run).await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if result.is_err() {
                tracing::warn!(
                    event = "container_idle_cleanup_unresolved",
                    "container cleanup responsibility retained"
                );
            }
        })
        .detach();
        Ok(())
    }

    async fn forget(
        self: &Arc<Self>,
        activation: &ContainerActivation,
        run: u64,
    ) -> anyhow::Result<()> {
        let cell = &activation.cell;
        {
            let cells = self.cells.lock().unwrap();
            anyhow::ensure!(
                cells
                    .get(&cell.scope)
                    .is_some_and(|current| Arc::ptr_eq(current, cell)),
                "legacy activation is detached"
            );
            let mut state = cell.state.lock().unwrap();
            anyhow::ensure!(
                state.activation_serial == activation.serial
                    && state.activation_epoch == activation.epoch
                    && state.run == run,
                "stale legacy release"
            );
            state.allocation_admitted = false;
            self.allocations.request_legacy_cleanup(
                &cell.scope,
                allocation::LegacyCleanup {
                    epoch: activation.epoch,
                    serial: activation.serial,
                    run,
                },
            )?;
        }
        self.legacy_request(
            cell,
            LegacyOperation::Destroy {
                owner: Some(allocation::LegacyCleanup {
                    epoch: activation.epoch,
                    serial: activation.serial,
                    run,
                }),
            },
        )
        .await?;
        let mut cells = self.cells.lock().unwrap();
        if !self.allocations.native_scope(&cell.scope)?
            && {
                let state = cell.state.lock().unwrap();
                state.activation_serial == activation.serial && !state.activation_pending
            }
            && cells
                .get(&cell.scope)
                .is_some_and(|current| Arc::ptr_eq(current, cell))
        {
            anyhow::ensure!(
                !cell.state.lock().unwrap().allocation_admitted,
                "legacy admission reopened before removal"
            );
            for id in cell.processes.lock().unwrap().drain(..) {
                drop_process(id);
            }
            cells.remove(&cell.scope);
        }
        Ok(())
    }

    pub async fn exec(
        &self,
        cell: &Arc<CellContainer>,
        params: ExecParams,
    ) -> anyhow::Result<Arc<ExecProcess>> {
        anyhow::ensure!(
            !self.allocations.native_scope(&cell.scope)?,
            "exec is unavailable for allocation scopes"
        );
        if !cell.running() {
            return Err(anyhow!("exec() requires a running container."));
        }
        let _permit = self
            .legacy_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("legacy operation admission is full"))?;
        let _guard = cell
            .legacy_lifecycle
            .clone()
            .try_lock_owned()
            .map_err(|_| anyhow!("legacy lifecycle is pending"))?;
        let ownership = self.legacy_running_target(cell).await?;
        let target = ownership
            .target
            .clone()
            .ok_or_else(|| anyhow!("legacy target missing"))?;
        let mut body = json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Tty": false,
            "Cmd": params.cmd,
        });
        if !params.env.is_empty() {
            body["Env"] = json!(params
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>());
        }
        if let Some(cwd) = &params.cwd {
            body["WorkingDir"] = json!(cwd);
        }
        if let Some(user) = &params.user {
            body["User"] = json!(user);
        }
        let created = self
            .allocation_call("POST", &format!("/containers/{target}/exec"), Some(body))
            .await?;
        anyhow::ensure!(
            created.status.is_success(),
            "legacy exec creation is unresolved"
        );
        let created = created.json()?;
        let exec_id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("exec create answered without an id"))?
            .to_string();
        let stream = asyncrt::timeout(
            self.allocation_wait,
            self.docker.hijack(
                &format!("/exec/{exec_id}/start"),
                json!({ "Detach": false, "Tty": false }),
            ),
        )
        .await
        .map_err(|_| anyhow!("legacy exec start deadline exceeded"))??;
        // Docker reports `Running: false` with no pid before it has spawned
        // the process, and a finished exec keeps its pid, so a pid of zero
        // is the one answer that means "not yet": retry it briefly, as
        // workerd does. Breaking on `Running: false` here lost the pid of a
        // short command whenever the inspect landed in that window.
        let mut pid = 0;
        for _ in 0..20 {
            let info = self
                .allocation_call("GET", &format!("/exec/{exec_id}/json"), None)
                .await?;
            anyhow::ensure!(
                info.status.is_success(),
                "legacy exec inspection unavailable"
            );
            let info = info.json()?;
            pid = info.get("Pid").and_then(Value::as_i64).unwrap_or(0);
            if pid != 0 {
                break;
            }
            asyncrt::sleep(Duration::from_millis(50)).await;
        }
        let (read, write) = tokio::io::split(stream);
        let (stdout_tx, stdout_rx) = mpsc::channel(16);
        let (stderr_tx, stderr_rx) = mpsc::channel(16);
        let combined = params.combined;
        let ended = watch::channel(false).0;
        let ended_ = ended.clone();
        asyncrt::spawn(async move {
            demux(read, stdout_tx, stderr_tx, combined).await;
            ended_.send_replace(true);
        })
        .detach();
        let process = Arc::new(ExecProcess {
            id: next_exec_id(),
            exec_id,
            container: target,
            ownership,
            node: self.node.clone(),
            legacy_slots: self.legacy_slots.clone(),
            pid,
            docker: self.docker.clone(),
            stdin: tokio::sync::Mutex::new(Some(write)),
            stdout: tokio::sync::Mutex::new(stdout_rx),
            stderr: tokio::sync::Mutex::new(stderr_rx),
            ended,
            exit_code: tokio::sync::Mutex::new(None),
        });
        processes()
            .lock()
            .unwrap()
            .insert(process.id, process.clone());
        cell.processes.lock().unwrap().push(process.id);
        Ok(process)
    }
}

pub struct ExecParams {
    pub cmd: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    /// stderr folded into stdout.
    pub combined: bool,
}

type WriteHalf = tokio::io::WriteHalf<Box<dyn Stream>>;

pub struct ExecProcess {
    pub id: u64,
    exec_id: String,
    container: String,
    ownership: allocation::LegacyRecord,
    node: String,
    legacy_slots: Arc<tokio::sync::Semaphore>,
    pub pid: i64,
    docker: Docker,
    stdin: tokio::sync::Mutex<Option<WriteHalf>>,
    stdout: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    stderr: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// True once the hijacked stream reached EOF, which the daemon sends
    /// when the process exits.
    ended: watch::Sender<bool>,
    exit_code: tokio::sync::Mutex<Option<i64>>,
}

fn processes() -> &'static Mutex<HashMap<u64, Arc<ExecProcess>>> {
    static PROCESSES: OnceLock<Mutex<HashMap<u64, Arc<ExecProcess>>>> = OnceLock::new();
    PROCESSES.get_or_init(Default::default)
}

fn next_exec_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn process(id: u64) -> Option<Arc<ExecProcess>> {
    processes().lock().unwrap().get(&id).cloned()
}

pub fn drop_process(id: u64) {
    processes().lock().unwrap().remove(&id);
}

impl ExecProcess {
    /// One chunk of stdout (`1`) or stderr (`2`); empty at end of stream.
    pub async fn read(&self, which: u8) -> Bytes {
        let mut receiver = match which {
            1 => self.stdout.lock().await,
            _ => self.stderr.lock().await,
        };
        receiver.recv().await.unwrap_or_default()
    }

    pub async fn write(&self, bytes: &[u8]) -> Result<(), String> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or("stdin is closed")?;
        stdin
            .write_all(bytes)
            .await
            .map_err(|error| format!("stdin write failed: {error}"))?;
        stdin
            .flush()
            .await
            .map_err(|error| format!("stdin flush failed: {error}"))
    }

    /// End stdin. Half-closing the hijacked connection is how the daemon
    /// learns the process's stdin reached EOF.
    pub async fn close_stdin(&self) {
        if let Some(mut stdin) = self.stdin.lock().await.take() {
            let _ = stdin.shutdown().await;
        }
    }

    pub async fn wait(&self) -> anyhow::Result<i64> {
        let mut exit = self.exit_code.lock().await;
        if let Some(code) = *exit {
            return Ok(code);
        }
        let mut ended = self.ended.subscribe();
        while !*ended.borrow_and_update() {
            if ended.changed().await.is_err() {
                break;
            }
        }
        // The stream closes when the process exits, but the daemon records
        // the exit code a moment later.
        let mut code = None;
        for _ in 0..40 {
            let info = self
                .docker
                .expect(
                    "GET",
                    &format!("/exec/{}/json", self.exec_id),
                    None,
                    "inspect exec",
                )
                .await?
                .json()?;
            if !info
                .get("Running")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                code = info.get("ExitCode").and_then(Value::as_i64);
                break;
            }
            asyncrt::sleep(Duration::from_millis(50)).await;
        }
        let code = code.ok_or_else(|| anyhow!("the process did not report an exit code"))?;
        *exit = Some(code);
        Ok(code)
    }

    /// The Engine API has no exec kill, so the signal is delivered by a
    /// second exec of `kill`, as workerd does.
    pub async fn kill(&self, signal: u32) -> anyhow::Result<()> {
        let _permit = self
            .legacy_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("legacy operation admission is full"))?;
        asyncrt::timeout(allocation::DEADLINE, self.kill_owned(signal))
            .await
            .map_err(|_| anyhow!("legacy process signal deadline exceeded"))?
    }

    async fn kill_owned(&self, signal: u32) -> anyhow::Result<()> {
        let inspected = asyncrt::timeout(
            allocation::DEADLINE,
            self.docker.call_bounded(
                "GET",
                &format!("/containers/{}/json", self.container),
                None,
                1024 * 1024,
            ),
        )
        .await
        .map_err(|_| anyhow!("legacy process target deadline exceeded"))??;
        anyhow::ensure!(
            inspected.status.is_success(),
            "legacy process target unavailable"
        );
        verify_legacy_identity(&inspected.json()?, &self.ownership, &self.node)?;
        let body = json!({
            "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
            "Cmd": ["kill", format!("-{signal}"), self.pid.to_string()],
        });
        let created = self
            .docker
            .expect(
                "POST",
                &format!("/containers/{}/exec", self.container),
                Some(body),
                "create exec",
            )
            .await?
            .json()?;
        let id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("exec create answered without an id"))?;
        self.docker
            .expect(
                "POST",
                &format!("/exec/{id}/start"),
                Some(json!({ "Detach": true })),
                "start exec",
            )
            .await?;
        Ok(())
    }
}

/// Split Docker's multiplexed stream into stdout and stderr chunks until
/// the daemon closes it.
async fn demux(
    mut read: tokio::io::ReadHalf<Box<dyn Stream>>,
    stdout: mpsc::Sender<Bytes>,
    stderr: mpsc::Sender<Bytes>,
    combined: bool,
) {
    let mut header = [0u8; 8];
    loop {
        if read.read_exact(&mut header).await.is_err() {
            return;
        }
        let (stream, length) = frame_header(&header);
        let mut payload = vec![0u8; length];
        if read.read_exact(&mut payload).await.is_err() {
            return;
        }
        let target = if stream == 2 && !combined {
            &stderr
        } else {
            &stdout
        };
        if target.send(Bytes::from(payload)).await.is_err() {
            // The reader went away; keep draining so the process is not
            // blocked on a full pipe.
            continue;
        }
    }
}

fn address_of(info: &Value) -> Address {
    if cfg!(target_os = "linux") {
        let ip = info
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .and_then(|networks| networks.values().next())
            .and_then(|network| network.get("IPAddress"))
            .and_then(Value::as_str)
            .filter(|ip| !ip.is_empty());
        return ip.map_or(Address::None, |ip| Address::Ip(ip.to_string()));
    }
    let mut ports = HashMap::new();
    if let Some(map) = info
        .pointer("/NetworkSettings/Ports")
        .and_then(Value::as_object)
    {
        for (key, bindings) in map {
            let Some(port) = key
                .strip_suffix("/tcp")
                .and_then(|port| port.parse::<u16>().ok())
            else {
                continue;
            };
            let host = bindings
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|binding| binding.get("HostPort")?.as_str()?.parse::<u16>().ok());
            if let Some(host) = host {
                ports.insert(port, host);
            }
        }
    }
    Address::Published(ports)
}

/// A Docker name from a node and a cell scope: the scope's characters are
/// not all legal, so the name is a hash and the scope rides in a label.
/// The node is part of it because two nodes can share one engine in a
/// development or test setup, and a name from the scope alone let one
/// node adopt, or reap, the other's container for the same object.
fn container_name(node: &str, scope: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{node}\n{scope}").as_bytes());
    format!("celld-{:x}", digest)[..30].to_string()
}
