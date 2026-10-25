// Host-bound integration fixtures deliberately use real OS files and Tokio deadlines.
#![allow(clippy::disallowed_methods)]

use super::*;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

use tokio::net::UnixListener;
use tokio::sync::{Notify, Semaphore};

#[derive(Clone)]
struct Gate {
    entered: Arc<Notify>,
    proceed: Arc<Semaphore>,
}

impl Gate {
    fn new() -> Self {
        Self {
            entered: Arc::new(Notify::new()),
            proceed: Arc::new(Semaphore::new(0)),
        }
    }
    async fn wait(&self) {
        self.entered.notify_one();
        self.proceed.acquire().await.unwrap().forget();
    }
    fn open(&self) {
        self.proceed.add_permits(1);
    }
}

#[derive(Default)]
struct DaemonState {
    images: HashMap<String, Value>,
    containers: HashMap<String, Value>,
    calls: Vec<(String, String, Value)>,
    next: u64,
    create_gate: Option<Gate>,
    image_gate: Option<Gate>,
    inspect_gate: Option<Gate>,
    after_create_inspect_gate: Option<Gate>,
    after_start_inspect_gate: Option<Gate>,
    create_rejection: Option<(u16, Value)>,
    late_create: Option<Gate>,
    late_reply_gate: Option<Gate>,
    lose_create_reply: bool,
    fail_delete: bool,
    delete_gate: Option<Gate>,
    lose_delete_reply: bool,
}

struct Daemon {
    state: Mutex<DaemonState>,
    changed: Notify,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Daemon {
    fn create(&self, path: &str, body: Value) -> String {
        let mut state = self.state.lock().unwrap();
        state.next += 1;
        let id = format!("{:064x}", state.next);
        let name = path.strip_prefix("/containers/create?name=").unwrap();
        let info = json!({
            "Id": id, "Name": format!("/{name}"), "Image": body["Image"],
            "Config": body, "State": { "Running": false, "Status": "created" },
            "NetworkSettings": { "Networks": { "internal": { "IPAddress": "172.30.0.2" } }, "Ports": { "8080/tcp": [{ "HostPort": "32123" }] } }
        });
        state.containers.insert(id.clone(), info);
        state.inspect_gate = state.after_create_inspect_gate.take();
        self.changed.notify_waiters();
        id
    }

    async fn handle(
        self: Arc<Self>,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::io::Error> {
        let method = request.method().as_str().to_string();
        let path = request.uri().to_string();
        let bytes = request
            .into_body()
            .collect()
            .await
            .map_err(std::io::Error::other)?
            .to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        self.state
            .lock()
            .unwrap()
            .calls
            .push((method.clone(), path.clone(), body.clone()));
        if path.starts_with("/containers/create?") {
            let name = path.strip_prefix("/containers/create?name=").unwrap();
            if self
                .state
                .lock()
                .unwrap()
                .containers
                .values()
                .any(|info| info["Name"] == format!("/{name}"))
            {
                return Ok(response(409, json!({"message": "name is already in use"})));
            }
            let rejection = self.state.lock().unwrap().create_rejection.take();
            if let Some((status, body)) = rejection {
                return Ok(response(status, body));
            }
            let (gate, late, lost) = {
                let mut state = self.state.lock().unwrap();
                (
                    state.create_gate.take(),
                    state.late_create.take(),
                    std::mem::take(&mut state.lose_create_reply),
                )
            };
            if let Some(gate) = late {
                let daemon = self.clone();
                let task = tokio::spawn(async move {
                    gate.wait().await;
                    daemon.create(&path, body);
                });
                self.tasks.lock().unwrap().push(task);
                let reply_gate = self.state.lock().unwrap().late_reply_gate.take();
                if let Some(reply_gate) = reply_gate {
                    reply_gate.wait().await;
                }
                return Err(std::io::Error::other("injected lost create reply"));
            }
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let id = self.create(&path, body);
            if lost {
                return Err(std::io::Error::other("injected lost create reply"));
            }
            return Ok(response(201, json!({ "Id": id })));
        }
        if let Some(id) = path
            .strip_prefix("/containers/")
            .and_then(|path| path.strip_suffix("/wait"))
        {
            loop {
                let notified = self.changed.notified();
                let running = self
                    .state
                    .lock()
                    .unwrap()
                    .containers
                    .iter()
                    .any(|(key, info)| {
                        (key == id || info["Name"] == format!("/{id}"))
                            && info["State"]["Running"] == true
                    });
                if !running {
                    return Ok(response(200, json!({ "StatusCode": 137 })));
                }
                notified.await;
            }
        }
        if path.starts_with("/containers/") && path.ends_with("/json") {
            let gate = self.state.lock().unwrap().inspect_gate.take();
            if let Some(gate) = gate {
                gate.wait().await;
            }
        }
        if path.starts_with("/images/") {
            let gate = self.state.lock().unwrap().image_gate.take();
            if let Some(gate) = gate {
                gate.wait().await;
            }
        }
        if method == "DELETE" {
            let gate = self.state.lock().unwrap().delete_gate.take();
            if let Some(gate) = gate {
                gate.wait().await;
            }
        }
        let mut state = self.state.lock().unwrap();
        if path.starts_with("/containers/json?") {
            let list: Vec<Value> = state
                .containers
                .values()
                .map(|info| json!({ "Id": info["Id"], "Labels": info["Config"]["Labels"] }))
                .collect();
            return Ok(response(200, json!(list)));
        }
        if let Some(image) = path
            .strip_prefix("/images/")
            .and_then(|path| path.strip_suffix("/json"))
        {
            return Ok(match state.images.get(image) {
                Some(image) => response(200, image.clone()),
                None => response(404, json!({})),
            });
        }
        if let Some(target) = path.strip_prefix("/containers/") {
            if let Some(target) = target.strip_suffix("/json") {
                let info = state.containers.get(target).or_else(|| {
                    state
                        .containers
                        .values()
                        .find(|info| info["Name"] == format!("/{target}"))
                });
                return Ok(match info {
                    Some(info) => response(200, info.clone()),
                    None => response(404, json!({})),
                });
            }
            if let Some(target) = target.strip_suffix("/kill?signal=SIGKILL") {
                let id = state
                    .containers
                    .iter()
                    .find(|(id, info)| {
                        id.as_str() == target || info["Name"] == format!("/{target}")
                    })
                    .map(|(id, _)| id.clone());
                if let Some(id) = id {
                    state.containers.get_mut(&id).unwrap()["State"] =
                        json!({"Running": false, "Status": "exited"});
                    self.changed.notify_waiters();
                    return Ok(response(204, Value::Null));
                }
                return Ok(response(404, json!({})));
            }
            if let Some(id) = target.strip_suffix("/start") {
                if let Some(info) = state.containers.get_mut(id) {
                    info["State"] = json!({ "Running": true, "Status": "running" });
                    if let Some(gate) = state.after_start_inspect_gate.take() {
                        state.inspect_gate = Some(gate);
                    }
                    return Ok(response(204, Value::Null));
                }
                return Ok(response(404, json!({})));
            }
            if method == "DELETE" {
                let id = target.split('?').next().unwrap();
                if std::mem::take(&mut state.fail_delete) {
                    return Ok(response(500, json!({ "message": "injected" })));
                }
                let resolved = state
                    .containers
                    .iter()
                    .find(|(key, info)| key.as_str() == id || info["Name"] == format!("/{id}"))
                    .map(|(key, _)| key.clone());
                let removed = resolved.is_some_and(|key| state.containers.remove(&key).is_some());
                self.changed.notify_waiters();
                if std::mem::take(&mut state.lose_delete_reply) {
                    return Err(std::io::Error::other("injected lost delete reply"));
                }
                return Ok(response(if removed { 204 } else { 404 }, Value::Null));
            }
        }
        Ok(response(
            500,
            json!({ "message": "unexpected fake Docker call" }),
        ))
    }
}

fn response(status: u16, body: Value) -> Response<Full<Bytes>> {
    let bytes = if status == 204 {
        Bytes::new()
    } else {
        Bytes::from(body.to_string())
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes))
        .unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    socket: PathBuf,
    daemon: Arc<Daemon>,
    listener: tokio::task::JoinHandle<()>,
    engine: Option<Arc<ContainerEngine>>,
    cell: Arc<CellContainer>,
    // Deployment specs are process-wide. Hold this after all other fixture fields
    // so parallel tests cannot replace a class while an owned operation uses it.
    _specs_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn new() -> Self {
        static SPECS_OWNER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let specs_guard = SPECS_OWNER.lock().await;
        crate::native_ws::native_ws_tests::init_host();
        let dir = tempfile::Builder::new().prefix("alloc-").tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let daemon = Arc::new(Daemon {
            state: Mutex::new(DaemonState::default()),
            changed: Notify::new(),
            tasks: Mutex::new(Vec::new()),
        });
        for (key, engine) in [('a', '1'), ('b', '2')] {
            let image = json!({ "Id": format!("sha256:{}", engine.to_string().repeat(64)), "Os": "linux", "Architecture": "amd64" });
            let mut state = daemon.state.lock().unwrap();
            state.images.insert(
                format!("celld-image:{}", key.to_string().repeat(64)),
                image.clone(),
            );
            state
                .images
                .insert(image["Id"].as_str().unwrap().to_string(), image);
        }
        let serving = daemon.clone();
        let listener = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let daemon = serving.clone();
                let task = tokio::spawn(async move {
                    let service =
                        hyper::service::service_fn(move |request| daemon.clone().handle(request));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
                serving.tasks.lock().unwrap().push(task);
            }
        });
        let cell = Arc::new(CellContainer {
            scope: format!(
                "scope-{}",
                dir.path().file_name().unwrap().to_string_lossy()
            ),
            name: container_name("test-node", &dir.path().to_string_lossy()),
            spec: Arc::new(ContainerSpec {
                class_name: "AllocationTest".to_string(),
                image: format!("celld-image:{}", "f".repeat(64)),
                instance_type: Some("basic".to_string()),
                max_instances: Some(1),
                runtime: Some("test-runtime".to_string()),
            }),
            state: Mutex::new(CellState::default()),
            legacy_lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            processes: Mutex::new(Vec::new()),
            exit: watch::channel(None).0,
        });
        let mut fixture = Self {
            dir,
            socket,
            daemon,
            listener,
            engine: None,
            cell,
            _specs_guard: specs_guard,
        };
        fixture.reopen().await.unwrap();
        fixture
    }

    fn activation(&self) -> ContainerActivation {
        let state = self.cell.state.lock().unwrap();
        ContainerActivation {
            cell: self.cell.clone(),
            epoch: state.activation_epoch,
            serial: state.activation_serial,
        }
    }

    async fn release(&self, mode: Release) -> anyhow::Result<()> {
        let ticket = self.engine().prepare_release(&self.activation(), mode)?;
        self.engine().release(ticket).await
    }

    fn engine(&self) -> &Arc<ContainerEngine> {
        self.engine.as_ref().unwrap()
    }

    async fn close_engine(&mut self) {
        if let Some(engine) = self.engine.take() {
            for _ in 0..100 {
                if Arc::strong_count(&engine) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(
                Arc::strong_count(&engine),
                1,
                "owned operation still active"
            );
            drop(engine);
        }
    }

    async fn reopen(&mut self) -> anyhow::Result<()> {
        self.close_engine().await;
        let engine = Arc::new(
            ContainerEngine::connect(
                Docker::new(&self.socket),
                "test-node".to_string(),
                None,
                None,
                Vec::new(),
                self.dir.path().join("state"),
            )
            .await?,
        );
        // inject an already verified firewall/network boundary, never a privileged container.
        *engine.fenced.lock().await = true;
        *engine.networks.lock().await =
            Some(("test-open".to_string(), "test-internal".to_string()));
        install_specs(vec![(*self.cell.spec).clone()], None);
        self.cell = engine
            .attach(&self.cell.scope, &self.cell.spec.class_name)
            .await?;
        self.engine = Some(engine);
        Ok(())
    }

    async fn legacy_cell(&self, suffix: &str, shared_class: bool) -> Arc<CellContainer> {
        let mut legacy = (*self.cell.spec).clone();
        legacy.image = self.options("unused", false).image;
        if shared_class {
            install_specs(vec![legacy.clone()], None);
        } else {
            legacy.class_name = "LegacyAllocationTest".to_string();
            legacy.max_instances = None;
            install_specs(vec![(*self.cell.spec).clone(), legacy.clone()], None);
        }
        self.engine()
            .attach(&format!("{}-{suffix}", self.cell.scope), &legacy.class_name)
            .await
            .unwrap()
    }

    async fn start_legacy(&self, cell: &Arc<CellContainer>) -> anyhow::Result<()> {
        self.engine()
            .start(
                cell,
                cell.begin_run(),
                StartParams {
                    entrypoint: None,
                    env: Vec::new(),
                    enable_internet: false,
                    labels: Vec::new(),
                },
            )
            .await
    }

    async fn legacy_settled(&self, cell: &Arc<CellContainer>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(guard) = cell.legacy_lifecycle.try_lock() {
                    drop(guard);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn options(&self, id: &str, second: bool) -> AllocationOptions {
        AllocationOptions {
            id: id.to_string(),
            image: format!("celld-image:{}", if second { "b" } else { "a" }.repeat(64)),
            engine_image: format!("sha256:{}", if second { "2" } else { "1" }.repeat(64)),
            platform: "linux/amd64".to_string(),
            entrypoint: Some(vec!["server".to_string()]),
            env: vec![(
                "TOKEN".to_string(),
                "private-allocation-test-value".to_string(),
            )],
            enable_internet: false,
        }
    }

    async fn call(&self, request: AllocationRequest) -> AllocationView {
        let receiver = self
            .engine()
            .allocation_request(self.cell.clone(), request)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    fn mutation_count(&self) -> usize {
        self.daemon
            .state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(method, path, _)| {
                method == "DELETE" || (method == "POST" && !path.ends_with("/wait"))
            })
            .count()
    }

    fn create_count(&self) -> usize {
        self.daemon
            .state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(method, path, _)| method == "POST" && path.starts_with("/containers/create?"))
            .count()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.listener.abort();
        for task in self.daemon.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

#[tokio::test]
async fn native_handoff_retirement_refuses_shared_admission_waiting_on_protection() {
    use crate::native_handoff::tests::{FaultStore, PutFault, StoreGate};
    for keep in [false, true] {
        for destroy in [false, true] {
            let fixture = Fixture::new().await;
            fixture.cell.state.lock().unwrap().activation_epoch = 1;
            fixture
                .call(AllocationRequest::Start(fixture.options("previous", false)))
                .await;
            fixture
                .call(AllocationRequest::Destroy("previous".into()))
                .await;
            let store = Arc::new(FaultStore::default());
            let bucket = store.bucket();
            let owner = Arc::new(crate::ownership_store::BucketOwnership::new(
                bucket.clone(),
                bucket,
                "test-node".into(),
                "generation-a".into(),
            ));
            owner
                .cas_owner(&fixture.cell.scope, celld_logic::CasGuard::Absent, 1)
                .await
                .unwrap();
            *fixture.engine().native_ownership_for_test.lock().unwrap() = Some(owner.clone());
            let gate = StoreGate::new();
            *store.put.lock().unwrap() = Some((
                crate::native_handoff::owner_key(&fixture.cell.scope),
                PutFault::Hold(gate.clone()),
            ));
            let request = if destroy {
                AllocationRequest::Destroy("queued".into())
            } else {
                AllocationRequest::Start(fixture.options("queued", false))
            };
            let waiting = fixture
                .engine()
                .allocation_request_from_event(fixture.cell.clone(), request, Some(1))
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .unwrap();
            let mutations = fixture.mutation_count();
            let ticket = fixture
                .engine()
                .prepare_runtime_release(
                    &fixture.activation(),
                    if keep {
                        Release::Keep
                    } else {
                        Release::Destroy
                    },
                )
                .unwrap();
            gate.open();
            assert!(tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            assert!(fixture
                .engine()
                .allocations
                .get(&fixture.cell.scope, "queued")
                .unwrap()
                .is_none());
            assert_eq!(fixture.mutation_count(), mutations);
            fixture.engine().release(ticket).await.unwrap();
            let previous = owner
                .read_owner(&fixture.cell.scope)
                .await
                .unwrap()
                .unwrap();
            owner
                .cas_owner(
                    &fixture.cell.scope,
                    celld_logic::CasGuard::Match(previous.etag),
                    2,
                )
                .await
                .unwrap();
            fixture
                .engine()
                .attach_activation(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
                .await
                .unwrap();
            let current = fixture
                .engine()
                .allocation_request_from_event(
                    fixture.cell.clone(),
                    AllocationRequest::Start(fixture.options("queued", false)),
                    Some(2),
                )
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), current)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .status,
                "running"
            );
            fixture
                .call(AllocationRequest::Destroy("queued".into()))
                .await;
        }
    }
}

#[tokio::test]
async fn native_handoff_failed_attachment_accepts_only_exact_retired_startup() {
    let fixture = Fixture::new().await;
    let scope = &fixture.cell.scope;
    let class = &fixture.cell.spec.class_name;
    fixture
        .engine()
        .attach_activation(scope, class, 1)
        .await
        .unwrap();
    fixture
        .call(AllocationRequest::Start(
            fixture.options("failed-start", false),
        ))
        .await;
    // This is the attachment that runtime placement/storage failure drops,
    // retaining the previous committed epoch and the new startup responsibility.
    let pending = fixture
        .engine()
        .attach_pending(scope, class, 2)
        .await
        .unwrap();
    drop(pending);
    assert_eq!(fixture.cell.state.lock().unwrap().activation_epoch, 1);
    assert!(fixture
        .engine()
        .close_native_handoff(scope, 2)
        .await
        .is_err());
    let ticket = fixture
        .engine()
        .prepare_startup_release(scope, 2)
        .unwrap()
        .unwrap();
    fixture.engine().release(ticket).await.unwrap();
    assert!(!fixture
        .engine()
        .close_native_handoff(scope, 2)
        .await
        .unwrap()
        .is_empty());
    fixture
        .engine()
        .attach_activation(scope, class, 3)
        .await
        .unwrap();
    assert!(fixture
        .engine()
        .prepare_dormant_native_release(
            scope,
            2,
            &fixture.engine().native_journal_identity().unwrap()
        )
        .is_err());
    assert!(fixture
        .engine()
        .close_native_handoff(scope, 2)
        .await
        .is_err());
}

#[tokio::test]
async fn native_handoff_restored_dormant_owner_closes_after_start_failure() {
    let fixture = Fixture::new().await;
    let cell = fixture
        .engine()
        .attach("AllocationTest:restored-start-failure", "AllocationTest")
        .await
        .unwrap();
    fixture
        .engine()
        .allocation_request(
            cell,
            AllocationRequest::Start(fixture.options("restored-failure", false)),
        )
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    crate::ltx_repl::native_handoff_tests::restored_dormant_release(
        fixture.engine().clone(),
        (*fixture.cell.spec).clone(),
        true,
    )
    .await;
}

#[tokio::test]
async fn native_handoff_restored_dormant_owner_retires_pre_attachment_failure() {
    let fixture = Fixture::new().await;
    let cell = fixture
        .engine()
        .attach("AllocationTest:restored-start-failure", "AllocationTest")
        .await
        .unwrap();
    fixture
        .engine()
        .allocation_request(
            cell,
            AllocationRequest::Start(fixture.options("before-attach", false)),
        )
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    crate::ltx_repl::native_handoff_tests::restored_dormant_release(
        fixture.engine().clone(),
        (*fixture.cell.spec).clone(),
        false,
    )
    .await;
}

#[tokio::test]
async fn native_handoff_runtime_retires_fetch_before_waiting_for_delete_and_retries_cleanup() {
    crate::native_ws::native_ws_tests::init_host();
    crate::js::Engine::init();
    let fixture = Fixture::new().await;
    fixture.cell.state.lock().unwrap().activation_epoch = 1;
    fixture
        .call(AllocationRequest::Start(fixture.options("retiring", false)))
        .await;
    let pool = crate::pool::Pool::new(
        crate::runtime::pool_limits(),
        Duration::from_secs(5),
        Box::new(|| {
            crate::js::Worker::load_config(Arc::new(crate::js::WorkerConfig::new(
                crate::js::WorkerConfigOptions {
                    src: "export default { fetch() { return new Response('ok'); } };".into(),
                    script_name: "handoff-stop-test".into(),
                    do_classes: vec![],
                    bindings: vec![],
                    r2_bindings: vec![],
                    d1_bindings: vec![],
                    kv_bindings: vec![],
                    queue_bindings: vec![],
                    queue_consumers: vec![],
                    workflow_bindings: vec![],
                    vars: vec![],
                    node: "test-node".into(),
                    modules: vec![],
                    compat: Default::default(),
                },
            )))
        }),
    );
    let (residency, alarm) = pool
        .place_cell()
        .unwrap()
        .adopt(
            &fixture.cell.scope,
            crate::js::CellStorage {
                path: ":memory:",
                epoch: 1,
                replicated_wake: false,
                vfs: None,
            },
        )
        .await
        .unwrap();
    let slot = residency.slot().clone();
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (positive, receiver) = tokio::sync::oneshot::channel();
    let current = slot
        .turn(|worker| {
            worker.native_handoff_post_verdict_fetch_for_test(
                &fixture.cell.scope,
                1,
                receiver,
                sends.clone(),
            )
        })
        .await;
    positive.send(()).unwrap();
    current.await.unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    let (release_fetch, receiver) = tokio::sync::oneshot::channel();
    let mut stale = Box::pin(
        slot.turn(|worker| {
            worker.native_handoff_post_verdict_fetch_for_test(
                &fixture.cell.scope,
                1,
                receiver,
                sends.clone(),
            )
        })
        .await,
    );
    assert!(futures_util::poll!(&mut stale).is_pending());
    let registry = Arc::new(Mutex::new(
        crate::runtime::CellRegistry::native_handoff_test_cell(
            fixture.cell.scope.clone(),
            1,
            fixture.activation(),
            residency,
            alarm,
        ),
    ));
    let delete = Gate::new();
    let retry_delete = Gate::new();
    fixture.daemon.state.lock().unwrap().delete_gate = Some(delete.clone());
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    let mut stopping = tokio::spawn(crate::actor::report_stopped_when_released(
        1,
        fixture.cell.scope.clone(),
        1,
        "test_bounded_retirement",
        Some(0), // already expired: incomplete retirement must still be retried
        {
            let registry = registry.clone();
            let engine = fixture.engine().clone();
            let daemon = fixture.daemon.clone();
            let scope = fixture.cell.scope.clone();
            let retry_delete = retry_delete.clone();
            move || {
                let registry = registry.clone();
                let engine = engine.clone();
                let daemon = daemon.clone();
                let scope = scope.clone();
                let retry_delete = retry_delete.clone();
                async move {
                    let result = crate::runtime::CellRegistry::retire(
                        &registry,
                        Some(engine),
                        &scope,
                        1,
                        &crate::runtime::StopMode::Evict {
                            preserve_local: false,
                            abandon: None,
                        },
                    )
                    .await;
                    if result.is_err() {
                        daemon.state.lock().unwrap().delete_gate = Some(retry_delete);
                    }
                    result
                }
            }
        },
    ));
    tokio::time::timeout(Duration::from_secs(5), delete.entered.notified())
        .await
        .unwrap();
    release_fetch.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), stale)
            .await
            .unwrap()
            .unwrap_err(),
        "actor continuation is retired"
    );
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "retired fetch must not poll outbound send"
    );
    delete.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        crate::asyncrt::select! {
            _ = &mut stopping => panic!("expired stop reported completion before cleanup settled"),
            _ = retry_delete.entered.notified() => {},
        }
    })
    .await
    .unwrap();
    assert!(!crate::runtime::CellRegistry::native_handoff_can_reserve(
        &registry,
        &fixture.cell.scope
    ));
    assert!(
        fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "retiring")
            .unwrap()
            .unwrap()
            .destroy_requested
    );
    retry_delete.open();
    let completed = tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        completed.event,
        celld_logic::Event::RuntimeStopped { op: 1 }
    ));
    assert!(crate::runtime::CellRegistry::native_handoff_can_reserve(
        &registry,
        &fixture.cell.scope
    ));
    assert_eq!(
        fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "retiring")
            .unwrap()
            .unwrap()
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_handoff_shared_protection_precedes_reservation_and_create() {
    let fixture = Fixture::new().await;
    fixture.cell.state.lock().unwrap().activation_epoch = 1;
    let bucket = crate::native_handoff::tests::bucket();
    let owner = Arc::new(crate::ownership_store::BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        "test-node".to_string(),
        "generation-a".to_string(),
    ));
    *fixture.engine().native_ownership_for_test.lock().unwrap() = Some(owner.clone());
    let refused = fixture
        .engine()
        .allocation_request_from_event(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("before-owner", false)),
            Some(1),
        )
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), refused)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "before-owner")
        .unwrap()
        .is_none());
    assert_eq!(fixture.create_count(), 0);
    owner
        .cas_owner(&fixture.cell.scope, celld_logic::CasGuard::Absent, 1)
        .await
        .unwrap();
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let start = fixture
        .engine()
        .allocation_request_from_event(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("protected", false)),
            Some(1),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let protected = owner
        .native_owner(&fixture.cell.scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(protected.node, "test-node");
    assert_eq!(protected.epoch, 1);
    assert_eq!(protected.generation, "generation-a");
    gate.open();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), start)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .status,
        "running"
    );
    fixture
        .engine()
        .close_native_handoff(&fixture.cell.scope, 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn native_handoff_unretired_foreign_owner_never_reserves_or_creates_on_successor() {
    let fixture = Fixture::new().await;
    fixture.cell.state.lock().unwrap().activation_epoch = 2;
    let bucket = crate::native_handoff::tests::bucket();
    let a = crate::ownership_store::BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        "donor".to_string(),
        "generation-a".to_string(),
    );
    let b = Arc::new(crate::ownership_store::BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        "test-node".to_string(),
        "generation-b".to_string(),
    ));
    a.cas_owner(&fixture.cell.scope, celld_logic::CasGuard::Absent, 1)
        .await
        .unwrap();
    a.protect_native(&fixture.cell.scope, 1, &"a".repeat(64))
        .await
        .unwrap();
    bucket
        .put(
            "nodes/donor.json",
            br#"{"node":"donor","expires_ms":0,"addr":"","probe_public_key":"generation-a"}"#
                .to_vec(),
        )
        .await
        .unwrap();
    let old = a.read_owner(&fixture.cell.scope).await.unwrap().unwrap();
    assert!(b
        .cas_owner(
            &fixture.cell.scope,
            celld_logic::CasGuard::Match(old.etag),
            2
        )
        .await
        .is_err());
    *fixture.engine().native_ownership_for_test.lock().unwrap() = Some(b);
    let start = fixture
        .engine()
        .allocation_request_from_event(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("successor", false)),
            Some(2),
        )
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), start)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "successor")
        .unwrap()
        .is_none());
    assert_eq!(fixture.create_count(), 0);
}

#[tokio::test]
async fn native_handoff_dormant_retained_cleanup_waits_and_cannot_retarget_successor() {
    let fixture = Fixture::new().await;
    let old = fixture
        .call(AllocationRequest::Start(fixture.options("retained", false)))
        .await;
    fixture.cell.set_inactivity(Duration::from_secs(60));
    fixture.release(Release::Keep).await.unwrap();
    assert!(fixture.cell.running());
    assert!(fixture
        .engine()
        .allocations
        .closed_attempts(&fixture.cell.scope)
        .is_err());
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().delete_gate = Some(gate.clone());
    let engine = fixture.engine().clone();
    let scope = fixture.cell.scope.clone();
    let epoch = fixture.activation().epoch;
    let closing = tokio::spawn(async move { engine.close_native_handoff(&scope, epoch).await });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(!closing.is_finished());
    assert!(fixture
        .engine()
        .allocations
        .closed_attempts(&fixture.cell.scope)
        .is_err());
    gate.open();
    let attempts = tokio::time::timeout(Duration::from_secs(5), closing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].container_id, old.container_id);
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    fixture
        .engine()
        .attach_activation(
            &fixture.cell.scope,
            &fixture.cell.spec.class_name,
            epoch + 1,
        )
        .await
        .unwrap();
    let next = fixture
        .call(AllocationRequest::Start(fixture.options("next", true)))
        .await;
    let mutations = fixture.mutation_count();
    assert!(fixture
        .engine()
        .close_native_handoff(&fixture.cell.scope, epoch)
        .await
        .is_err());
    assert_eq!(fixture.mutation_count(), mutations);
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("next".to_string()))
            .await
            .container_id,
        next.container_id
    );
    fixture
        .call(AllocationRequest::Destroy("next".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_immutable_selection_replay_and_teardown() {
    let fixture = Fixture::new().await;
    let options = fixture.options("first", false);
    let first = fixture
        .call(AllocationRequest::Start(options.clone()))
        .await;
    assert_eq!(first.status, "running");
    assert_eq!(
        first.observed.as_ref().unwrap().engine_image,
        options.engine_image
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(options.clone()))
            .await
            .container_id,
        first.container_id
    );
    assert_eq!(fixture.create_count(), 1);
    let mut changed = options.clone();
    changed.env[0].1 = "changed".to_string();
    let before = fixture.mutation_count();
    assert!(fixture
        .engine()
        .allocation_request(fixture.cell.clone(), AllocationRequest::Start(changed))
        .is_err());
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("second", true))
        )
        .is_err());
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("first", true))
        )
        .is_err());
    assert_eq!(fixture.mutation_count(), before);
    {
        let state = fixture.daemon.state.lock().unwrap();
        let body = &state
            .calls
            .iter()
            .find(|(_, path, _)| path.starts_with("/containers/create?"))
            .unwrap()
            .2;
        assert_eq!(body["Image"], options.engine_image);
        assert_eq!(body["HostConfig"]["Memory"], 1024 * 1024 * 1024u64);
        assert_eq!(body["HostConfig"]["Runtime"], "test-runtime");
        assert_eq!(body["HostConfig"]["CapDrop"], json!(["ALL"]));
        assert_eq!(
            body["HostConfig"]["SecurityOpt"],
            json!(["no-new-privileges"])
        );
        assert_eq!(body["HostConfig"]["PidsLimit"], PIDS_LIMIT);
        assert_eq!(
            body["HostConfig"]["NetworkMode"],
            if cfg!(target_os = "linux") {
                "test-internal"
            } else {
                "test-open"
            }
        );
    }
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("first".to_string()))
            .await
            .status,
        "destroyed"
    );
    assert_eq!(
        fixture.call(AllocationRequest::Start(options)).await.status,
        "destroyed"
    );
    let second = fixture
        .call(AllocationRequest::Start(fixture.options("second", true)))
        .await;
    assert_eq!(second.status, "running");
    assert_ne!(second.container_id, first.container_id);
    assert_ne!(
        second.observed.unwrap().engine_image,
        first.observed.unwrap().engine_image
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("first".to_string()))
            .await
            .status,
        "destroyed"
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("second".to_string()))
            .await
            .status,
        "running"
    );
    fixture
        .call(AllocationRequest::Destroy("second".to_string()))
        .await;
    let state = fixture.daemon.state.lock().unwrap();
    for (_, path, _) in state
        .calls
        .iter()
        .filter(|(method, _, _)| method == "DELETE")
    {
        let id = path
            .strip_prefix("/containers/")
            .unwrap()
            .split('?')
            .next()
            .unwrap();
        assert!(hex_value(id, 64), "cleanup must never delete by name");
    }
    drop(state);
    for entry in std::fs::read_dir(fixture.dir.path().join("state")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private-allocation-test-value"));
    }
}

#[tokio::test]
async fn native_allocation_abandoned_start_is_owned_until_destroy_settles() {
    let fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let receiver = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("delayed", false)),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let intent = fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "delayed")
        .unwrap()
        .unwrap();
    assert_eq!(intent.status, "creating");
    assert!(intent.create_dispatched && !intent.create_confirmed);
    drop(receiver);
    let mut destroyed = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("delayed".to_string()),
        )
        .unwrap();
    assert!(matches!(
        destroyed.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .all(|(method, _, _)| method != "DELETE"));
    gate.open();
    let result = tokio::time::timeout(Duration::from_secs(5), destroyed)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.status, "destroyed");
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(fixture.options("delayed", false)))
            .await
            .status,
        "destroyed"
    );
    assert_eq!(fixture.create_count(), 1);
}

#[tokio::test]
async fn native_allocation_ownership_release_closes_admission_and_waits_for_queued_start() {
    let fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let start = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("released", false)),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    drop(start);
    let engine = fixture.engine().clone();
    let ticket = engine
        .prepare_release(&fixture.activation(), Release::Destroy)
        .unwrap();
    let release = tokio::spawn(async move {
        engine.release(ticket).await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.cell.state.lock().unwrap().allocation_admitted {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(!release.is_finished());
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("after-release", true))
        )
        .is_err());
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), release)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("released".to_string()))
            .await
            .status,
        "destroyed"
    );
    assert_eq!(fixture.create_count(), 1);
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("after-release", true))
        )
        .is_err());
    fixture
        .engine()
        .attach(&fixture.cell.scope, &fixture.cell.spec.class_name)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(
                fixture.options("after-release", true)
            ))
            .await
            .status,
        "running"
    );
    fixture
        .call(AllocationRequest::Destroy("after-release".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_destroy_before_start_is_a_permanent_tombstone() {
    let fixture = Fixture::new().await;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("never-started".to_string()))
            .await
            .status,
        "destroyed"
    );
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("never-started", false))
        )
        .is_err());
    assert_eq!(fixture.create_count(), 0);
}

#[tokio::test]
async fn native_allocation_failed_delete_and_lost_delete_reply_are_retryable() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("retry", false)))
        .await;
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("retry".to_string()))
            .await
            .status,
        "unknown"
    );
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("blocked", true))
        )
        .is_err());
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("retry".to_string()))
            .await
            .status,
        "cleanupPending"
    );
    fixture.daemon.state.lock().unwrap().lose_delete_reply = true;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("retry".to_string()))
            .await
            .status,
        "unknown"
    );
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("retry".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_foreign_labels_never_authorise_removal() {
    let fixture = Fixture::new().await;
    let view = fixture
        .call(AllocationRequest::Start(fixture.options("owned", false)))
        .await;
    let id = view.container_id.unwrap();
    for label in [
        "celld.node",
        "celld.cell",
        "celld.class",
        "celld.allocation.attempt",
        "celld.allocation.id",
    ] {
        let original = {
            let mut state = fixture.daemon.state.lock().unwrap();
            let labels = &mut state.containers.get_mut(&id).unwrap()["Config"]["Labels"];
            let original = labels[label].clone();
            labels[label] = json!("foreign");
            original
        };
        assert_eq!(
            fixture
                .call(AllocationRequest::Destroy("owned".to_string()))
                .await
                .status,
            "unknown"
        );
        let mut state = fixture.daemon.state.lock().unwrap();
        assert!(state.calls.iter().all(|(method, _, _)| method != "DELETE"));
        state.containers.get_mut(&id).unwrap()["Config"]["Labels"][label] = original;
    }
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .get_mut(&id)
        .unwrap()["State"] = json!({});
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("owned".to_string()))
            .await
            .status,
        "unknown"
    );
    assert!(!fixture.cell.running());
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("owned".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_late_create_after_lost_reply_stays_unknown_across_restart() {
    let mut fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().late_create = Some(gate.clone());
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(fixture.options("late", false)))
            .await
            .status,
        "unknown"
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("late".to_string()))
            .await
            .status,
        "unknown"
    );
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("late".to_string()))
            .await
            .status,
        "unknown"
    );
    gate.open();
    for _ in 0..100 {
        if !fixture.daemon.state.lock().unwrap().containers.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let observed = fixture
        .call(AllocationRequest::Inspect("late".to_string()))
        .await;
    assert_eq!(observed.status, "unknown");
    assert!(observed.container_id.is_some());
    assert_eq!(observed.observed.unwrap().status, "created");
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("late".to_string()))
            .await
            .status,
        "unknown"
    );
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("replacement", true))
        )
        .is_err());
    assert_eq!(fixture.create_count(), 1);
}

#[tokio::test]
async fn native_allocation_restart_preserves_selection_tombstones_and_failed_cleanup() {
    let mut fixture = Fixture::new().await;
    let first = fixture
        .call(AllocationRequest::Start(fixture.options("restart", false)))
        .await;
    fixture.reopen().await.unwrap();
    let observed = fixture
        .call(AllocationRequest::Inspect("restart".to_string()))
        .await;
    assert_eq!(observed.status, "running");
    assert_eq!(observed.container_id, first.container_id);
    assert_eq!(fixture.create_count(), 1);
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    fixture
        .call(AllocationRequest::Destroy("restart".to_string()))
        .await;
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("restart".to_string()))
            .await
            .status,
        "cleanupPending"
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("restart".to_string()))
            .await
            .status,
        "destroyed"
    );
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(fixture.options("restart", false)))
            .await
            .status,
        "destroyed"
    );
    assert_eq!(fixture.create_count(), 1);
}

#[tokio::test]
async fn native_allocation_corrupt_and_missing_expected_journal_fail_closed() {
    for fault in ["corrupt", "missing-db", "missing-row", "missing-marker"] {
        let mut fixture = Fixture::new().await;
        fixture
            .call(AllocationRequest::Start(fixture.options("record", false)))
            .await;
        fixture.close_engine().await;
        let path = fixture
            .dir
            .path()
            .join("state/container-allocations.sqlite");
        match fault {
            "corrupt" => {
                let connection = Connection::open(&path).unwrap();
                connection
                    .execute("UPDATE attempts SET body = X'7b7d'", [])
                    .unwrap();
            }
            "missing-row" => {
                let connection = Connection::open(&path).unwrap();
                connection.execute("DELETE FROM attempts", []).unwrap();
            }
            "missing-marker" => std::fs::remove_file(
                fixture
                    .dir
                    .path()
                    .join("state/container-allocations.expected"),
            )
            .unwrap(),
            _ => std::fs::remove_file(path).unwrap(),
        }
        let before = fixture.mutation_count();
        assert!(fixture.reopen().await.is_err());
        assert_eq!(fixture.mutation_count(), before);
    }
}

#[tokio::test]
async fn native_allocation_missing_image_id_and_platform_mismatch_never_create() {
    for fault in ["missing", "id", "platform"] {
        let fixture = Fixture::new().await;
        let options = fixture.options("image", false);
        {
            let mut state = fixture.daemon.state.lock().unwrap();
            match fault {
                "missing" => {
                    state.images.remove(&options.image);
                }
                "id" => {
                    state.images.get_mut(&options.image).unwrap()["Id"] =
                        json!(format!("sha256:{}", "9".repeat(64)));
                }
                _ => {
                    state.images.get_mut(&options.image).unwrap()["Architecture"] = json!("arm64");
                }
            }
        }
        assert_eq!(
            fixture.call(AllocationRequest::Start(options)).await.status,
            "failed"
        );
        assert_eq!(fixture.create_count(), 0);
        assert_eq!(
            fixture
                .call(AllocationRequest::Destroy("image".to_string()))
                .await
                .status,
            "destroyed"
        );
    }
}

#[tokio::test]
async fn native_allocation_legacy_paths_cannot_replace_or_reap_an_attempt() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("native", false)))
        .await;
    assert!(fixture
        .engine()
        .legacy_start_admission(&fixture.cell)
        .is_err());
    assert!(fixture
        .engine()
        .start(
            &fixture.cell,
            fixture.cell.current_run(),
            StartParams {
                entrypoint: None,
                env: Vec::new(),
                enable_internet: false,
                labels: Vec::new()
            }
        )
        .await
        .is_err());
    fixture.engine().reap().await.unwrap();
    assert!(fixture
        .engine()
        .forget(&fixture.activation(), fixture.cell.current_run())
        .await
        .is_err());
    assert_eq!(fixture.daemon.state.lock().unwrap().containers.len(), 1);
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    assert!(fixture.engine().destroy(&fixture.cell).await.is_err());
    let cleanup = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("native".to_string()),
        )
        .unwrap();
    assert_eq!(cleanup.await.unwrap().unwrap().status, "unknown");
    assert!(fixture.engine().cell(&fixture.cell.scope).is_some());
    fixture.release(Release::Destroy).await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("native".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_lost_create_reply_with_visible_container_never_claims_settlement() {
    let mut fixture = Fixture::new().await;
    fixture.daemon.state.lock().unwrap().lose_create_reply = true;
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(fixture.options("lost", false)))
            .await
            .status,
        "unknown"
    );
    fixture.reopen().await.unwrap();
    let view = fixture
        .call(AllocationRequest::Inspect("lost".to_string()))
        .await;
    assert_eq!(view.status, "unknown");
    assert!(view.container_id.is_some());
    assert_eq!(
        view.observed.unwrap().engine_image,
        fixture.options("lost", false).engine_image
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("lost".to_string()))
            .await
            .status,
        "unknown"
    );
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("lost".to_string()))
            .await
            .status,
        "unknown"
    );
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    assert_eq!(fixture.create_count(), 1);
}

#[tokio::test]
async fn native_allocation_old_idle_release_cannot_destroy_successor() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("old", false)))
        .await;
    fixture.cell.set_inactivity(Duration::from_millis(30));
    fixture.release(Release::Keep).await.unwrap();
    fixture
        .call(AllocationRequest::Destroy("old".to_string()))
        .await;
    let successor = fixture
        .call(AllocationRequest::Start(fixture.options("successor", true)))
        .await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("successor".to_string()))
            .await
            .container_id,
        successor.container_id
    );
    assert_eq!(fixture.daemon.state.lock().unwrap().containers.len(), 1);
    fixture
        .call(AllocationRequest::Destroy("successor".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_reactivation_cancels_idle_cleanup() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("active", false)))
        .await;
    fixture.cell.set_inactivity(Duration::from_millis(50));
    fixture.release(Release::Keep).await.unwrap();
    fixture
        .engine()
        .attach(&fixture.cell.scope, &fixture.cell.spec.class_name)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("active".to_string()))
            .await
            .status,
        "running"
    );
    fixture
        .call(AllocationRequest::Destroy("active".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_invalid_inputs_and_scope_isolation() {
    let fixture = Fixture::new().await;
    for id in ["", "../unsafe", "bad/id", "bad?query", "bad\nlabel"] {
        assert!(fixture
            .engine()
            .allocation_request(
                fixture.cell.clone(),
                AllocationRequest::Start(fixture.options(id, false))
            )
            .is_err());
    }
    let mut options = fixture.options("invalid", false);
    options.engine_image = "latest".to_string();
    assert!(fixture
        .engine()
        .allocation_request(fixture.cell.clone(), AllocationRequest::Start(options))
        .is_err());
    assert_eq!(fixture.create_count(), 0);
    fixture
        .call(AllocationRequest::Start(fixture.options("shared", false)))
        .await;
    let other = fixture
        .engine()
        .attach("another-test-scope", &fixture.cell.spec.class_name)
        .await
        .unwrap();
    let lookup = fixture
        .engine()
        .allocation_request(
            other.clone(),
            AllocationRequest::Inspect("shared".to_string()),
        )
        .unwrap();
    assert!(lookup.await.unwrap().is_err());
    let destroy = fixture
        .engine()
        .allocation_request(other, AllocationRequest::Destroy("shared".to_string()))
        .unwrap();
    assert_eq!(destroy.await.unwrap().unwrap().status, "destroyed");
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("shared".to_string()))
            .await
            .status,
        "running"
    );
    fixture
        .call(AllocationRequest::Destroy("shared".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_cleanup_intent_survives_full_queue_and_release_refusal() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("full", false)))
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.engine().allocation_slots.available_permits() != 64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let permits = fixture
        .engine()
        .allocation_slots
        .clone()
        .try_acquire_many_owned(64)
        .unwrap();
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("full".to_string())
        )
        .is_err());
    let record = fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "full")
        .unwrap()
        .unwrap();
    assert!(record.destroy_requested);
    assert_eq!(record.status, "cleanupPending");
    assert!(fixture.release(Release::Destroy).await.is_err());
    assert!(!fixture.cell.state.lock().unwrap().allocation_admitted);
    assert_eq!(fixture.daemon.state.lock().unwrap().containers.len(), 1);
    drop(permits);
    fixture.release(Release::Destroy).await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("full".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_saturated_destroy_cannot_be_overwritten_by_late_create() {
    let fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let start = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("late-intent", false)),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let permits = fixture
        .engine()
        .allocation_slots
        .clone()
        .try_acquire_many_owned(63)
        .unwrap();
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("late-intent".to_string())
        )
        .is_err());
    assert!(
        fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "late-intent")
            .unwrap()
            .unwrap()
            .destroy_requested
    );
    drop(start);
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture
                .engine()
                .allocations
                .get(&fixture.cell.scope, "late-intent")
                .unwrap()
                .unwrap()
                .status
                == "destroyed"
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    assert_eq!(fixture.create_count(), 1);
    drop(permits);
}

#[tokio::test]
async fn native_allocation_late_observation_preserves_cleanup_status_in_reply_and_journal() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(
            fixture.options("observe-intent", false),
        ))
        .await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().image_gate = Some(gate.clone());
    let inspect = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Inspect("observe-intent".to_string()),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let permits = fixture
        .engine()
        .allocation_slots
        .clone()
        .try_acquire_many_owned(63)
        .unwrap();
    assert!(fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("observe-intent".to_string()),
        )
        .is_err());
    gate.open();
    let result = tokio::time::timeout(Duration::from_secs(5), inspect)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.status, "cleanupPending");
    assert_eq!(result.observed.unwrap().status, "running");
    assert!(!fixture.cell.running());
    let record = fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "observe-intent")
        .unwrap()
        .unwrap();
    assert!(record.destroy_requested);
    assert_eq!(record.status, "cleanupPending");
    drop(permits);
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("observe-intent".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_cleanup_intent_survives_execution_deadline_and_restart() {
    let mut fixture = Fixture::new().await;
    Arc::get_mut(fixture.engine.as_mut().unwrap())
        .unwrap()
        .allocation_wait = Duration::from_millis(10);
    fixture
        .call(AllocationRequest::Start(fixture.options("blocked", false)))
        .await;
    {
        let guard = fixture.engine().lifecycle.lock().await;
        let ticket = fixture
            .engine()
            .prepare_release(&fixture.activation(), Release::Destroy)
            .unwrap();
        assert!(fixture.engine().release(ticket).await.is_err());
        let record = fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "blocked")
            .unwrap()
            .unwrap();
        assert!(record.destroy_requested);
        assert_eq!(record.status, "cleanupPending");
        drop(guard);
    }
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("blocked".to_string()))
            .await
            .status,
        "cleanupPending"
    );
    fixture.release(Release::Destroy).await.unwrap();
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
}

#[tokio::test]
async fn native_allocation_missing_database_and_marker_keep_initialisation_evidence() {
    let mut fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().late_create = Some(gate.clone());
    fixture
        .call(AllocationRequest::Start(
            fixture.options("lost-state", false),
        ))
        .await;
    fixture.close_engine().await;
    let state = fixture.dir.path().join("state");
    std::fs::remove_file(state.join("container-allocations.sqlite")).unwrap();
    std::fs::remove_file(state.join("container-allocations.expected")).unwrap();
    assert!(state.join("container-allocations.lock").exists());
    assert!(fixture.reopen().await.is_err());
    assert!(!state.join("container-allocations.sqlite").exists());
    assert!(!state.join("container-allocations.expected").exists());
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.daemon.state.lock().unwrap().containers.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(fixture.reopen().await.is_err());
    assert_eq!(fixture.create_count(), 1);
    assert!(fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .all(|(method, _, _)| method != "DELETE"));
}

#[tokio::test]
async fn native_allocation_stale_activation_and_attempt_release_never_delete_successor() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("a", false)))
        .await;
    let activation_a = fixture.activation();
    let release_a = fixture
        .engine()
        .prepare_release(&activation_a, Release::Destroy)
        .unwrap();
    fixture
        .call(AllocationRequest::Destroy("a".to_string()))
        .await;
    let activation_b = fixture
        .engine()
        .attach_activation(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
        .await
        .unwrap();
    let b = fixture
        .call(AllocationRequest::Start(fixture.options("b", true)))
        .await;
    let before = fixture.mutation_count();
    assert!(fixture
        .engine()
        .prepare_release(&activation_a, Release::Destroy)
        .is_err());
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&fixture.cell, Some(0))
        .is_err());
    fixture
        .engine()
        .authorise_allocation_epoch(&fixture.cell, Some(2))
        .unwrap();
    for request in [
        AllocationRequest::Start(fixture.options("stale-start", false)),
        AllocationRequest::Inspect("b".to_string()),
        AllocationRequest::Destroy("b".to_string()),
    ] {
        assert!(fixture
            .engine()
            .allocation_request_from_event(fixture.cell.clone(), request, Some(0),)
            .is_err());
    }
    assert!(fixture
        .engine()
        .allocation_request_from_event(
            fixture.cell.clone(),
            AllocationRequest::Destroy("b".to_string()),
            None,
        )
        .is_err());
    assert!(fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "stale-start")
        .unwrap()
        .is_none());
    assert!(
        !fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "b")
            .unwrap()
            .unwrap()
            .destroy_requested
    );
    assert!(fixture.engine().destroy(&fixture.cell).await.is_err());
    assert!(fixture.engine().signal(&fixture.cell, 9).await.is_err());
    fixture.engine().release(release_a).await.unwrap();
    let old_inactivity = fixture.cell.state.lock().unwrap().inactivity;
    assert!(fixture
        .engine()
        .with_allocation_event_cell(&fixture.cell.scope, Some(0), |handle| {
            handle.set_inactivity(Duration::from_millis(1));
            Ok(())
        })
        .is_err());
    assert_eq!(
        fixture.cell.state.lock().unwrap().inactivity,
        old_inactivity
    );
    assert!(fixture
        .engine()
        .with_legacy_cell(&fixture.cell.scope, |handle| {
            handle.address(8080).map_err(anyhow::Error::msg)
        })
        .is_err());
    assert!(fixture
        .engine()
        .with_allocation_event_cell(&fixture.cell.scope, Some(2), |handle| {
            handle.address(8080).map_err(anyhow::Error::msg)
        })
        .is_ok());
    assert_eq!(fixture.mutation_count(), before);
    let inspected = fixture
        .call(AllocationRequest::Inspect("b".to_string()))
        .await;
    assert_eq!(inspected.container_id, b.container_id);
    assert_eq!(inspected.status, "running");
    let release_b = fixture
        .engine()
        .prepare_release(&activation_b, Release::Destroy)
        .unwrap();
    fixture.engine().release(release_b).await.unwrap();
}

#[tokio::test]
async fn native_allocation_delayed_idle_ticket_does_not_retarget_within_activation() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("old-idle", false)))
        .await;
    let stale = fixture
        .engine()
        .prepare_release(&fixture.activation(), Release::Keep)
        .unwrap();
    fixture
        .call(AllocationRequest::Destroy("old-idle".to_string()))
        .await;
    let successor = fixture
        .call(AllocationRequest::Start(fixture.options("new-idle", true)))
        .await;
    assert!(fixture.engine().release(stale).await.is_err());
    let current = fixture
        .call(AllocationRequest::Inspect("new-idle".to_string()))
        .await;
    assert_eq!(current.status, "running");
    assert_eq!(current.container_id, successor.container_id);
    fixture
        .call(AllocationRequest::Destroy("new-idle".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_reaper_requires_exact_recorded_legacy_ownership() {
    let fixture = Fixture::new().await;
    let owned = "d".repeat(64);
    let foreign = "e".repeat(64);
    let scope = "recorded-legacy-scope";
    let class = "AllocationTest";
    fixture.engine().allocations.claim_legacy(scope).unwrap();
    fixture
        .engine()
        .allocations
        .save_legacy(&mut LegacyRecord {
            scope: scope.to_string(),
            spec: (*fixture.cell.spec).clone(),
            target: Some(owned.clone()),
            phase: "running".to_string(),
            cleanup: None,
        })
        .unwrap();
    let info = json!({ "Id": owned, "Name": format!("/{}", container_name("test-node", scope)),
        "Config": { "Labels": { "celld.node": "test-node", "celld.cell": scope, "celld.class": class } } });
    {
        let mut state = fixture.daemon.state.lock().unwrap();
        state.containers.insert(owned.clone(), info.clone());
        state.containers.insert(foreign.clone(), json!({ "Id": foreign, "Name": "/unowned", "Config": { "Labels": { "celld.node": "test-node", "celld.cell": "unknown", "celld.class": class } } }));
    }
    for field in ["name", "class", "scope", "id", "node"] {
        let mut wrong = info.clone();
        match field {
            "name" => wrong["Name"] = json!("/foreign-name"),
            "id" => wrong["Id"] = json!(foreign),
            "class" => wrong["Config"]["Labels"]["celld.class"] = json!("ForeignClass"),
            "node" => wrong["Config"]["Labels"]["celld.node"] = json!("other-node"),
            _ => wrong["Config"]["Labels"]["celld.cell"] = json!("foreign-scope"),
        }
        fixture
            .daemon
            .state
            .lock()
            .unwrap()
            .containers
            .insert(owned.clone(), wrong);
        fixture.engine().reap().await.unwrap();
        assert!(fixture
            .daemon
            .state
            .lock()
            .unwrap()
            .calls
            .iter()
            .all(|(method, _, _)| method != "DELETE"));
    }
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .insert(owned.clone(), info);
    fixture.engine().reap().await.unwrap();
    let state = fixture.daemon.state.lock().unwrap();
    assert!(!state.containers.contains_key(&owned));
    assert!(state.containers.contains_key(&foreign));
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|(method, _, _)| method == "DELETE")
            .count(),
        1
    );
}

#[tokio::test]
async fn native_allocation_docker_response_limit_is_enforced_before_stream_end() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::Builder::new()
        .prefix("alloc-body-")
        .tempdir()
        .unwrap();
    let socket = dir.path().join("d.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() <= 8192);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let chunk = vec![b'x'; 65536];
        for _ in 0..17 {
            if stream.write_all(b"10000\r\n").await.is_err() {
                return;
            }
            if stream.write_all(&chunk).await.is_err() {
                return;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        std::future::pending::<()>().await;
    });
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        Docker::new(socket).call_bounded("GET", "/images/test/json", None, 1024 * 1024),
    )
    .await
    .unwrap();
    assert!(reply.err().unwrap().to_string().contains("exceeds limit"));
    server.abort();
}

#[tokio::test]
async fn native_allocation_attachment_rejects_replay_before_lifecycle_admission() {
    let fixture = Fixture::new().await;
    let started = fixture
        .call(AllocationRequest::Start(fixture.options("adopted", false)))
        .await;
    let lock = fixture.engine().lifecycle.lock().await;
    let mut attachment = Box::pin(fixture.engine().attach_activation(
        &fixture.cell.scope,
        &fixture.cell.spec.class_name,
        2,
    ));
    assert!(futures_util::poll!(attachment.as_mut()).is_pending());
    let replay = fixture.engine().allocation_request_from_event(
        fixture.cell.clone(),
        AllocationRequest::Start(fixture.options("adopted", false)),
        Some(0),
    );
    // registration now refuses the old event before it can enter the execution queue.
    assert!(replay
        .err()
        .unwrap()
        .to_string()
        .contains("stale, missing or pending"));
    drop(lock);
    attachment.await.unwrap();
    let observed = fixture
        .call(AllocationRequest::Inspect("adopted".to_string()))
        .await;
    assert_eq!(observed.status, "running");
    assert_eq!(observed.container_id, started.container_id);
    assert!(
        !fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "adopted")
            .unwrap()
            .unwrap()
            .destroy_requested
    );
    assert!(fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .all(|(method, _, _)| method != "DELETE"));
    fixture
        .call(AllocationRequest::Destroy("adopted".to_string()))
        .await;
}

fn pending_runtime_core(scope: &str) -> (celld_logic::State, u64, u64) {
    use celld_logic::{
        on_event, CasOutcome, Config, Effect, Event, OwnerRecord, OwnershipOnEvict, RestoreOutcome,
        State,
    };
    let mut state = State::new(
        "test-node",
        Config {
            max_resident: 4,
            max_activations: 4,
            max_evictions: 1,
            max_releases: 1,
            max_outbound_websockets: 1,
            ownership_on_evict: OwnershipOnEvict::Sticky,
            require_node_lease: false,
            peer_protocol: 1,
            operation_deadline_ms: None,
            owner_log_recovery_backoff_ms: 1,
            owner_log_recovery_attempts: 1,
            alarm_resident_ms: 0,
            idle_evict_ms: None,
            pressure: celld_logic::pressure::PressureConfig::from_limits(None, Some(0)),
        },
    );
    let effects = on_event(
        &mut state,
        Event::Request {
            request: 1,
            cell: scope.to_string(),
        },
    );
    let op = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::ReadOwner { op, .. } => Some(op),
            _ => None,
        })
        .unwrap();
    let effects = on_event(
        &mut state,
        Event::OwnerRead {
            op,
            now_ms: 0,
            result: Ok(Some(OwnerRecord {
                node: Some("test-node".to_string()),
                epoch: 1,
                etag: "owned".to_string(),
            })),
        },
    );
    let op = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::CasOwner { op, .. } => Some(op),
            _ => None,
        })
        .unwrap();
    let effects = on_event(
        &mut state,
        Event::OwnerCasCompleted {
            op,
            result: Ok(CasOutcome::Applied),
        },
    );
    let op = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Restore { op, .. } => Some(op),
            _ => None,
        })
        .unwrap();
    let effects = on_event(
        &mut state,
        Event::RestoreCompleted {
            op,
            result: Ok(RestoreOutcome {
                restored: true,
                alarm: None,
            }),
        },
    );
    let (op, epoch) = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::StartRuntime { op, epoch, .. } => Some((op, epoch)),
            _ => None,
        })
        .unwrap();
    (state, op, epoch)
}

#[tokio::test]
async fn native_allocation_pending_fenced_startup_failure_retires_only_recovered_attempt() {
    pending_fenced_startup_failure(false).await;
}

#[tokio::test]
async fn native_allocation_pending_admission_timeout_fence_retires_recovered_attempt() {
    pending_fenced_startup_failure(true).await;
}

async fn pending_fenced_startup_failure(admission_timeout: bool) {
    use celld_logic::{on_event, Effect, Event, Failure, StopCause};
    for fail_before_fence in [false, true] {
        let mut fixture = Fixture::new().await;
        let started = fixture
            .call(AllocationRequest::Start(
                fixture.options("fenced-startup", false),
            ))
            .await;
        let unrelated = fixture.legacy_cell("unrelated-fence", false).await;
        let unrelated_id = fixture
            .engine()
            .allocation_request(
                unrelated.clone(),
                AllocationRequest::Start(fixture.options("unrelated-fence", false)),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap()
            .container_id
            .unwrap();
        fixture.close_engine().await;
        let mut engine = Arc::new(
            ContainerEngine::connect(
                Docker::new(&fixture.socket),
                "test-node".to_string(),
                None,
                None,
                Vec::new(),
                fixture.dir.path().join("state"),
            )
            .await
            .unwrap(),
        );
        assert!(engine.cell(&fixture.cell.scope).is_none());
        let unrelated_capacity = instance_memory_bytes(unrelated.spec.instance_type.as_deref());
        assert_eq!(
            engine.reserved_memory_bytes(),
            unrelated_capacity + instance_memory_bytes(fixture.cell.spec.instance_type.as_deref())
        );
        if admission_timeout {
            Arc::get_mut(&mut engine).unwrap().allocation_wait = Duration::from_millis(100);
        }
        let admission = if admission_timeout {
            Some(engine.lifecycle.lock().await)
        } else {
            None
        };
        let (mut core, op, epoch) = pending_runtime_core(&fixture.cell.scope);
        let scope = fixture.cell.scope.clone();
        let class = fixture.cell.spec.class_name.clone();
        let gate = Gate::new();
        let startup_gate = gate.clone();
        let startup_engine = engine.clone();
        let startup = tokio::spawn(async move {
            let attachment = startup_engine.attach_pending(&scope, &class, epoch);
            tokio::pin!(attachment);
            if admission_timeout {
                // the first await is blocked before any observation or committed handle.
                assert!(futures_util::poll!(attachment.as_mut()).is_pending());
                startup_gate.entered.notify_one();
            }
            let _pending = attachment.await?;
            // placement and storage failures share this pre-commit ownership boundary.
            startup_gate.wait().await;
            Err::<(), anyhow::Error>(anyhow!("injected runtime startup failure"))
        });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
        let mut effects = if fail_before_fence {
            Vec::new()
        } else {
            on_event(&mut core, Event::NodeFenced)
        };
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::StopRuntime { .. })));
        gate.open();
        let error = tokio::time::timeout(Duration::from_secs(5), startup)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        if admission_timeout {
            assert_eq!(error.to_string(), "container attachment deadline exceeded");
            let recovered = engine.cell(&fixture.cell.scope).unwrap();
            {
                let state = recovered.state.lock().unwrap();
                assert_eq!(state.activation_serial, 0);
                assert!(!state.activation_pending);
                assert_eq!(state.startup.as_ref().unwrap().epoch, epoch);
            }
            // a stale retry cannot replace the failed successor's cleanup responsibility.
            assert!(engine
                .attach_pending(
                    &fixture.cell.scope,
                    &fixture.cell.spec.class_name,
                    epoch - 1
                )
                .await
                .is_err());
        }
        drop(admission);
        let completed = on_event(
            &mut core,
            Event::RuntimeStarted {
                op,
                isolate: None,
                generation: 0,
                result: Err(Failure::Definite),
            },
        );
        effects.extend(completed);
        if fail_before_fence {
            assert!(!effects
                .iter()
                .any(|effect| matches!(effect, Effect::StopRuntime { .. })));
            effects.extend(on_event(&mut core, Event::NodeFenced));
        }
        let stops: Vec<_> = effects
            .into_iter()
            .filter_map(|effect| match effect {
                Effect::StopRuntime {
                    cell,
                    epoch,
                    cause: StopCause::Fence,
                    bounded: false,
                    ..
                } => Some((cell, epoch)),
                _ => None,
            })
            .collect();
        assert_eq!(stops, vec![(fixture.cell.scope.clone(), epoch)]);
        assert!(engine
            .prepare_startup_release(&fixture.cell.scope, epoch + 1)
            .unwrap()
            .is_none());
        let runtimes = crate::runtime::CellRegistry::default();
        let cleanup = runtimes
            .prepare_container_stop(
                Some(engine.clone()),
                &stops[0].0,
                stops[0].1,
                &crate::runtime::StopMode::CloseInPlace,
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), cleanup)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(engine.reserved_memory_bytes(), unrelated_capacity);
        assert_eq!(
            engine
                .allocations
                .get(&fixture.cell.scope, "fenced-startup")
                .unwrap()
                .unwrap()
                .status,
            "destroyed"
        );
        assert!(engine
            .prepare_startup_release(&fixture.cell.scope, epoch)
            .unwrap()
            .is_none());
        {
            let daemon = fixture.daemon.state.lock().unwrap();
            assert_eq!(daemon.containers[&unrelated_id]["State"]["Running"], true);
            let deletes: Vec<_> = daemon
                .calls
                .iter()
                .filter(|(method, _, _)| method == "DELETE")
                .map(|(_, path, _)| path.clone())
                .collect();
            assert_eq!(
                deletes,
                vec![format!(
                    "/containers/{}?force=true&v=true",
                    started.container_id.unwrap()
                )]
            );
        }
        if admission_timeout {
            let successor = engine
                .attach_activation(
                    &fixture.cell.scope,
                    &fixture.cell.spec.class_name,
                    epoch + 1,
                )
                .await
                .unwrap();
            *engine.fenced.lock().await = true;
            *engine.networks.lock().await =
                Some(("test-open".to_string(), "test-internal".to_string()));
            let running = engine
                .allocation_request(
                    successor.cell.clone(),
                    AllocationRequest::Start(fixture.options("fenced-successor", false)),
                )
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(running.status, "running");
            let mutations = fixture.mutation_count();
            runtimes
                .prepare_container_stop(
                    Some(engine.clone()),
                    &fixture.cell.scope,
                    epoch,
                    &crate::runtime::StopMode::CloseInPlace,
                )
                .unwrap()
                .await
                .unwrap();
            assert_eq!(fixture.mutation_count(), mutations);
            assert_eq!(
                engine.reserved_memory_bytes(),
                unrelated_capacity
                    + instance_memory_bytes(fixture.cell.spec.instance_type.as_deref())
            );
            assert_eq!(
                fixture.daemon.state.lock().unwrap().containers
                    [running.container_id.as_ref().unwrap()]["State"]["Running"],
                true
            );
            let ticket = engine
                .prepare_release(&successor, Release::Destroy)
                .unwrap();
            engine.release(ticket).await.unwrap();
        }
        let unrelated = engine
            .attach_activation(&unrelated.scope, &unrelated.spec.class_name, 0)
            .await
            .unwrap();
        let ticket = engine
            .prepare_release(&unrelated, Release::Destroy)
            .unwrap();
        engine.release(ticket).await.unwrap();
    }
}

#[tokio::test]
async fn native_allocation_pending_legacy_create_progress_keeps_exact_operation_cleanup() {
    for outcome in [
        "acknowledged",
        "replacement-progress",
        "newer-run",
        "same-run",
        "unknown",
    ] {
        let fixture = Fixture::new().await;
        let unrelated = fixture
            .call(AllocationRequest::Start(
                fixture.options("unrelated-legacy-progress", false),
            ))
            .await;
        assert_eq!(unrelated.status, "running");
        let legacy = fixture.legacy_cell("pending-create-progress", false).await;
        let replacing = outcome == "replacement-progress";
        let previous = if replacing {
            fixture.start_legacy(&legacy).await.unwrap();
            fixture.legacy_settled(&legacy).await;
            fixture
                .engine()
                .allocations
                .legacy_record(&legacy.scope)
                .unwrap()
                .unwrap()
                .target
        } else {
            None
        };
        let gate = Gate::new();
        {
            let mut daemon = fixture.daemon.state.lock().unwrap();
            if replacing {
                daemon.image_gate = Some(gate.clone());
            } else {
                daemon.create_gate = Some(gate.clone());
            }
            daemon.lose_create_reply = outcome == "unknown";
        }
        let engine = fixture.engine().clone();
        let starting = legacy.clone();
        let caller = tokio::spawn(async move {
            engine
                .start(
                    &starting,
                    starting.begin_run(),
                    StartParams {
                        entrypoint: None,
                        env: Vec::new(),
                        enable_internet: false,
                        labels: Vec::new(),
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
        let error = fixture
            .engine()
            .attach_pending(&legacy.scope, &legacy.spec.class_name, 2)
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "legacy lifecycle operation is still pending"
        );
        {
            let state = legacy.state.lock().unwrap();
            let owner = state.startup.as_ref().unwrap();
            assert_eq!(owner.legacy_target, previous);
            assert!(owner.legacy_start_pending);
            assert!(owner.legacy_start == state.legacy_start);
            assert!(!state.activation_pending);
        }
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        gate.open();
        fixture.legacy_settled(&legacy).await;
        let record = fixture
            .engine()
            .allocations
            .legacy_record(&legacy.scope)
            .unwrap()
            .unwrap();
        if outcome != "unknown" {
            assert_eq!(record.phase, "running");
            assert!(record.target.is_some());
            assert!(legacy.running());
        }
        if outcome == "newer-run" {
            fixture.engine().destroy(&legacy).await.unwrap();
            fixture.start_legacy(&legacy).await.unwrap();
            fixture.legacy_settled(&legacy).await;
            let next = fixture
                .engine()
                .allocations
                .legacy_record(&legacy.scope)
                .unwrap()
                .unwrap();
            assert_ne!(next.target, record.target);
        } else if outcome == "same-run" {
            // a separately admitted start is not the captured operation, even with the same run.
            fixture
                .engine()
                .start(
                    &legacy,
                    legacy.current_run(),
                    StartParams {
                        entrypoint: None,
                        env: Vec::new(),
                        enable_internet: false,
                        labels: Vec::new(),
                    },
                )
                .await
                .unwrap();
            fixture.legacy_settled(&legacy).await;
        }
        let mutations = fixture.mutation_count();
        let runtime = crate::runtime::CellRegistry::default();
        let cleanup = runtime
            .prepare_container_stop(
                Some(fixture.engine().clone()),
                &legacy.scope,
                2,
                &crate::runtime::StopMode::CloseInPlace,
            )
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), cleanup)
            .await
            .unwrap();
        let unrelated_capacity = instance_memory_bytes(fixture.cell.spec.instance_type.as_deref());
        if outcome == "acknowledged" || replacing {
            result.unwrap();
            assert_eq!(fixture.engine().reserved_memory_bytes(), unrelated_capacity);
            let daemon = fixture.daemon.state.lock().unwrap();
            let deletes: Vec<_> = daemon
                .calls
                .iter()
                .filter(|(method, _, _)| method == "DELETE")
                .map(|(_, path, _)| path.clone())
                .collect();
            let mut expected = Vec::new();
            if let Some(previous) = previous {
                assert_ne!(record.target.as_ref(), Some(&previous));
                expected.push(format!("/containers/{previous}?force=true"));
            }
            expected.push(format!("/containers/{}?force=true", record.target.unwrap()));
            assert_eq!(deletes, expected);
        } else {
            assert_eq!(fixture.mutation_count(), mutations);
            assert_eq!(
                fixture.engine().reserved_memory_bytes(),
                unrelated_capacity + instance_memory_bytes(legacy.spec.instance_type.as_deref())
            );
            let retained = fixture
                .engine()
                .allocations
                .legacy_record(&legacy.scope)
                .unwrap()
                .unwrap();
            if outcome == "unknown" {
                assert!(result.is_err());
                assert_eq!(retained.phase, "creating");
                assert!(retained.target.is_none());
                assert!(retained.cleanup.is_some());
            } else {
                result.unwrap();
                assert_eq!(retained.phase, "running");
                assert!(retained.cleanup.is_none());
                assert!(legacy.running());
                fixture.engine().destroy(&legacy).await.unwrap();
            }
        }
        assert_eq!(
            fixture.daemon.state.lock().unwrap().containers
                [unrelated.container_id.as_ref().unwrap()]["State"]["Running"],
            true
        );
        fixture
            .call(AllocationRequest::Destroy(
                "unrelated-legacy-progress".to_string(),
            ))
            .await;
    }
}

#[tokio::test]
async fn native_allocation_pending_legacy_idle_cleanup_resumes_without_client_operation() {
    for cancel in [true, false] {
        let fixture = Fixture::new().await;
        let cell = fixture.legacy_cell("pending-idle", false).await;
        fixture.start_legacy(&cell).await.unwrap();
        fixture.legacy_settled(&cell).await;
        let activation = ContainerActivation {
            cell: cell.clone(),
            epoch: 0,
            serial: cell.state.lock().unwrap().activation_serial,
        };
        let target = fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .target
            .unwrap();
        let ticket = fixture
            .engine()
            .prepare_release(&activation, Release::Keep)
            .unwrap();
        let engine = fixture.engine().clone();
        let startup_cell = cell.clone();
        let gate = Gate::new();
        let startup_gate = gate.clone();
        let startup = tokio::spawn(async move {
            let pending = engine
                .attach_pending(&startup_cell.scope, &startup_cell.spec.class_name, 2)
                .await
                .unwrap();
            startup_gate.wait().await;
            pending.commit()
        });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
        cell.set_inactivity(Duration::ZERO);
        fixture.engine().release(ticket).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture
                .engine()
                .allocations
                .legacy_record(&cell.scope)
                .unwrap()
                .unwrap()
                .cleanup
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
        if cancel {
            startup.abort();
            assert!(startup.await.err().unwrap().is_cancelled());
        } else {
            gate.open();
            startup.await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture
                .engine()
                .allocations
                .legacy_record(&cell.scope)
                .unwrap()
                .unwrap()
                .phase
                != "idle"
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.legacy_settled(&cell).await;
        assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
        let state = fixture.daemon.state.lock().unwrap();
        assert!(state.containers.is_empty());
        let deletes: Vec<_> = state
            .calls
            .iter()
            .filter(|(method, _, _)| method == "DELETE")
            .map(|(_, path, _)| path.clone())
            .collect();
        assert_eq!(deletes, vec![format!("/containers/{target}?force=true")]);
    }
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn native_allocation_debug_startup_drop_settles_before_retry() {
    use crate::allocation_debug::{self as debug, tests as controls, Control};
    for signal in ["cancel", "timeout", "invalid"] {
        let fixture = Fixture::new().await;
        let started = fixture
            .call(AllocationRequest::Start(fixture.options("retained", false)))
            .await;
        let prior = fixture.activation();
        let mutations = fixture.mutation_count();
        let dir = controls::directory(
            &fixture.cell.scope,
            "cancel-startup",
            None,
            if signal == "timeout" { 100 } else { 2000 },
        );
        let control = Control::claim(
            dir.path(),
            &fixture.cell.scope,
            "cancel-startup",
            None,
            2,
            Some(41),
        )
        .unwrap();
        let engine = fixture.engine().clone();
        let cell = fixture.cell.clone();
        let startup = tokio::spawn(debug::startup_control(control, async move {
            let pending = engine
                .attach_pending(&cell.scope, &cell.spec.class_name, 2)
                .await?;
            debug::post_attach(&cell.scope, 2).await?;
            Ok::<_, anyhow::Error>(pending.commit())
        }));
        let entered = controls::ack(dir.path(), "entered.json").await;
        assert_eq!(entered["epoch"], 2);
        assert_eq!(entered["op"], 41);
        assert!(fixture.cell.state.lock().unwrap().activation_pending);
        match signal {
            "cancel" => controls::signal(dir.path(), "cancel.json"),
            "invalid" => controls::write(
                dir.path(),
                "cancel.json",
                json!({"version":1,"nonce":"wrong"}),
            ),
            _ => {}
        }
        let settled = controls::ack(dir.path(), "settled.json").await;
        assert_eq!(
            settled["status"],
            match signal {
                "cancel" => "cancelled",
                "timeout" => "timed-out",
                _ => "failed",
            }
        );
        // settlement is evidence of drop, not just receipt of the external signal.
        {
            let state = fixture.cell.state.lock().unwrap();
            assert!(!state.activation_pending);
            assert_eq!(state.activation_epoch, prior.epoch);
            assert_eq!(state.activation_serial, prior.serial);
        }
        assert!(tokio::time::timeout(Duration::from_secs(5), startup)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let record = fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "retained")
            .unwrap()
            .unwrap();
        assert!(!record.destroy_requested);
        assert_eq!(record.status, "running");
        assert_eq!(record.container_id, started.container_id);
        assert_eq!(fixture.mutation_count(), mutations);
        let retry_control = Control::claim(
            dir.path(),
            &fixture.cell.scope,
            "cancel-startup",
            None,
            3,
            Some(42),
        )
        .unwrap();
        assert!(retry_control.is_none());
        debug::startup_control(retry_control, async {
            let pending = fixture
                .engine()
                .attach_pending(&fixture.cell.scope, &fixture.cell.spec.class_name, 3)
                .await?;
            debug::post_attach(&fixture.cell.scope, 3).await?;
            Ok::<_, anyhow::Error>(pending.commit())
        })
        .await
        .unwrap();
        assert_eq!(
            fixture
                .call(AllocationRequest::Inspect("retained".into()))
                .await
                .container_id,
            started.container_id
        );
        fixture.release(Release::Destroy).await.unwrap();
    }
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn native_allocation_debug_delayed_destroy_uses_captured_epoch() {
    use crate::allocation_debug::{self as debug, tests as controls, Control};
    for successor in ["same", "future", "current"] {
        let fixture = Fixture::new().await;
        let a = fixture
            .call(AllocationRequest::Start(fixture.options("a", false)))
            .await;
        let epoch = fixture.activation().epoch;
        let id = if successor == "future" { "b" } else { "a" };
        let dir = controls::directory(&fixture.cell.scope, "delay-destroy", Some(id), 2000);
        let control = Control::claim(
            dir.path(),
            &fixture.cell.scope,
            "delay-destroy",
            Some(id),
            epoch,
            None,
        )
        .unwrap()
        .unwrap();
        control.enter().unwrap();
        let delayed = tokio::spawn(debug::delayed_destroy(
            control,
            fixture.engine().clone(),
            fixture.cell.clone(),
            AllocationRequest::Destroy(id.into()),
        ));
        controls::ack(dir.path(), "entered.json").await;
        // capture must not reserve even a future target or publish cleanup intent.
        assert!(
            !fixture
                .engine()
                .allocations
                .get(&fixture.cell.scope, "a")
                .unwrap()
                .unwrap()
                .destroy_requested
        );
        assert!(fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "b")
            .unwrap()
            .is_none());
        let expected = if successor == "future" {
            fixture.call(AllocationRequest::Destroy("a".into())).await;
            fixture
                .engine()
                .attach_activation(
                    &fixture.cell.scope,
                    &fixture.cell.spec.class_name,
                    epoch + 1,
                )
                .await
                .unwrap();
            fixture
                .call(AllocationRequest::Start(fixture.options("b", true)))
                .await
        } else {
            if successor == "same" {
                fixture
                    .engine()
                    .attach_activation(
                        &fixture.cell.scope,
                        &fixture.cell.spec.class_name,
                        epoch + 1,
                    )
                    .await
                    .unwrap();
            }
            a
        };
        let before = fixture.mutation_count();
        controls::signal(dir.path(), "release.json");
        tokio::time::timeout(Duration::from_secs(5), delayed)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let settled = controls::ack(dir.path(), "settled.json").await;
        assert_eq!(settled["epoch"], epoch);
        let record = fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, id)
            .unwrap()
            .unwrap();
        if successor == "current" {
            // the hook cannot fake a fence by refusing every delayed request.
            assert_eq!(settled["status"], "completed");
            assert_eq!(settled["allocationStatus"], "destroyed");
            assert_eq!(record.status, "destroyed");
            assert!(fixture.mutation_count() > before);
        } else {
            assert_eq!(settled["status"], "refused");
            assert_eq!(settled["reason"], "stale-owner");
            assert_eq!(settled["admitted"], false);
            assert_eq!(fixture.mutation_count(), before);
            assert_eq!(record.container_id, expected.container_id);
            assert_eq!(record.status, "running");
            assert!(!record.destroy_requested);
            let receiver = fixture
                .engine()
                .allocation_request_from_event(
                    fixture.cell.clone(),
                    AllocationRequest::Destroy(id.into()),
                    Some(epoch + 1),
                )
                .unwrap();
            assert_eq!(receiver.await.unwrap().unwrap().status, "destroyed");
        }
    }
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn native_allocation_debug_destroy_without_valid_release_never_admits() {
    use crate::allocation_debug::{self as debug, tests as controls, Control};
    for invalid in [false, true] {
        let fixture = Fixture::new().await;
        fixture
            .call(AllocationRequest::Start(fixture.options("a", false)))
            .await;
        let dir = controls::directory(&fixture.cell.scope, "delay-destroy", Some("a"), 100);
        let control = Control::claim(
            dir.path(),
            &fixture.cell.scope,
            "delay-destroy",
            Some("a"),
            fixture.activation().epoch,
            None,
        )
        .unwrap()
        .unwrap();
        control.enter().unwrap();
        if invalid {
            controls::write(
                dir.path(),
                "release.json",
                json!({"version":1,"nonce":"wrong"}),
            );
        }
        let before = fixture.mutation_count();
        debug::delayed_destroy(
            control,
            fixture.engine().clone(),
            fixture.cell.clone(),
            AllocationRequest::Destroy("a".into()),
        )
        .await
        .unwrap();
        let settled = controls::ack(dir.path(), "settled.json").await;
        assert_eq!(
            settled["status"],
            if invalid { "failed" } else { "timed-out" }
        );
        assert_eq!(settled["admitted"], false);
        assert_eq!(fixture.mutation_count(), before);
        assert!(
            !fixture
                .engine()
                .allocations
                .get(&fixture.cell.scope, "a")
                .unwrap()
                .unwrap()
                .destroy_requested
        );
        fixture.release(Release::Destroy).await.unwrap();
    }
}

#[tokio::test]
async fn native_allocation_pending_activation_failure_and_cancellation_retain_workload() {
    for boundary in ["failure", "cancel-attach", "cancel-placement"] {
        let fixture = Fixture::new().await;
        let started = fixture
            .call(AllocationRequest::Start(fixture.options("startup", false)))
            .await;
        fixture.release(Release::Keep).await.unwrap();
        let prior = fixture.activation();
        let before = fixture.mutation_count();
        let inactivity_epoch = fixture.cell.state.lock().unwrap().inactivity_epoch;
        if boundary != "failure" {
            let gate = Gate::new();
            if boundary == "cancel-attach" {
                fixture.daemon.state.lock().unwrap().inspect_gate = Some(gate.clone());
            }
            let engine = fixture.engine().clone();
            let cell = fixture.cell.clone();
            let startup_gate = gate.clone();
            let startup = tokio::spawn(async move {
                let pending = engine
                    .attach_pending(&cell.scope, &cell.spec.class_name, 2)
                    .await?;
                if boundary == "cancel-placement" {
                    startup_gate.wait().await;
                }
                Ok::<_, anyhow::Error>(pending)
            });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .unwrap();
            startup.abort();
            assert!(startup.await.err().unwrap().is_cancelled());
            gate.open();
        } else {
            let failed_startup = async {
                let _pending = fixture
                    .engine()
                    .attach_pending(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
                    .await?;
                // this is the placement/storage failure boundary before runtime publication.
                Err::<(), anyhow::Error>(anyhow!("injected startup failure"))
            }
            .await;
            assert!(failed_startup.is_err());
        }
        {
            let state = fixture.cell.state.lock().unwrap();
            assert!(state.allocation_admitted);
            assert!(!state.activation_pending);
            assert_eq!(state.activation_epoch, prior.epoch);
            assert_eq!(state.activation_serial, prior.serial);
            assert_eq!(state.inactivity_epoch, inactivity_epoch);
            assert!(!state.allocation_sweeper.as_ref().unwrap().is_cancelled());
        }
        let retained = fixture
            .engine()
            .allocations
            .get(&fixture.cell.scope, "startup")
            .unwrap()
            .unwrap();
        assert!(!retained.destroy_requested);
        assert_eq!(retained.status, "running");
        assert_eq!(fixture.mutation_count(), before);
        assert!(fixture
            .engine()
            .authorise_allocation_epoch(&fixture.cell, Some(2))
            .is_err());
        let retry = fixture
            .engine()
            .attach_activation(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
            .await
            .unwrap();
        let observed = fixture
            .call(AllocationRequest::Inspect("startup".to_string()))
            .await;
        assert_eq!(observed.status, "running");
        assert_eq!(observed.container_id, started.container_id);
        assert_eq!(fixture.mutation_count(), before);
        assert!(fixture
            .engine()
            .prepare_release(&prior, Release::Destroy)
            .is_err());
        let ticket = fixture
            .engine()
            .prepare_release(&retry, Release::Destroy)
            .unwrap();
        fixture.engine().release(ticket).await.unwrap();
        assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    }
}

#[tokio::test]
async fn native_allocation_pending_activation_has_no_workload_authority() {
    let fixture = Fixture::new().await;
    let scope = format!("{}-pending", fixture.cell.scope);
    let pending = fixture
        .engine()
        .attach_pending(&scope, &fixture.cell.spec.class_name, 2)
        .await
        .unwrap();
    let cell = fixture.engine().cell(&scope).unwrap();
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&cell, Some(2))
        .is_err());
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&cell, Some(0))
        .is_err());
    assert!(fixture.engine().legacy_start_admission(&cell).is_err());
    assert!(fixture
        .engine()
        .allocation_request(
            cell.clone(),
            AllocationRequest::Start(fixture.options("speculative", false))
        )
        .is_err());
    assert!(fixture
        .engine()
        .allocations
        .active(&scope)
        .unwrap()
        .is_none());
    assert!(fixture
        .engine()
        .attach_pending(&scope, &fixture.cell.spec.class_name, 3)
        .await
        .is_err());
    drop(pending);
    assert!(fixture.engine().cell(&scope).is_none());
    assert_eq!(fixture.mutation_count(), 0);

    let committed = fixture
        .engine()
        .attach_activation(&scope, &fixture.cell.spec.class_name, 3)
        .await
        .unwrap();
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&committed.cell, Some(3))
        .is_ok());
    assert!(fixture
        .engine()
        .attach_pending(&scope, &fixture.cell.spec.class_name, 2)
        .await
        .is_err());
    let pending = fixture
        .engine()
        .attach_pending(&scope, &fixture.cell.spec.class_name, 4)
        .await
        .unwrap();
    let serial = committed.cell.state.lock().unwrap().activation_serial;
    assert_eq!(serial, committed.serial);
    drop(pending);
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&committed.cell, Some(3))
        .is_ok());
    assert!(fixture
        .engine()
        .authorise_allocation_epoch(&committed.cell, Some(4))
        .is_err());
    let ticket = fixture
        .engine()
        .prepare_release(&committed, Release::Destroy)
        .unwrap();
    fixture.engine().release(ticket).await.unwrap();
}

#[tokio::test]
async fn native_allocation_pending_recovery_retains_record_without_granting_default_authority() {
    let mut fixture = Fixture::new().await;
    let started = fixture
        .call(AllocationRequest::Start(
            fixture.options("recovered", false),
        ))
        .await;
    fixture.close_engine().await;
    let engine = Arc::new(
        ContainerEngine::connect(
            Docker::new(&fixture.socket),
            "test-node".to_string(),
            None,
            None,
            Vec::new(),
            fixture.dir.path().join("state"),
        )
        .await
        .unwrap(),
    );
    let before = fixture.mutation_count();
    let pending = engine
        .attach_pending(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
        .await
        .unwrap();
    let recovered = engine.cell(&fixture.cell.scope).unwrap();
    drop(pending);
    assert!(engine
        .cell(&recovered.scope)
        .is_some_and(|cell| Arc::ptr_eq(&cell, &recovered)));
    assert!(engine
        .authorise_allocation_epoch(&recovered, Some(0))
        .is_err());
    assert!(engine
        .authorise_allocation_epoch(&recovered, Some(2))
        .is_err());
    let record = engine
        .allocations
        .get(&recovered.scope, "recovered")
        .unwrap()
        .unwrap();
    assert_eq!(record.container_id, started.container_id);
    assert_eq!(record.status, "running");
    assert!(!record.destroy_requested);
    assert_eq!(fixture.mutation_count(), before);
    let retry = engine
        .attach_activation(&recovered.scope, &recovered.spec.class_name, 2)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&retry.cell, &recovered));
    assert!(engine
        .authorise_allocation_epoch(&recovered, Some(2))
        .is_ok());
    let ticket = engine.prepare_release(&retry, Release::Destroy).unwrap();
    engine.release(ticket).await.unwrap();
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
}

#[tokio::test]
async fn native_allocation_pending_activation_preserves_existing_cleanup_intent() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("cleanup", false)))
        .await;
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    fixture
        .call(AllocationRequest::Destroy("cleanup".to_string()))
        .await;
    let before = fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "cleanup")
        .unwrap()
        .unwrap();
    assert!(before.destroy_requested);
    let prior = fixture.activation();
    let mutations = fixture.mutation_count();
    let pending = fixture
        .engine()
        .attach_pending(&fixture.cell.scope, &fixture.cell.spec.class_name, 2)
        .await
        .unwrap();
    drop(pending);
    let after = fixture
        .engine()
        .allocations
        .get(&fixture.cell.scope, "cleanup")
        .unwrap()
        .unwrap();
    assert!(after.destroy_requested);
    assert_eq!(after.status, "cleanupPending");
    assert_eq!(after.container_id, before.container_id);
    assert_eq!(fixture.activation().serial, prior.serial);
    assert_eq!(fixture.mutation_count(), mutations);
    fixture.daemon.state.lock().unwrap().fail_delete = false;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("cleanup".to_string()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn native_allocation_pending_legacy_activation_retains_workload_on_failure_and_cancel() {
    for cancel in [false, true] {
        let fixture = Fixture::new().await;
        let cell = fixture.legacy_cell("pending-retained", false).await;
        fixture.start_legacy(&cell).await.unwrap();
        fixture.legacy_settled(&cell).await;
        let prior = ContainerActivation {
            cell: cell.clone(),
            epoch: 0,
            serial: cell.state.lock().unwrap().activation_serial,
        };
        let ticket = fixture
            .engine()
            .prepare_release(&prior, Release::Keep)
            .unwrap();
        fixture.engine().release(ticket).await.unwrap();
        let target = fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .target;
        let before = fixture.mutation_count();
        if cancel {
            let gate = Gate::new();
            fixture.daemon.state.lock().unwrap().inspect_gate = Some(gate.clone());
            let engine = fixture.engine().clone();
            let cell = cell.clone();
            let task = tokio::spawn(async move {
                engine
                    .attach_pending(&cell.scope, &cell.spec.class_name, 2)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.err().unwrap().is_cancelled());
            gate.open();
        } else {
            let pending = fixture
                .engine()
                .attach_pending(&cell.scope, &cell.spec.class_name, 2)
                .await
                .unwrap();
            drop(pending);
        }
        assert_eq!(cell.state.lock().unwrap().activation_serial, prior.serial);
        let retained = fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap();
        assert_eq!(retained.target, target);
        assert_eq!(retained.phase, "running");
        assert!(retained.cleanup.is_none());
        assert_eq!(fixture.mutation_count(), before);
        let retry = fixture
            .engine()
            .attach_activation(&cell.scope, &cell.spec.class_name, 2)
            .await
            .unwrap();
        assert!(cell.running());
        assert_eq!(fixture.mutation_count(), before);
        assert!(fixture
            .engine()
            .prepare_release(&prior, Release::Destroy)
            .is_err());
        let ticket = fixture
            .engine()
            .prepare_release(&retry, Release::Destroy)
            .unwrap();
        fixture.engine().release(ticket).await.unwrap();
        assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
    }
}

#[tokio::test]
async fn native_allocation_cleanup_during_prestart_inspection_never_dispatches_start() {
    let fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .after_create_inspect_gate = Some(gate.clone());
    let start = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("prestart", false)),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let destroy = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("prestart".to_string()),
        )
        .unwrap();
    gate.open();
    assert_eq!(start.await.unwrap().unwrap().status, "destroyed");
    assert_eq!(destroy.await.unwrap().unwrap().status, "destroyed");
    let daemon = fixture.daemon.state.lock().unwrap();
    assert!(daemon.containers.is_empty());
    assert!(daemon
        .calls
        .iter()
        .all(|(method, path, _)| method != "POST" || !path.ends_with("/start")));
}

#[tokio::test]
async fn native_allocation_unverified_fence_refuses_without_dispatching_helper() {
    let fixture = Fixture::new().await;
    *fixture.engine().fenced.lock().await = false;
    let before = fixture.mutation_count();
    let result = fixture
        .call(AllocationRequest::Start(fixture.options("unfenced", false)))
        .await;
    assert_eq!(result.status, "failed");
    assert_eq!(result.reason.as_deref(), Some("fenceNotVerified"));
    assert_eq!(fixture.mutation_count(), before);
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("unfenced".to_string()))
            .await
            .status,
        "destroyed"
    );
    let guard = fixture.engine().fenced.lock().await;
    let busy = fixture
        .call(AllocationRequest::Start(
            fixture.options("busy-fence", false),
        ))
        .await;
    assert_eq!(busy.reason.as_deref(), Some("fenceNotVerified"));
    assert_eq!(fixture.mutation_count(), before);
    drop(guard);
}

#[tokio::test]
async fn native_allocation_complete_create_rejection_is_settleable_but_ambiguous_replies_are_not() {
    for (status, body, definite) in [
        (404, json!({"message": "No such image"}), true),
        (404, json!({}), false),
        (500, json!({"message": "daemon failed"}), false),
    ] {
        let fixture = Fixture::new().await;
        fixture.daemon.state.lock().unwrap().create_rejection = Some((status, body));
        let result = fixture
            .call(AllocationRequest::Start(fixture.options("rejected", false)))
            .await;
        assert_eq!(result.status, if definite { "failed" } else { "unknown" });
        assert_eq!(
            result.reason.as_deref(),
            Some(if definite {
                "createRejected"
            } else {
                "createOutcomeUnknown"
            })
        );
        assert_eq!(fixture.create_count(), 1);
        let replay = fixture
            .call(AllocationRequest::Start(fixture.options("rejected", false)))
            .await;
        assert_eq!(replay.status, result.status);
        assert_eq!(fixture.create_count(), 1);
        let cleanup = fixture
            .call(AllocationRequest::Destroy("rejected".to_string()))
            .await;
        assert_eq!(
            cleanup.status,
            if definite { "destroyed" } else { "unknown" }
        );
        if definite {
            assert_eq!(
                fixture
                    .call(AllocationRequest::Start(
                        fixture.options("replacement", true)
                    ))
                    .await
                    .status,
                "running"
            );
            fixture
                .call(AllocationRequest::Destroy("replacement".to_string()))
                .await;
        } else {
            assert!(fixture
                .engine()
                .allocation_request(
                    fixture.cell.clone(),
                    AllocationRequest::Start(fixture.options("blocked", true))
                )
                .is_err());
        }
    }
}

#[tokio::test]
async fn native_allocation_stalled_legacy_create_does_not_hold_native_lifecycle() {
    let fixture = Fixture::new().await;
    let mut legacy_spec = (*fixture.cell.spec).clone();
    legacy_spec.class_name = "LegacyAllocationTest".to_string();
    legacy_spec.image = fixture.options("unused", false).image;
    legacy_spec.max_instances = None;
    install_specs(
        vec![(*fixture.cell.spec).clone(), legacy_spec.clone()],
        None,
    );
    let legacy = fixture
        .engine()
        .attach(
            &format!("{}-legacy", fixture.cell.scope),
            &legacy_spec.class_name,
        )
        .await
        .unwrap();
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let engine = fixture.engine().clone();
    let starting = legacy.clone();
    let caller = tokio::spawn(async move {
        engine
            .start(
                &starting,
                starting.begin_run(),
                StartParams {
                    entrypoint: None,
                    env: Vec::new(),
                    enable_internet: false,
                    labels: Vec::new(),
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let native = fixture
        .call(AllocationRequest::Start(
            fixture.options("unrelated", false),
        ))
        .await;
    assert_eq!(native.status, "running");
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture
            .engine()
            .attach_activation(&fixture.cell.scope, &fixture.cell.spec.class_name, 2),
    )
    .await
    .unwrap()
    .unwrap();
    caller.abort();
    assert!(caller.await.err().unwrap().is_cancelled());
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(guard) = legacy.legacy_lifecycle.try_lock() {
                drop(guard);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(legacy.running());
    fixture.engine().destroy(&legacy).await.unwrap();
    fixture
        .call(AllocationRequest::Destroy("unrelated".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_lost_legacy_create_retains_intent_across_restart_without_reaping() {
    let mut fixture = Fixture::new().await;
    Arc::get_mut(fixture.engine.as_mut().unwrap())
        .unwrap()
        .allocation_wait = Duration::from_millis(100);
    let mut legacy_spec = (*fixture.cell.spec).clone();
    legacy_spec.class_name = "LegacyAllocationTest".to_string();
    legacy_spec.image = fixture.options("unused", false).image;
    legacy_spec.max_instances = None;
    install_specs(
        vec![(*fixture.cell.spec).clone(), legacy_spec.clone()],
        None,
    );
    let legacy_scope = format!("{}-legacy", fixture.cell.scope);
    let legacy = fixture
        .engine()
        .attach(&legacy_scope, &legacy_spec.class_name)
        .await
        .unwrap();
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().late_create = Some(gate.clone());
    fixture.daemon.state.lock().unwrap().late_reply_gate = Some(Gate::new());
    assert!(fixture
        .engine()
        .start(
            &legacy,
            legacy.begin_run(),
            StartParams {
                entrypoint: None,
                env: Vec::new(),
                enable_internet: false,
                labels: Vec::new()
            }
        )
        .await
        .is_err());
    assert!(fixture.engine().destroy(&legacy).await.is_err());
    let pending = fixture
        .engine()
        .allocations
        .legacy_record(&legacy_scope)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, "creating");
    assert!(pending.target.is_none());
    assert!(pending.cleanup.is_some());
    fixture.reopen().await.unwrap();
    let recovered = fixture
        .engine()
        .allocations
        .legacy_record(&legacy_scope)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.phase, "creating");
    assert!(recovered.target.is_none());
    assert_eq!(recovered.cleanup, pending.cleanup);
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.daemon.state.lock().unwrap().containers.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = fixture.mutation_count();
    fixture.engine().reap().await.unwrap();
    assert_eq!(fixture.mutation_count(), before);
    install_specs(
        vec![(*fixture.cell.spec).clone(), legacy_spec.clone()],
        None,
    );
    assert!(fixture
        .engine()
        .attach(&legacy_scope, &legacy_spec.class_name)
        .await
        .is_err());
    let legacy = fixture.engine().cell(&legacy_scope).unwrap();
    assert!(!legacy.running());
    assert!(fixture.engine().destroy(&legacy).await.is_err());
    assert!(fixture
        .engine()
        .start(
            &legacy,
            legacy.begin_run(),
            StartParams {
                entrypoint: None,
                env: Vec::new(),
                enable_internet: false,
                labels: Vec::new()
            }
        )
        .await
        .is_err());
    assert_eq!(fixture.mutation_count(), before);
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(
                fixture.options("unrelated", false)
            ))
            .await
            .status,
        "running"
    );
    fixture
        .call(AllocationRequest::Destroy("unrelated".to_string()))
        .await;
}

#[tokio::test]
async fn native_allocation_legacy_name_collision_never_grants_adoption_or_cleanup() {
    let fixture = Fixture::new().await;
    let cell = fixture.legacy_cell("collision", false).await;
    let foreign = "f".repeat(64);
    fixture.daemon.state.lock().unwrap().containers.insert(foreign.clone(), json!({
        "Id": foreign, "Name": format!("/{}", cell.name),
        "Config": {"Labels": {"celld.node": "test-node", "celld.cell": cell.scope, "celld.class": cell.spec.class_name}},
        "State": {"Running": true, "Status": "running"}
    }));
    let pending = fixture
        .engine()
        .attach_pending(&cell.scope, &cell.spec.class_name, 2)
        .await
        .unwrap();
    assert!(!cell.running());
    drop(pending);
    assert!(fixture.engine().cell(&cell.scope).is_some());
    let cell = fixture
        .engine()
        .attach_activation(&cell.scope, &cell.spec.class_name, 2)
        .await
        .unwrap()
        .cell;
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase,
        "idle"
    );
    fixture.engine().destroy(&cell).await.unwrap();
    let state = fixture.daemon.state.lock().unwrap();
    assert_eq!(state.containers[&foreign]["State"]["Running"], true);
    assert!(state
        .calls
        .iter()
        .all(|(method, path, _)| method != "DELETE" && !path.contains("/kill")));
}

#[tokio::test]
async fn native_allocation_legacy_labels_guard_start_adoption_signal_exec_and_delete() {
    let fixture = Fixture::new().await;
    let cell = fixture.legacy_cell("labels", false).await;
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    let id = fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .unwrap()
        .target
        .unwrap();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .get_mut(&id)
        .unwrap()["Config"]["Labels"]["celld.cell"] = json!("foreign-scope");
    let before = fixture.mutation_count();
    assert!(fixture.engine().signal(&cell, 9).await.is_err());
    assert!(fixture
        .engine()
        .exec(
            &cell,
            ExecParams {
                cmd: vec!["true".to_string()],
                env: Vec::new(),
                cwd: None,
                user: None,
                combined: false
            }
        )
        .await
        .is_err());
    assert!(fixture
        .engine()
        .attach_pending(&cell.scope, &cell.spec.class_name, 2)
        .await
        .is_err());
    let retained = fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .unwrap();
    assert_eq!(retained.phase, "running");
    assert!(retained.cleanup.is_none());
    fixture.legacy_settled(&cell).await;
    assert!(fixture.engine().destroy(&cell).await.is_err());
    assert!(fixture.start_legacy(&cell).await.is_err());
    assert_eq!(fixture.mutation_count(), before);
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .get_mut(&id)
        .unwrap()["Config"]["Labels"]["celld.cell"] = json!(cell.scope);
    fixture.engine().destroy(&cell).await.unwrap();
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());

    let replacement = fixture.legacy_cell("replacement-labels", false).await;
    fixture.start_legacy(&replacement).await.unwrap();
    fixture.legacy_settled(&replacement).await;
    let target = fixture
        .engine()
        .allocations
        .legacy_record(&replacement.scope)
        .unwrap()
        .unwrap()
        .target
        .unwrap();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .get_mut(&target)
        .unwrap()["Config"]["Labels"]["celld.cell"] = json!("foreign-scope");
    let before = fixture.mutation_count();
    assert!(replacement.state.lock().unwrap().allocation_admitted);
    assert!(fixture.start_legacy(&replacement).await.is_err());
    fixture.legacy_settled(&replacement).await;
    let record = fixture
        .engine()
        .allocations
        .legacy_record(&replacement.scope)
        .unwrap()
        .unwrap();
    assert_eq!(record.phase, "deleting");
    assert_eq!(record.target.as_deref(), Some(target.as_str()));
    assert_eq!(fixture.mutation_count(), before);
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .get_mut(&target)
        .unwrap()["Config"]["Labels"]["celld.cell"] = json!(replacement.scope);
    fixture.engine().destroy(&replacement).await.unwrap();
    assert!(fixture.daemon.state.lock().unwrap().containers.is_empty());
}

#[tokio::test]
async fn native_allocation_legacy_capacity_and_missing_image_failures_are_retryable() {
    let fixture = Fixture::new().await;
    fixture
        .call(AllocationRequest::Start(fixture.options("a", false)))
        .await;
    let cell = fixture.legacy_cell("capacity", true).await;
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase,
        "idle"
    );
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    fixture
        .call(AllocationRequest::Destroy("a".to_string()))
        .await;
    let image = fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .images
        .remove(&cell.spec.image)
        .unwrap();
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .images
        .insert(cell.spec.image.clone(), image);
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    let other = fixture.legacy_cell("blocked", true).await;
    assert!(fixture.start_legacy(&other).await.is_err());
    fixture.legacy_settled(&other).await;
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    fixture.engine().destroy(&cell).await.unwrap();
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
}

#[tokio::test]
async fn native_allocation_legacy_delete_faults_retry_exact_target_across_restart() {
    let mut fixture = Fixture::new().await;
    let cell = fixture.legacy_cell("delete", false).await;
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    let target = fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .unwrap()
        .target
        .unwrap();
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    assert!(fixture.engine().destroy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    let record = fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .unwrap();
    assert_eq!(record.phase, "deleting");
    assert_eq!(record.target.as_deref(), Some(target.as_str()));
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    let mut successor = fixture.daemon.state.lock().unwrap().containers[&target].clone();
    fixture.daemon.state.lock().unwrap().lose_delete_reply = true;
    assert!(fixture.engine().destroy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    let foreign = "e".repeat(64);
    successor["Id"] = json!(foreign);
    successor["State"] = json!({"Running": true, "Status": "running"});
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .insert(foreign.clone(), successor);
    fixture.reopen().await.unwrap();
    install_specs(
        vec![(*fixture.cell.spec).clone(), (*cell.spec).clone()],
        None,
    );
    let cell = fixture
        .engine()
        .attach(&cell.scope, &cell.spec.class_name)
        .await
        .unwrap();
    assert!(!cell.running());
    fixture.legacy_settled(&cell).await;
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
    fixture.engine().destroy(&cell).await.unwrap();
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
    let state = fixture.daemon.state.lock().unwrap();
    assert!(state.containers.contains_key(&foreign));
    assert!(state
        .calls
        .iter()
        .filter(|(method, _, _)| method == "DELETE")
        .all(|(_, path, _)| path == &format!("/containers/{target}?force=true")));
}

#[tokio::test]
async fn native_allocation_legacy_attach_and_forget_cannot_retarget_a_successor() {
    let fixture = Fixture::new().await;
    let cell = fixture.legacy_cell("release", false).await;
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    let activation = ContainerActivation {
        cell: cell.clone(),
        epoch: 0,
        serial: cell.state.lock().unwrap().activation_serial,
    };
    let stale_idle = fixture
        .engine()
        .prepare_release(&activation, Release::Keep)
        .unwrap();
    fixture.engine().destroy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    assert!(fixture.engine().release(stale_idle).await.is_err());
    assert!(cell.running());
    let run = cell.current_run();
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().delete_gate = Some(gate.clone());
    let mut release = Box::pin(fixture.engine().forget(&activation, run));
    assert!(futures_util::poll!(release.as_mut()).is_pending());
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(fixture
        .engine()
        .attach_activation(&cell.scope, &cell.spec.class_name, 2)
        .await
        .is_err());
    assert!(fixture.engine().legacy_start_admission(&cell).is_err());
    assert!(fixture.start_legacy(&cell).await.is_err());
    gate.open();
    fixture.legacy_settled(&cell).await;
    // leave the old release waiter suspended at the delete-to-registry-removal boundary.
    fixture
        .engine()
        .attach_activation(&cell.scope, &cell.spec.class_name, 2)
        .await
        .unwrap();
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    let successor = fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .unwrap()
        .target;
    release.await.unwrap();
    assert!(fixture
        .engine()
        .cell(&cell.scope)
        .is_some_and(|current| Arc::ptr_eq(&current, &cell)));
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .target,
        successor
    );
    assert!(cell.running());
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    assert!(fixture.engine().forget(&activation, run).await.is_err());
    fixture.engine().destroy(&cell).await.unwrap();
}

#[tokio::test]
async fn native_allocation_legacy_accounting_is_continuous_through_confirmed_start() {
    let fixture = Fixture::new().await;
    let cell = fixture.legacy_cell("accounting", true).await;
    let gate = Gate::new();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .after_create_inspect_gate = Some(gate.clone());
    let mut start = Box::pin(fixture.start_legacy(&cell));
    assert!(futures_util::poll!(start.as_mut()).is_pending());
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase,
        "starting"
    );
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase
            != "running"
        {
            assert_eq!(
                fixture.engine().running_instances_by_class()["AllocationTest"],
                1
            );
            assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    start.await.unwrap();
    fixture.legacy_settled(&cell).await;
    cell.state.lock().unwrap().running = false;
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    fixture.engine().destroy(&cell).await.unwrap();
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
}

#[tokio::test]
async fn native_allocation_legacy_preparation_and_aggregate_admission_are_bounded() {
    let mut fixture = Fixture::new().await;
    Arc::get_mut(fixture.engine.as_mut().unwrap())
        .unwrap()
        .allocation_wait = Duration::from_millis(100);
    let cell = fixture.legacy_cell("bounded", false).await;
    let permits = fixture
        .engine()
        .legacy_slots
        .clone()
        .try_acquire_many_owned(64)
        .unwrap();
    assert!(fixture.start_legacy(&cell).await.is_err());
    assert!(!cell.running());
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        fixture.engine().monitor(&cell, cell.current_run())
    )
    .await
    .unwrap()
    .is_err());
    assert!(fixture
        .engine()
        .allocations
        .legacy_record(&cell.scope)
        .unwrap()
        .is_none());
    drop(permits);
    *fixture.engine().fenced.lock().await = false;
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    *fixture.engine().fenced.lock().await = true;
    let networks = fixture.engine().networks.lock().await.take();
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    *fixture.engine().networks.lock().await = networks;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().image_gate = Some(gate.clone());
    assert!(fixture.start_legacy(&cell).await.is_err());
    fixture.legacy_settled(&cell).await;
    // the lifecycle lock is released before the owned task's final publication and permit drop.
    let permits = tokio::time::timeout(
        Duration::from_secs(5),
        fixture.engine().legacy_slots.clone().acquire_many_owned(64),
    )
    .await
    .expect("legacy preparation task did not return all admission permits")
    .unwrap();
    drop(permits);
    assert_eq!(fixture.engine().legacy_slots.available_permits(), 64);
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase,
        "idle"
    );
    assert_eq!(fixture.mutation_count(), 0);
    gate.open();
    fixture.start_legacy(&cell).await.unwrap();
    fixture.legacy_settled(&cell).await;
    let permits = tokio::time::timeout(
        Duration::from_secs(5),
        fixture.engine().legacy_slots.clone().acquire_many_owned(64),
    )
    .await
    .expect("legacy start task did not return all admission permits")
    .unwrap();
    assert_eq!(fixture.engine().legacy_slots.available_permits(), 0);
    assert!(fixture.engine().destroy(&cell).await.is_err());
    assert_eq!(
        fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap()
            .phase,
        "deleting"
    );
    drop(permits);
    fixture.engine().destroy(&cell).await.unwrap();
}

#[tokio::test]
async fn native_allocation_legacy_cleanup_survives_abandoned_start_and_idle_release() {
    for (boundary, cleanup) in [
        ("image", "idle"),
        ("create", "idle"),
        ("create", "destroy"),
        ("prestart", "destroy"),
        ("completion", "release"),
        ("image", "release"),
    ] {
        let fixture = Fixture::new().await;
        let cell = fixture.legacy_cell("abandoned-cleanup", false).await;
        let gate = Gate::new();
        {
            let mut state = fixture.daemon.state.lock().unwrap();
            match boundary {
                "image" => state.image_gate = Some(gate.clone()),
                "create" => state.create_gate = Some(gate.clone()),
                "prestart" => state.after_create_inspect_gate = Some(gate.clone()),
                _ => state.after_start_inspect_gate = Some(gate.clone()),
            }
        }
        let mut start = Box::pin(fixture.start_legacy(&cell));
        assert!(futures_util::poll!(start.as_mut()).is_pending());
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
        drop(start);
        let activation = {
            let state = cell.state.lock().unwrap();
            ContainerActivation {
                cell: cell.clone(),
                epoch: state.activation_epoch,
                serial: state.activation_serial,
            }
        };
        let run = cell.current_run();
        match cleanup {
            "idle" => {
                cell.set_inactivity(Duration::from_millis(10));
                let ticket = fixture
                    .engine()
                    .prepare_release(&activation, Release::Keep)
                    .unwrap();
                fixture.engine().release(ticket).await.unwrap();
            }
            "release" => {
                let ticket = fixture
                    .engine()
                    .prepare_release(&activation, Release::Destroy)
                    .unwrap();
                assert!(fixture
                    .engine()
                    .allocations
                    .legacy_record(&cell.scope)
                    .unwrap()
                    .unwrap()
                    .cleanup
                    .is_some());
                if boundary == "image" {
                    // the synchronous ticket alone must retain responsibility if its waiter vanishes.
                    drop(ticket);
                } else {
                    assert!(fixture.engine().release(ticket).await.is_err());
                }
            }
            _ => assert!(fixture.engine().destroy(&cell).await.is_err()),
        }
        let pending = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let record = fixture
                    .engine()
                    .allocations
                    .legacy_record(&cell.scope)
                    .unwrap()
                    .unwrap();
                if record.cleanup.is_some() {
                    break record;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            pending.cleanup,
            Some(LegacyCleanup {
                epoch: activation.epoch,
                serial: activation.serial,
                run,
            })
        );
        assert_eq!(
            pending.phase,
            match boundary {
                "image" => "preparing",
                "create" => "creating",
                _ => "starting",
            }
        );
        gate.open();
        fixture.legacy_settled(&cell).await;
        let settled = fixture
            .engine()
            .allocations
            .legacy_record(&cell.scope)
            .unwrap()
            .unwrap();
        assert_eq!(settled.phase, "idle", "{boundary}/{cleanup}");
        assert!(settled.target.is_none());
        assert!(settled.cleanup.is_none());
        assert!(!cell.running());
        assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
        let state = fixture.daemon.state.lock().unwrap();
        assert!(state.containers.is_empty());
        if boundary != "completion" {
            assert!(state
                .calls
                .iter()
                .all(|(_, path, _)| !path.ends_with("/start")));
        }
        if boundary == "image" {
            assert!(state.calls.iter().all(|(method, _, _)| method == "GET"));
        }
    }
}

#[tokio::test]
async fn native_allocation_legacy_reaper_retries_acknowledged_starting_and_deleting_targets() {
    let fixture = Fixture::new().await;
    let scope = format!("{}-reap-starting", fixture.cell.scope);
    let owned = "c".repeat(64);
    let foreign = "d".repeat(64);
    fixture
        .engine()
        .allocations
        .save_legacy(&mut LegacyRecord {
            scope: scope.clone(),
            spec: (*fixture.cell.spec).clone(),
            target: Some(owned.clone()),
            phase: "starting".to_string(),
            cleanup: None,
        })
        .unwrap();
    let info = json!({
        "Id": owned, "Name": format!("/{}", container_name("test-node", &scope)),
        "Config": {"Labels": {"celld.node": "test-node", "celld.cell": scope,
            "celld.class": fixture.cell.spec.class_name}},
        "State": {"Running": true, "Status": "running"}
    });
    {
        let mut state = fixture.daemon.state.lock().unwrap();
        state.containers.insert(owned.clone(), info.clone());
        let mut collision = info;
        collision["Id"] = json!(foreign);
        state.containers.insert(foreign.clone(), collision);
        state.fail_delete = true;
    }
    fixture.engine().reap().await.unwrap();
    let pending = fixture
        .engine()
        .allocations
        .legacy_record(&scope)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, "deleting");
    assert_eq!(pending.target.as_deref(), Some(owned.as_str()));
    assert!(fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .containers
        .contains_key(&owned));
    fixture.engine().reap().await.unwrap();
    let settled = fixture
        .engine()
        .allocations
        .legacy_record(&scope)
        .unwrap()
        .unwrap();
    assert_eq!(settled.phase, "idle");
    assert!(settled.target.is_none());
    fixture.engine().reap().await.unwrap();
    let state = fixture.daemon.state.lock().unwrap();
    assert!(!state.containers.contains_key(&owned));
    assert_eq!(state.containers[&foreign]["State"]["Running"], true);
    let deletes: Vec<_> = state
        .calls
        .iter()
        .filter(|(method, _, _)| method == "DELETE")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes
        .iter()
        .all(|(_, path, _)| path == &format!("/containers/{owned}?force=true")));
}

#[tokio::test]
async fn native_allocation_pending_and_unknown_attempts_reserve_class_capacity() {
    let fixture = Fixture::new().await;
    let gate = Gate::new();
    fixture.daemon.state.lock().unwrap().create_gate = Some(gate.clone());
    let pending = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(fixture.options("capacity", false)),
        )
        .unwrap();
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    assert_eq!(
        fixture.engine().running_instances_by_class()["AllocationTest"],
        1
    );
    gate.entered.notified().await;
    gate.open();
    pending.await.unwrap().unwrap();
    fixture.daemon.state.lock().unwrap().fail_delete = true;
    fixture
        .call(AllocationRequest::Destroy("capacity".to_string()))
        .await;
    assert_eq!(fixture.engine().reserved_memory_bytes(), 1024 * 1024 * 1024);
    fixture
        .call(AllocationRequest::Destroy("capacity".to_string()))
        .await;
    assert_eq!(fixture.engine().reserved_memory_bytes(), 0);
}
