use super::super::simulation::{Control, Point, Registration};
use super::*;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};

fn disk_record(path: &Path, scope: &str, id: &str) -> Value {
    let connection =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let body: Vec<u8> = connection
        .query_row(
            "SELECT body FROM attempts WHERE scope=?1 AND id=?2",
            params![scope, id],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn directory(record: &Value) -> PathBuf {
    PathBuf::from(record["gate"]["directory"].as_str().unwrap())
}

fn release_bytes(record: &Value) -> Vec<u8> {
    std::fs::read(directory(record).join("release")).unwrap()
}

fn assert_release_safety(record: &Value) {
    let bytes = release_bytes(record);
    assert_eq!(bytes.len(), 66);
    assert_eq!(
        &bytes[1..65],
        record["attempt"].as_str().unwrap().as_bytes()
    );
    assert_eq!(bytes[65], b'\n');
    if bytes[0] == b'1' {
        assert!(record["create_confirmed"] == true);
        assert!(
            matches!(
                record["gate"]["phase"].as_str(),
                Some("releasePending" | "released")
            ),
            "release byte became visible without committed approval: phase={}",
            record["gate"]["phase"]
        );
    } else {
        assert_eq!(bytes[0], b'0');
    }
}

async fn sandbox_fixture() -> (Fixture, Arc<Control>, Registration) {
    sandbox_fixture_with(Some("runc"), None, Vec::new()).await
}

async fn sandbox_fixture_with(
    class_runtime: Option<&str>,
    node_runtime: Option<&str>,
    dns: Vec<String>,
) -> (Fixture, Arc<Control>, Registration) {
    let mut fixture = Fixture::new().await;
    if node_runtime.is_some() || !dns.is_empty() {
        fixture
            .reopen_with(node_runtime.map(str::to_string), dns)
            .await
            .unwrap();
    }
    let mut spec = (*fixture.cell.spec).clone();
    spec.class_name = "SandboxLifecycleTest".into();
    spec.runtime = class_runtime.map(str::to_string);
    spec.max_instances = None;
    install_specs(vec![spec.clone()], None);
    fixture.cell = fixture
        .engine()
        .attach(&format!("{}-sandbox", fixture.cell.scope), &spec.class_name)
        .await
        .unwrap();
    for image in fixture.daemon.state.lock().unwrap().images.values_mut() {
        image["Config"] = json!({"Entrypoint":["/image-entry"],"Cmd":["image-arg"],"Volumes":{}});
    }
    let source = fixture.dir.path().join("installed-gate");
    let mut bytes = vec![0u8; 128];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(&source, bytes).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o555)).unwrap();
    let control = Control::new(source);
    let registration = Registration::new(
        fixture.engine().allocations.path.parent().unwrap(),
        control.clone(),
    );
    (fixture, control, registration)
}

#[tokio::test]
async fn sandbox_node_runc_and_docker_default_release_without_resolver_binds() {
    for node_runtime in [Some("runc"), None] {
        let (fixture, _control, _registration) =
            sandbox_fixture_with(None, node_runtime, Vec::new()).await;
        assert!(fixture.engine().resolv_conf.as_ref().unwrap().is_file());
        let result = fixture
            .call(AllocationRequest::Start(options(&fixture, "resolver")))
            .await;
        assert_eq!(result.status, "running", "node={node_runtime:?}");
        {
            let state = fixture.daemon.state.lock().unwrap();
            let body = &state
                .calls
                .iter()
                .find(|(_, path, _)| path.starts_with("/containers/create?"))
                .unwrap()
                .2;
            assert_eq!(body["HostConfig"]["Runtime"], "runc");
            assert!(body["HostConfig"].get("Binds").is_none());
            assert_eq!(body["HostConfig"]["Mounts"].as_array().unwrap().len(), 2);
        }
        let record = oracle(&fixture, "resolver")();
        assert_eq!(record["gate"]["phase"], "released");
        assert_eq!(release_bytes(&record)[0], b'1');
        assert_eq!(fixture.create_count(), 1);
        assert_eq!(
            fixture
                .call(AllocationRequest::Destroy("resolver".into()))
                .await
                .status,
            "destroyed"
        );
        assert!(!directory(&record).exists());
    }
}

#[tokio::test]
async fn sandbox_explicit_operator_dns_preserves_resolver_and_refuses_before_create() {
    for (class_runtime, node_runtime) in [(Some("runc"), None), (None, Some("runc"))] {
        let (fixture, _control, _registration) =
            sandbox_fixture_with(class_runtime, node_runtime, vec!["9.9.9.9".into()]).await;
        assert_eq!(
            std::fs::read_to_string(fixture.engine().resolv_conf.as_ref().unwrap()).unwrap(),
            "nameserver 9.9.9.9\n"
        );
        let result = fixture
            .call(AllocationRequest::Start(options(&fixture, "operator-dns")))
            .await;
        assert_eq!(result.status, "failed");
        assert_eq!(result.reason.as_deref(), Some("sandboxControlsUnsupported"));
        assert_eq!(fixture.create_count(), 0);
        let record = oracle(&fixture, "operator-dns")();
        assert_eq!(record["create_dispatched"], false);
        assert_eq!(record["gate"]["phase"], "waiting");
        assert_eq!(release_bytes(&record)[0], b'0');
        assert_eq!(
            fixture
                .call(AllocationRequest::Destroy("operator-dns".into()))
                .await
                .status,
            "destroyed"
        );
        assert!(!directory(&record).exists());
    }
}

fn options(fixture: &Fixture, id: &str) -> AllocationOptions {
    let mut options = fixture.options(id, false);
    options.sandbox = Some(serde_json::from_value(json!({
        "version":1,"profile":"small","enforcement":"overlay2-xfs-v1",
        "cpuMillis":250,"memoryBytes":268435456,"diskBytes":67108864,"pidsLimit":128,"shmBytes":8388608
    })).unwrap());
    options
}

fn oracle(fixture: &Fixture, id: &str) -> impl Fn() -> Value + Send + Sync + 'static {
    let path = fixture.engine().allocations.path.clone();
    let scope = fixture.cell.scope.clone();
    let id = id.to_string();
    move || disk_record(&path, &scope, &id)
}

async fn receive(
    receiver: tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>,
) -> Result<AllocationView, String> {
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .expect("coordinator deadline")
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tokio::test]
async fn sandbox_journalled_prepare_create_start_release_and_cleanup() {
    let (mut fixture, control, _registration) = sandbox_fixture().await;
    assert_eq!(fixture.cell.spec.runtime.as_deref(), Some("runc"));
    assert!(fixture.engine().resolv_conf.as_ref().unwrap().is_file());
    let snapshot = oracle(&fixture, "complete");
    let source = std::fs::read(&control.source).unwrap();
    fixture.daemon.state.lock().unwrap().sandbox_create_check = Some(Arc::new(move |body| {
        let record = snapshot();
        assert_eq!(record["status"], "creating");
        assert_eq!(record["create_dispatched"], true);
        assert_eq!(record["create_confirmed"], false);
        assert_eq!(record["gate"]["phase"], "waiting");
        for (name, field, mode) in [
            ("gate", "executableIdentity", 0o555),
            ("release", "releaseIdentity", 0o644),
        ] {
            let metadata = std::fs::metadata(directory(&record).join(name)).unwrap();
            assert_eq!(
                json!([metadata.dev(), metadata.ino()]),
                record["gate"][field]
            );
            assert_eq!(metadata.mode() & 0o7777, mode);
        }
        let metadata = std::fs::metadata(directory(&record)).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(
            json!([metadata.dev(), metadata.ino()]),
            record["gate"]["directoryIdentity"]
        );
        assert_eq!(
            std::fs::read(directory(&record).join("gate")).unwrap(),
            source
        );
        assert_eq!(release_bytes(&record)[0], b'0');
        assert_eq!(body["Entrypoint"][0], "/.grapefuit-sandbox/gate");
        assert_eq!(body["Entrypoint"][6], "server");
        assert_eq!(body["Healthcheck"]["Test"], json!(["NONE"]));
        assert_eq!(body["HostConfig"]["Init"], false);
        assert_eq!(body["HostConfig"]["Runtime"], "runc");
        assert!(body["HostConfig"].get("Binds").is_none());
    }));
    let snapshot = oracle(&fixture, "complete");
    fixture.daemon.state.lock().unwrap().sandbox_start_check = Some(Arc::new(move || {
        let record = snapshot();
        assert_eq!(record["create_confirmed"], true);
        assert_eq!(release_bytes(&record)[0], b'0');
    }));
    let snapshot = oracle(&fixture, "complete");
    control.set_hook(Some(Arc::new(move |point, _| {
        if matches!(
            point,
            Point::ApprovalCommit | Point::ReleaseWrite | Point::ReleaseSync | Point::FinalCommit
        ) {
            assert_release_safety(&snapshot());
        }
        Ok(())
    })));
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(options(&fixture, "complete")))
            .await
            .status,
        "running"
    );
    let record = oracle(&fixture, "complete")();
    assert_eq!(record["gate"]["phase"], "released");
    assert_eq!(release_bytes(&record)[0], b'1');
    assert!(control.host_checks.load(Ordering::SeqCst) >= 3);
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("complete".into()))
            .await
            .status,
        "running"
    );
    assert_eq!(fixture.create_count(), 1);
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("complete".into()))
            .await
            .status,
        "destroyed"
    );
    assert!(!directory(&record).exists());
    fixture.reopen().await.unwrap();
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("complete".into()))
            .await
            .status,
        "destroyed"
    );
}

#[tokio::test]
async fn sandbox_release_fault_boundaries_reopen_without_unapproved_execution() {
    for seed in [7, 42] {
        for point in [
            Point::ApprovalCommit,
            Point::ReleaseWrite,
            Point::ReleaseSync,
            Point::FinalCommit,
        ] {
            for after in [false, true] {
                let (mut fixture, control, _registration) = sandbox_fixture().await;
                let snapshot = oracle(&fixture, "release-fault");
                let fired = Arc::new(AtomicBool::new(false));
                let injected = fired.clone();
                control.set_hook(Some(Arc::new(move |seen, edge| {
                    assert_release_safety(&snapshot());
                    if seen == point && edge == after && !injected.load(Ordering::SeqCst) {
                        injected.store(true, Ordering::SeqCst);
                        if seed == 7 {
                            panic!(
                                "injected coordinator crash: seed={seed} {point:?} after={after}"
                            );
                        }
                        anyhow::bail!("injected I/O failure: seed={seed} {point:?} after={after}");
                    }
                    Ok(())
                })));
                let receiver = fixture
                    .engine()
                    .allocation_request(
                        fixture.cell.clone(),
                        AllocationRequest::Start(options(&fixture, "release-fault")),
                    )
                    .unwrap();
                let result = receive(receiver).await;
                assert!(
                    fired.load(Ordering::SeqCst),
                    "fault was not reached: seed={seed} {point:?} after={after}: {result:?}"
                );
                if seed == 7 {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap().status, "unknown");
                }
                let record = oracle(&fixture, "release-fault")();
                assert_release_safety(&record);
                if seed == 7 {
                    let expected = match (point, after) {
                        (Point::ApprovalCommit, false) => "waiting",
                        (Point::FinalCommit, true) => "released",
                        _ => "releasePending",
                    };
                    assert_eq!(
                        record["gate"]["phase"], expected,
                        "seed={seed} {point:?} after={after}"
                    );
                }
                control.set_hook(None);
                fixture.reopen().await.unwrap();
                assert_eq!(
                    fixture
                        .call(AllocationRequest::Inspect("release-fault".into()))
                        .await
                        .status,
                    "running"
                );
                assert_eq!(fixture.create_count(), 1);
                assert_eq!(
                    oracle(&fixture, "release-fault")()["gate"]["phase"],
                    "released"
                );
                fixture
                    .call(AllocationRequest::Destroy("release-fault".into()))
                    .await;
            }
        }
    }
}

#[tokio::test]
async fn sandbox_cleanup_fault_boundaries_preserve_authority_and_recover() {
    for seed in [7, 42] {
        for point in [
            Point::GateUnlink,
            Point::ReleaseUnlink,
            Point::DirectorySync,
            Point::DirectoryRemove,
            Point::ParentSync,
            Point::TombstoneCommit,
        ] {
            for after in [false, true] {
                let (mut fixture, control, _registration) = sandbox_fixture().await;
                assert_eq!(
                    fixture
                        .call(AllocationRequest::Start(options(&fixture, "cleanup-fault")))
                        .await
                        .status,
                    "running"
                );
                let record = oracle(&fixture, "cleanup-fault")();
                let owned_directory = directory(&record);
                let snapshot = oracle(&fixture, "cleanup-fault");
                let daemon = fixture.daemon.clone();
                let fired = Arc::new(AtomicBool::new(false));
                let injected = fired.clone();
                control.set_hook(Some(Arc::new(move |seen, edge| {
                    let record = snapshot();
                    assert_eq!(record["destroy_requested"], true);
                    assert!(
                        daemon.state.lock().unwrap().containers.is_empty(),
                        "gate cleanup preceded confirmed native absence"
                    );
                    let dir = directory(&record);
                    if matches!(
                        seen,
                        Point::DirectoryRemove | Point::ParentSync | Point::TombstoneCommit
                    ) {
                        assert!(!dir.join("gate").exists());
                        assert!(!dir.join("release").exists());
                    }
                    if seen == Point::TombstoneCommit {
                        assert!(!dir.exists());
                    }
                    if seen == point && edge == after && !injected.load(Ordering::SeqCst) {
                        injected.store(true, Ordering::SeqCst);
                        if seed == 7 {
                            panic!("injected cleanup crash: seed={seed} {point:?} after={after}");
                        }
                        anyhow::bail!(
                            "injected cleanup I/O failure: seed={seed} {point:?} after={after}"
                        );
                    }
                    Ok(())
                })));
                let receiver = fixture
                    .engine()
                    .allocation_request(
                        fixture.cell.clone(),
                        AllocationRequest::Destroy("cleanup-fault".into()),
                    )
                    .unwrap();
                let result = receive(receiver).await;
                assert!(
                    fired.load(Ordering::SeqCst),
                    "fault was not reached: seed={seed} {point:?} after={after}: {result:?}"
                );
                let record = oracle(&fixture, "cleanup-fault")();
                assert_eq!(record["destroy_requested"], true);
                if point != Point::TombstoneCommit || !after {
                    assert_ne!(record["status"], "destroyed");
                }
                control.set_hook(None);
                fixture.reopen().await.unwrap();
                assert_eq!(
                    fixture
                        .call(AllocationRequest::Destroy("cleanup-fault".into()))
                        .await
                        .status,
                    "destroyed",
                    "seed={seed} {point:?} after={after}"
                );
                assert!(!owned_directory.exists());
                assert_eq!(fixture.create_count(), 1);
                let deletes = fixture
                    .daemon
                    .state
                    .lock()
                    .unwrap()
                    .calls
                    .iter()
                    .filter(|(method, _, _)| method == "DELETE")
                    .count();
                assert_eq!(deletes, 1);
            }
        }
    }
}

#[tokio::test]
async fn sandbox_cancelled_waiter_and_concurrent_destroy_do_not_release_workload() {
    let (fixture, control, _registration) = sandbox_fixture().await;
    let hold = Gate::new();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .after_start_inspect_gate = Some(hold.clone());
    let receiver = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(options(&fixture, "cancelled")),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
        .await
        .unwrap();
    drop(receiver);
    let record = oracle(&fixture, "cancelled")();
    assert_eq!(release_bytes(&record)[0], b'0');
    let first = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("cancelled".into()),
        )
        .unwrap();
    let second = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Destroy("cancelled".into()),
        )
        .unwrap();
    assert_eq!(oracle(&fixture, "cancelled")()["destroy_requested"], true);
    control.set_hook(Some(Arc::new(move |point, _| {
        assert!(
            !matches!(
                point,
                Point::ApprovalCommit
                    | Point::ReleaseWrite
                    | Point::ReleaseSync
                    | Point::FinalCommit
            ),
            "cleanup closed release admission"
        );
        Ok(())
    })));
    hold.open();
    assert_eq!(receive(first).await.unwrap().status, "destroyed");
    assert_eq!(receive(second).await.unwrap().status, "destroyed");
    assert!(!directory(&record).exists());
    assert_eq!(fixture.create_count(), 1);
}

#[tokio::test]
async fn sandbox_cleanup_racing_approval_retains_monotonic_intent() {
    for after in [false, true] {
        let (fixture, control, _registration) = sandbox_fixture().await;
        let engine = Arc::downgrade(fixture.engine());
        let cell = fixture.cell.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let injected = fired.clone();
        control.set_hook(Some(Arc::new(move |point, edge| {
            if point == Point::ApprovalCommit
                && edge == after
                && !injected.swap(true, Ordering::SeqCst)
            {
                engine
                    .upgrade()
                    .unwrap()
                    .request_allocation_cleanup(&cell, "approval-race")
                    .unwrap();
            }
            Ok(())
        })));
        let view = fixture
            .call(AllocationRequest::Start(options(&fixture, "approval-race")))
            .await;
        assert!(fired.load(Ordering::SeqCst));
        assert_ne!(view.status, "running");
        let record = oracle(&fixture, "approval-race")();
        assert_eq!(record["destroy_requested"], true);
        assert_eq!(release_bytes(&record)[0], if after { b'1' } else { b'0' });
        assert!(!fixture.cell.running());
        control.set_hook(None);
        assert_eq!(
            fixture
                .call(AllocationRequest::Destroy("approval-race".into()))
                .await
                .status,
            "destroyed"
        );
    }
}

#[tokio::test]
async fn sandbox_cancelled_waiter_does_not_cancel_an_owned_start() {
    let (fixture, _control, _registration) = sandbox_fixture().await;
    let hold = Gate::new();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .after_start_inspect_gate = Some(hold.clone());
    let receiver = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(options(&fixture, "waiter-dropped")),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
        .await
        .unwrap();
    drop(receiver);
    assert_eq!(
        release_bytes(&oracle(&fixture, "waiter-dropped")())[0],
        b'0'
    );
    hold.open();
    assert_eq!(
        fixture
            .call(AllocationRequest::Inspect("waiter-dropped".into()))
            .await
            .status,
        "running"
    );
    let record = oracle(&fixture, "waiter-dropped")();
    assert_eq!(record["gate"]["phase"], "released");
    assert_eq!(release_bytes(&record)[0], b'1');
    assert_eq!(fixture.create_count(), 1);
    fixture
        .call(AllocationRequest::Destroy("waiter-dropped".into()))
        .await;
}

#[tokio::test]
async fn sandbox_failed_host_verification_and_unconfirmed_delete_keep_gate_closed_or_owned() {
    let (fixture, control, _registration) = sandbox_fixture().await;
    let hold = Gate::new();
    fixture
        .daemon
        .state
        .lock()
        .unwrap()
        .after_start_inspect_gate = Some(hold.clone());
    let receiver = fixture
        .engine()
        .allocation_request(
            fixture.cell.clone(),
            AllocationRequest::Start(options(&fixture, "host-denied")),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
        .await
        .unwrap();
    control.host_allowed.store(false, Ordering::SeqCst);
    hold.open();
    assert_eq!(receive(receiver).await.unwrap().status, "unknown");
    let record = oracle(&fixture, "host-denied")();
    assert_eq!(release_bytes(&record)[0], b'0');
    fixture.daemon.state.lock().unwrap().lose_delete_reply = true;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("host-denied".into()))
            .await
            .status,
        "unknown"
    );
    assert!(directory(&record).join("gate").exists());
    assert!(directory(&record).join("release").exists());
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("host-denied".into()))
            .await
            .status,
        "destroyed"
    );
    assert!(!directory(&record).exists());
}

#[tokio::test]
async fn sandbox_delete_acknowledgement_without_absence_cannot_remove_gate() {
    let (fixture, _control, _registration) = sandbox_fixture().await;
    assert_eq!(
        fixture
            .call(AllocationRequest::Start(options(
                &fixture,
                "delete-still-present",
            )))
            .await
            .status,
        "running"
    );
    let record = oracle(&fixture, "delete-still-present")();
    fixture.daemon.state.lock().unwrap().retain_after_delete = true;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("delete-still-present".into()))
            .await
            .status,
        "unknown"
    );
    assert!(directory(&record).join("gate").exists());
    assert!(directory(&record).join("release").exists());
    assert_eq!(
        oracle(&fixture, "delete-still-present")()["destroy_requested"],
        true
    );
    fixture.daemon.state.lock().unwrap().retain_after_delete = false;
    assert_eq!(
        fixture
            .call(AllocationRequest::Destroy("delete-still-present".into()))
            .await
            .status,
        "destroyed"
    );
    assert!(!directory(&record).exists());
}
