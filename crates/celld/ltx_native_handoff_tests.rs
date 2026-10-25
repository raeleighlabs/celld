// Real SQLite/V8 fixture teardown uses host deadlines, outside the simulated domain.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::native_handoff::{
    self,
    tests::{FaultStore, PutFault, StoreGate},
};
use crate::ownership_store::BucketOwnership;
use celld_logic::{CasGuard, CasOutcome};

struct Fixture {
    directory: tempfile::TempDir,
    store: Arc<FaultStore>,
    ownership: Arc<BucketOwnership>,
    repl: Arc<LtxRepl>,
}

impl Fixture {
    fn new(store: Arc<FaultStore>, node: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let bucket = store.bucket();
        let ownership = Arc::new(BucketOwnership::new(
            bucket.clone(),
            bucket,
            node.into(),
            format!("{node}-process"),
        ));
        let mut repl = LtxRepl::assemble(
            directory.path(),
            store.clone(),
            TimestampMetadataKey::default(),
            "test".into(),
            String::new(),
            None,
            "auto".into(),
            None,
            None,
            0,
            LtxHost::default(),
            None,
            5_000,
            LtxConfig {
                epoch_gc_grace_ms: None,
                hydrate_bytes_per_s: 0,
                paged_restore: false,
                paged_min_bytes: u64::MAX,
                truncate_pages: 0,
            },
        );
        repl.native_ownership_for_test = Some(ownership.clone());
        Self {
            directory,
            store,
            ownership,
            repl: Arc::new(repl),
        }
    }

    async fn populate(&self, scope: &str) {
        self.ownership
            .cas_owner(scope, CasGuard::Absent, 1)
            .await
            .unwrap();
        let active = self.repl.activate(options(scope, 1, true)).await.unwrap();
        self.ownership
            .protect_native(scope, 1, &"a".repeat(64))
            .await
            .unwrap();
        let connection = rusqlite::Connection::open(&active.path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE control (value TEXT NOT NULL); INSERT INTO control VALUES ('retained-receipt');").unwrap();
    }

    async fn close(self) {
        let owner = self.repl.take_task_owner();
        self.repl.shutdown_local_fallback();
        tokio::time::timeout(Duration::from_secs(5), owner.join())
            .await
            .unwrap();
        if let Some(close) = self.repl.start_close_local_replicas() {
            tokio::time::timeout(Duration::from_secs(5), close)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

fn options(cell: &str, epoch: u64, fresh: bool) -> ActivationOptions<'_> {
    ActivationOptions {
        cell,
        epoch,
        fresh,
        took_over: !fresh,
        resume_local: false,
        prior: None,
    }
}

fn value(path: &Path) -> String {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row("SELECT value FROM control", [], |row| row.get(0))
        .unwrap()
}

pub(crate) async fn restored_dormant_release(
    engine: Arc<crate::container::ContainerEngine>,
    container: crate::container::ContainerSpec,
    post_attachment: bool,
) {
    crate::js::Engine::init();
    let store = Arc::new(FaultStore::default());
    let scope = "AllocationTest:restored-start-failure";
    native_handoff::tests::released_control(&store, scope).await;
    let b = Fixture::new(store.clone(), "b");
    let released = b.ownership.read_owner(scope).await.unwrap().unwrap();
    assert_eq!(
        b.ownership
            .cas_owner(scope, CasGuard::Match(released.etag), 2)
            .await
            .unwrap(),
        CasOutcome::Applied
    );
    b.repl.activate(options(scope, 2, false)).await.unwrap();
    b.ownership
        .protect_native(scope, 2, &engine.native_journal_identity().unwrap())
        .await
        .unwrap();
    assert!(b
        .ownership
        .native_owner(scope)
        .await
        .unwrap()
        .unwrap()
        .restore
        .is_none());
    let runtime = crate::runtime::RuntimeManager::native_handoff_test_runtime(
        b.directory.path().to_path_buf(),
        crate::ltx_replication::Replication::native_handoff_test_replication(b.repl.clone()),
        post_attachment.then_some(container),
    );
    // Retain a real earlier attachment. Worker loading then fails after the
    // newer attach_pending, before its activation can commit.
    engine
        .attach_activation(scope, "AllocationTest", 1)
        .await
        .unwrap();
    let error = runtime
        .start_cell_with_engine(scope.into(), 2, false, Some(engine.clone()))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains(if post_attachment {
            "injected Worker load failure"
        } else {
            "no Worker exports"
        }),
        "{error:#}"
    );
    assert_eq!(
        b.ownership
            .release_inherited_native(scope, 2)
            .await
            .unwrap(),
        None
    );
    assert!(b.repl.native_closed_checkpoint(scope, 2).is_err());
    runtime.facets.register(
        scope,
        &celld_logic::RestoreSpec {
            epoch: 2,
            fresh: true,
            took_over: false,
            resume_local: false,
            prior: None,
        },
    );
    let names = vec!["child".to_string()];
    let facet = crate::engine_api::facet_cell(scope, &names);
    let (facet_path, _) = runtime
        .facets
        .open(
            runtime.replication.as_ref(),
            |cell, epoch| b.repl.db_path(cell, epoch),
            scope,
            2,
            &names,
        )
        .await
        .unwrap();
    {
        let connection = rusqlite::Connection::open(facet_path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE child(value TEXT); INSERT INTO child VALUES ('retained');").unwrap();
    }
    // A failed publication keeps the dormant replica retryable and the owner held.
    *store.put.lock().unwrap() = Some((format!("cells/{scope}/ltx/e2/0009/"), PutFault::Fail));
    assert!(runtime
        .stop_cell_with_engine(
            scope,
            2,
            crate::runtime::StopMode::DormantRelease,
            Some(engine.clone())
        )
        .await
        .is_err());
    assert!(b.repl.is_resident(scope, 2));
    assert_eq!(
        b.ownership
            .read_owner(scope)
            .await
            .unwrap()
            .unwrap()
            .node
            .as_deref(),
        Some("b")
    );
    let gate = StoreGate::new();
    *store.put.lock().unwrap() = Some((
        format!("cells/{facet}/ltx/e2/"),
        PutFault::Hold(gate.clone()),
    ));
    let mut stopping = Box::pin(runtime.stop_cell_with_engine(
        scope,
        2,
        crate::runtime::StopMode::DormantRelease,
        Some(engine.clone()),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        crate::asyncrt::select! {
            result = &mut stopping => panic!("stop completed before facet gate: {result:?}"),
            _ = gate.entered.notified() => {},
        }
    })
    .await
    .unwrap();
    assert!(!b.repl.is_resident(scope, 2));
    assert!(b.repl.is_resident(&facet, 2));
    assert!(runtime
        .facets
        .open(
            runtime.replication.as_ref(),
            |cell, epoch| b.repl.db_path(cell, epoch),
            scope,
            2,
            &names,
        )
        .await
        .is_err());
    gate.open();
    tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();
    assert!(!b.repl.is_resident(&facet, 2));
    let (checkpoint, attempts) = runtime
        .native_handoff_closure(scope, 2, engine.clone())
        .await
        .unwrap();
    assert!(!b.repl.is_resident(scope, 2));
    // Releasing after a lost reply must not require a second live replica.
    assert_eq!(
        runtime
            .native_handoff_closure(scope, 2, engine)
            .await
            .unwrap()
            .0,
        checkpoint
    );
    assert_eq!(
        b.ownership
            .release_native(scope, 2, checkpoint, attempts)
            .await
            .unwrap(),
        CasOutcome::Applied
    );
    assert_cold_successor_state(&b, scope, false).await;
    drop(runtime);
    b.close().await;
}

#[tokio::test]
async fn native_handoff_restore_retries_retire_superseded_epochs() {
    for fault in [
        "baseline",
        "visibility",
        "completion",
        "committed-cancellation",
    ] {
        let store = Arc::new(FaultStore::default());
        let a = Fixture::new(store.clone(), "a");
        let scope = format!("Native:epoch-retry-{fault}");
        a.populate(&scope).await;
        a.repl.evict(&scope, 1, false, None).await.unwrap();
        a.ownership
            .release_native(
                &scope,
                1,
                a.repl.native_closed_checkpoint(&scope, 1).unwrap(),
                vec![],
            )
            .await
            .unwrap();
        let b = Fixture::new(store.clone(), "b");
        let mut old_handles: Vec<CellHandle> = Vec::new();
        for epoch in 2..=4 {
            let owner = b.ownership.read_owner(&scope).await.unwrap().unwrap();
            assert_eq!(
                b.ownership
                    .cas_owner(&scope, CasGuard::Match(owner.etag), epoch)
                    .await
                    .unwrap(),
                CasOutcome::Applied
            );
            if epoch == 2 {
                match fault {
                    "baseline" => {
                        *store.put.lock().unwrap() =
                            Some((format!("cells/{scope}/ltx/e2/0009/"), PutFault::Fail))
                    }
                    "visibility" => {
                        *store.list.lock().unwrap() = Some(format!("cells/{scope}/ltx/e2"))
                    }
                    "completion" => {
                        *store.put.lock().unwrap() =
                            Some((native_handoff::owner_key(&scope), PutFault::Fail))
                    }
                    _ => {}
                }
                if fault == "committed-cancellation" {
                    let gate = StoreGate::new();
                    *store.put.lock().unwrap() = Some((
                        native_handoff::owner_key(&scope),
                        PutFault::CommitThenLose(gate.clone()),
                    ));
                    let mut activating = Box::pin(b.repl.activate(options(&scope, epoch, false)));
                    tokio::time::timeout(Duration::from_secs(5), async {
                        crate::asyncrt::select! {
                            _ = &mut activating => panic!("restore passed held completion"),
                            _ = gate.entered.notified() => {},
                        }
                    })
                    .await
                    .unwrap();
                    drop(activating);
                } else {
                    assert!(b
                        .repl
                        .activate(options(&scope, epoch, false))
                        .await
                        .is_err());
                }
            } else if epoch == 3 && fault != "committed-cancellation" {
                *store.put.lock().unwrap() =
                    Some((format!("cells/{scope}/ltx/e3/0009/"), PutFault::Fail));
                assert!(b
                    .repl
                    .activate(options(&scope, epoch, false))
                    .await
                    .is_err());
            } else {
                let restored = b
                    .repl
                    .activate(options(&scope, epoch, false))
                    .await
                    .unwrap();
                assert_eq!(value(&restored.path), "retained-receipt");
            }
            for old in &old_handles {
                assert!(
                    old.replica.lock().unwrap().is_none(),
                    "superseded replica still open: {fault}, epoch {epoch}"
                );
            }
            assert_eq!(b.repl.cells.lock().unwrap().len(), 1);
            assert!(b.repl.stopped_cells.lock().unwrap().is_empty());
            let handle = b.repl.cells.lock().unwrap()[&(scope.clone(), epoch)].clone();
            if handle.native_restore.lock().unwrap().is_some() {
                old_handles.push(handle);
            } else {
                b.repl.evict(&scope, epoch, false, None).await.unwrap();
                break;
            }
        }
        assert!(b.repl.cells.lock().unwrap().is_empty());
        b.close().await;
        a.close().await;
    }
}

async fn assert_cold_successor_state(b: &Fixture, scope: &str, expect_new_write: bool) {
    let c = Fixture::new(b.store.clone(), "c");
    let released = b.ownership.read_owner(scope).await.unwrap().unwrap();
    assert!(released.node.is_none());
    assert_eq!(
        c.ownership
            .cas_owner(scope, CasGuard::Match(released.etag), 3)
            .await
            .unwrap(),
        CasOutcome::Applied
    );
    let active = c.repl.activate(options(scope, 3, false)).await.unwrap();
    let connection = rusqlite::Connection::open(&active.path).unwrap();
    let pending: Vec<u8> = connection
        .query_row("SELECT value FROM control", [], |row| row.get(0))
        .unwrap();
    assert_eq!(pending, native_handoff::tests::UNKNOWN_BATCH);
    if expect_new_write {
        let marker: String = connection
            .query_row("SELECT value FROM new_work", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker, "must-not-discard");
    }
    assert!(c
        .ownership
        .remote_attempt(scope, 3, "allocation-a")
        .await
        .unwrap()
        .is_some());
    drop(connection);
    c.close().await;
}

#[tokio::test]
async fn native_handoff_cold_release_after_restore_failure_or_cancellation_preserves_unknown_batch()
{
    tokio::time::timeout(Duration::from_secs(10), async {
        for fault in ["checkpoint-read", "cancelled-baseline", "snapshot-budget"] {
            let store = Arc::new(FaultStore::default());
            let scope = format!("Native:cold-restore-{fault}");
            let (_, inherited) = native_handoff::tests::released_control(&store, &scope).await;
            let b = Fixture::new(store.clone(), "b");
            let released = b.ownership.read_owner(&scope).await.unwrap().unwrap();
            assert_eq!(b.ownership.cas_owner(&scope, CasGuard::Match(released.etag), 2).await.unwrap(), CasOutcome::Applied);
            if fault == "checkpoint-read" {
                *store.get.lock().unwrap() = Some(format!("cells/{scope}/native-checkpoints/"));
                assert!(b.repl.activate(options(&scope, 2, false)).await.is_err());
            } else if fault == "snapshot-budget" {
                b.repl.snapshot_budget_bytes.store(1, Ordering::Relaxed);
                assert!(b.repl.activate(options(&scope, 2, false)).await.is_err());
                assert!(b.repl.is_resident(&scope, 2));
            } else {
                let gate = StoreGate::new();
                *store.put.lock().unwrap() = Some((format!("cells/{scope}/ltx/e2/0009/"), PutFault::Hold(gate.clone())));
                let mut activating = Box::pin(b.repl.activate(options(&scope, 2, false)));
                crate::asyncrt::select! {
                    result = &mut activating => panic!("restore passed held baseline: {}", result.is_ok()),
                    _ = gate.entered.notified() => {}
                }
                drop(activating);
            }
            assert_eq!(b.ownership.native_owner(&scope).await.unwrap().unwrap().restore.as_deref(), Some(inherited.as_str()));
            assert!(b.repl.native_closed_checkpoint(&scope, 2).is_err());
            let runtime = crate::runtime::RuntimeManager::native_handoff_test_runtime(
                b.directory.path().to_path_buf(),
                crate::ltx_replication::Replication::native_handoff_test_replication(b.repl.clone()), None,
            );
            runtime.stop_cell_with_engine(&scope, 2, crate::runtime::StopMode::DormantRelease, None).await.unwrap();
            assert!(!b.repl.is_resident(&scope, 2));
            assert_eq!(b.ownership.release_inherited_native(&scope, 2).await.unwrap(), Some(CasOutcome::Applied));
            assert_cold_successor_state(&b, &scope, false).await;
            drop(runtime);
            b.close().await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn native_handoff_cold_release_and_real_restore_completion_are_cas_exclusive() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for restore_wins in [false, true] {
            let store = Arc::new(FaultStore::default());
            let scope = format!("Native:cold-race-{restore_wins}");
            native_handoff::tests::released_control(&store, &scope).await;
            let b = Fixture::new(store.clone(), "b");
            let released = b.ownership.read_owner(&scope).await.unwrap().unwrap();
            assert_eq!(b.ownership.cas_owner(&scope, CasGuard::Match(released.etag), 2).await.unwrap(), CasOutcome::Applied);
            let gate = StoreGate::new();
            if restore_wins {
                *store.put.lock().unwrap() = Some((native_handoff::owner_key(&scope), PutFault::Hold(gate.clone())));
                let mut releasing = Box::pin(b.ownership.release_inherited_native(&scope, 2));
                crate::asyncrt::select! {
                    result = &mut releasing => panic!("release passed held owner cas: {result:?}"),
                    _ = gate.entered.notified() => {}
                }
                let active = b.repl.activate(options(&scope, 2, false)).await.unwrap();
                let connection = rusqlite::Connection::open(&active.path).unwrap();
                connection.execute_batch("CREATE TABLE new_work (value TEXT); INSERT INTO new_work VALUES ('must-not-discard');").unwrap();
                drop(connection);
                let before = b.ownership.read_owner(&scope).await.unwrap().unwrap();
                gate.open();
                assert!(releasing.await.is_err());
                assert_eq!(b.ownership.read_owner(&scope).await.unwrap().unwrap(), before);
                assert_eq!(b.ownership.release_inherited_native(&scope, 2).await.unwrap(), None);
                assert!(b.repl.native_closed_checkpoint(&scope, 2).is_err());
                // completed restore must take the ordinary closed snapshot path, including new work.
                b.repl.evict(&scope, 2, false, None).await.unwrap();
                let checkpoint = b.repl.native_closed_checkpoint(&scope, 2).unwrap();
                assert_eq!(b.ownership.release_native(&scope, 2, checkpoint, vec![]).await.unwrap(), CasOutcome::Applied);
            } else {
                *store.put.lock().unwrap() = Some((format!("cells/{scope}/ltx/e2/0009/"), PutFault::Hold(gate.clone())));
                let mut activating = Box::pin(b.repl.activate(options(&scope, 2, false)));
                crate::asyncrt::select! {
                    result = &mut activating => panic!("restore passed held baseline: {}", result.is_ok()),
                    _ = gate.entered.notified() => {}
                }
                assert_eq!(b.ownership.release_inherited_native(&scope, 2).await.unwrap(), Some(CasOutcome::Applied));
                let before = b.ownership.read_owner(&scope).await.unwrap().unwrap();
                gate.open();
                assert!(activating.await.is_err());
                assert_eq!(b.ownership.read_owner(&scope).await.unwrap().unwrap(), before);
                assert!(b.ownership.protect_native(&scope, 2, &"b".repeat(64)).await.is_err());
            }
            assert_cold_successor_state(&b, &scope, restore_wins).await;
            b.close().await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn native_handoff_real_evict_retries_snapshot_put_visibility_and_checkpoint_readback() {
    for fault in ["snapshot-put", "snapshot-list", "checkpoint-put-readback"] {
        let fixture = Fixture::new(Arc::new(FaultStore::default()), "a");
        let scope = format!("Native:evict-{fault}");
        fixture.populate(&scope).await;
        let key = (scope.clone(), 1);
        let handle = fixture.repl.cells.lock().unwrap()[&key].clone();
        match fault {
            "snapshot-put" => {
                *fixture.store.put.lock().unwrap() =
                    Some((format!("cells/{scope}/ltx/e1/0009/"), PutFault::Fail))
            }
            "snapshot-list" => {
                *fixture.store.list.lock().unwrap() = Some(format!("cells/{scope}/ltx/e1"))
            }
            _ => {
                *fixture.store.put.lock().unwrap() =
                    Some((format!("cells/{scope}/native-checkpoints/"), PutFault::Fail));
                *fixture.store.get.lock().unwrap() =
                    Some(format!("cells/{scope}/native-checkpoints/"));
            }
        }
        assert!(tokio::time::timeout(
            Duration::from_secs(5),
            fixture.repl.evict(&scope, 1, false, None)
        )
        .await
        .unwrap()
        .is_err());
        assert!(!handle.snapshot_declined.load(Ordering::Relaxed));
        assert!(Arc::ptr_eq(
            &fixture.repl.cells.lock().unwrap()[&key],
            &handle
        ));
        assert_eq!(value(&fixture.repl.db_path(&scope, 1)), "retained-receipt");
        assert!(fixture.repl.native_closed_checkpoint(&scope, 1).is_err());
        assert_eq!(
            fixture
                .ownership
                .read_owner(&scope)
                .await
                .unwrap()
                .unwrap()
                .node
                .as_deref(),
            Some("a")
        );
        assert!(fixture.store.put.lock().unwrap().is_none());
        assert!(fixture.store.list.lock().unwrap().is_none());
        assert!(fixture.store.get.lock().unwrap().is_none());
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                fixture.repl.evict(&scope, 1, false, None)
            )
            .await
            .unwrap()
            .unwrap(),
            EvictionRestoreArtifact::Snapshot
        ));
        let checkpoint = fixture.repl.native_closed_checkpoint(&scope, 1).unwrap();
        let bytes = native_handoff::load_checkpoint(
            &fixture.ownership.bucket_client(),
            &scope,
            &checkpoint,
        )
        .await
        .unwrap();
        let restored = fixture.directory.path().join("check.sqlite");
        replica::restore_certified_snapshot(&LtxHost::default(), &restored, bytes).unwrap();
        assert_eq!(value(&restored), "retained-receipt");
        assert!(matches!(
            fixture
                .ownership
                .release_native(&scope, 1, checkpoint, vec![])
                .await
                .unwrap(),
            CasOutcome::Applied
        ));
        fixture.close().await;
    }
}

#[tokio::test]
async fn native_handoff_cancelled_successor_baseline_or_completion_reuses_exact_restored_handle() {
    for committed_completion in [false, true] {
        let store = Arc::new(FaultStore::default());
        let a = Fixture::new(store.clone(), "a");
        let scope = format!("Native:restore-cancel-{committed_completion}");
        a.populate(&scope).await;
        a.repl.evict(&scope, 1, false, None).await.unwrap();
        let checkpoint = a.repl.native_closed_checkpoint(&scope, 1).unwrap();
        a.ownership
            .release_native(&scope, 1, checkpoint, vec![])
            .await
            .unwrap();
        let released = a.ownership.read_owner(&scope).await.unwrap().unwrap();
        let b = Fixture::new(store.clone(), "b");
        assert!(matches!(
            b.ownership
                .cas_owner(&scope, CasGuard::Match(released.etag), 2)
                .await
                .unwrap(),
            CasOutcome::Applied
        ));
        let gate = StoreGate::new();
        *store.put.lock().unwrap() = Some(if committed_completion {
            (
                native_handoff::owner_key(&scope),
                PutFault::CommitThenLose(gate.clone()),
            )
        } else {
            (
                format!("cells/{scope}/ltx/e2/0009/"),
                PutFault::Hold(gate.clone()),
            )
        });
        let mut activating = Box::pin(b.repl.activate(options(&scope, 2, false)));
        tokio::time::timeout(Duration::from_secs(5), async {
            crate::asyncrt::select! {
                result = &mut activating => panic!("restore completed before controlled boundary: {}", result.is_ok()),
                _ = gate.entered.notified() => {}
            }
        }).await.unwrap();
        let key = (scope.clone(), 2);
        let handle = b.repl.cells.lock().unwrap()[&key].clone();
        let hash = handle.native_restore.lock().unwrap().clone().unwrap();
        assert_eq!(value(&b.repl.db_path(&scope, 2)), "retained-receipt");
        drop(activating);
        assert_eq!(
            handle.native_restore.lock().unwrap().as_deref(),
            Some(hash.as_str())
        );
        if !committed_completion {
            assert!(b
                .ownership
                .remote_attempt(&scope, 2, "absent")
                .await
                .is_err());
            assert!(b
                .ownership
                .protect_native(&scope, 2, &"b".repeat(64))
                .await
                .is_err());
        }
        let retry = tokio::time::timeout(
            Duration::from_secs(5),
            b.repl.activate(options(&scope, 2, false)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(Arc::ptr_eq(&b.repl.cells.lock().unwrap()[&key], &handle));
        assert!(handle.native_restore.lock().unwrap().is_none());
        assert_eq!(value(&retry.path), "retained-receipt");
        assert!(b
            .ownership
            .native_owner(&scope)
            .await
            .unwrap()
            .unwrap()
            .restore
            .is_none());
        b.ownership
            .protect_native(&scope, 2, &"b".repeat(64))
            .await
            .unwrap();
        b.close().await;
        a.close().await;
    }
}
