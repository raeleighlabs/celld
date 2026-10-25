// Host-bound storage fault fixtures use real files and deadlines.
#![allow(clippy::disallowed_methods)]

use super::*;
use celld_logic::{CasGuard, CasOutcome};
use futures_util::{stream::BoxStream, StreamExt};
use object_store::{
    path::Path, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::sync::Mutex;

#[derive(Debug)]
pub(crate) struct StoreGate {
    pub entered: tokio::sync::Notify,
    proceed: tokio::sync::Semaphore,
}

impl StoreGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            proceed: tokio::sync::Semaphore::new(0),
        })
    }

    async fn wait(&self) {
        self.entered.notify_one();
        self.proceed.acquire().await.unwrap().forget();
    }

    pub(crate) fn open(&self) {
        self.proceed.add_permits(1);
    }
}

#[derive(Debug)]
pub(crate) enum PutFault {
    Fail,
    Hold(Arc<StoreGate>),
    CommitThenLose(Arc<StoreGate>),
}

#[derive(Debug, Default)]
pub(crate) struct FaultStore {
    inner: object_store::memory::InMemory,
    pub put: Mutex<Option<(String, PutFault)>>,
    pub get: Mutex<Option<String>>,
    pub list: Mutex<Option<String>>,
    pub reads: Mutex<Vec<String>>,
    pub writes: Mutex<Vec<String>>,
}

impl FaultStore {
    pub(crate) fn bucket(self: &Arc<Self>) -> Bucket {
        crate::native_ws::native_ws_tests::init_host();
        Bucket::with_stores(
            self.clone(),
            self.clone(),
            crate::bucket::StorageBackend::S3,
            "native-handoff-fault-test".into(),
            String::new(),
        )
    }
}

fn store_error() -> object_store::Error {
    object_store::Error::Generic {
        store: "native-handoff-test",
        source: "injected one-shot store fault".into(),
    }
}

impl std::fmt::Display for FaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native-handoff-test-store")
    }
}

#[async_trait::async_trait]
impl ObjectStore for FaultStore {
    async fn put_opts(
        &self,
        path: &Path,
        payload: PutPayload,
        options: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.writes.lock().unwrap().push(path.to_string());
        let fault = {
            let mut fault = self.put.lock().unwrap();
            if fault
                .as_ref()
                .is_some_and(|(prefix, _)| path.as_ref().starts_with(prefix))
            {
                fault.take().map(|(_, fault)| fault)
            } else {
                None
            }
        };
        match fault {
            Some(PutFault::Fail) => Err(store_error()),
            Some(PutFault::Hold(gate)) => {
                gate.wait().await;
                self.inner.put_opts(path, payload, options).await
            }
            Some(PutFault::CommitThenLose(gate)) => {
                self.inner.put_opts(path, payload, options).await?;
                gate.wait().await;
                Err(store_error())
            }
            None => self.inner.put_opts(path, payload, options).await,
        }
    }

    async fn put_multipart_opts(
        &self,
        path: &Path,
        options: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(path, options).await
    }

    async fn get_opts(&self, path: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        self.reads.lock().unwrap().push(path.to_string());
        let fail = {
            let mut fault = self.get.lock().unwrap();
            if fault
                .as_ref()
                .is_some_and(|prefix| path.as_ref().starts_with(prefix))
            {
                fault.take().is_some()
            } else {
                false
            }
        };
        if fail {
            return Err(store_error());
        }
        self.inner.get_opts(path, options).await
    }

    async fn delete(&self, path: &Path) -> object_store::Result<()> {
        self.inner.delete(path).await
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        let fail = {
            let mut fault = self.list.lock().unwrap();
            if fault.as_ref().is_some_and(|expected| {
                prefix.is_some_and(|prefix| prefix.as_ref().starts_with(expected))
            }) {
                fault.take().is_some()
            } else {
                false
            }
        };
        if fail {
            return futures_util::stream::once(async { Err(store_error()) }).boxed();
        }
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.inner.copy(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.inner.copy_if_not_exists(from, to).await
    }
}

pub(crate) fn bucket() -> Bucket {
    crate::native_ws::native_ws_tests::init_host();
    let store = Arc::new(object_store::memory::InMemory::new());
    Bucket::with_stores(
        store.clone(),
        store,
        crate::bucket::StorageBackend::S3,
        "native-handoff-test".to_string(),
        String::new(),
    )
}

fn node(bucket: &Bucket, node: &str, generation: &str) -> BucketOwnership {
    BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        node.to_string(),
        generation.to_string(),
    )
}

async fn own(owner: &BucketOwnership, scope: &str) {
    assert!(matches!(
        owner.cas_owner(scope, CasGuard::Absent, 1).await.unwrap(),
        CasOutcome::Applied
    ));
    owner
        .protect_native(scope, 1, &"a".repeat(64))
        .await
        .unwrap();
}

fn attempt() -> DestroyedAttempt {
    DestroyedAttempt {
        id: "allocation-a".to_string(),
        attempt: "a".repeat(64),
        fingerprint: Some("b".repeat(64)),
        container_id: Some("c".repeat(64)),
        image: Some(format!("celld-image:{}", "d".repeat(64))),
        engine_image: Some(format!("sha256:{}", "e".repeat(64))),
        platform: Some("linux/amd64".to_string()),
    }
}

pub(crate) const UNKNOWN_BATCH: &[u8] = br#"{ "version":1, "phase":"open", "dispatched":true, "operations":[{"id":"unsettled-list","kind":"List"},{"id":"unsettled-put","kind":"Put"}], "results":[] }"#;

pub(crate) async fn released_control(store: &Arc<FaultStore>, scope: &str) -> (Checkpoint, String) {
    let bucket = store.bucket();
    let a = node(&bucket, "a", "gen-a");
    own(&a, scope).await;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("control.sqlite");
    let connection = rusqlite::Connection::open(&source).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE control (value BLOB NOT NULL);")
        .unwrap();
    connection
        .execute("INSERT INTO control VALUES (?1)", [UNKNOWN_BATCH])
        .unwrap();
    let mut db = celld_ltx::Db::open(&source).unwrap();
    db.sync().unwrap();
    let mut bytes = Vec::new();
    let position = db.snapshot_to_writer(&mut bytes).unwrap();
    let checkpoint = publish_checkpoint(&bucket, scope, 1, position.txid.0, &bytes)
        .await
        .unwrap();
    assert_eq!(
        a.release_native(scope, 1, checkpoint.clone(), vec![attempt()])
            .await
            .unwrap(),
        CasOutcome::Applied
    );
    let native = a.native_owner(scope).await.unwrap().unwrap();
    (checkpoint, native.closed.unwrap())
}

pub(crate) fn assert_unknown_batch(bytes: Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("check.sqlite");
    celld_ltx::replica::restore_certified_snapshot(&celld_ltx::LtxHost::default(), &path, bytes)
        .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let retained: Vec<u8> = connection
        .query_row("SELECT value FROM control", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retained, UNKNOWN_BATCH);
}

#[test]
fn native_handoff_certified_ltx_restore_loads_control_state_and_never_erases_existing_data() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.sqlite");
    let application = rusqlite::Connection::open(&source).unwrap();
    application.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE control (value TEXT NOT NULL); INSERT INTO control VALUES ('retained-receipt');").unwrap();
    let mut db = celld_ltx::Db::open(&source).unwrap();
    db.sync().unwrap();
    let mut bytes = Vec::new();
    let position = db.snapshot_to_writer(&mut bytes).unwrap();
    assert!(position.txid.0 > 0);
    let host = celld_ltx::LtxHost::default();
    let restored = directory.path().join("restored.sqlite");
    celld_ltx::replica::restore_certified_snapshot(&host, &restored, bytes.clone()).unwrap();
    let connection = rusqlite::Connection::open(&restored).unwrap();
    let value: String = connection
        .query_row("SELECT value FROM control", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "retained-receipt");
    assert!(celld_ltx::replica::restore_certified_snapshot(&host, &restored, bytes).is_err());
    let value: String = connection
        .query_row("SELECT value FROM control", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "retained-receipt");
    let corrupt = directory.path().join("corrupt.sqlite");
    assert!(celld_ltx::replica::restore_certified_snapshot(
        &host,
        &corrupt,
        b"invalid ltx".to_vec()
    )
    .is_err());
    assert!(!corrupt.exists());
    // the imported image must support a new authoritative baseline before admission opens.
    let mut baseline = celld_ltx::Db::open(&restored).unwrap();
    baseline.sync().unwrap();
    let mut bytes = Vec::new();
    assert!(baseline.snapshot_to_writer(&mut bytes).unwrap().txid.0 > 0);
}

#[tokio::test]
async fn native_handoff_protected_epoch_is_incompatible_with_old_readers_and_partial_downgrades() {
    #[derive(Deserialize)]
    struct OldOwner {
        node: String,
        epoch: u64,
    }
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:wire";
    a.cas_owner(scope, CasGuard::Absent, 1).await.unwrap();
    let (unprotected, _) = bucket.get(&owner_key(scope)).await.unwrap().unwrap();
    let old: OldOwner = serde_json::from_slice(&unprotected).unwrap();
    assert_eq!((old.node.as_str(), old.epoch), ("a", 1));
    a.protect_native(scope, 1, &"a".repeat(64)).await.unwrap();
    let (protected, _) = bucket.get(&owner_key(scope)).await.unwrap().unwrap();
    assert!(serde_json::from_slice::<OldOwner>(&protected).is_err());
    let value: serde_json::Value = serde_json::from_slice(&protected).unwrap();
    assert_eq!(
        value["epoch"],
        serde_json::json!({"nativeHandoff": 1, "value": 1})
    );
    for malformed in [
        {
            let mut v = value.clone();
            v["epoch"] = serde_json::json!(1);
            v
        },
        {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove("native");
            v
        },
        {
            let mut v = value.clone();
            v["epoch"]["nativeHandoff"] = serde_json::json!(2);
            v
        },
        {
            let mut v = value.clone();
            v["epoch"]["value"] = serde_json::json!(2);
            v
        },
    ] {
        assert!(serde_json::from_value::<OwnerWire>(malformed).is_err());
    }
    let checkpoint = publish_checkpoint(&bucket, scope, 1, 1, b"wire-test")
        .await
        .unwrap();
    a.release_native(scope, 1, checkpoint, vec![attempt()])
        .await
        .unwrap();
    let (released, etag) = bucket.get(&owner_key(scope)).await.unwrap().unwrap();
    assert!(serde_json::from_slice::<OldOwner>(&released).is_err());
    b.cas_owner(scope, CasGuard::Match(etag), 2).await.unwrap();
    let (claimed, _) = bucket.get(&owner_key(scope)).await.unwrap().unwrap();
    assert!(serde_json::from_slice::<OldOwner>(&claimed).is_err());
    assert_eq!(
        serde_json::from_slice::<OwnerWire>(&claimed).unwrap().epoch,
        2
    );
}

#[tokio::test]
async fn native_handoff_old_inflight_cas_cannot_strip_new_protection() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let scope = "Native:old-cas";
    a.cas_owner(scope, CasGuard::Absent, 1).await.unwrap();
    let (_, old_etag) = bucket.get(&owner_key(scope)).await.unwrap().unwrap();
    a.protect_native(scope, 1, &"a".repeat(64)).await.unwrap();
    assert!(bucket
        .put_cas(
            &owner_key(scope),
            br#"{"node":"old-node","epoch":2}"#.to_vec(),
            Some(&old_etag)
        )
        .await
        .unwrap()
        .is_none());
    let (current, _) = read_owner(&bucket, scope).await.unwrap().unwrap();
    assert_eq!(current.node, "a");
    assert!(current.native.is_some());
}

#[tokio::test]
async fn native_handoff_missing_proof_refuses_expired_owner_takeover() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:expired";
    own(&a, scope).await;
    bucket
        .put(
            "nodes/a.json",
            br#"{"node":"a","expires_ms":0,"addr":"","probe_public_key":"generation-a"}"#.to_vec(),
        )
        .await
        .unwrap();
    let before = a.read_owner(scope).await.unwrap().unwrap();
    assert!(b
        .cas_owner(scope, CasGuard::Match(before.etag.clone()), 2)
        .await
        .is_err());
    assert!(a.release_owner(scope, 1).await.is_err());
    let after = a.read_owner(scope).await.unwrap().unwrap();
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.node.as_deref(), Some("a"));
}

#[tokio::test]
async fn native_handoff_claim_preserves_closure_and_gates_remote_inspection_on_restore() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:lineage";
    own(&a, scope).await;
    // this adapter test authenticates bytes, not an ltx restore. the runtime owns that additional check.
    let checkpoint = publish_checkpoint(&bucket, scope, 1, 7, b"closed control state")
        .await
        .unwrap();
    a.release_native(scope, 1, checkpoint.clone(), vec![attempt()])
        .await
        .unwrap();
    let (released, etag) = read_owner(&bucket, scope).await.unwrap().unwrap();
    let hash = released.native.unwrap().head.unwrap();
    let closure = load_closure(&bucket, scope, &hash).await.unwrap();
    assert_eq!(closure.checkpoint, checkpoint);
    assert_eq!(closure.attempts, vec![attempt()]);
    assert_eq!(closure.generation, "generation-a");
    assert!(matches!(
        b.cas_owner(scope, CasGuard::Match(etag), 2).await.unwrap(),
        CasOutcome::Applied
    ));
    let native = b.native_owner(scope).await.unwrap().unwrap();
    assert_eq!(native.head.as_deref(), Some(hash.as_str()));
    assert_eq!(native.restore.as_deref(), Some(hash.as_str()));
    assert!(b.remote_attempt(scope, 2, "allocation-a").await.is_err());
    assert!(b.protect_native(scope, 2, &"b".repeat(64)).await.is_err());
    b.finish_native_restore(scope, 2, &hash).await.unwrap();
    assert_eq!(
        b.remote_attempt(scope, 2, "allocation-a").await.unwrap(),
        Some(attempt())
    );
    b.protect_native(scope, 2, &"b".repeat(64)).await.unwrap();
    let (_, etag) = read_owner(&bucket, scope).await.unwrap().unwrap();
    assert!(a
        .cas_owner(scope, CasGuard::Match(etag.clone()), 3)
        .await
        .is_err());
    let restarted_a = node(&bucket, "a", "new-generation-a");
    assert!(restarted_a
        .cas_owner(scope, CasGuard::Match(etag), 3)
        .await
        .is_err());
    assert!(a.protect_native(scope, 1, &"a".repeat(64)).await.is_err());
    assert!(a.remote_attempt(scope, 1, "allocation-a").await.is_err());
}

#[tokio::test]
async fn native_handoff_missing_or_corrupt_checkpoint_never_releases_or_claims() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:checkpoint";
    own(&a, scope).await;
    let missing = Checkpoint {
        epoch: 1,
        txid: 1,
        digest: "a".repeat(64),
        bytes: 1,
    };
    assert!(a
        .release_native(scope, 1, missing, vec![attempt()])
        .await
        .is_err());
    assert_eq!(
        a.read_owner(scope).await.unwrap().unwrap().node.as_deref(),
        Some("a")
    );
    let checkpoint = publish_checkpoint(&bucket, scope, 1, 1, b"checkpoint")
        .await
        .unwrap();
    a.release_native(scope, 1, checkpoint.clone(), vec![attempt()])
        .await
        .unwrap();
    let released = a.read_owner(scope).await.unwrap().unwrap();
    let key = checkpoint_key(scope, &checkpoint.digest).unwrap();
    bucket.delete(&key).await.unwrap();
    assert!(b
        .cas_owner(scope, CasGuard::Match(released.etag.clone()), 2)
        .await
        .is_err());
    bucket.put(&key, b"corrupted".to_vec()).await.unwrap();
    assert!(b
        .cas_owner(scope, CasGuard::Match(released.etag), 2)
        .await
        .is_err());
    assert!(b.read_owner(scope).await.unwrap().unwrap().node.is_none());
}

#[tokio::test]
async fn native_handoff_lost_reply_readback_never_overwrites_a_successor() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let scope = "Native:readback";
    own(&a, scope).await;
    let (before, etag) = read_owner(&bucket, scope).await.unwrap().unwrap();
    let mut committed = before.clone();
    committed.epoch = 2;
    committed.native.as_mut().unwrap().epoch = 2;
    // discard the successful write result as a transport would after committing then losing its reply.
    bucket
        .put_cas(
            &owner_key(scope),
            serde_json::to_vec(&committed).unwrap(),
            Some(&etag),
        )
        .await
        .unwrap();
    let committed_etag = read_owner(&bucket, scope).await.unwrap().unwrap().1;
    replace_owner(&bucket, scope, &etag, &committed)
        .await
        .unwrap();
    assert_eq!(
        read_owner(&bucket, scope).await.unwrap().unwrap().1,
        committed_etag
    );
    assert!(replace_owner(&bucket, scope, &etag, &before).await.is_err());
    assert_eq!(
        read_owner(&bucket, scope).await.unwrap().unwrap().0,
        committed
    );
}

#[tokio::test]
async fn native_handoff_release_lost_reply_with_successor_before_readback_refuses_then_reconciles()
{
    let store = Arc::new(FaultStore::default());
    let bucket = store.bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:release-successor-readback";
    own(&a, scope).await;
    let checkpoint = publish_checkpoint(&bucket, scope, 1, 1, b"closed control state")
        .await
        .unwrap();
    let gate = StoreGate::new();
    *store.put.lock().unwrap() = Some((owner_key(scope), PutFault::CommitThenLose(gate.clone())));
    let mut release = Box::pin(a.release_native(scope, 1, checkpoint.clone(), vec![attempt()]));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        crate::asyncrt::select! {
            result = &mut release => panic!("release completed before held reply: {result:?}"),
            _ = gate.entered.notified() => {}
        }
    })
    .await
    .unwrap();
    let released = a.read_owner(scope).await.unwrap().unwrap();
    assert!(released.node.is_none());
    assert!(matches!(
        b.cas_owner(scope, CasGuard::Match(released.etag), 2)
            .await
            .unwrap(),
        CasOutcome::Applied
    ));
    let successor = read_owner(&bucket, scope).await.unwrap().unwrap();
    gate.open();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), release)
            .await
            .unwrap()
            .is_err()
    );
    // rejection on retry means the old owner is gone, not that its release cas was acknowledged.
    assert!(matches!(
        a.release_native(scope, 1, checkpoint, vec![attempt()])
            .await
            .unwrap(),
        CasOutcome::Rejected
    ));
    assert_eq!(
        read_owner(&bucket, scope).await.unwrap().unwrap(),
        successor
    );
    assert!(a.protect_native(scope, 1, &"a".repeat(64)).await.is_err());
    let head = successor.0.native.unwrap().head.unwrap();
    b.finish_native_restore(scope, 2, &head).await.unwrap();
    assert_eq!(
        b.remote_attempt(scope, 2, "allocation-a").await.unwrap(),
        Some(attempt())
    );
}

#[tokio::test]
async fn native_handoff_process_replacement_requires_the_exact_locked_local_journal() {
    let bucket = bucket();
    let a = node(&bucket, "a", "old-process");
    let scope = "Native:local-recovery";
    own(&a, scope).await;
    let (owner, _) = read_owner(&bucket, scope).await.unwrap().unwrap();
    assert!(
        claim_native(&bucket, scope, &owner, "a", "new-process", 2, None)
            .await
            .is_err()
    );
    assert!(claim_native(
        &bucket,
        scope,
        &owner,
        "a",
        "new-process",
        2,
        Some(&"b".repeat(64))
    )
    .await
    .is_err());
    let recovered = claim_native(
        &bucket,
        scope,
        &owner,
        "a",
        "new-process",
        2,
        Some(&"a".repeat(64)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(recovered.generation, "new-process");
    assert_eq!(recovered.journal, "a".repeat(64));
    assert!(claim_native(
        &bucket,
        scope,
        &owner,
        "b",
        "new-process",
        2,
        Some(&"a".repeat(64))
    )
    .await
    .is_err());
}

#[tokio::test]
async fn native_handoff_cold_release_faults_and_cancellation_keep_restore_closed() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for fault in ["read", "missing", "corrupt", "cancel"] {
            let store = Arc::new(FaultStore::default());
            let scope = format!("Native:cold-release-{fault}");
            let (checkpoint, inherited) = released_control(&store, &scope).await;
            let bucket = store.bucket();
            let b = node(&bucket, "b", "gen-b");
            let released = b.read_owner(&scope).await.unwrap().unwrap();
            assert_eq!(b.cas_owner(&scope, CasGuard::Match(released.etag), 2).await.unwrap(), CasOutcome::Applied);
            let before = read_owner(&bucket, &scope).await.unwrap().unwrap();
            let key = checkpoint_key(&scope, &checkpoint.digest).unwrap();
            let bytes = load_checkpoint(&bucket, &scope, &checkpoint).await.unwrap();
            match fault {
                "read" => *store.get.lock().unwrap() = Some(key.clone()),
                "missing" => store.delete(&Path::from(key.clone())).await.unwrap(),
                "corrupt" => { bucket.put(&key, b"not the certified checkpoint".to_vec()).await.unwrap(); }
                _ => {}
            }
            if fault == "cancel" {
                let gate = StoreGate::new();
                *store.put.lock().unwrap() = Some((owner_key(&scope), PutFault::Hold(gate.clone())));
                let mut release = Box::pin(b.release_inherited_native(&scope, 2));
                crate::asyncrt::select! {
                    result = &mut release => panic!("cold release settled before held cas: {result:?}"),
                    _ = gate.entered.notified() => {}
                }
                drop(release);
            } else {
                assert!(b.release_inherited_native(&scope, 2).await.is_err());
            }
            assert_eq!(read_owner(&bucket, &scope).await.unwrap().unwrap(), before);
            assert_eq!(b.native_owner(&scope).await.unwrap().unwrap().restore.as_deref(), Some(inherited.as_str()));
            assert!(b.protect_native(&scope, 2, &"b".repeat(64)).await.is_err());
            if matches!(fault, "missing" | "corrupt") {
                bucket.put(&key, bytes.clone()).await.unwrap();
            }
            assert_eq!(b.release_inherited_native(&scope, 2).await.unwrap(), Some(CasOutcome::Applied));
            let current = b.native_owner(&scope).await.unwrap().unwrap();
            let closure = load_closure(&bucket, &scope, current.closed.as_deref().unwrap()).await.unwrap();
            assert_eq!(closure.previous.as_deref(), Some(inherited.as_str()));
            assert_eq!(load_checkpoint(&bucket, &scope, &closure.checkpoint).await.unwrap(), bytes);
            assert_unknown_batch(bytes);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn native_handoff_history_survives_multiple_cooperative_transfers() {
    let bucket = bucket();
    let a = node(&bucket, "a", "generation-a");
    let b = node(&bucket, "b", "generation-b");
    let scope = "Native:history";
    own(&a, scope).await;
    let checkpoint = publish_checkpoint(&bucket, scope, 1, 1, b"first")
        .await
        .unwrap();
    a.release_native(scope, 1, checkpoint, vec![attempt()])
        .await
        .unwrap();
    let released = a.read_owner(scope).await.unwrap().unwrap();
    b.cas_owner(scope, CasGuard::Match(released.etag), 2)
        .await
        .unwrap();
    let first = b.native_owner(scope).await.unwrap().unwrap().head.unwrap();
    b.finish_native_restore(scope, 2, &first).await.unwrap();
    let checkpoint = publish_checkpoint(&bucket, scope, 2, 3, b"second")
        .await
        .unwrap();
    b.release_native(scope, 2, checkpoint, vec![])
        .await
        .unwrap();
    let released = b.read_owner(scope).await.unwrap().unwrap();
    a.cas_owner(scope, CasGuard::Match(released.etag), 3)
        .await
        .unwrap();
    let second = a.native_owner(scope).await.unwrap().unwrap().head.unwrap();
    assert_eq!(
        load_closure(&bucket, scope, &second)
            .await
            .unwrap()
            .previous
            .as_deref(),
        Some(first.as_str())
    );
    a.finish_native_restore(scope, 3, &second).await.unwrap();
    assert_eq!(
        a.remote_attempt(scope, 3, "allocation-a").await.unwrap(),
        Some(attempt())
    );
    assert!(load_closure(&bucket, scope, &first).await.is_ok());
}
