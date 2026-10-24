// These host-bound actor fixtures use real Tokio deadlines, outside the simulated domain.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::cell_dispatch::{
    dispatch_call_attempt, route_error_result, CallAttempt, CallContext, CallPayload,
    RoutedRequestError,
};
use crate::native_handoff::tests::{FaultStore, PutFault, StoreGate};

use std::time::Duration;

#[tokio::test]
async fn native_handoff_claim_read_preserves_upstream_lost_owner_refusal() {
    let store = Arc::new(FaultStore::default());
    let bucket = store.bucket();
    let owner = Arc::new(BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        "a".into(),
        "gen-a".into(),
    ));
    let scope = "Native:lost-owner-read";
    let ownership = Ownership::Bucket(owner.clone());
    assert!(ownership
        .read_owner_for_claim(scope)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        owner.cas_owner(scope, CasGuard::Absent, 1).await.unwrap(),
        CasOutcome::Applied
    );
    owner
        .protect_native(scope, 1, &"a".repeat(64))
        .await
        .unwrap();
    let protected = ownership
        .read_owner_for_claim(scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(protected.node.as_deref(), Some("a"));
    assert_eq!(protected.epoch, 1);
    bucket
        .put(&format!("cells/{scope}/ltx/e1/retained.ltx"), vec![1])
        .await
        .unwrap();
    bucket
        .delete(&format!("cells/{scope}/own.json"))
        .await
        .unwrap();
    store.writes.lock().unwrap().clear();
    assert!(matches!(
        ownership.read_owner_for_claim(scope).await,
        Err(Failure::Definite)
    ));
    let reads = store.reads.lock().unwrap().len();
    assert!(matches!(
        ownership.read_owner_for_claim(scope).await,
        Err(Failure::Definite)
    ));
    assert_eq!(store.reads.lock().unwrap().len(), reads);
    assert!(store.writes.lock().unwrap().is_empty());
    assert!(ownership.read_owner(scope).await.unwrap().is_none());
}

#[tokio::test]
async fn native_handoff_claim_read_does_not_treat_unavailable_history_as_fresh() {
    let store = Arc::new(FaultStore::default());
    let bucket = store.bucket();
    let ownership = Ownership::Bucket(Arc::new(BucketOwnership::new(
        bucket.clone(),
        bucket,
        "a".into(),
        "gen-a".into(),
    )));
    let scope = "Native:unavailable-history-read";
    *store.list.lock().unwrap() = Some(format!("cells/{scope}/ltx"));
    assert!(matches!(
        ownership.read_owner_for_claim(scope).await,
        Err(Failure::Definite)
    ));
    assert!(store.writes.lock().unwrap().is_empty());
    // The transient read failure creates neither an owner nor a lost-record hold.
    assert!(ownership
        .read_owner_for_claim(scope)
        .await
        .unwrap()
        .is_none());
}

fn config(require_node_lease: bool) -> Config {
    Config {
        max_resident: 4,
        max_activations: 4,
        max_evictions: 1,
        max_releases: 1,
        max_outbound_websockets: 1,
        ownership_on_evict: OwnershipOnEvict::Sticky,
        require_node_lease,
        peer_protocol: crate::peer_auth::PROTOCOL_VERSION,
        operation_deadline_ms: Some(1000),
        owner_log_recovery_backoff_ms: 1,
        owner_log_recovery_attempts: 1,
        alarm_resident_ms: 0,
        idle_evict_ms: None,
        pressure: celld_logic::pressure::PressureConfig::from_limits(None, Some(0)),
    }
}

#[test]
fn native_handoff_shutdown_waits_for_dormant_retirement() {
    let mut status = DrainStatus {
        retiring_dormant: 1,
        ..DrainStatus::default()
    };
    assert!(!status.handoff_complete());
    status.retiring_dormant = 0;
    status.releasing = 1;
    assert!(!status.handoff_complete());
    status.releasing = 0;
    assert!(status.handoff_complete());
}

fn app(tx: mpsc::UnboundedSender<Message>) -> AppHandle {
    let (websockets, _) = mpsc::unbounded_channel();
    let (reload, _) = crate::generation::reload_channel();
    AppHandle {
        tx,
        runtime: None,
        #[cfg(celld_internal_tests)]
        scripted_activity_host: None,
        reload,
        peer_http: reqwest::Client::new(),
        peer_auth: Arc::new(PeerAuth::new([1; 32], "b").unwrap()),
        advertise: String::new(),
        websockets,
        max_outbound_websockets: 1,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fleet_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        public_in_flight: Arc::new(AtomicUsize::new(0)),
        drain_pins: Default::default(),
        follower: None,
        trust_forwarded_headers: false,
        max_request_body_bytes: 1024,
        operation_deadline_ms: 1000,
    }
}

#[tokio::test]
async fn native_handoff_unretired_owner_settles_actual_actor_route_without_reconciliation() {
    let store = Arc::new(FaultStore::default());
    let bucket = store.bucket();
    let a = BucketOwnership::new(bucket.clone(), bucket.clone(), "a".into(), "gen-a".into());
    let b = Arc::new(BucketOwnership::new(
        bucket.clone(),
        bucket.clone(),
        "b".into(),
        "gen-b".into(),
    ));
    let scope = "Native:route-refusal";
    assert_eq!(
        a.cas_owner(scope, CasGuard::Absent, 1).await.unwrap(),
        CasOutcome::Applied
    );
    a.protect_native(scope, 1, &"a".repeat(64)).await.unwrap();
    bucket
        .put(
            "nodes/a.json",
            br#"{"node":"a","expires_ms":0,"addr":"","probe_public_key":"gen-a"}"#.to_vec(),
        )
        .await
        .unwrap();
    let before = a.read_owner(scope).await.unwrap().unwrap();
    store.reads.lock().unwrap().clear();
    store.writes.lock().unwrap().clear();
    let (fence, mut fences) = mpsc::unbounded_channel();
    let mut actor = Actor::from_environment(
        AdmissionLimits {
            resident: 4,
            activations: 4,
            releases: 1,
            placement_weight: 1,
            #[cfg(celld_internal_tests)]
            evictions: 1,
        },
        false,
        fence,
        None,
        Some(Ownership::Bucket(b)),
        ActorIdentity {
            node: "b".into(),
            advertise: "http://127.0.0.1:1".into(),
            region: String::new(),
        },
        None,
    )
    .await
    .unwrap();
    // use a deterministic pressure budget but retain the real node lease and actor loop.
    actor.state = ActorState::from(State::new("b", config(true)));
    let (tx, rx) = mpsc::unbounded_channel();
    let app = app(tx);
    let (_, responses) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(actor.run(rx), async {
            let mut responses = Vec::new();
            // a new caller may retry, but neither request may retry its refused claim internally.
            for _ in 0..2 {
                let mut call = CallContext {
                    scope: scope.into(),
                    request_id: None,
                    parent: None,
                    deliver_abort_to_handler: false,
                    cancel: None,
                    order: None,
                    body_guard: crate::http_streams::RequestBodyGuard(None),
                };
                let payload = CallPayload {
                    name: None,
                    url: "http://cell/state".into(),
                    method: "GET".into(),
                    body: Vec::new().into(),
                    headers: Vec::new(),
                };
                let attempt = dispatch_call_attempt(&app, &mut call, payload, || {
                    panic!("refused ownership must not resolve a route or dispatch a handler")
                })
                .await;
                let CallAttempt::RouteError(error) = attempt else {
                    panic!("expected a route refusal");
                };
                assert!(matches!(
                    error.downcast_ref::<RoutedRequestError>(),
                    Some(RoutedRequestError(
                        RequestError::CooperativeRetirementRequired
                    ))
                ));
                responses.push(route_error_result(error).unwrap());
            }
            drop(app);
            responses
        })
    })
    .await
    .expect("deterministic refusal must not wait for node authority or retry deadlines");
    assert_eq!(responses.len(), 2);
    for response in responses {
        assert_eq!(response.status, 503);
        assert_eq!(
            response.headers,
            vec![("content-type".into(), "application/json".into())]
        );
        assert_eq!(response.body, br#"{"error":"CooperativeRetirementRequired","code":"cooperative-retirement-required"}"#);
        assert!(response.stream.is_none() && response.websocket.is_none());
    }
    assert_eq!(
        request_error_phase(RequestError::CooperativeRetirementRequired),
        "ownership_acquire"
    );
    assert!(fences.try_recv().is_err());
    let key = format!("cells/{scope}/own.json");
    let reads = store.reads.lock().unwrap().clone();
    // one routing read and one pre-cas guard read per explicit request, no reconciliation read.
    assert_eq!(reads.iter().filter(|path| **path == key).count(), 4);
    assert!(reads
        .iter()
        .all(|path| path == &key || path.starts_with("nodes/")));
    assert!(store
        .writes
        .lock()
        .unwrap()
        .iter()
        .all(|path| path.starts_with("nodes/")));
    assert_eq!(a.read_owner(scope).await.unwrap().unwrap(), before);
}

#[tokio::test]
async fn native_handoff_actor_transport_and_lost_cas_reply_still_reconcile() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for committed in [false, true] {
            let store = Arc::new(FaultStore::default());
            let bucket = store.bucket();
            let b = Arc::new(BucketOwnership::new(
                bucket.clone(),
                bucket,
                "b".into(),
                "gen-b".into(),
            ));
            let ownership = Ownership::Bucket(b.clone());
            let scope = if committed {
                "Native:lost-cas"
            } else {
                "Native:transport"
            };
            assert_eq!(
                b.cas_owner(scope, CasGuard::Absent, 1).await.unwrap(),
                CasOutcome::Applied
            );
            let mut state = State::new("b", config(false));
            let effects = on_event(
                &mut state,
                Event::Request {
                    request: 1,
                    cell: scope.into(),
                },
            );
            let op = effects
                .iter()
                .find_map(|effect| match effect {
                    Effect::ReadOwner { op, .. } => Some(*op),
                    _ => None,
                })
                .unwrap();
            let owner = ownership.read_owner(scope).await.unwrap();
            let effects = on_event(
                &mut state,
                Event::OwnerRead {
                    op,
                    now_ms: 0,
                    result: Ok(owner),
                },
            );
            let (op, guard, epoch) = effects
                .into_iter()
                .find_map(|effect| match effect {
                    Effect::CasOwner {
                        op, guard, epoch, ..
                    } => Some((op, guard, epoch)),
                    _ => None,
                })
                .unwrap();
            let key = format!("cells/{scope}/own.json");
            if committed {
                let gate = StoreGate::new();
                gate.open();
                *store.put.lock().unwrap() = Some((key.clone(), PutFault::CommitThenLose(gate)));
            } else {
                *store.get.lock().unwrap() = Some(key.clone());
            }
            let result = ownership.cas_owner(scope, guard, epoch).await;
            assert_eq!(result, Err(Failure::Ambiguous));
            let effects = on_event(&mut state, Event::OwnerCasCompleted { op, result });
            assert!(matches!(
                state.phase(scope),
                Some(Phase::ReconcilingAcquire { .. })
            ));
            assert_eq!(
                effects
                    .iter()
                    .filter(|effect| matches!(effect, Effect::ReadOwner { .. }))
                    .count(),
                1
            );
            assert!(!effects
                .iter()
                .any(|effect| matches!(effect, Effect::Restore { .. } | Effect::CasOwner { .. })));
            let op = effects
                .iter()
                .find_map(|effect| match effect {
                    Effect::ReadOwner { op, .. } => Some(*op),
                    _ => None,
                })
                .unwrap();
            let owner = ownership.read_owner(scope).await.unwrap().unwrap();
            assert_eq!(owner.epoch, if committed { 2 } else { 1 });
            let effects = on_event(
                &mut state,
                Event::OwnerRead {
                    op,
                    now_ms: 0,
                    result: Ok(Some(owner)),
                },
            );
            if committed {
                assert!(matches!(state.phase(scope), Some(Phase::Restoring { .. })));
                assert_eq!(
                    effects
                        .iter()
                        .filter(|effect| matches!(effect, Effect::Restore { .. }))
                        .count(),
                    1
                );
                assert!(!effects
                    .iter()
                    .any(|effect| matches!(effect, Effect::CasOwner { .. })));
            } else {
                assert!(matches!(state.phase(scope), Some(Phase::Acquiring { .. })));
                assert_eq!(
                    effects
                        .iter()
                        .filter(|effect| matches!(effect, Effect::CasOwner { .. }))
                        .count(),
                    1
                );
                assert!(!effects
                    .iter()
                    .any(|effect| matches!(effect, Effect::Restore { .. })));
            }
            let writes = store.writes.lock().unwrap();
            assert_eq!(
                writes.iter().filter(|path| **path == key).count(),
                if committed { 2 } else { 1 }
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_handoff_cold_claim_shutdown_releases_through_actual_actor_effect() {
    use crate::native_handoff::{
        self,
        tests::{assert_unknown_batch, released_control},
    };
    use futures_util::StreamExt as _;

    tokio::time::timeout(Duration::from_secs(5), async {
        let store = Arc::new(FaultStore::default());
        let scope = "Native:cold-actor-release";
        let (checkpoint, predecessor) = released_control(&store, scope).await;
        let bucket = store.bucket();
        let b = Arc::new(BucketOwnership::new(
            bucket.clone(),
            bucket.clone(),
            "b".into(),
            "gen-b".into(),
        ));
        let (fence, _) = mpsc::unbounded_channel();
        let mut actor = Actor::from_environment(
            AdmissionLimits {
                resident: 4,
                activations: 4,
                releases: 1,
                placement_weight: 1,
                #[cfg(celld_internal_tests)]
                evictions: 1,
            },
            false,
            fence,
            None,
            Some(Ownership::Bucket(b.clone())),
            ActorIdentity {
                node: "b".into(),
                advertise: "http://127.0.0.1:1".into(),
                region: String::new(),
            },
            None,
        )
        .await
        .unwrap();
        // exercise the real claim and release effects without a runtime or node watchdog.
        actor.state = ActorState::from(State::new("b", config(false)));
        let mut out = StepOutput::default();
        actor.drive(
            Event::HandoffRequestAt {
                request: 1,
                cell: scope.into(),
                now_ms: now_ms(),
                now_mono_ms: crate::asyncrt::mono_ms(),
            },
            &mut out,
        );
        let mut effects = FuturesUnordered::new();
        let mut delays = DelayQueue::new();
        let mut slots = TimerSlots::default();
        for _ in 0..5 {
            drain_step_output(&mut out, &mut effects, &mut delays, &mut slots);
            let completed = effects.next().await.expect("cold claim has no next effect");
            assert!(matches!(
                completed.event,
                Event::OwnerRead { .. }
                    | Event::CapacityPeersRead { .. }
                    | Event::OwnerCasCompleted { .. }
            ));
            actor.drive(completed.event, &mut out);
            if matches!(actor.state.phase(scope), Some(Phase::Dormant { epoch: 2 })) {
                break;
            }
        }
        assert!(matches!(
            actor.state.phase(scope),
            Some(Phase::Dormant { epoch: 2 })
        ));
        assert!(effects.is_empty());
        assert_eq!(
            b.native_owner(scope)
                .await
                .unwrap()
                .unwrap()
                .restore
                .as_deref(),
            Some(predecessor.as_str())
        );
        store.writes.lock().unwrap().clear();
        actor.drive(Event::ReleaseAll, &mut out);
        drain_step_output(&mut out, &mut effects, &mut delays, &mut slots);
        assert_eq!(effects.len(), 1);
        let completed = effects.next().await.unwrap();
        assert!(matches!(
            completed.event,
            Event::OwnerReleased {
                result: Ok(CasOutcome::Applied),
                ..
            }
        ));
        let followup = on_event(&mut actor.state, completed.event);
        assert!(!followup.iter().any(|effect| matches!(
            effect,
            Effect::ReleaseOwner { .. } | Effect::Restore { .. } | Effect::StartRuntime { .. }
        )));
        let (released, _) = native_handoff::read_owner(&bucket, scope)
            .await
            .unwrap()
            .unwrap();
        assert!(released.node.is_empty());
        let native = released.native.unwrap();
        assert!(native.journal.is_empty() && native.restore.is_none());
        let closure =
            native_handoff::load_closure(&bucket, scope, native.closed.as_deref().unwrap())
                .await
                .unwrap();
        assert_eq!(closure.epoch, 2);
        assert_eq!(closure.previous.as_deref(), Some(predecessor.as_str()));
        assert!(closure.attempts.is_empty());
        assert_eq!(
            closure.checkpoint,
            native_handoff::Checkpoint {
                epoch: 2,
                ..checkpoint
            }
        );
        assert_unknown_batch(
            native_handoff::load_checkpoint(&bucket, scope, &closure.checkpoint)
                .await
                .unwrap(),
        );
        assert_eq!(
            native_handoff::load_closure(&bucket, scope, &predecessor)
                .await
                .unwrap()
                .attempts
                .len(),
            1
        );
        // no runtime, replica materialisation or container engine is needed for this cold release.
        assert!(store
            .writes
            .lock()
            .unwrap()
            .iter()
            .all(|path| path == &native_handoff::owner_key(scope)
                || path.contains("/native-closures/")
                || path.contains("/native-checkpoints/")));
    })
    .await
    .unwrap();
}

#[test]
fn native_handoff_route_refusal_does_not_classify_text_or_other_errors() {
    assert!(route_error_result(anyhow::anyhow!("cooperative-retirement-required")).is_err());
    for error in [
        RequestError::AcquireFailed,
        RequestError::NodeFenced,
        RequestError::ResolveFailed,
    ] {
        let Err(result) = route_error_result(anyhow::Error::new(RoutedRequestError(error))) else {
            panic!("unrelated route error became a cooperative retirement response");
        };
        assert_eq!(
            result.downcast_ref::<RoutedRequestError>().unwrap().0,
            error
        );
    }
}
