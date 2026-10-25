use super::*;

#[tokio::test]
async fn native_effect_fetch_retirement_during_gate_wait_never_polls_send() {
    crate::native_ws::native_ws_tests::init_host();
    for retire in [false, true] {
        let runtime = Arc::new(ActorRuntimeState::default());
        let cell = format!("native-effect-gate-{}", crate::ws_registry::ws_next_id());
        runtime.native_activations.replace(&cell, true);
        let origin = ActorEffectOrigin {
            owner: runtime.native_activations.owner(&cell),
            activations: Arc::downgrade(&runtime.native_activations),
            cell: cell.clone(),
            #[cfg(all(debug_assertions, unix))]
            epoch: Some(7),
        };
        let polls = AtomicUsize::new(0);
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let mut fetch = Box::pin(async {
            gate.await.map_err(|_| "gate dropped".to_string())?;
            admit_fetch(Some(&origin), &mut FetchGatePermit::default(), async {
                polls.fetch_add(1, Ordering::SeqCst);
                17
            })
            .await
        });
        assert!(futures_util::poll!(&mut fetch).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        if retire {
            assert!(runtime.reset_actor_generation(&cell, origin.owner.generation().key()));
        }
        release.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), fetch)
            .await
            .unwrap();
        if retire {
            assert_eq!(result.unwrap_err(), RETIRED_EFFECT);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            let successor = ActorEffectOrigin {
                owner: runtime.native_activations.owner(&cell),
                activations: Arc::downgrade(&runtime.native_activations),
                cell,
                #[cfg(all(debug_assertions, unix))]
                epoch: Some(8),
            };
            assert_eq!(
                admit_fetch(Some(&successor), &mut FetchGatePermit::default(), async {
                    19
                })
                .await
                .unwrap(),
                19
            );
            drop(runtime);
            assert!(
                admit_fetch(Some(&successor), &mut FetchGatePermit::default(), async {
                    panic!("retired runtime dispatched")
                })
                .await
                .is_err()
            );
        } else {
            assert_eq!(result.unwrap(), 17);
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
    }
    // a worker has no actor activation and keeps its ordinary dispatch path.
    assert_eq!(
        admit_fetch(None, &mut FetchGatePermit::default(), async { 23 })
            .await
            .unwrap(),
        23
    );
}

#[cfg(all(debug_assertions, unix))]
#[tokio::test]
async fn native_effect_debug_fetch_gate_releases_real_admission_or_refuses_retirement() {
    use crate::allocation_debug::{tests, Control, FetchGate};
    crate::native_ws::native_ws_tests::init_host();
    for retire in [false, true] {
        let runtime = Arc::new(ActorRuntimeState::default());
        let cell = format!("fetch-control-{}", crate::ws_registry::ws_next_id());
        runtime.native_activations.replace(&cell, true);
        let origin = ActorEffectOrigin {
            owner: runtime.native_activations.owner(&cell),
            activations: Arc::downgrade(&runtime.native_activations),
            cell: cell.clone(),
            epoch: Some(19),
        };
        let directory = tests::directory(&cell, "fetch-gate", None, 2000);
        let control = Control::claim(directory.path(), &cell, "fetch-gate", None, 19, None)
            .unwrap()
            .unwrap();
        let mut permit = FetchGatePermit {
            control: Some(FetchGate::new(control)),
        };
        let (release_verdict, verdict) = tokio::sync::oneshot::channel::<()>();
        let polls = AtomicUsize::new(0);
        let mut fetch = Box::pin(async {
            permit
                .control
                .as_mut()
                .unwrap()
                .wait(true, async {
                    verdict.await.map_err(|_| "verdict dropped".to_string())
                })
                .await?;
            admit_fetch(Some(&origin), &mut permit, async {
                polls.fetch_add(1, Ordering::SeqCst);
                1
            })
            .await
        });
        assert!(futures_util::poll!(&mut fetch).is_pending());
        assert!(!directory.path().join("entered.json").exists());
        release_verdict.send(()).unwrap();
        assert!(futures_util::poll!(&mut fetch).is_pending());
        let entered = tests::ack(directory.path(), "entered.json").await;
        assert_eq!(entered["epoch"], 19);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        if retire {
            assert!(runtime.reset_actor_generation(&cell, origin.owner.generation().key()));
        }
        tests::signal(directory.path(), "release.json");
        let result = tokio::time::timeout(Duration::from_secs(3), fetch)
            .await
            .unwrap();
        assert_eq!(result.is_err(), retire);
        let settled = tests::ack(directory.path(), "settled.json").await;
        assert_eq!(
            settled["status"],
            if retire { "refused" } else { "admitted" }
        );
        assert_eq!(settled["admitted"], !retire);
        assert_eq!(polls.load(Ordering::SeqCst), usize::from(!retire));
    }
}

#[test]
fn native_ws_actor_event_retirement_keeps_pending_io_for_later_event() {
    crate::native_ws::native_ws_tests::init_host();
    let runtime = Arc::new(ActorRuntimeState::default());
    let actor = format!("native-lifetime-{}", crate::ws_registry::ws_next_id());
    runtime.native_activations.replace(&actor, true);
    let first = IoContext::tracked(&runtime);
    first.bind_native_activation(&runtime, &actor);
    let table = first.native_upgrades();
    let id = crate::ws_registry::ws_next_id();
    let pending = table.reserve(id).unwrap();
    first.close_sockets();
    drop(first);
    assert!(!pending.cancel.is_cancelled());

    let later = IoContext::tracked(&runtime);
    later.bind_native_activation(&runtime, &actor);
    assert!(Arc::ptr_eq(&table, &later.native_upgrades()));
    let _cleanup = later.native_upgrades().cleanup(id).unwrap();
    later.close_sockets();
    assert!(!pending.cancel.is_cancelled());
    runtime.native_activations.replace(&actor, false);
    assert!(pending.cancel.is_cancelled());
    assert!(later
        .native_upgrades()
        .reserve(crate::ws_registry::ws_next_id())
        .is_err());
}

#[test]
fn native_ws_activation_replacement_fences_old_continuations_and_other_actors() {
    crate::native_ws::native_ws_tests::init_host();
    let runtime = Arc::new(ActorRuntimeState::default());
    let actor = format!("native-generation-{}", crate::ws_registry::ws_next_id());
    let foreign = format!("native-foreign-{}", crate::ws_registry::ws_next_id());
    runtime.native_activations.replace(&actor, true);
    runtime.native_activations.replace(&foreign, true);
    let old = IoContext::tracked(&runtime);
    old.bind_native_activation(&runtime, &actor);
    let id = crate::ws_registry::ws_next_id();
    let pending = old.native_upgrades().reserve(id).unwrap();
    let outsider = IoContext::tracked(&runtime);
    outsider.bind_native_activation(&runtime, &foreign);
    assert!(outsider.native_upgrades().cleanup(id).is_err());
    assert!(outsider.native_upgrades().take(id).is_err());
    outsider.native_upgrades().remove(id);
    assert!(!pending.cancel.is_cancelled());

    runtime.native_activations.replace(&actor, true);
    let successor = IoContext::tracked(&runtime);
    successor.bind_native_activation(&runtime, &actor);
    assert!(pending.cancel.is_cancelled());
    assert!(!Arc::ptr_eq(
        &old.native_upgrades(),
        &successor.native_upgrades()
    ));
    assert!(old.native_upgrades().reserve(id).is_err());
    let replacement = successor.native_upgrades().reserve(id).unwrap();
    drop(pending);
    old.close_sockets();
    assert!(!replacement.cancel.is_cancelled());
    drop(runtime);
    assert!(replacement.cancel.is_cancelled());
}

#[test]
fn native_ws_worker_retirement_cancels_pending_and_consumed_sockets() {
    crate::native_ws::native_ws_tests::init_host();
    let context = IoContext::new();
    let id = crate::ws_registry::ws_next_id();
    let pending = context.native_upgrades().reserve(id).unwrap();
    let consumed = tokio_util::sync::CancellationToken::new();
    context
        .native_socket_cancels
        .lock()
        .unwrap()
        .push(consumed.clone());
    context.close_sockets();
    assert!(pending.cancel.is_cancelled());
    assert!(consumed.is_cancelled());
    assert!(context.native_upgrades().reserve(id).is_err());
}

#[test]
fn native_ws_absent_activation_is_not_a_fresh_owner() {
    crate::native_ws::native_ws_tests::init_host();
    let runtime = ActorRuntimeState::default();
    let context = IoContext::new();
    context.bind_native_activation(&runtime, "not-adopted");
    assert!(context
        .native_upgrades()
        .reserve(crate::ws_registry::ws_next_id())
        .is_err());
}

#[test]
fn native_ws_real_actor_reset_paths_revoke_only_the_old_generation() {
    crate::native_ws::native_ws_tests::init_host();
    Engine::init();
    for path in ["concurrency", "gate", "retire", "break", "abort", "queued"] {
        let runtime = Arc::new(ActorRuntimeState::default());
        let actor = format!("native-reset-{path}-{}", crate::ws_registry::ws_next_id());
        runtime.native_activations.replace(&actor, true);
        let event = IoContext::tracked(&runtime);
        event.bind_native_activation(&runtime, &actor);
        let table = event.native_upgrades();
        let pending = table.reserve(crate::ws_registry::ws_next_id()).unwrap();
        let consumed = table.revocation();
        let key = table.generation().key().to_string();
        let _current = CurrentGuard::enter(event.clone());
        let mut isolate = v8::Isolate::new(Default::default());
        isolate.set_slot(runtime.clone());
        v8::scope!(let scope, &mut isolate);
        let realm = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, realm);
        let caught = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut caught.init();
        install_io_context(scope, &event);
        macro_rules! install {
            ($name:literal, $callback:path) => {{
                let name = v8::String::new(scope, $name).unwrap();
                let function = v8::Function::new(scope, $callback).unwrap();
                let global = scope.get_current_context().global(scope);
                global.set(scope, name.into(), function.into());
            }};
        }
        install!("__ws_native_generation", websocket::op_ws_native_generation);
        install!(
            "__ws_native_generation_live",
            websocket::op_ws_native_generation_live
        );
        install!(
            "__ws_reset_native_actor",
            websocket::op_ws_reset_native_actor
        );
        install!("__gate_release", op_gate_release);
        install!("__actor_abort", op_actor_abort);
        install!(
            "__storage_cancel_pending_puts",
            storage_ops::op_storage_cancel_pending_puts
        );
        macro_rules! evaluate {
            ($source:expr) => {{
                let source = v8::String::new(scope, $source).unwrap();
                let result =
                    v8::Script::compile(scope, source, None).and_then(|script| script.run(scope));
                result.unwrap_or_else(|| {
                    let error = scope
                        .exception()
                        .map(|error| error.to_rust_string_lossy(scope));
                    panic!("native reset path {path}: {error:?}")
                })
            }};
        }
        let harness = include_str!("harness.js");
        let slice = |start: &str, end: &str| {
            let start = harness.find(start).unwrap();
            let end = start + harness[start..].find(end).unwrap();
            &harness[start..end]
        };
        let setup = include_str!("native_ws_harness_setup.js")
            .lines()
            .filter(|line| {
                !line.starts_with("const __ws_native_generation =")
                    && !line.starts_with("const __ws_native_generation_live =")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let events = slice(
            "if (!globalThis.Event) {",
            "if (!globalThis.DOMException) {",
        );
        let sockets = slice(
            "const __sockets = __celld.__sockets",
            "// Cloudflare exposes the time of the last I/O",
        );
        let state = slice(
            "const __nativeActorStates = new WeakMap();",
            "function _instance(scope)",
        );
        let retire = slice(
            "__celld.__retireInputGateContext = (context) => {",
            "// Race a pending dispatch",
        );
        let breaking = slice(
            "const __brokenActors = new Map();",
            "// Everything this isolate holds",
        );
        evaluate!(&format!(
            r#"
            {setup}
            Object.assign(__cell, {{ instances: {{}}, facetConfigs: {{}}, idNames: {{}}, containers: {{}} }});
            class DurableObjectStorage {{}}
            class DurableObjectFacets {{}}
            class DurableObjectId {{}}
            const __cellBlocks = new Map();
            const __stubEntries = new Map();
            const __endActorEvent = () => {{}};
            const __endActorEventsForContext = () => {{}};
            {events}
            {sockets}
            {state}
            {retire}
            {breaking}
            actorScope = {actor:?};
            throws(() => __ws_native_generation("another-actor"), "event minted a foreign generation");
            const state = new DurableObjectState(actorScope);
            __cell.instances[actorScope] = {{ __celldState: state }};
            const socket = __makeNativeSocket(__ws_alloc(), "");
            let callbacks = 0;
            socket.addEventListener("error", () => callbacks++);
            socket.addEventListener("close", () => callbacks++);
            __celld;
        "#
        ));
        let internals = evaluate!("__celld").try_cast::<v8::Object>().unwrap();
        assert!(runtime
            .internals
            .set(v8::Global::new(scope, internals))
            .is_ok());
        let gate_event = NEXT_GATE_EVENT.fetch_add(1, Ordering::Relaxed);
        let context_id = event.continuation_id().unwrap();
        if matches!(path, "gate" | "retire") {
            assert!(matches!(
                acquire_cell_gate(&event, &actor, gate_event, Some(context_id), &mut None),
                CellGateAcquisition::Acquired
            ));
            event
                .native_gate_generations
                .lock()
                .unwrap()
                .insert(gate_event, (actor.clone(), key.clone()));
        }
        match path {
            "concurrency" => {
                evaluate!("state._resetAfterConcurrencyFailure(new Error('failed block'));");
            }
            "gate" => {
                evaluate!(&format!(
                    "__gate_release(actorScope, {gate_event}, '{context_id}', 'failed gate');"
                ));
            }
            "break" => {
                evaluate!("__actorBreak(actorScope, new Error('broken'), __nativeActorStates.get(state));");
            }
            "abort" => {
                runtime.pending_puts.lock().unwrap().insert(
                    actor.clone(),
                    PendingPutBatch {
                        owner: table.clone(),
                        entries: vec![("before-abort".into(), vec![1])],
                    },
                );
                // a leaf call can return before v8 polls its termination
                // interrupt. the loop forces a safepoint and the catch checks
                // that actor abort cannot become a catchable javascript error.
                let source = v8::String::new(
                    scope,
                    "let caughtAbort = false; try { state.abort('current generation abort'); for (;;) {} } catch { caughtAbort = true; }",
                )
                .unwrap();
                let result =
                    v8::Script::compile(scope, source, None).and_then(|script| script.run(scope));
                assert!(
                    result.is_none(),
                    "abort returned: terminating={}, recorded={}, revoked={}, context={:?}",
                    scope.is_execution_terminating(),
                    runtime.termination.lock().unwrap().is_some(),
                    consumed.is_cancelled(),
                    reaction_continuation_id(scope),
                );
                scope.cancel_terminate_execution();
                let termination = runtime
                    .termination
                    .lock()
                    .unwrap()
                    .take()
                    .expect("current abort did not terminate");
                assert_eq!(termination.actor_scope.as_deref(), Some(actor.as_str()));
                assert_eq!(termination.context_id, event.continuation_id());
                assert_eq!(
                    termination.error,
                    "__CELLD_ACTOR_ABORT__:current generation abort"
                );
                assert!(!runtime.pending_puts.lock().unwrap().contains_key(&actor));
                evaluate!("check(!caughtAbort, 'actor abort became catchable');");
            }
            "retire" | "queued" => {
                let holder = if path == "retire" {
                    gate_event
                } else {
                    gate_event + 1
                };
                evaluate!(&format!("__cellBlocks.set(actorScope, {{holder: {holder}, events: new Map([[{gate_event}, {{owner: '{context_id}', reaction: '{context_id}', nativeGeneration: __nativeActorStates.get(state), settleReady() {{}}}}]])}});"));
                if path == "retire" {
                    abandon_context_input_gates(&event);
                    assert!(consumed.is_cancelled());
                }
                evaluate!(&format!(
                    "__celld.__retireInputGateContext('{context_id}');"
                ));
            }
            _ => unreachable!(),
        }
        if path == "queued" {
            assert!(!pending.cancel.is_cancelled());
            assert!(!consumed.is_cancelled());
            evaluate!("check(__sockets.has(socket._id), 'queued retirement reset live actor');");
        } else {
            assert!(
                pending.cancel.is_cancelled(),
                "pending opening survived {path}"
            );
            assert!(consumed.is_cancelled(), "consumed owner survived {path}");
            assert!(table.reserve(crate::ws_registry::ws_next_id()).is_err());
            evaluate!("check(callbacks === 0 && !__sockets.has(socket._id), 'reset retained roots or called old listeners');");
            let successor = runtime.native_activations.owner(&actor);
            assert!(!Arc::ptr_eq(&successor, &table));
            evaluate!("throws(() => __ws_native_generation(actorScope), 'stale event minted successor generation');");
            evaluate!(&format!("check(!__ws_reset_native_actor(actorScope, {key:?}), 'stale reset reached successor'); check(!__ws_reset_native_actor('another-actor', {key:?}), 'reset crossed actor scope');"));
            assert!(Arc::ptr_eq(
                &successor,
                &runtime.native_activations.owner(&actor)
            ));
            let next = IoContext::tracked(&runtime);
            next.bind_native_activation(&runtime, &actor);
            install_io_context(scope, &next);
            let _next_current = CurrentGuard::enter(next.clone());
            let new_key =
                evaluate!("__ws_native_generation(actorScope)").to_rust_string_lossy(scope);
            assert_eq!(new_key, successor.generation().key());
            assert_ne!(new_key, key);
            if path == "gate" {
                // gate failure left the old state object reachable without
                // setting its javascript aborted flag. call the actual method.
                evaluate!("check(!state._aborted, 'stale fixture was already aborted'); const successorState = new DurableObjectState(actorScope); __cell.instances[actorScope] = {__celldState: successorState};");
                let pending = successor.reserve(crate::ws_registry::ws_next_id()).unwrap();
                let expected_puts = vec![("successor-put".to_string(), vec![7, 8])];
                runtime.pending_puts.lock().unwrap().insert(
                    actor.clone(),
                    PendingPutBatch {
                        owner: successor.clone(),
                        entries: expected_puts.clone(),
                    },
                );
                evaluate!("state.abort({toString() { throw new Error('stale abort coerced its reason'); }});");
                evaluate!(&format!(
                    "__actor_abort(actorScope, 'stale host abort', {key:?});"
                ));
                evaluate!(&format!("actorScope = ''; state.abort('stale cross-context abort'); check(!__actorBreak({actor:?}, new Error('stale break'), {key:?}), 'stale break was authorised'); actorScope = {actor:?}; state._resetAfterConcurrencyFailure(new Error('stale failure'));"));
                evaluate!("check(!__brokenActors.has(actorScope), 'stale abort broke successor'); check(__cell.instances[actorScope].__celldState === successorState && !successorState._aborted, 'stale abort replaced successor state');");
                assert!(runtime.termination.lock().unwrap().is_none());
                assert_eq!(
                    runtime
                        .pending_puts
                        .lock()
                        .unwrap()
                        .get(&actor)
                        .map(|batch| &batch.entries),
                    Some(&expected_puts)
                );
                assert!(!pending.cancel.is_cancelled());
                assert!(Arc::ptr_eq(
                    &successor,
                    &runtime.native_activations.owner(&actor)
                ));
            }
        }
    }
}

#[tokio::test]
async fn native_ws_notification_wait_uses_existing_gate_and_generation() {
    crate::native_ws::native_ws_tests::init_host();
    let runtime = Arc::new(ActorRuntimeState::default());
    let cell = format!(
        "native-notification-gate-{}",
        crate::ws_registry::ws_next_id()
    );
    runtime.native_activations.replace(&cell, true);
    let context = IoContext::tracked(&runtime);
    context.bind_native_activation(&runtime, &cell);
    let table = context.native_upgrades();
    for reset in [false, true] {
        let event = NEXT_GATE_EVENT.fetch_add(1, Ordering::Relaxed);
        assert!(matches!(
            acquire_cell_gate(&context, &cell, event, context.continuation_id(), &mut None),
            CellGateAcquisition::Acquired
        ));
        let mut waiting = Box::pin(wait_for_cell_input_gate(&cell, Some(table.generation())));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        if reset {
            assert!(runtime.reset_actor_generation(&cell, table.generation().key()));
            assert!(tokio::time::timeout(Duration::from_secs(3), &mut waiting)
                .await
                .unwrap()
                .is_err());
            assert!(!cell_gates()
                .lock()
                .unwrap()
                .get(&cell)
                .unwrap()
                .gate
                .is_open());
        }
        assert!(context.release_input_gate(&cell, event));
        release_cell_gate(&cell, event, Ok(()));
        if !reset {
            assert!(tokio::time::timeout(Duration::from_secs(3), &mut waiting)
                .await
                .unwrap()
                .is_ok());
        }
    }
    assert!(wait_for_cell_input_gate(&cell, Some(table.generation()))
        .await
        .is_err());
    assert!(runtime
        .native_activations
        .owner(&cell)
        .generation()
        .is_live());
    assert!(!gate_waiters().lock().unwrap().contains_key(&cell));
}

#[test]
fn native_ws_harness_implicit_consumption_and_pair_controls() {
    crate::native_ws::native_ws_tests::init_host();
    Engine::init();
    let mut isolate = v8::Isolate::new(Default::default());
    v8::scope!(let scope, &mut isolate);
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    let caught = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut caught.init();
    let harness = include_str!("harness.js");
    let slice = |start: &str, end: &str| {
        let start = harness.find(start).unwrap();
        let end = start + harness[start..].find(end).unwrap();
        &harness[start..end]
    };
    // exercise the shipping event, websocket and response-extraction code.
    // only host operations and unrelated platform types are fixture stubs.
    let events = slice(
        "if (!globalThis.Event) {",
        "if (!globalThis.DOMException) {",
    );
    let sockets = slice(
        "const __sockets = __celld.__sockets",
        "// Cloudflare exposes the time of the last I/O",
    );
    let response = &harness[harness.find("__celld.__readResponse = (r) => {").unwrap()..];
    let generations = slice(
        "const __nativeActorStates = new WeakMap();",
        "class DurableObjectState {",
    );
    let actor_events = slice(
        "const __actorEventStack = [];",
        "const __incomingRequestSignals = new Map();",
    );
    let setup = include_str!("native_ws_harness_setup.js")
        .lines()
        .filter(|line| !line.starts_with("const __currentActorScope ="))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "{setup}\n{actor_events}\nsetActorScope(actorScope);\n{events}\n{generations}\n{sockets}\n{response}\n{}",
        include_str!("native_ws_harness_tests.js")
    );
    let source = v8::String::new(scope, &source).unwrap();
    let result = v8::Script::compile(scope, source, None).and_then(|script| script.run(scope));
    if result.is_none() {
        let error = scope
            .exception()
            .map(|error| error.to_rust_string_lossy(scope));
        panic!("native WebSocket harness regression: {error:?}");
    }
    let completion = result.unwrap().try_cast::<v8::Promise>().unwrap();
    scope.perform_microtask_checkpoint();
    assert_eq!(
        completion.state(),
        v8::PromiseState::Fulfilled,
        "native lifecycle notification regression: {}",
        completion.result(scope).to_rust_string_lossy(scope)
    );
}
