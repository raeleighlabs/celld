use super::*;

#[test]
fn native_allocation_v8_authority_brands_events_and_bounds_raw_arguments() {
    crate::native_ws::native_ws_tests::init_host();
    Engine::init();
    let runtime = Arc::new(ActorRuntimeState::default());
    let actor = format!("allocation-a-{}", crate::ws_registry::ws_next_id());
    let other = format!("allocation-b-{}", crate::ws_registry::ws_next_id());
    let cells = storage::Cells::default();
    let _storage = cells.install();
    storage::open(&actor, ":memory:").unwrap();
    runtime.native_activations.replace(&actor, true);
    runtime.native_activations.replace(&other, true);
    let event = IoContext::tracked(&runtime);
    event.bind_native_activation(&runtime, &actor);
    event.egress.lock().unwrap().push(EgressFrame {
        storage: actor.clone(),
        before: 0,
        epoch: Some(11),
        root: None,
    });
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
    install!("__container_bind", op_container_bind);
    install!("__fetch", op_fetch);
    install!("__storage_queue_put", storage_ops::op_storage_queue_put);
    install!(
        "__storage_flush_pending_puts",
        storage_ops::op_storage_flush_pending_puts
    );
    install!(
        "__storage_cancel_pending_puts",
        storage_ops::op_storage_cancel_pending_puts
    );
    install!("__storage_delete", storage_ops::op_storage_delete);
    install!("__storage_delete_all", storage_ops::op_storage_delete_all);
    install!(
        "__storage_transaction_control",
        storage_ops::op_storage_transaction_control
    );
    install!("__sql_cursor_start", storage_ops::op_sql_cursor_start);
    install!("__sql_cursor_next", storage_ops::op_sql_cursor_next);
    install!("__sql_cursor_close", storage_ops::op_sql_cursor_close);
    install!("__sql_ingest", storage_ops::op_sql_ingest);
    install!(
        "__container_start_allocation",
        op_container_start_allocation
    );
    install!(
        "__container_inspect_allocation",
        op_container_inspect_allocation
    );
    install!(
        "__container_destroy_allocation",
        op_container_destroy_allocation
    );
    macro_rules! evaluate {
        ($source:expr) => {{
            let source = v8::String::new(scope, $source).unwrap();
            v8::Script::compile(scope, source, None)
                .and_then(|script| script.run(scope))
                .unwrap_or_else(|| {
                    panic!(
                        "allocation authority javascript failed: {:?}",
                        scope
                            .exception()
                            .map(|error| error.to_rust_string_lossy(scope))
                    )
                })
        }};
    }
    let harness = include_str!("harness.js");
    let begin = harness.find("const __containerEnvList =").unwrap();
    let end = harness.find("const __nativeActorStates =").unwrap();
    evaluate!(&format!(
        r#"
        function check(value, message) {{ if (!value) throw new Error(message); }}
        function throws(call, text) {{
          let error;
          try {{ call(); }} catch (caught) {{ error = caught; }}
          check(error && String(error).includes(text), "wrong refusal: " + error);
        }}
        const actor = {actor:?};
        const other = {other:?};
        const tokenA = __container_bind(actor);
        throws(() => __container_bind(other), "not owned");
        throws(() => __container_start_allocation(other, "x".repeat(70000)), "receiver or activation");
        throws(() => __container_start_allocation(tokenA, "x".repeat(65537)), "exceeds limit");
        throws(() => __container_start_allocation(tokenA, "界".repeat(40000)), "byte limit");
        throws(() => __container_start_allocation(tokenA, "{{}}"), "invalid allocation options");
        throws(() => __container_inspect_allocation(tokenA, "x".repeat(65)), "exceeds limit");
        throws(() => __container_destroy_allocation(tokenA, "x".repeat(65)), "exceeds limit");
        {}
        const owner = new Container(actor);
        const forged = {{ _scope: actor }};
        const errors = [];
        Container.prototype.inspectAllocation.call(forged, "a").catch(error => errors.push(String(error)));
        Container.prototype.destroyAllocation.call(forged, "a").catch(error => errors.push(String(error)));
        Container.prototype.startAllocation.call(forged, {{}}).catch(error => errors.push(String(error)));
        owner._scope = other;
        owner.startAllocation({{ id: "a", image: "celld-image:" + "a".repeat(64), engineImage: "sha256:" + "1".repeat(64), platform: "linux/amd64", env: "bad" }}).catch(error => errors.push(String(error)));
    "#,
        &harness[begin..end]
    ));
    scope.perform_microtask_checkpoint();
    evaluate!(
        r#"
        check(errors.length === 4, "missing facade refusals");
        check(errors.slice(0, 3).every(error => error.includes("receiver or activation")), "forged receiver accepted");
        check(errors[3].includes("env must be"), "mutated scope changed authority or bypassed shape validation");
    "#
    );
    let token = evaluate!("tokenA");
    assert_eq!(allocation_authority(scope, token).unwrap(), actor);
    evaluate!(
        r#"
        __storage_queue_put(tokenA, "old", 1);
        __storage_flush_pending_puts(tokenA);
        __sql_cursor_start(tokenA, "CREATE TABLE fenced(value INTEGER); INSERT INTO fenced VALUES (1), (2)", "[]");
        const oldCursor = __sql_cursor_start(tokenA, "SELECT value FROM fenced", "[]").cursorId;
        __storage_queue_put(tokenA, "abandoned", 2);
        let resumeOld;
        let oldRan = false;
        const oldContinuation = new Promise(resolve => { resumeOld = resolve; }).then(() => {
          oldRan = true;
          for (const receiver of [tokenA, tokenB]) {
            throws(() => __storage_queue_put(receiver, "poison", 9), "activation");
            throws(() => __storage_flush_pending_puts(receiver), "activation");
            throws(() => __storage_cancel_pending_puts(receiver), "activation");
            throws(() => __storage_delete(receiver, "successor"), "activation");
            throws(() => __storage_delete_all(receiver, true), "activation");
            throws(() => __storage_transaction_control(receiver, "rollback", false, ""), "activation");
            throws(() => __sql_cursor_start(receiver, "DELETE FROM fenced", "[]"), "activation");
            throws(() => __sql_ingest(receiver, "DELETE FROM fenced;"), "activation");
            throws(() => __sql_cursor_next(oldCursor, receiver), "activation");
          }
          throws(() => __fetch("POST", "http://127.0.0.1:1/stale", null, "[]", "manual"), "retired");
        });
    "#
    );

    // the continuation's host event, not the mutable receiver or ambient turn, owns the op.
    let foreign_event = IoContext::tracked(&runtime);
    foreign_event.bind_native_activation(&runtime, &other);
    foreign_event.egress.lock().unwrap().push(EgressFrame {
        storage: other.clone(),
        before: 0,
        epoch: Some(12),
        root: None,
    });
    install_io_context(scope, &foreign_event);
    evaluate!(
        r#"
        throws(() => __container_bind(actor), "not owned");
        throws(() => __container_inspect_allocation(tokenA, "a"), "receiver or activation");
        throws(() => __container_destroy_allocation(tokenA, "a"), "receiver or activation");
        throws(() => __container_start_allocation(tokenA, "{}"), "receiver or activation");
        throws(() => __storage_queue_put(tokenA, "foreign", 1), "receiver or activation");
    "#
    );
    install_io_context(scope, &event);
    runtime.native_activations.replace(&actor, true);
    evaluate!(
        r#"throws(() => __container_inspect_allocation(tokenA, "a"), "activation is not owned");"#
    );
    let replacement = IoContext::tracked(&runtime);
    replacement.bind_native_activation(&runtime, &actor);
    replacement.egress.lock().unwrap().push(EgressFrame {
        storage: actor.clone(),
        before: 0,
        epoch: Some(13),
        root: None,
    });
    install_io_context(scope, &replacement);
    evaluate!(
        r#"
        const tokenB = __container_bind(actor);
        check(tokenB !== tokenA, "activation reused authority");
        throws(() => __container_destroy_allocation(tokenA, "a"), "receiver or activation");
    "#
    );
    let token = evaluate!("tokenB");
    assert_eq!(allocation_authority(scope, token).unwrap(), actor);
    evaluate!(
        r#"
        throws(() => __storage_queue_put(tokenA, "old-receiver", 1), "receiver or activation");
        throws(() => __storage_queue_put(actor, "forged", 1), "receiver or activation");
        __storage_queue_put(tokenB, "successor", 7);
        resumeOld();
    "#
    );
    scope.perform_microtask_checkpoint();
    evaluate!(
        r#"
        check(oldRan, "old javascript continuation did not run");
        check(oldContinuation instanceof Promise, "missing continuation");
    "#
    );
    let continuation = evaluate!("oldContinuation")
        .try_cast::<v8::Promise>()
        .unwrap();
    assert_eq!(continuation.state(), v8::PromiseState::Fulfilled);
    let pending = runtime.pending_puts.lock().unwrap();
    assert_eq!(pending[&actor].entries.len(), 1);
    assert_eq!(pending[&actor].entries[0].0, "successor");
    drop(pending);
    evaluate!(
        r#"
        __storage_flush_pending_puts(tokenB);
        const currentCursor = __sql_cursor_start(tokenB, "SELECT value FROM fenced", "[]").cursorId;
        throws(() => __sql_cursor_next(oldCursor, tokenB), "another activation");
        __sql_cursor_close(oldCursor, tokenA);
        __sql_cursor_close(currentCursor, tokenA);
        check(Array.isArray(__sql_cursor_next(currentCursor, tokenB)), "current cursor was damaged");
        __sql_cursor_close(currentCursor, tokenB);
        __storage_transaction_control(tokenB, "start", false, "current");
        __storage_queue_put(tokenB, "committed", 8);
        __storage_transaction_control(tokenB, "commit", false, "current");
        __storage_queue_put(tokenB, "cancelled", 9);
        __storage_cancel_pending_puts(tokenB);
        __storage_flush_pending_puts(tokenB);
    "#
    );
    assert!(storage::get_stored(&actor, "successor").unwrap().is_some());
    assert!(storage::get_stored(&actor, "committed").unwrap().is_some());
    assert!(storage::get_stored(&actor, "cancelled").unwrap().is_none());
    assert!(storage::get_stored(&actor, "poison").unwrap().is_none());
    assert!(storage::get_stored(&actor, "abandoned").unwrap().is_none());
    assert!(runtime.pending_puts.lock().unwrap().is_empty());

    let _ambient = CurrentGuard::enter(replacement.clone());
    let retired = IoContext::tracked(&runtime);
    retired.bind_native_activation(&runtime, &actor);
    retired.egress.lock().unwrap().push(EgressFrame {
        storage: actor.clone(),
        before: 0,
        epoch: Some(13),
        root: None,
    });
    install_io_context(scope, &retired);
    drop(retired);
    assert!(current_reaction_io_context(scope).is_none());
    evaluate!(
        r#"
        throws(() => __container_bind(actor), "continuation is retired");
        check(__container_bind(actor, true) === undefined, "retired continuation borrowed ambient binding");
        throws(() => __container_start_allocation(tokenB, "{}"), "continuation is retired");
        throws(() => __container_inspect_allocation(tokenB, "a"), "continuation is retired");
        throws(() => __container_destroy_allocation(tokenB, "a"), "continuation is retired");
        throws(() => __storage_queue_put(tokenB, "dead", 1), "continuation is retired");
        throws(() => __fetch("GET", "http://127.0.0.1:1/dead", null, "[]", "manual"), "continuation is retired");
    "#
    );
    storage::close(&actor);
}

#[test]
fn native_effect_retired_transaction_rolls_back_before_successor_access() {
    crate::native_ws::native_ws_tests::init_host();
    Engine::init();
    let runtime = Arc::new(ActorRuntimeState::default());
    let actor = format!("retired-transaction-{}", crate::ws_registry::ws_next_id());
    let cells = storage::Cells::default();
    let _storage = cells.install();
    storage::open(&actor, ":memory:").unwrap();
    runtime.native_activations.replace(&actor, true);
    let event = IoContext::tracked(&runtime);
    event.bind_native_activation(&runtime, &actor);
    event.egress.lock().unwrap().push(EgressFrame {
        storage: actor.clone(),
        before: 0,
        epoch: Some(1),
        root: None,
    });
    let old = event.native_upgrades();
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
            scope
                .get_current_context()
                .global(scope)
                .set(scope, name.into(), function.into());
        }};
    }
    install!("__container_bind", op_container_bind);
    install!("__storage_put", storage_ops::op_storage_put);
    install!(
        "__storage_transaction_control",
        storage_ops::op_storage_transaction_control
    );
    install!("__ws_native_generation", websocket::op_ws_native_generation);
    install!(
        "__ws_reset_native_actor",
        websocket::op_ws_reset_native_actor
    );
    install!("__io_context_id", op_io_context_id);
    install!("__with_input_gate_context", op_with_input_gate_context);
    macro_rules! evaluate {
        ($source:expr) => {{
            let source = v8::String::new(scope, $source).unwrap();
            v8::Script::compile(scope, source, None)
                .and_then(|script| script.run(scope))
                .unwrap_or_else(|| {
                    panic!(
                        "transaction fixture failed: {:?}",
                        scope.exception().map(|e| e.to_rust_string_lossy(scope))
                    )
                })
        }};
    }
    let harness = include_str!("harness.js");
    let storage_source = &harness[harness.find("const __storageReceivers =").unwrap()
        ..harness.find("class DurableObjectId {").unwrap()];
    let state_source = &harness[harness.find("const __nativeActorStates =").unwrap()
        ..harness.find("function _instance(scope)").unwrap()];
    evaluate!(&format!(
        r#"
        const actor = {actor:?};
        const __cell = {{ instances: {{}}, facetConfigs: {{}}, containers: {{}}, idNames: {{}} }};
        const __celld = {{}};
        const __currentActorScope = () => actor;
        const __retireNativeGeneration = () => {{}};
        const __describeFailure = String;
        class DurableObjectFacets {{}}
        class DurableObjectId {{}}
        function check(value, message) {{ if (!value) throw new Error(message); }}
        {storage_source}
        {state_source}
        const oldState = new DurableObjectState(actor);
        let caughtFailure = false;
        try {{
          oldState._runConcurrencyBlock(() => oldState.storage.transactionSync(() => {{
            oldState.storage.kv.put("old-write", 1);
            oldState.blockConcurrencyWhile(() => {{ throw new Error("nested failure"); }});
          }}));
        }} catch (error) {{ caughtFailure = String(error).includes("nested failure"); }}
        check(caughtFailure && oldState._aborted, "nested failure did not reset the actor");
    "#
    ));
    assert!(!old.generation().is_live());
    assert!(runtime
        .storage_transactions
        .lock()
        .unwrap()
        .contains_key(&actor));
    assert!(storage::get_stored(&actor, "old-write").unwrap().is_some());
    let successor = IoContext::tracked(&runtime);
    successor.bind_native_activation(&runtime, &actor);
    successor.egress.lock().unwrap().push(EgressFrame {
        storage: actor.clone(),
        before: 0,
        epoch: Some(1),
        root: None,
    });
    // this is the same trusted pre-entry cleanup start_cell_event performs.
    runtime
        .native_activations
        .admit(&actor, &successor.native_upgrades(), || {
            storage_ops::retire_storage_generations(
                &runtime,
                &actor,
                Some(&successor.native_upgrades()),
            )
        })
        .unwrap()
        .unwrap();
    assert!(storage::get_stored(&actor, "old-write").unwrap().is_none());
    let _successor = CurrentGuard::enter(successor.clone());
    install_io_context(scope, &successor);
    evaluate!(
        r#"
        const fresh = new DurableObjectState(actor);
        fresh.storage.transactionSync(() => fresh.storage.kv.put("fresh-write", 2));
        const token = __container_bind(actor);
        __storage_transaction_control(token, "start", false, "current");
        fresh.storage.kv.put("successor-open", 3);
        let staleRefused = false;
        try { oldState.storage._transactionRollback("old"); } catch { staleRefused = true; }
        check(staleRefused, "stale rollback was authorised");
    "#
    );
    storage_ops::retire_storage_transaction(&runtime, &actor, &old).unwrap();
    evaluate!(r#"__storage_transaction_control(token, "commit", false, "current");"#);
    assert!(storage::get_stored(&actor, "old-write").unwrap().is_none());
    assert!(storage::get_stored(&actor, "fresh-write")
        .unwrap()
        .is_some());
    assert!(storage::get_stored(&actor, "successor-open")
        .unwrap()
        .is_some());
    assert!(!runtime
        .storage_transactions
        .lock()
        .unwrap()
        .contains_key(&actor));
    evaluate!(r#"__storage_transaction_control(token, "start", false, "missing");"#);
    let current = successor.native_upgrades();
    assert!(runtime.reset_actor_generation(&actor, current.generation().key()));
    storage::close(&actor);
    assert!(storage_ops::retire_storage_transaction(&runtime, &actor, &current).is_err());
    assert!(runtime
        .storage_transactions
        .lock()
        .unwrap()
        .contains_key(&actor));
    assert!(storage::activation_epoch(&actor).is_none());
    assert!(storage::sql_critical_error(&actor)
        .unwrap()
        .contains("cleanup failed"));
    storage::close(&actor);
}

#[test]
fn native_allocation_javascript_shapes_and_unsupported_legacy_calls_are_observable() {
    crate::native_ws::native_ws_tests::init_host();
    Engine::init();
    let mut isolate = v8::Isolate::new(Default::default());
    v8::scope!(let scope, &mut isolate);
    let realm = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, realm);
    let caught = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut caught.init();
    macro_rules! evaluate {
        ($source:expr) => {{
            let source = v8::String::new(scope, $source).unwrap();
            v8::Script::compile(scope, source, None)
                .and_then(|script| script.run(scope))
                .unwrap_or_else(|| {
                    panic!(
                        "allocation facade javascript failed: {:?}",
                        scope
                            .exception()
                            .map(|error| error.to_rust_string_lossy(scope))
                    )
                })
        }};
    }
    let harness = include_str!("harness.js");
    let begin = harness.find("const __containerEnvList =").unwrap();
    let end = harness.find("const __nativeActorStates =").unwrap();
    evaluate!(&format!(
        r#"
        let calls = 0;
        const __container_bind = () => "host-token";
        const __container_running = () => true;
        const __container_start_allocation = () => {{ calls++; return Promise.resolve('{{"status":"running"}}'); }};
        const __container_destroy = () => {{ throw new Error("legacy operation is unavailable"); }};
        const __container_signal = () => {{ throw new Error("legacy operation is unavailable"); }};
        {}
        const owner = new Container("actor");
        const options = {{ id: "a", image: "celld-image:" + "a".repeat(64), engineImage: "sha256:" + "1".repeat(64), platform: "linux/amd64" }};
        const errors = [];
        for (const env of ["bad", 1, null, [], new Map(), {{ TOKEN: 1 }}])
          owner.startAllocation({{ ...options, env }}).catch(error => errors.push(String(error)));
        for (const entrypoint of ["serve", 1, null, [1], [undefined]])
          owner.startAllocation({{ ...options, entrypoint }}).catch(error => errors.push(String(error)));
        owner.destroy().catch(error => errors.push(String(error)));
        let signalError;
        try {{ owner.signal(9); }} catch (error) {{ signalError = String(error); }}
    "#,
        &harness[begin..end]
    ));
    scope.perform_microtask_checkpoint();
    evaluate!(
        r#"
        if (calls !== 0 || errors.length !== 12 || !signalError.includes("legacy operation is unavailable"))
          throw new Error("invalid inputs or unsupported legacy operation escaped refusal");
        if (!errors.every(error => /env|entrypoint|legacy operation/.test(error))) throw new Error("wrong refusal");
        owner.startAllocation({ ...options, env: { TOKEN: "value" }, entrypoint: ["serve"] });
    "#
    );
    scope.perform_microtask_checkpoint();
    evaluate!(r#"if (calls !== 1) throw new Error("valid options did not reach boundary");"#);
}
