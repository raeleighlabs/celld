// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! WebSockets inside the isolate: the registry, the ops JS calls, and the
//! frames waiting to leave.
//!
//! A socket outlives the event that created it, so the registry is what
//! connects the two — JS holds an id, and this module knows what that id
//! is attached to. Frames emitted inside an output-gate region are held
//! until the gate opens, which is why emitting is not simply a send.
use super::*;
pub use crate::ws_registry::*;

#[derive(Default)]
pub(super) struct WsCapture {
    frames: WsBatch,
    /// The handler whose outcome authorizes an incremental flush. This is
    /// installed after the synchronous dispatch returns its promise; until
    /// then no turn-end flush can run.
    promise: Option<v8::Global<v8::Promise>>,
}

fn prepare_worker_websocket_handoff(id: u64) {
    let (inbound, receiver) = ws_pull_channel();
    ws_pull_register(id, receiver);
    ws_register_outbound(id, "", None);
    ws_track_request_socket(id);
    let registry = ws_registry();
    let replaced = registry.lock().unwrap().worker_handoffs.insert(id, inbound);
    drop(replaced);
}

pub(super) fn transfer_worker_websocket_handoff(id: u64) -> Option<WorkerWebSocket> {
    let inbound = ws_registry().lock().unwrap().worker_handoffs.remove(&id)?;
    // The response now owns cleanup. Transfer the frame channel and request
    // ownership together so request retirement cannot close a returned socket.
    current_context()
        .sockets
        .lock()
        .unwrap()
        .retain(|opened| *opened != id);
    Some(WorkerWebSocket { id, inbound })
}

/// Close every isolate-polled socket a finished request opened.
///
/// The close frame is what actually ends the connection: the connector task
/// writes it to the wire and stops pumping, and only then does it drop the
/// `WsPull` sender that this socket's `__ws_next` is waiting on. Unregistering
/// first would strand the task instead — it detects a dead isolate by the
/// send failing, and nothing else tells it to go.
pub(super) fn ws_close_request_sockets(opened: Vec<u64>) {
    for id in opened {
        let registry = ws_registry();
        let handoff = registry.lock().unwrap().worker_handoffs.remove(&id);
        drop(handoff);
        // A socket whose remote already hung up has no output sender left,
        // and that is the ordinary case rather than an error. `ws_emit` logs
        // a dropped frame for an unknown id, so ask before sending.
        let open = ws_registry().lock().unwrap().outputs.contains_key(&id);
        if open {
            // The event's own end, run by its turn: the owner is the context.
            ws_emit(
                &current_context(),
                id,
                WsOut::Close(1001, "request ended".into()),
            );
        }
        ws_pull_unregister(id);
        ws_unregister(id);
    }
}

/// Account a Worker socket to the request that opened it.
fn ws_track_request_socket(id: u64) {
    current_context().sockets.lock().unwrap().push(id);
}

pub(super) fn ws_capture_begin() {
    current_context()
        .ws_capture
        .lock()
        .unwrap()
        .push(WsCapture::default());
}

pub(super) fn ws_capture_set_promise(context: &IoContext, promise: v8::Global<v8::Promise>) {
    context
        .ws_capture
        .lock()
        .unwrap()
        .last_mut()
        .expect("a WebSocket handler has an active capture")
        .promise = Some(promise);
}

pub(super) fn ws_capture_take() -> WsBatch {
    current_context()
        .ws_capture
        .lock()
        .unwrap()
        .pop()
        .unwrap_or_default()
        .frames
}

pub(super) fn ws_capture_discard(context: &IoContext) {
    if let Some(capture) = context.ws_capture.lock().unwrap().pop() {
        capture.frames.discard();
    }
}

/// Release what a running `webSocketMessage` handler has sent so far.
///
/// Called at the end of every turn, so a handler that suspends delivers the
/// frames it has already sent instead of holding them until it returns. An
/// AI chat agent streams its answer through this path: it sends a chunk, it
/// awaits the next one, and a client that receives the whole answer in one
/// burst at the end has lost the streaming the application was written for
/// (denoland/celld#229).
///
/// One ticket covers the turn rather than one for each frame, because a
/// broadcast sends the same chunk to every client in one turn and a ticket
/// for each of them would cost a core round trip for each of them.
///
/// The capture stays in place, so the frames of a later turn are held and
/// released the same way. A handler that never suspends captures its frames
/// in one turn and answers in it, so `ws_capture_take` finds them first and
/// this releases nothing: that handler still leaves through the cell's
/// barrier queue, exactly as before.
fn ws_capture_flush(tc: &mut v8::PinScope, context: &IoContext) {
    let frames = {
        let mut capture = context.ws_capture.lock().unwrap();
        let Some(pending) = capture.last() else {
            return;
        };
        let Some(promise) = pending.promise.as_ref() else {
            return;
        };
        match v8::Local::new(tc, promise).state() {
            v8::PromiseState::Pending => {}
            // The event's own settlement takes a fulfilled capture with its
            // dispatch. Flushing it here would split the established batch.
            v8::PromiseState::Fulfilled => return,
            // A foreign handler can reject wholly inside this turn's
            // checkpoint, before its own driver gets a turn in which to run
            // `settle`. Drop its frames now instead of publishing output
            // from a failed dispatch.
            v8::PromiseState::Rejected => {
                std::mem::take(&mut capture.last_mut().unwrap().frames).discard();
                return;
            }
        }
        let pending = capture.last_mut().unwrap();
        if pending.frames.is_empty() {
            return;
        }
        std::mem::take(&mut pending.frames)
    };
    // Every captured frame belongs to a hibernatable socket, because that is
    // what `ws_emit` captures, so one channel names the whole batch.
    let gate = egress_gate_request(context, celld_logic::Channel::WsHibernatable);
    // On the HOST runtime, for the reason `ws_emit` spawns there: this flush
    // must outlive the turn that produced the frames, and the ticket it waits
    // for resolves with no isolate involvement.
    asyncrt::op_handle().spawn(async move {
        let held = await_egress_gate(gate).await;
        frames.release(held);
    });
}

/// Flush every capture that received a frame during this isolate turn.
///
/// Weak references make this list bookkeeping rather than event ownership.
/// A context that retires before the turn ends therefore disappears instead
/// of being kept alive only to flush output that its dispatch cannot return.
pub(super) fn ws_capture_flush_touched(tc: &mut v8::PinScope, runtime_state: &ActorRuntimeState) {
    let touched = std::mem::take(&mut *runtime_state.ws_capture_touched.lock().unwrap());
    for context in touched.into_iter().filter_map(|context| context.upgrade()) {
        ws_capture_flush(tc, &context);
    }
}

/// Send or hold one frame. `context` is the event the sending JavaScript
/// belongs to: the continuation's own for a V8 entry point, so a reaction of
/// cell A that runs inside another event's checkpoint is captured by and
/// gated against A, not the checkpoint's owner.
fn ws_emit(context: &Arc<IoContext>, id: u64, out: WsOut) {
    let mut capture = context.ws_capture.lock().unwrap();
    if !capture.is_empty() && ws_channel(id) == celld_logic::Channel::WsHibernatable {
        capture.last_mut().unwrap().frames.capture(id, out);
        let runtime_state = context
            .continuation
            .as_ref()
            .and_then(|(_, runtime_state)| runtime_state.upgrade())
            .expect("a WebSocket capture belongs to a live tracked context");
        let mut touched = runtime_state.ws_capture_touched.lock().unwrap();
        if !touched.iter().any(|candidate| {
            candidate
                .upgrade()
                .is_some_and(|candidate| Arc::ptr_eq(&candidate, context))
        }) {
            touched.push(Arc::downgrade(context));
        }
        return;
    }
    drop(capture);
    // A socket the isolate opened itself, which the capture above deliberately
    // will not hold: releasing captured frames waits for the handler to
    // return, and this handler may be awaiting a reply to the very frame being
    // held. Waiting on the DURABILITY ticket instead has no such cycle -- it
    // is resolved by the replicator, which does not need this event loop -- so
    // the frame can be held without deadlocking the script that sent it.
    let gate = egress_gate_request(context, ws_channel(id));
    // Resolved here, on the thread the frame was sent from; the registry is
    // moved into the flush below. The flush runs on a runtime that has no
    // services of its own, so a lookup inside it would answer with whichever
    // instance that runtime reaches — the socket's frames and the socket's
    // registry could then come from two different instances.
    let flush = ws_flush_state();
    let registry = ws_registry();
    // Gated for a read-only frame as well, and deliberately: the frame reveals
    // what the cell holds, so it has to ask the core whether a barrier is open
    // rather than assume its own event opened one. A cell with nothing
    // outstanding answers at once and the queue flushes on the same tick.
    let Some(flushing) =
        flush.emit_or_defer(&registry, std::iter::once((id, out)), gate.is_gated())
    else {
        return;
    };
    // Detached onto the HOST runtime (`op_handle`) deliberately: this flush
    // exists precisely to outlive the dispatch that produced the frames — a
    // writing connect handler's ready frame, an alarm broadcast — and it
    // awaits a durability ticket that resolves with no isolate involvement.
    // Both region-owned homes silently kill it: `asyncrt::enqueue`'s future is
    // aborted when the dispatch region closes, and the isolate thread's local
    // request driver stops polling its operation future the moment the
    // dispatch returns. Either way the frames never left the process.
    asyncrt::op_handle().spawn(async move {
        let held = await_egress_gate(gate).await;
        flushing.release(&registry, held);
    });
}

pub(super) fn op_ws_send(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let data = args.get(1).to_rust_string_lossy(scope);
    ws_emit(&event_context(scope), id, WsOut::Text(data));
}
pub(super) fn op_ws_send_binary(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let data = view_bytes(args.get(1)).unwrap_or_default();
    ws_emit(&event_context(scope), id, WsOut::Binary(data));
}
pub(super) fn op_ws_close(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let code = args.get(1).uint32_value(scope).unwrap_or(1000) as u16;
    let reason = args.get(2).to_rust_string_lossy(scope);
    ws_emit(&event_context(scope), id, WsOut::Close(code, reason));
}
pub(super) fn op_ws_alloc(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    rv.set(v8::Number::new(scope, ws_next_id() as f64).into());
}

pub(super) fn op_ws_prepare_worker_handoff(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    prepare_worker_websocket_handoff(id);
}
/// The facet record of an outbound socket that `cell` opens, when the running
/// event belongs to a Durable Object facet.
///
/// A facet is not a cell. A socket that names the facet's scope as its cell
/// starts an activation of a class that no Worker exports, so the upgrade
/// fails with `RuntimeFailed`. The socket must route, register, and gate
/// through the facet's root instead. The record comes from the frame that
/// the host installed when the event started, not from `cell`, because the
/// scope crosses application JavaScript.
fn dialing_facet(scope: &mut v8::PinScope, cell: &str) -> Result<Option<FacetSocket>, String> {
    if cell.is_empty() {
        return Ok(None);
    }
    let Some(EgressFrame {
        storage,
        root: Some(root),
        ..
    }) = current_cell_event(&event_context(scope))
    else {
        return Ok(None);
    };
    if storage != cell {
        return Err(format!(
            "websocket: the socket names {cell}, but the running Durable Object facet is {storage}"
        ));
    }
    let opening = storage::facet_opening(&storage).ok_or(
        "websocket: the Durable Object facet that opened this socket is no longer running",
    )?;
    Ok(Some(FacetSocket {
        root: root.cell,
        stream: root.stream,
        epoch: root.epoch,
        opening,
    }))
}

/// `fetch(url, { headers: { Upgrade: "websocket" } })`. Returns a JSON
/// envelope: either an upgraded socket, or the ordinary response a server sent
/// instead, which the caller returns unchanged.
pub(super) fn op_ws_upgrade(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    match &actor_runtime_state(scope).egress {
        EgressPolicy::Allow => {}
        EgressPolicy::Deny => {
            return loader_throw(
                scope,
                "This worker is not permitted to access the internet via global functions.",
            );
        }
        EgressPolicy::Broker(_) => {
            return loader_throw(
                scope,
                "A globalOutbound Fetcher cannot broker WebSockets in celld.",
            );
        }
    }
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let context = event_context(scope);
    let cell = current_cell_event(&context)
        .map(|event| event.storage)
        .unwrap_or_default();
    let facet = match dialing_facet(scope, &cell) {
        Ok(facet) => facet,
        Err(error) => return loader_throw(scope, &error),
    };
    let url = args.get(2).to_rust_string_lossy(scope);
    // The subprotocol list is read back out of these headers, so a silent
    // default opened the socket with no headers and no subprotocol at all.
    let headers: Vec<(String, String)> =
        match serde_json::from_str(&args.get(3).to_rust_string_lossy(scope)) {
            Ok(headers) => headers,
            Err(error) => {
                return loader_throw(
                    scope,
                    &format!("websocket: the upgrade headers are not a name/value list: {error}"),
                )
            }
        };
    let protocols: Vec<String> = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .map(|(_, value)| value.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();
    let reservation = match context.native_upgrades().reserve(id) {
        Ok(reservation) => reservation,
        Err(error) => return loader_throw(scope, &error.to_string()),
    };
    let cancel = Some(reservation.cancel.clone());
    let owner_cancel = context
        .native_actor_upgrades
        .get()
        .map(|owner| owner.generation());
    let (tx, rx) = tokio::sync::oneshot::channel();
    let sent = outbound_ws_tx().is_some_and(|sender| {
        sender
            .send(OutboundWsReq {
                scope: cell,
                id,
                url,
                protocols,
                pull: None,
                headers,
                want_response: true,
                connection: None,
                cancel,
                owner_cancel,
                native_closed: None,
                registration: None,
                target: None,
                facet,
                reply: tx,
            })
            .is_ok()
    });
    let async_id = asyncrt::enqueue(async move {
        if !sent {
            return Err("no outbound WebSocket channel".into());
        }
        let open = match rx.await {
            Ok(Ok(open)) => open,
            Ok(Err(error)) => return Err(format!("WebSocket upgrade failed: {error}")),
            Err(error) => return Err(format!("WebSocket connector dropped: {error}")),
        };
        Ok(match open.declined {
            Some(declined) => serde_json::json!({
                "upgraded": false,
                "status": declined.status,
                "headers": declined.headers,
                "body": declined.body,
            })
            .to_string(),
            None => {
                let connection = open.connection.ok_or("upgrade has no native transport")?;
                reservation
                    .complete(connection)
                    .map_err(|error| error.to_string())?;
                serde_json::json!({
                    "upgraded": true,
                    "protocol": open.protocol.unwrap_or_default(),
                })
                .to_string()
            }
        })
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_ws_release_native(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args.get(0).integer_value(scope).unwrap_or(0).max(0) as u64;
    event_context(scope).native_upgrades().remove(id);
}

pub(super) fn op_ws_native_generation(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let table = event_context(scope).native_upgrades();
    let runtime = actor_runtime_state(scope);
    if !table.generation().is_live()
        || (!cell.is_empty() && !runtime.native_activations.authorises(&cell, &table))
    {
        // constructing an http-only actor need not acquire native resources.
        // an actual websocket operation always requires the strict claim.
        if args.get(1).is_true() {
            return;
        }
        return loader_throw(
            scope,
            "native WebSocket actor generation is not owned by this event",
        );
    }
    rv.set(
        v8::String::new(scope, table.generation().key())
            .unwrap()
            .into(),
    );
}

pub(super) fn op_ws_native_generation_live(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let key = args.get(1).to_rust_string_lossy(scope);
    let live = if cell.is_empty() {
        let owner = event_context(scope).native_upgrades().generation();
        owner.is_live() && owner.key() == key
    } else {
        actor_runtime_state(scope)
            .native_activations
            .matches(&cell, &key)
    };
    rv.set_bool(live);
}

pub(super) fn op_ws_reset_native_actor(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let key = args.get(1).to_rust_string_lossy(scope);
    rv.set_bool(actor_runtime_state(scope).reset_actor_generation(&cell, &key));
}

pub(super) fn op_ws_track_native(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let id = args.get(0).integer_value(scope).unwrap_or(0).max(0) as u64;
    let cleanup = match event_context(scope).native_upgrades().cleanup(id) {
        Ok(cleanup) => cleanup,
        Err(error) => return loader_throw(scope, &error.to_string()),
    };
    // only cleanup crosses a gc turn. this opaque capability cannot consume
    // or transfer a socket and is local to the issuing isolate.
    let runtime = actor_runtime_state(scope);
    let token = {
        let mut handles = runtime.native_cleanup.lock().unwrap();
        let mut rng = asyncrt::rng("native-ws-cleanup");
        let token = loop {
            let token = format!(
                "{:016x}{:016x}",
                rand::RngCore::next_u64(&mut rng),
                rand::RngCore::next_u64(&mut rng)
            );
            if !handles.contains_key(&token) {
                break token;
            }
        };
        handles.insert(token.clone(), cleanup);
        token
    };
    rv.set(v8::String::new(scope, &token).unwrap().into());
}

pub(super) fn op_ws_drop_native_handle(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let token = args.get(0).to_rust_string_lossy(scope);
    let removed = actor_runtime_state(scope)
        .native_cleanup
        .lock()
        .unwrap()
        .remove(&token);
    drop(removed);
}

pub(super) fn op_ws_consume_native(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let id = args.get(0).integer_value(scope).unwrap_or(0).max(0) as u64;
    let context = event_context(scope);
    let cell = current_cell_event(&context)
        .map(|event| event.storage)
        .unwrap_or_default();
    let facet = match dialing_facet(scope, &cell) {
        Ok(facet) => facet,
        Err(error) => return loader_throw(scope, &error),
    };
    let connection = match context.native_upgrades().take(id) {
        Ok(connection) => connection,
        Err(error) => return loader_throw(scope, &error.to_string()),
    };
    if connection.lease.revocation().is_cancelled() {
        return loader_throw(scope, "WebSocket owner activation ended");
    }
    let protocols = connection
        .connection
        .headers
        .get(hyper::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default();
    let cancel = tokio_util::sync::CancellationToken::new();
    let pull = if cell.is_empty() {
        let (sender, receiver) = ws_pull_channel();
        ws_pull_register(id, receiver);
        context.sockets.lock().unwrap().push(id);
        context
            .native_socket_cancels
            .lock()
            .unwrap()
            .push(cancel.clone());
        Some(sender)
    } else {
        None
    };
    let origin_cell = facet
        .as_ref()
        .map_or(cell.as_str(), |facet| facet.root.as_str());
    let consumer_owner = context.native_upgrades().generation();
    let origin_owned = connection.lease.owns(origin_cell, &consumer_owner);
    let admission_id = connection.lease.admission_id();
    // accept is synchronous, so sends immediately after it must have a queue
    // even before the existing outbound task resumes this transport.
    ws_register_outbound(id, &cell, facet.clone());
    if origin_owned {
        ws_link_native_admission(id, admission_id);
    }
    let (closed, closed_rx) = tokio::sync::oneshot::channel();
    let (reply, receive) = tokio::sync::oneshot::channel();
    let sent = outbound_ws_tx().is_some_and(|sender| {
        sender
            .send(OutboundWsReq {
                scope: cell,
                id,
                url: String::new(),
                protocols,
                pull,
                headers: Vec::new(),
                want_response: false,
                connection: Some(connection),
                cancel: Some(cancel),
                owner_cancel: Some(consumer_owner.clone()),
                native_closed: Some(closed),
                registration: (admission_id != id).then(|| WsRegistrationGuard::new(id)),
                target: None,
                facet,
                reply,
            })
            .is_ok()
    });
    if !sent {
        ws_pull_unregister(id);
        ws_unregister(id);
        return loader_throw(scope, "no outbound WebSocket channel");
    }
    let async_id = asyncrt::enqueue(async move {
        match receive.await {
            Ok(Ok(_)) => Ok(String::new()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(format!("WebSocket consume cancelled: {error}")),
        }
    });
    // lifecycle notification stays in the consuming continuation. it never
    // routes a new actor event or materialises a replacement incarnation.
    let ended = asyncrt::enqueue_io_context(async move {
        let close = closed_rx.await.unwrap_or_default();
        serde_json::to_string(&close).map_err(|error| error.to_string())
    });
    let opening = promise_for(scope, async_id);
    let ended = promise_for(scope, ended);
    let result = v8::Array::new(scope, 2);
    result.set_index(scope, 0, opening);
    result.set_index(scope, 1, ended);
    rv.set(result.into());
}

/// Await the next inbound event on an isolate-polled socket. Resolves with a
/// tagged buffer; a closed queue resolves as a 1006 close so the JS pump always
/// terminates rather than hanging on a dropped sender.
pub(super) fn op_ws_next(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let queue = ws_pull().lock().unwrap().get(&id).cloned();
    let async_id = asyncrt::enqueue_io_context(async move {
        let Some(queue) = queue else {
            return Ok(WsPull::Close(1006, "socket is not registered".into(), false).encode());
        };
        let mut queue = queue.lock().await;
        Ok(queue
            .recv()
            .await
            .unwrap_or_else(|| WsPull::Close(1006, String::new(), false))
            .encode())
    });
    rv.set(promise_for(scope, async_id));
}

pub(super) fn op_ws_connect(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    match &actor_runtime_state(scope).egress {
        EgressPolicy::Allow => {}
        EgressPolicy::Deny => {
            return loader_throw(
                scope,
                "This worker is not permitted to access the internet via global functions.",
            );
        }
        EgressPolicy::Broker(_) => {
            return loader_throw(
                scope,
                "A globalOutbound Fetcher cannot broker WebSockets in celld.",
            );
        }
    }
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let cell = args.get(1).to_rust_string_lossy(scope);
    let facet = match dialing_facet(scope, &cell) {
        Ok(facet) => facet,
        Err(error) => return loader_throw(scope, &error),
    };
    let url = args.get(2).to_rust_string_lossy(scope);
    let protocols: Vec<String> =
        match serde_json::from_str(&args.get(3).to_rust_string_lossy(scope)) {
            Ok(protocols) => protocols,
            Err(error) => {
                return loader_throw(
                    scope,
                    &format!("websocket: the subprotocol list is not a JSON array: {error}"),
                )
            }
        };
    // No cell means a Worker socket: the isolate polls it, so register the
    // queue here on the JS thread and track it against the running request.
    let pull = cell.is_empty().then(|| {
        let (pull_tx, pull_rx) = ws_pull_channel();
        ws_pull_register(id, pull_rx);
        ws_track_request_socket(id);
        pull_tx
    });
    let (tx, rx) = tokio::sync::oneshot::channel();
    let sent = outbound_ws_tx().is_some_and(|sender| {
        sender
            .send(OutboundWsReq {
                scope: cell,
                id,
                url,
                protocols,
                pull,
                headers: Vec::new(),
                want_response: false,
                connection: None,
                cancel: None,
                owner_cancel: None,
                native_closed: None,
                registration: None,
                target: None,
                facet,
                reply: tx,
            })
            .is_ok()
    });
    let async_id = asyncrt::enqueue(async move {
        if !sent {
            return Err("no outbound WebSocket channel".into());
        }
        match rx.await {
            Ok(Ok(open)) => Ok(open.protocol.unwrap_or_default()),
            Ok(Err(error)) => Err(format!("WebSocket connection failed: {error}")),
            Err(error) => Err(format!("WebSocket connector dropped: {error}")),
        }
    });
    rv.set(promise_for(scope, async_id));
}

/// Join this isolate's client socket to a Durable Object socket that a
/// subrequest already upgraded. The cell end lives in another isolate, so
/// the host carries each direction: it is the same route an external client
/// takes, with a pull queue in place of a TCP connection.
///
/// Called from `accept()`, never from the upgrade itself. A Worker that
/// passes the response straight back out never accepts the socket, and the
/// host binds that 101 to the real client instead — binding here as well
/// would give one cell socket two readers.
pub(super) fn op_ws_bind_target(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let Ok(target) = serde_json::from_str::<WsTarget>(&args.get(1).to_rust_string_lossy(scope))
    else {
        return loader_throw(scope, "WebSocket target is not valid");
    };
    // The caller's scope, which is empty for a Worker — the socket is
    // accounted against the isolate holding it, exactly as `op_ws_connect`
    // accounts an outbound one.
    let cell = args.get(2).to_rust_string_lossy(scope);
    // The caller end's frames reach this isolate through its pull queue, so
    // they never route by `cell`. The record still matters: a facet that
    // stops closes its sockets by it, and this end would otherwise keep the
    // other Durable Object's socket open after the facet is gone.
    let facet = match dialing_facet(scope, &cell) {
        Ok(facet) => facet,
        Err(error) => return loader_throw(scope, &error),
    };
    let (pull_tx, pull_rx) = ws_pull_channel();
    ws_pull_register(id, pull_rx);
    if cell.is_empty() {
        ws_track_request_socket(id);
    }
    // Registered here, on the JS thread, so a frame sent between this op and
    // the pipe task buffers as a pending frame instead of being dropped for
    // a socket the registry has never heard of. `accept()` opens the socket
    // synchronously, so that window is reachable by an ordinary `send()`.
    ws_register_outbound(id, &cell, facet);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let sent = outbound_ws_tx().is_some_and(|sender| {
        sender
            .send(OutboundWsReq {
                scope: target.scope.clone(),
                id,
                url: String::new(),
                protocols: Vec::new(),
                pull: Some(pull_tx),
                headers: Vec::new(),
                want_response: false,
                connection: None,
                cancel: None,
                owner_cancel: None,
                native_closed: None,
                registration: None,
                target: Some(target),
                // `scope` names the target, which keeps its own route.
                facet: None,
                reply: tx,
            })
            .is_ok()
    });
    // Nothing observes the outcome: the socket is already open, so there is
    // no handshake for JS to await. The task keeps the reply receiver alive
    // until the connector answers. A bind failure drops the pull sender, so
    // `op_ws_next` reports the caller socket as abnormally closed.
    asyncrt::enqueue(async move {
        if !sent {
            return Err::<String, String>("no outbound WebSocket channel".into());
        }
        match rx.await {
            Ok(Ok(_)) => Ok(String::new()),
            Ok(Err(error)) => Err(format!("WebSocket bind failed: {error}")),
            Err(error) => Err(format!("WebSocket connector dropped: {error}")),
        }
    });
}
pub(super) fn op_ws_accept(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let cell = args.get(1).to_rust_string_lossy(scope);
    // Tags are how `state.getWebSockets(tag)` finds this socket again after a
    // hibernation, so a silent default accepted the socket untagged and the
    // Worker could not address it by tag; only a bare `getWebSockets()` still
    // returned it.
    let tags: Vec<String> = match serde_json::from_str(&args.get(2).to_rust_string_lossy(scope)) {
        Ok(tags) => tags,
        Err(error) => {
            return loader_throw(
                scope,
                &format!("websocket: the tag list is not a JSON array: {error}"),
            )
        }
    };
    let replaced_regular_scope = {
        let registry = ws_registry();
        let mut registry = registry.lock().unwrap();
        let sockets = &mut registry.metadata;
        let replaced_regular_scope = sockets
            .get(&id)
            .filter(|meta| !meta.hibernatable)
            .map(|meta| meta.scope.clone());
        sockets
            .entry(id)
            .and_modify(|meta| {
                meta.scope = cell.clone();
                meta.hibernatable = true;
                meta.tags = tags.clone();
            })
            .or_insert(WsMeta {
                scope: cell.clone(),
                hibernatable: true,
                tags,
                attachment: None,
                pending: Vec::new(),
                auto_response_at: None,
                facet: None,
            });
        replaced_regular_scope
    };
    if let Some(scope) = replaced_regular_scope {
        decrement_regular_ws(&scope);
    }
    tracing::info!(ws_id = id, scope = %cell, "accepted hibernatable WebSocket");
}
pub(super) fn op_ws_accept_regular(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let cell = args.get(1).to_rust_string_lossy(scope);
    let inserted = {
        let registry = ws_registry();
        let mut registry = registry.lock().unwrap();
        let sockets = &mut registry.metadata;
        if let std::collections::hash_map::Entry::Vacant(entry) = sockets.entry(id) {
            entry.insert(WsMeta {
                scope: cell.clone(),
                hibernatable: false,
                tags: Vec::new(),
                attachment: None,
                pending: Vec::new(),
                auto_response_at: None,
                facet: None,
            });
            true
        } else {
            false
        }
    };
    if inserted {
        increment_regular_ws(&cell);
    }
    tracing::info!(ws_id = id, scope = %cell, "accepted regular WebSocket");
}
pub(super) fn op_ws_list(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let tag = args.get(1);
    let tag = if tag.is_undefined() || tag.is_null() {
        None
    } else {
        Some(tag.to_rust_string_lossy(scope))
    };
    let rows = ws_registry()
        .lock()
        .unwrap()
        .metadata
        .iter()
        .filter(|(_, meta)| {
            meta.hibernatable
                && meta.scope == cell
                && tag.as_ref().is_none_or(|tag| meta.tags.contains(tag))
        })
        .map(|(id, meta)| {
            serde_json::json!({
                "id": id,
                "tags": meta.tags,
                "attachment": meta.attachment,
            })
        })
        .collect::<Vec<_>>();
    let json = serde_json::to_string(&rows).unwrap();
    rv.set(v8::String::new(scope, &json).unwrap().into());
}
pub(super) fn op_ws_attachment_set(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let Some(attachment) = view_bytes(args.get(1)) else {
        let message = v8::String::new(scope, "__ws_attachment_set expects bytes").unwrap();
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
        return;
    };
    if let Some(meta) = ws_registry().lock().unwrap().metadata.get_mut(&id) {
        meta.attachment = Some(attachment.to_vec());
    }
}

pub(super) fn op_ws_auto_response_set(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let request = args.get(1);
    if request.is_null() || request.is_undefined() {
        ws_auto_responses().lock().unwrap().remove(&cell);
        return;
    }
    let request = request.to_rust_string_lossy(scope);
    let response = args.get(2).to_rust_string_lossy(scope);
    ws_auto_responses()
        .lock()
        .unwrap()
        .insert(cell, (request, response));
}
pub(super) fn op_ws_auto_response_get(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let cell = args.get(0).to_rust_string_lossy(scope);
    let pair = ws_auto_responses().lock().unwrap().get(&cell).cloned();
    let json = match pair {
        Some((request, response)) => serde_json::to_string(&[request, response]).unwrap(),
        None => "null".to_string(),
    };
    rv.set(v8::String::new(scope, &json).unwrap().into());
}
pub(super) fn op_ws_auto_response_ts(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let id = args
        .get(0)
        .to_integer(scope)
        .map(|n| n.value() as u64)
        .unwrap_or(0);
    let stamped = ws_registry()
        .lock()
        .unwrap()
        .metadata
        .get(&id)
        .and_then(|meta| meta.auto_response_at);
    match stamped {
        Some(ms) => rv.set(v8::Number::new(scope, ms).into()),
        None => rv.set(v8::null(scope).into()),
    }
}
