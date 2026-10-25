// Real socket/V8 integration fixtures use host clocks and Tokio task ownership.
#![allow(clippy::disallowed_methods)]

use super::*;
use fastwebsockets::Role;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

// these adapter tests exercise the shipping execution facade, not the
// separately injected simulation backend. keep its single host alive.
pub(crate) fn init_host() {
    static HOST: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        crate::asyncrt::set_host_handle(runtime.handle().clone());
        runtime
    });
}

#[test]
fn native_effect_admission_holds_existing_activation_lock() {
    let activations = ActivationUpgrades::default();
    let cell = format!(
        "native-effect-admission-{}",
        crate::ws_registry::ws_next_id()
    );
    activations.replace(&cell, true);
    let old = activations.owner(&cell);
    assert_eq!(
        activations
            .admit(&cell, &old, || {
                assert!(activations.owners.try_lock().is_err());
                1
            })
            .unwrap(),
        1
    );
    activations.replace(&cell, true);
    assert!(activations
        .admit(&cell, &old, || panic!("retired action ran"))
        .is_err());
    let current = activations.owner(&cell);
    assert!(activations
        .admit("wrong-scope", &current, || panic!("foreign action ran"))
        .is_err());
    assert_eq!(activations.admit(&cell, &current, || 2).unwrap(), 2);
}

struct Tracked(Arc<AtomicUsize>);
impl Drop for Tracked {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn native_ws_handoff_has_one_owner_across_response_and_request_retirement() {
    let drops = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(PendingUpgrades::default());
    let caller = Arc::new(PendingUpgrades::default());
    source
        .reserve(1)
        .unwrap()
        .complete(Tracked(drops.clone()))
        .unwrap();
    let response = source.take(1).unwrap();
    assert!(source.take(1).is_err());
    source.close();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    caller.reserve(2).unwrap().complete(response).unwrap();
    let transport = caller.take(2).unwrap();
    caller.close();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(transport);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn native_ws_other_request_cannot_claim_or_cancel_transport() {
    let owner = Arc::new(PendingUpgrades::<usize>::default());
    let stranger = Arc::new(PendingUpgrades::<usize>::default());
    let reservation = owner.reserve(42).unwrap();
    let cancel = reservation.cancel.clone();
    reservation.complete(7).unwrap();
    assert!(stranger.take(42).is_err());
    stranger.remove(42);
    stranger.close();
    assert!(!cancel.is_cancelled());
    assert_eq!(owner.take(42).unwrap(), 7);
}

#[test]
fn native_ws_declined_failed_and_cancelled_openings_release_reservations() {
    let owner = Arc::new(PendingUpgrades::<usize>::default());
    let declined = owner.reserve(1).unwrap();
    let cancelled = declined.cancel.clone();
    drop(declined);
    assert!(cancelled.is_cancelled());
    assert!(owner.take(1).is_err());
    let pending = owner.reserve(2).unwrap();
    let cancelled = pending.cancel.clone();
    owner.remove(2);
    assert!(cancelled.is_cancelled());
    assert!(pending.complete(5).is_err());
    assert!(owner.take(2).is_err());
}

#[test]
fn native_ws_retirement_drops_unreturned_response_and_refuses_late_completion() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(PendingUpgrades::default());
    owner
        .reserve(1)
        .unwrap()
        .complete(Tracked(drops.clone()))
        .unwrap();
    let late = owner.reserve(2).unwrap();
    let cancelled = late.cancel.clone();
    owner.close();
    owner.close();
    assert!(cancelled.is_cancelled());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(late.complete(Tracked(drops.clone())).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(owner.reserve(3).is_err());
}

#[test]
fn native_ws_dropped_host_response_releases_transport() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(PendingUpgrades::default());
    owner
        .reserve(1)
        .unwrap()
        .complete(Tracked(drops.clone()))
        .unwrap();
    let response = owner.take(1).unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    sender.send(response).ok().unwrap();
    drop(receiver);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn native_ws_stale_reservation_cannot_replace_or_remove_successor() {
    let owner = Arc::new(PendingUpgrades::default());
    let stale = owner.reserve(1).unwrap();
    assert!(owner.reserve(1).is_err());
    owner.remove(1);
    owner.reserve(1).unwrap().complete(17).unwrap();
    assert!(stale.complete(99).is_err());
    assert_eq!(owner.take(1).unwrap(), 17);
}

#[test]
fn native_ws_fragment_limit_and_utf8_are_checked_before_forwarding() {
    let mut message = Message::default();
    let first = Frame::new(false, OpCode::Text, None, Payload::Owned(vec![0xe2]));
    assert!(message.accept(first).unwrap().is_none());
    let last = Frame::new(
        true,
        OpCode::Continuation,
        None,
        Payload::Owned(vec![0x82, 0xac]),
    );
    let text = message.accept(last).unwrap().unwrap();
    assert_eq!(text.opcode, OpCode::Text);
    assert_eq!(&text.payload[..], "€".as_bytes());

    let mut message = Message::default();
    assert!(message
        .accept(Frame::new(
            false,
            OpCode::Binary,
            None,
            Payload::Owned(vec![0; PASSTHROUGH_MAX_MESSAGE_BYTES])
        ))
        .unwrap()
        .is_none());
    assert!(message
        .accept(Frame::new(
            true,
            OpCode::Continuation,
            None,
            Payload::Owned(vec![1])
        ))
        .is_err());
    assert_eq!(message.bytes.len(), PASSTHROUGH_MAX_MESSAGE_BYTES);

    let mut message = Message::default();
    assert!(message.accept(Frame::text(vec![0xff].into())).is_err());
    let mut message = Message::default();
    assert!(message
        .accept(Frame::new(
            true,
            OpCode::Continuation,
            None,
            Payload::Owned(vec![])
        ))
        .is_err());
}

#[test]
fn native_ws_close_payload_is_preserved_and_reserved_codes_are_rejected() {
    let mut message = Message::default();
    let close = message
        .accept(Frame::close(1000, b"container-done"))
        .unwrap()
        .unwrap();
    assert_eq!(&close.payload[..2], &1000u16.to_be_bytes());
    assert_eq!(&close.payload[2..], b"container-done");
    assert!(message
        .accept(Frame::close(1006, b"not on the wire"))
        .is_err());
    assert!(message.accept(Frame::close_raw(vec![1].into())).is_err());
    assert!(message.accept(Frame::close(1000, &[0xff])).is_err());
    let empty = message
        .accept(Frame::close_raw(Vec::new().into()))
        .unwrap()
        .unwrap();
    assert!(empty.payload.is_empty());
}

fn sockets() -> (
    WebSocket<DuplexStream>,
    WebSocket<DuplexStream>,
    WebSocket<DuplexStream>,
    WebSocket<DuplexStream>,
) {
    let (client, accepted) = tokio::io::duplex(256);
    let (dialled, container) = tokio::io::duplex(256);
    (
        WebSocket::after_handshake(client, Role::Client),
        WebSocket::after_handshake(accepted, Role::Server),
        WebSocket::after_handshake(dialled, Role::Client),
        WebSocket::after_handshake(container, Role::Server),
    )
}

async fn bounded(future: impl std::future::Future<Output = ()>) {
    init_host();
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("test timed out");
}

#[tokio::test]
async fn native_ws_passthrough_preserves_early_frames_text_binary_ping_and_close() {
    bounded(async {
        let (mut client, accepted, dialled, mut container) = sockets();
        // the container greeting arrives before the response is handed off.
        container
            .write_frame(Frame::text(b"container-ready".to_vec().into()))
            .await
            .unwrap();
        let pump = tokio::spawn(passthrough(accepted, dialled));
        let greeting = client.read_frame().await.unwrap();
        assert_eq!(&greeting.payload[..], b"container-ready");
        client
            .write_frame(Frame::text(b"after-return".to_vec().into()))
            .await
            .unwrap();
        let text = container.read_frame().await.unwrap();
        assert_eq!(text.opcode, OpCode::Text);
        assert_eq!(&text.payload[..], b"after-return");
        container
            .write_frame(Frame::binary(vec![0, 1, 127, 255].into()))
            .await
            .unwrap();
        let binary = client.read_frame().await.unwrap();
        assert_eq!(binary.opcode, OpCode::Binary);
        assert_eq!(&binary.payload[..], &[0, 1, 127, 255]);
        client.set_auto_pong(false);
        container.set_auto_pong(false);
        client
            .write_frame(Frame::new(
                true,
                OpCode::Ping,
                None,
                b"probe".to_vec().into(),
            ))
            .await
            .unwrap();
        let ping = container.read_frame().await.unwrap();
        assert_eq!(ping.opcode, OpCode::Ping);
        container
            .write_frame(Frame::pong(ping.payload))
            .await
            .unwrap();
        let pong = client.read_frame().await.unwrap();
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(&pong.payload[..], b"probe");
        container
            .write_frame(Frame::close(1000, b"container-done"))
            .await
            .unwrap();
        let close = client.read_frame().await.unwrap();
        assert_eq!(&close.payload[2..], b"container-done");
        assert_eq!(container.read_frame().await.unwrap().opcode, OpCode::Close);
        pump.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn native_ws_passthrough_client_close_and_fragmented_binary() {
    bounded(async {
        let (mut client, accepted, dialled, mut container) = sockets();
        let pump = tokio::spawn(passthrough(accepted, dialled));
        client
            .write_frame(Frame::new(false, OpCode::Binary, None, vec![0, 255].into()))
            .await
            .unwrap();
        client
            .write_frame(Frame::new(
                true,
                OpCode::Continuation,
                None,
                vec![7, 8].into(),
            ))
            .await
            .unwrap();
        let data = container.read_frame().await.unwrap();
        assert_eq!(data.opcode, OpCode::Binary);
        assert_eq!(&data.payload[..], &[0, 255, 7, 8]);
        client
            .write_frame(Frame::close(1000, b"client-done"))
            .await
            .unwrap();
        let close = container.read_frame().await.unwrap();
        assert_eq!(&close.payload[2..], b"client-done");
        assert_eq!(client.read_frame().await.unwrap().opcode, OpCode::Close);
        pump.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn native_ws_passthrough_uses_client_masking_only_towards_container() {
    bounded(async {
        let (mut client, accepted) = tokio::io::duplex(256);
        let (dialled, mut container) = tokio::io::duplex(256);
        let pump = tokio::spawn(passthrough(
            WebSocket::after_handshake(accepted, Role::Server),
            WebSocket::after_handshake(dialled, Role::Client),
        ));
        // masked client text "x", with a known mask.
        client
            .write_all(&[0x81, 0x81, 1, 2, 3, 4, b'x' ^ 1])
            .await
            .unwrap();
        let mut wire = [0; 7];
        container.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[0], 0x81);
        assert_eq!(wire[1], 0x81);
        assert_eq!(wire[6] ^ wire[2], b'x');
        container.write_all(&[0x82, 1, 255]).await.unwrap();
        let mut wire = [0; 3];
        client.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, [0x82, 1, 255]);
        drop(container);
        assert!(pump.await.unwrap().is_err());
        let mut end = [0; 1];
        assert_eq!(client.read(&mut end).await.unwrap(), 0);
    })
    .await;
}

#[tokio::test]
async fn native_ws_passthrough_backpressure_does_not_block_reverse_traffic() {
    bounded(async {
        let (client, accepted, dialled, mut container) = sockets();
        let pump = tokio::spawn(passthrough(accepted, dialled));
        let (mut client_read, mut client_write) = client.split(tokio::io::split);
        let sending = tokio::spawn(async move {
            for _ in 0..4 {
                client_write
                    .write_frame(Frame::binary(vec![9; 64 * 1024].into()))
                    .await
                    .unwrap();
            }
        });
        // the container is not reading. the other direction must still work.
        container
            .write_frame(Frame::text(b"reverse".to_vec().into()))
            .await
            .unwrap();
        let frame = client_read
            .read_frame(&mut |_| async { Ok::<(), std::io::Error>(()) })
            .await
            .unwrap();
        assert_eq!(&frame.payload[..], b"reverse");
        assert!(!sending.is_finished());
        for _ in 0..4 {
            let frame = container.read_frame().await.unwrap();
            assert_eq!(frame.payload.len(), 64 * 1024);
        }
        sending.await.unwrap();
        pump.abort();
        assert!(pump.await.unwrap_err().is_cancelled());
    })
    .await;
}

#[test]
fn native_ws_cleanup_claim_is_bound_to_owner_and_reservation_generation() {
    let owner = Arc::new(PendingUpgrades::default());
    let foreign = Arc::new(PendingUpgrades::<Tracked>::default());
    let drops = Arc::new(AtomicUsize::new(0));
    let id = crate::ws_registry::ws_next_id();
    owner
        .reserve(id)
        .unwrap()
        .complete(Tracked(drops.clone()))
        .unwrap();
    let cleanup = owner.cleanup(id).unwrap();
    assert!(foreign.cleanup(id).is_err());
    let transferred = owner.take(id).unwrap();
    owner
        .reserve(id)
        .unwrap()
        .complete(Tracked(drops.clone()))
        .unwrap();
    drop(cleanup);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let abandoned = owner.cleanup(id).unwrap();
    drop(abandoned);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(owner.take(id).is_err());
    drop(transferred);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

fn admission_app() -> (
    crate::actor::AppHandle,
    tokio::sync::mpsc::UnboundedReceiver<crate::actor::Message>,
) {
    let (tx, receiver) = tokio::sync::mpsc::unbounded_channel();
    let (websockets, _) = tokio::sync::mpsc::unbounded_channel();
    let (reload, _) = crate::generation::reload_channel();
    let app = crate::actor::AppHandle {
        tx,
        runtime: None,
        reload,
        #[cfg(celld_internal_tests)]
        scripted_activity_host: None,
        peer_http: reqwest::Client::new(),
        peer_auth: Arc::new(crate::peer_auth::PeerAuth::new([1; 32], "native-ws-test").unwrap()),
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
    };
    (app, receiver)
}

async fn admitted_connection(connection: Connection) -> NativeUpgrade {
    let (app, _) = admission_app();
    let id = crate::ws_registry::ws_next_id();
    NativeUpgrade {
        connection,
        lease: NativeLease::admit(&app, id, "", None, NativeOwner::default())
            .await
            .unwrap(),
    }
}

async fn route_admission(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<crate::actor::Message>,
) -> tokio::sync::oneshot::Sender<bool> {
    use crate::actor::{Message, Routed};
    match receiver.recv().await.unwrap() {
        Message::Request { request, reply, .. } => {
            reply
                .send(Ok(Routed {
                    request,
                    route: celld_logic::Route::Local,
                }))
                .ok()
                .unwrap();
        }
        _ => panic!("native admission did not route through the actor"),
    }
    match receiver.recv().await.unwrap() {
        Message::WebSocketOpened { kind, reply, .. } => {
            assert_eq!(kind, celld_logic::WebSocketKind::Outbound);
            reply
        }
        _ => panic!("native admission bypassed websocket_opened"),
    }
}

async fn expect_core_release(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<crate::actor::Message>,
    id: u64,
) {
    loop {
        match receiver.recv().await.unwrap() {
            crate::actor::Message::WebSocketClosed { websocket, .. } => {
                assert_eq!(websocket, id);
                return;
            }
            crate::actor::Message::ActivityFinished { .. } => {}
            _ => panic!("unexpected admission lifecycle message"),
        }
    }
}

#[tokio::test]
async fn native_ws_roundtrip_to_same_activation_reuses_physical_admission() {
    bounded(async {
        let (connection, _server) = connection_pair().await;
        let (app, mut receiver) = admission_app();
        let a = Arc::new(PendingUpgrades::default());
        let owner = a.generation();
        let id = crate::ws_registry::ws_next_id();
        let cell = format!("native-roundtrip-{id}");
        let opening_app = app.clone();
        let opening_owner = owner.clone();
        let opening_cell = cell.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&opening_app, id, &opening_cell, None, opening_owner).await
        });
        route_admission(&mut receiver).await.send(true).unwrap();
        let lease = opening.await.unwrap().unwrap();
        let streams = Arc::new(crate::http_streams::HttpStreamService::default());
        let b = Arc::new(PendingUpgrades::default());
        let mut native = NativeUpgrade { connection, lease };
        let mut handle = id;
        for table in [&b, &a] {
            let json = crate::http_streams::encode_http_response(
                native_response(native),
                true,
                &streams,
                Some(table),
            )
            .unwrap();
            handle = serde_json::from_str::<serde_json::Value>(&json).unwrap()["wsNative"]
                .as_u64()
                .unwrap();
            native = table.take(handle).unwrap();
        }
        assert_ne!(handle, id);
        assert!(native
            .lease
            .admit_consumer(&app, handle, &cell, None, owner.clone())
            .await
            .unwrap()
            .is_none());
        assert_eq!(native.lease.admission_id(), id);
        assert!(!native.lease.owns(&cell, &NativeOwner::default()));
        while let Ok(message) = receiver.try_recv() {
            assert!(
                matches!(message, crate::actor::Message::ActivityFinished { .. }),
                "duplicate admission at quota one"
            );
        }
        crate::ws_registry::ws_register_outbound(handle, &cell, None);
        crate::ws_registry::ws_link_native_admission(handle, id);
        assert_eq!(crate::ws_registry::ws_admission_id(handle), id);
        drop(crate::ws_registry::WsRegistrationGuard::new(handle));
        drop(native);
        expect_core_release(&mut receiver, id).await;
    })
    .await;
}

#[test]
fn native_ws_queued_application_close_is_not_lifecycle_revocation() {
    init_host();
    use crate::ws_registry::*;
    let id = ws_next_id();
    let scope = format!("native-queued-close-{id}");
    ws_register_outbound(id, &scope, None);
    ws_registry()
        .lock()
        .unwrap()
        .emit(id, WsOut::Text("last".into()));
    ws_registry()
        .lock()
        .unwrap()
        .emit(id, WsOut::Close(1000, "done".into()));
    let revoked = CancellationToken::new();
    let registration = ws_register_native(id, &scope, None, revoked.clone());
    assert!(!revoked.is_cancelled());
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    ws_register(id, send);
    assert!(matches!(receive.try_recv(), Ok(WsOut::Text(text)) if text == "last"));
    assert!(matches!(receive.try_recv(), Ok(WsOut::Close(1000, reason)) if reason == "done"));
    drop(registration);

    let id = ws_next_id();
    ws_register_outbound(id, &scope, None);
    ws_close(id, 1011, "owner revoked before registration");
    let revoked = CancellationToken::new();
    let registration = ws_register_native(id, &scope, None, revoked.clone());
    assert!(revoked.is_cancelled());
    drop(registration);
}

#[tokio::test]
async fn native_ws_core_refusal_does_not_leave_a_registration() {
    bounded(async {
        let (app, mut receiver) = admission_app();
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-refused-{id}");
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&app, id, &task_scope, None, NativeOwner::default()).await
        });
        route_admission(&mut receiver).await.send(false).unwrap();
        assert!(opening.await.unwrap().is_err());
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
    })
    .await;
}

#[tokio::test]
async fn native_ws_cancel_after_core_admission_before_reply_releases_it() {
    bounded(async {
        let (app, mut receiver) = admission_app();
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-cancelled-admission-{id}");
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&app, id, &task_scope, None, NativeOwner::default()).await
        });
        let reply = route_admission(&mut receiver).await;
        opening.abort();
        assert!(matches!(opening.await, Err(error) if error.is_cancelled()));
        assert!(reply.send(true).is_err());
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
    })
    .await;
}

#[tokio::test]
async fn native_ws_owner_revocation_follows_transferred_response_and_stops_pump() {
    bounded(async {
        let (connection, mut server) = connection_pair().await;
        let (app, mut receiver) = admission_app();
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-owner-{id}");
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&app, id, &task_scope, None, NativeOwner::default()).await
        });
        route_admission(&mut receiver).await.send(true).unwrap();
        let lease = opening.await.unwrap().unwrap();
        let streams = Arc::new(crate::http_streams::HttpStreamService::default());
        let caller = Arc::new(PendingUpgrades::default());
        let json = crate::http_streams::encode_http_response(
            native_response(NativeUpgrade { connection, lease }),
            true,
            &streams,
            Some(&caller),
        )
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&json).unwrap();
        let transferred_id = envelope["wsNative"].as_u64().unwrap();
        assert_ne!(id, transferred_id);
        let native = caller.take(transferred_id).unwrap();
        caller.close();
        assert!(crate::ws_registry::has_regular_websocket(&scope));
        let (client, accepted) = tokio::io::duplex(256);
        let mut client = WebSocket::after_handshake(client, Role::Client);
        let pump = tokio::spawn(native.run(WebSocket::after_handshake(accepted, Role::Server)));
        client
            .write_frame(Frame::text(b"pump-running".to_vec().into()))
            .await
            .unwrap();
        assert_eq!(
            &server.read_frame().await.unwrap().payload[..],
            b"pump-running"
        );
        let mut client = client.into_inner();
        crate::ws_registry::ws_close_scope(&scope, 1011, "durability unproven");
        assert!(pump.await.unwrap().is_err());
        assert!(server.read_frame().await.is_err());
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
    })
    .await;
}

#[tokio::test]
async fn native_ws_admission_deadline_reclaims_registration() {
    bounded(async {
        let (mut app, mut receiver) = admission_app();
        app.operation_deadline_ms = 200;
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-admission-deadline-{id}");
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&app, id, &task_scope, None, NativeOwner::default()).await
        });
        let reply = route_admission(&mut receiver).await;
        let result = opening.await.unwrap();
        assert!(matches!(result, Err(error) if error.to_string().contains("timed out")));
        assert!(reply.send(true).is_err());
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
    })
    .await;
}

#[tokio::test]
async fn native_ws_dropped_admitted_response_releases_core_and_connection() {
    bounded(async {
        let (connection, mut server) = connection_pair().await;
        let (app, mut receiver) = admission_app();
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-drop-response-{id}");
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&app, id, &task_scope, None, NativeOwner::default()).await
        });
        route_admission(&mut receiver).await.send(true).unwrap();
        let lease = opening.await.unwrap().unwrap();
        drop(native_response(NativeUpgrade { connection, lease }));
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
        assert!(server.read_frame().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn native_ws_executor_shutdown_drops_queued_transport_and_admission() {
    bounded(async {
        let (connection, mut server) = connection_pair().await;
        let (mut app, mut receiver) = admission_app();
        let (websockets, executor) = tokio::sync::mpsc::unbounded_channel();
        app.websockets = websockets;
        let id = crate::ws_registry::ws_next_id();
        let scope = format!("native-executor-stop-{id}");
        let opening_app = app.clone();
        let task_scope = scope.clone();
        let opening = tokio::spawn(async move {
            NativeLease::admit(&opening_app, id, &task_scope, None, NativeOwner::default()).await
        });
        route_admission(&mut receiver).await.send(true).unwrap();
        let native = NativeUpgrade {
            connection,
            lease: opening.await.unwrap().unwrap(),
        };
        let (mut client, accepted) = tokio::io::duplex(256);
        assert!(app
            .websockets
            .send(Box::pin(async move {
                let _ = native
                    .run(WebSocket::after_handshake(accepted, Role::Server))
                    .await;
            }))
            .is_ok());
        drop(executor);
        expect_core_release(&mut receiver, id).await;
        assert!(!crate::ws_registry::has_regular_websocket(&scope));
        assert!(server.read_frame().await.is_err());
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    })
    .await;
}

async fn raw_handshake(
    response: String,
    headers: hyper::HeaderMap,
) -> (
    std::result::Result<Connection, crate::ws_client::Error>,
    String,
) {
    use base64::Engine;
    use sha1::Digest;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
            assert!(request.len() < 8192);
        }
        let request = String::from_utf8(request).unwrap();
        let key = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| value.trim())
            })
            .unwrap();
        let digest = sha1::Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
        let accept = base64::engine::general_purpose::STANDARD.encode(digest);
        // an oversized body may be rejected before the server finishes writing.
        let _ = stream
            .write_all(response.replace("{accept}", &accept).as_bytes())
            .await;
        request
    });
    let result = crate::ws_client::connect(&format!("http://{address}/"), headers).await;
    (result, server.await.unwrap())
}

#[tokio::test]
async fn native_ws_declined_body_is_preserved_or_fails_without_empty_fallback() {
    bounded(async {
        let (result, _) = raw_handshake(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nX-Reason: denied\r\n\r\ndenied".into(),
            hyper::HeaderMap::new(),
        )
        .await;
        match result {
            Err(crate::ws_client::Error::Declined(response)) => {
                assert_eq!(response.status, hyper::StatusCode::FORBIDDEN);
                assert_eq!(response.headers["x-reason"], "denied");
                assert_eq!(response.body, b"denied");
            }
            _ => panic!("declined response was not preserved"),
        }
        let (result, _) = raw_handshake(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 99\r\n\r\ntruncated".into(),
            hyper::HeaderMap::new(),
        )
        .await;
        assert!(matches!(result, Err(crate::ws_client::Error::Failed(error))
            if error.to_string().contains("read declined WebSocket response")));
    })
    .await;
}

#[tokio::test]
async fn native_ws_declined_body_collection_is_bounded() {
    bounded(async {
        let body = "x".repeat(crate::ws_client::MAX_DECLINED_BODY_BYTES + 1);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (result, _) = raw_handshake(response, hyper::HeaderMap::new()).await;
        assert!(matches!(result, Err(crate::ws_client::Error::Failed(error))
            if error.to_string().contains("read declined WebSocket response")));
    })
    .await;
}

#[tokio::test]
async fn native_ws_extensions_are_neither_offered_nor_accepted() {
    bounded(async {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::SEC_WEBSOCKET_EXTENSIONS, "permessage-deflate".parse().unwrap());
        let (result, request) = raw_handshake(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n".into(),
            headers,
        ).await;
        assert!(!request.to_ascii_lowercase().contains("sec-websocket-extensions:"));
        assert!(matches!(result, Err(crate::ws_client::Error::Failed(error))
            if error.to_string().contains("unsupported WebSocket extensions")));
    }).await;
}

async fn connection_pair() -> (
    Connection,
    WebSocket<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
) {
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let serving = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(
            move |mut request: hyper::Request<hyper::body::Incoming>| {
                let sender = sender.clone();
                async move {
                    let (mut response, upgrade) =
                        fastwebsockets::upgrade::upgrade(&mut request).unwrap();
                    response.headers_mut().insert(
                        hyper::header::SEC_WEBSOCKET_PROTOCOL,
                        "probe.v1".parse().unwrap(),
                    );
                    tokio::spawn(async move {
                        let _ = sender.send(upgrade.await.unwrap()).await;
                    });
                    Ok::<_, std::convert::Infallible>(response)
                }
            },
        );
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
            .unwrap();
    });
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        hyper::header::SEC_WEBSOCKET_PROTOCOL,
        "probe.v1".parse().unwrap(),
    );
    let connection = crate::ws_client::connect(&format!("http://{address}/"), headers)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let server = receiver.recv().await.unwrap();
    serving.await.unwrap();
    (connection, server)
}

fn native_response(connection: NativeUpgrade) -> crate::engine_api::HttpResponse {
    crate::engine_api::HttpResponse {
        status: 101,
        body: Vec::new(),
        stream: None,
        headers: vec![("sec-websocket-protocol".into(), "probe.v1".into())],
        websocket: Some(crate::engine_api::HttpResponseWebSocket::Native(Box::new(
            connection,
        ))),
        write_position: None,
        observed_position: None,
    }
}

#[tokio::test]
async fn native_ws_response_encoding_transfers_connection_not_cell_target() {
    bounded(async {
        let (connection, mut server) = connection_pair().await;
        let connection = admitted_connection(connection).await;
        let owner = Arc::new(PendingUpgrades::default());
        let foreign = PendingUpgrades::<NativeUpgrade>::default();
        let streams = Arc::new(crate::http_streams::HttpStreamService::default());
        server
            .write_frame(Frame::text(b"early".to_vec().into()))
            .await
            .unwrap();
        let json = crate::http_streams::encode_http_response(
            native_response(connection),
            true,
            &streams,
            Some(&owner),
        )
        .unwrap();
        let response: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(response["wsTarget"].is_null());
        assert_eq!(response["headers"][0][1], "probe.v1");
        let id = response["wsNative"].as_u64().unwrap();
        assert!(foreign.take(id).is_err());
        let mut connection = owner.take(id).unwrap();
        owner.close();
        assert!(owner.take(id).is_err());
        assert_eq!(
            connection.connection.headers[hyper::header::SEC_WEBSOCKET_PROTOCOL],
            "probe.v1"
        );
        let frame = connection.connection.socket.read_frame().await.unwrap();
        assert_eq!(&frame.payload[..], b"early");
        drop(native_response(connection));
        assert!(server.read_frame().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn native_ws_response_to_retired_caller_closes_real_connection() {
    bounded(async {
        let (connection, mut server) = connection_pair().await;
        let connection = admitted_connection(connection).await;
        let owner = Arc::new(PendingUpgrades::default());
        owner.close();
        let streams = Arc::new(crate::http_streams::HttpStreamService::default());
        assert!(crate::http_streams::encode_http_response(
            native_response(connection),
            true,
            &streams,
            Some(&owner)
        )
        .is_err());
        assert!(server.read_frame().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn native_ws_cancelled_handshake_stops_its_http_driver() {
    bounded(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let opening = tokio::spawn(async move {
            crate::ws_client::connect(&format!("http://{address}/"), hyper::HeaderMap::new()).await
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(server.read_u8().await.unwrap());
            assert!(headers.len() < 8192);
        }
        opening.abort();
        assert!(matches!(opening.await, Err(error) if error.is_cancelled()));
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    })
    .await;
}

#[test]
fn native_ws_dropped_consumer_request_reclaims_native_registration() {
    init_host();
    use crate::ws_registry::*;
    let id = ws_next_id();
    let scope = format!("native-ws-consumer-{id}");
    let (output, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_input, incoming) = ws_pull_channel();
    ws_pull_register(id, incoming);
    ws_register_outbound(id, &scope, None);
    ws_register(id, output);
    assert!(has_regular_websocket(&scope));
    drop(WsRegistrationGuard::new(id));
    assert!(!has_regular_websocket(&scope));
    assert!(!ws_pull().lock().unwrap().contains_key(&id));
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}

#[tokio::test]
async fn native_ws_passthrough_cancellation_drops_both_transports_mid_frame() {
    bounded(async {
        let (mut client, accepted) = tokio::io::duplex(256);
        let (dialled, mut container) = tokio::io::duplex(256);
        let pump = tokio::spawn(passthrough(
            WebSocket::after_handshake(accepted, Role::Server),
            WebSocket::after_handshake(dialled, Role::Client),
        ));
        client
            .write_all(&[0x82, 0xfe, 0, 128, 1, 2, 3, 4, 0])
            .await
            .unwrap();
        tokio::task::yield_now().await;
        pump.abort();
        assert!(pump.await.unwrap_err().is_cancelled());
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(container.read(&mut byte).await.unwrap(), 0);
    })
    .await;
}
