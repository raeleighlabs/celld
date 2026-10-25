use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use fastwebsockets::{Frame, OpCode, Payload, WebSocket, WebSocketRead, WebSocketWrite};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::ws_client::Connection;

// a table belongs to a worker request or an adopted actor activation. ids
// are meaningful only in that table, including across response transfers.
pub(crate) struct PendingUpgrades<T = NativeUpgrade> {
    entries: Mutex<Option<HashMap<u64, Pending<T>>>>,
    lifetime: NativeOwner,
}

#[derive(Clone)]
pub struct NativeOwner {
    identity: Arc<std::sync::OnceLock<String>>,
    cancel: CancellationToken,
}

impl Default for NativeOwner {
    fn default() -> Self {
        Self::from(CancellationToken::new())
    }
}

impl From<CancellationToken> for NativeOwner {
    fn from(cancel: CancellationToken) -> Self {
        Self {
            identity: Arc::new(std::sync::OnceLock::new()),
            cancel,
        }
    }
}

impl NativeOwner {
    pub(crate) fn key(&self) -> &str {
        self.identity
            .get_or_init(|| {
                let mut rng = crate::asyncrt::rng("native-ws-owner");
                format!(
                    "{:016x}{:016x}",
                    rand::RngCore::next_u64(&mut rng),
                    rand::RngCore::next_u64(&mut rng)
                )
            })
            .as_str()
    }
    pub fn is_live(&self) -> bool {
        !self.cancel.is_cancelled()
    }
    pub fn revocation(&self) -> CancellationToken {
        self.cancel.child_token()
    }
    fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

#[derive(Default)]
pub(crate) struct ActivationUpgrades {
    owners: Mutex<HashMap<String, Arc<PendingUpgrades>>>,
}

impl ActivationUpgrades {
    pub(crate) fn replace(&self, scope: &str, owned: bool) {
        let previous = {
            let mut owners = self.owners.lock().unwrap();
            let previous = owners.remove(scope);
            if owned {
                owners.insert(scope.to_string(), Arc::new(PendingUpgrades::default()));
            }
            previous
        };
        if let Some(previous) = previous {
            previous.close();
        }
    }

    pub(crate) fn matches(&self, scope: &str, key: &str) -> bool {
        self.owners
            .lock()
            .unwrap()
            .get(scope)
            .is_some_and(|owner| owner.lifetime.key() == key && owner.lifetime.is_live())
    }

    // only a capability minted for the current activation can reset it.
    // stale continuations retain their closed table, never the successor.
    pub(crate) fn reset(&self, scope: &str, key: &str) -> bool {
        let previous = {
            let mut owners = self.owners.lock().unwrap();
            if owners
                .get(scope)
                .is_none_or(|owner| owner.lifetime.key() != key)
            {
                return false;
            }
            let previous = owners.remove(scope).unwrap();
            previous.close();
            owners.insert(scope.to_string(), Arc::new(PendingUpgrades::default()));
            previous
        };
        drop(previous);
        true
    }

    pub(crate) fn reset_bound(&self, owner: &Arc<PendingUpgrades>) -> Option<(String, String)> {
        let scope = self
            .owners
            .lock()
            .unwrap()
            .iter()
            .find_map(|(scope, current)| Arc::ptr_eq(current, owner).then(|| scope.clone()));
        let scope = scope?;
        let key = owner.lifetime.key().to_string();
        self.reset(&scope, &key).then_some((scope, key))
    }

    pub(crate) fn authorises(&self, scope: &str, owner: &Arc<PendingUpgrades>) -> bool {
        self.owners
            .lock()
            .unwrap()
            .get(scope)
            .is_some_and(|current| Arc::ptr_eq(current, owner) && current.lifetime.is_live())
    }

    // the action must be synchronous and must not enter javascript or reacquire this lock.
    pub(crate) fn admit<R>(
        &self,
        scope: &str,
        owner: &Arc<PendingUpgrades>,
        action: impl FnOnce() -> R,
    ) -> Result<R, String> {
        let owners = self.owners.lock().unwrap();
        if !owners
            .get(scope)
            .is_some_and(|current| Arc::ptr_eq(current, owner) && current.lifetime.is_live())
        {
            return Err("actor continuation is retired".to_string());
        }
        Ok(action())
    }

    pub(crate) fn owner(&self, scope: &str) -> Arc<PendingUpgrades> {
        self.owners
            .lock()
            .unwrap()
            .get(scope)
            .cloned()
            .unwrap_or_else(|| {
                let absent = Arc::new(PendingUpgrades::default());
                absent.close();
                absent
            })
    }
}

impl Drop for ActivationUpgrades {
    fn drop(&mut self) {
        for owner in self.owners.get_mut().unwrap().values() {
            owner.close();
        }
    }
}

struct Pending<T> {
    generation: Arc<()>,
    connection: Option<T>,
    cancel: CancellationToken,
}

impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl<T> Default for PendingUpgrades<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Some(HashMap::new())),
            lifetime: NativeOwner::default(),
        }
    }
}

impl<T> PendingUpgrades<T> {
    pub(crate) fn reserve(self: &Arc<Self>, id: u64) -> Result<UpgradeReservation<T>> {
        let mut entries = self.entries.lock().unwrap();
        let entries = entries.as_mut().context("WebSocket request has retired")?;
        ensure!(
            !entries.contains_key(&id),
            "WebSocket upgrade already owned"
        );
        let cancel = self.lifetime.revocation();
        let generation = Arc::new(());
        entries.insert(
            id,
            Pending {
                generation: generation.clone(),
                connection: None,
                cancel: cancel.clone(),
            },
        );
        Ok(UpgradeReservation {
            owner: self.clone(),
            id,
            generation,
            cancel,
            armed: true,
        })
    }

    pub(crate) fn cleanup(self: &Arc<Self>, id: u64) -> Result<UpgradeCleanup<T>> {
        let entries = self.entries.lock().unwrap();
        let entry = entries
            .as_ref()
            .and_then(|entries| entries.get(&id))
            .context("WebSocket upgrade is not owned by this activation or request")?;
        Ok(UpgradeCleanup {
            owner: Arc::downgrade(self),
            id,
            generation: entry.generation.clone(),
        })
    }

    pub(crate) fn take(&self, id: u64) -> Result<T> {
        self.entries
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|entries| entries.remove(&id))
            .and_then(|mut entry| entry.connection.take())
            .context("WebSocket upgrade is not owned by this request or was already consumed")
    }

    pub(crate) fn remove(&self, id: u64) {
        let removed = self
            .entries
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|entries| entries.remove(&id));
        drop(removed);
    }

    fn remove_reservation(&self, id: u64, generation: &Arc<()>) {
        let removed = {
            let mut entries = self.entries.lock().unwrap();
            entries.as_mut().and_then(|entries| {
                if entries
                    .get(&id)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.generation, generation))
                {
                    entries.remove(&id)
                } else {
                    None
                }
            })
        };
        drop(removed);
    }

    #[cfg(test)]
    pub(crate) fn revocation(&self) -> CancellationToken {
        self.lifetime.revocation()
    }

    pub(crate) fn generation(&self) -> NativeOwner {
        self.lifetime.clone()
    }

    pub(crate) fn close(&self) {
        self.lifetime.cancel.cancel();
        let entries = self.entries.lock().unwrap().take();
        drop(entries);
    }
}

// a gc cleanup claim cannot acquire a transport or affect a successor handle.
// it captures the owner rather than consulting the finalizer's current event.
pub(crate) struct UpgradeCleanup<T> {
    owner: std::sync::Weak<PendingUpgrades<T>>,
    id: u64,
    generation: Arc<()>,
}

impl<T> Drop for UpgradeCleanup<T> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.remove_reservation(self.id, &self.generation);
        }
    }
}

pub(crate) struct UpgradeReservation<T> {
    owner: Arc<PendingUpgrades<T>>,
    id: u64,
    generation: Arc<()>,
    pub(crate) cancel: CancellationToken,
    armed: bool,
}

impl<T> UpgradeReservation<T> {
    pub(crate) fn complete(mut self, connection: T) -> Result<()> {
        let mut entries = self.owner.entries.lock().unwrap();
        let entry = entries
            .as_mut()
            .and_then(|entries| entries.get_mut(&self.id))
            .context("WebSocket upgrade was cancelled")?;
        ensure!(
            Arc::ptr_eq(&entry.generation, &self.generation) && entry.connection.is_none(),
            "WebSocket upgrade already completed"
        );
        entry.connection = Some(connection);
        self.armed = false;
        Ok(())
    }
}

impl<T> Drop for UpgradeReservation<T> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.remove_reservation(self.id, &self.generation);
        }
    }
}

// the admission identity stays with the transport even when its javascript
// handle moves to another request, actor or node-facing response.
#[derive(serde::Serialize)]
pub struct NativeClose {
    pub code: u16,
    pub reason: String,
    pub clean: bool,
    pub notify: bool,
}

impl Default for NativeClose {
    fn default() -> Self {
        Self {
            code: 1006,
            reason: "native transport ended".into(),
            clean: false,
            notify: true,
        }
    }
}

pub struct NativeUpgrade {
    pub connection: Connection,
    pub lease: NativeLease,
}

pub struct NativeLease {
    id: u64,
    cell: String,
    owner: NativeOwner,
    revoked: CancellationToken,
    _registration: crate::ws_registry::WsRegistrationGuard,
    core: Option<CoreSocketLease>,
}

struct CoreSocketLease {
    app: crate::actor::AppHandle,
    cell: String,
    id: u64,
}

impl Drop for CoreSocketLease {
    fn drop(&mut self) {
        self.app.websocket_closed(self.cell.clone(), self.id);
    }
}

impl NativeLease {
    pub async fn admit(
        app: &crate::actor::AppHandle,
        id: u64,
        scope: &str,
        facet: Option<crate::ws_registry::FacetSocket>,
        owner: NativeOwner,
    ) -> Result<Self> {
        ensure!(owner.is_live(), "WebSocket owner activation ended");
        let revoked = owner.revocation();
        let cell = facet
            .as_ref()
            .map_or(scope, |facet| facet.root.as_str())
            .to_string();
        let registration =
            crate::ws_registry::ws_register_native(id, scope, facet, revoked.clone());
        let mut lease = Self {
            id,
            cell: cell.clone(),
            owner,
            revoked,
            _registration: registration,
            core: None,
        };
        if !cell.is_empty() {
            let revoked = lease.revoked.clone();
            let admission = async {
                let routed = app
                    .request(cell.clone())
                    .await
                    .map_err(|error| anyhow::anyhow!("route native WebSocket: {error:?}"))?;
                ensure!(
                    routed.route == celld_logic::Route::Local,
                    "WebSocket owner moved off node"
                );
                let _activity = app.activity(routed.request, cell.clone());
                // arm before awaiting the reply. cancellation after the core
                // admits but before the reply arrives still queues its release.
                lease.core = Some(CoreSocketLease {
                    app: app.clone(),
                    cell: cell.clone(),
                    id,
                });
                app.websocket_opened(cell, id, celld_logic::WebSocketKind::Outbound)
                    .await
            };
            crate::asyncrt::select! {
                _ = revoked.cancelled() => anyhow::bail!("WebSocket owner activation ended"),
                result = crate::asyncrt::timeout(
                    Duration::from_millis(app.operation_deadline_ms), admission
                ) => result.context("native WebSocket admission timed out")??,
            }
        }
        ensure!(
            !lease.revoked.is_cancelled(),
            "WebSocket admission was revoked"
        );
        Ok(lease)
    }

    pub fn revocation(&self) -> CancellationToken {
        self.revoked.clone()
    }
    pub fn owns(&self, cell: &str, owner: &NativeOwner) -> bool {
        self.cell == cell && self.owner.same_generation(owner) && owner.is_live()
    }

    pub fn admission_id(&self) -> u64 {
        self.id
    }

    pub async fn admit_consumer(
        &self,
        app: &crate::actor::AppHandle,
        id: u64,
        scope: &str,
        facet: Option<crate::ws_registry::FacetSocket>,
        owner: NativeOwner,
    ) -> Result<Option<Self>> {
        ensure!(
            !self.revoked.is_cancelled() && owner.is_live(),
            "WebSocket owner activation ended"
        );
        let cell = facet.as_ref().map_or(scope, |facet| facet.root.as_str());
        if cell.is_empty() || self.owns(cell, &owner) {
            return Ok(None);
        }
        Self::admit(app, id, scope, facet, owner).await.map(Some)
    }
}

impl NativeUpgrade {
    pub async fn run<S>(self, client: WebSocket<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Self { connection, lease } = self;
        let revoked = lease.revocation();
        ensure!(!revoked.is_cancelled(), "WebSocket admission was revoked");
        let result = crate::asyncrt::select! {
            _ = revoked.cancelled() => Err(anyhow::anyhow!("WebSocket admission was revoked")),
            result = passthrough(client, connection.socket) => result,
        };
        drop(lease);
        result
    }
}

pub const PASSTHROUGH_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

// fastwebsockets 0.8.1 bounds individual frames, but its fragment collector
// does not bound the aggregate. keep our own bounded message accumulator.
#[derive(Default)]
struct Message {
    opcode: Option<OpCode>,
    bytes: Vec<u8>,
}

impl Message {
    fn accept(&mut self, frame: Frame<'_>) -> Result<Option<Frame<'static>>> {
        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                ensure!(self.opcode.is_none(), "interleaved WebSocket messages");
                self.opcode = Some(frame.opcode);
            }
            OpCode::Continuation => {
                ensure!(self.opcode.is_some(), "unexpected WebSocket continuation");
            }
            OpCode::Close => {
                ensure!(frame.payload.len() != 1, "invalid WebSocket close payload");
                if frame.payload.len() >= 2 {
                    let code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                    ensure!(
                        celld_logic::schedule::websocket_close_code_is_allowed(code),
                        "invalid WebSocket close code"
                    );
                    std::str::from_utf8(&frame.payload[2..])
                        .context("invalid WebSocket close reason")?;
                }
                return Ok(Some(Frame::new(
                    true,
                    OpCode::Close,
                    None,
                    Payload::Owned(frame.payload.to_vec()),
                )));
            }
            OpCode::Ping | OpCode::Pong => {
                return Ok(Some(Frame::new(
                    true,
                    frame.opcode,
                    None,
                    Payload::Owned(frame.payload.to_vec()),
                )));
            }
        }
        ensure!(
            frame.payload.len() <= PASSTHROUGH_MAX_MESSAGE_BYTES.saturating_sub(self.bytes.len()),
            "WebSocket message exceeds passthrough limit"
        );
        self.bytes.extend_from_slice(&frame.payload);
        if !frame.fin {
            return Ok(None);
        }
        let opcode = self.opcode.take().unwrap();
        if opcode == OpCode::Text {
            std::str::from_utf8(&self.bytes).context("invalid WebSocket text")?;
        }
        Ok(Some(Frame::new(
            true,
            opcode,
            None,
            Payload::Owned(std::mem::take(&mut self.bytes)),
        )))
    }
}

async fn direction<R, W>(mut reader: WebSocketRead<R>, mut writer: WebSocketWrite<W>) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut message = Message::default();
    loop {
        // both automatic responses are disabled. ping/pong and close traverse
        // the native transport, with the destination writer's masking role.
        let frame = reader
            .read_frame(&mut |_| async {
                Err::<(), _>(std::io::Error::other(
                    "unexpected automatic WebSocket reply",
                ))
            })
            .await?;
        let Some(frame) = message.accept(frame)? else {
            continue;
        };
        let close = frame.opcode == OpCode::Close;
        crate::asyncrt::timeout(WRITE_DEADLINE, writer.write_frame(frame))
            .await
            .context("WebSocket passthrough write timed out")??;
        if close {
            return Ok(());
        }
    }
}

// each direction owns a continuously polled read and one bounded write. no
// frame queue, javascript callback, registry sender or detached pump is used.
// cancellation drops both transports, and no partially read socket is reused.
pub async fn passthrough<A, B>(mut client: WebSocket<A>, mut upstream: WebSocket<B>) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    client.set_auto_close(false);
    client.set_auto_pong(false);
    client.set_max_message_size(PASSTHROUGH_MAX_MESSAGE_BYTES + 1);
    upstream.set_auto_close(false);
    upstream.set_auto_pong(false);
    upstream.set_max_message_size(PASSTHROUGH_MAX_MESSAGE_BYTES + 1);
    let (client_read, client_write) = client.split(tokio::io::split);
    let (upstream_read, upstream_write) = upstream.split(tokio::io::split);
    let to_upstream = direction(client_read, upstream_write);
    let to_client = direction(upstream_read, client_write);
    let mut to_upstream = std::pin::pin!(to_upstream);
    let mut to_client = std::pin::pin!(to_client);
    crate::asyncrt::select! {
        result = &mut to_upstream => {
            result?;
            crate::asyncrt::timeout(CLOSE_DEADLINE, &mut to_client)
                .await.context("upstream WebSocket close timed out")??;
        }
        result = &mut to_client => {
            result?;
            crate::asyncrt::timeout(CLOSE_DEADLINE, &mut to_upstream)
                .await.context("client WebSocket close timed out")??;
        }
    }
    Ok(())
}

#[cfg(all(test, not(celld_internal_tests)))]
#[path = "native_ws_tests.rs"]
pub(crate) mod native_ws_tests;
