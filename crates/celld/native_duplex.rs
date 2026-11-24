use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_util::sync::CancellationToken;

use crate::native_ws::NativeOwner;

pub const AUTHORITY: &str = "celld-duplex:1";
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const MAX_PENDING: usize = 256;

pub struct DuplexCapability {
    pub target: crate::container::AllocationDuplexTarget,
    pub owner: NativeOwner,
    expires_ms: u64,
}

#[derive(Debug)]
pub enum DuplexAdmissionError {
    InvalidCapability,
    Capacity,
}

pub struct DuplexService {
    pending: Mutex<HashMap<String, DuplexCapability>>,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
    tasks: Mutex<Vec<crate::asyncrt::TaskHandle<()>>>,
}

impl Default for DuplexService {
    fn default() -> Self {
        Self {
            pending: Mutex::default(),
            slots: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_PENDING)),
            tasks: Mutex::default(),
        }
    }
}

impl Drop for DuplexService {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl DuplexService {
    pub fn take_admitted(
        &self,
        token: &str,
    ) -> Result<(DuplexCapability, tokio::sync::OwnedSemaphorePermit), DuplexAdmissionError> {
        let capability = self
            .take(token)
            .map_err(|_| DuplexAdmissionError::InvalidCapability)?;
        let permit = self.admit().map_err(|_| DuplexAdmissionError::Capacity)?;
        Ok((capability, permit))
    }

    pub fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.slots
            .clone()
            .try_acquire_owned()
            .context("duplex transport capacity exhausted")
    }

    pub fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(crate::asyncrt::spawn(future));
    }

    pub fn mint(
        &self,
        target: crate::container::AllocationDuplexTarget,
        owner: NativeOwner,
    ) -> Result<String> {
        ensure!(owner.is_live(), "duplex activation retired");
        let now = crate::asyncrt::mono_ms();
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, entry| {
            entry.expires_ms > now && entry.owner.is_live() && !entry.target.revoked.is_cancelled()
        });
        ensure!(
            pending.len() < MAX_PENDING,
            "duplex capability capacity exhausted"
        );
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(
            &mut crate::asyncrt::rng("native-duplex-capability"),
            &mut bytes,
        );
        let token = crate::engine_api::durable_object_id_hex(&bytes);
        ensure!(!pending.contains_key(&token), "duplex capability collision");
        pending.insert(
            token.clone(),
            DuplexCapability {
                target,
                owner,
                expires_ms: now.saturating_add(CONNECT_DEADLINE.as_millis() as u64),
            },
        );
        Ok(token)
    }

    /// Consumes authority even if admission or connection subsequently fails.
    pub fn take(&self, token: &str) -> Result<DuplexCapability> {
        ensure!(
            token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid duplex capability"
        );
        let entry = self
            .pending
            .lock()
            .unwrap()
            .remove(token)
            .context("unknown or consumed duplex capability")?;
        ensure!(
            entry.expires_ms > crate::asyncrt::mono_ms()
                && entry.owner.is_live()
                && !entry.target.revoked.is_cancelled(),
            "duplex capability expired or retired"
        );
        Ok(entry)
    }
}

/// Copies bounded buffers independently, preserving TCP half-close in both directions.
/// Revocation drops both streams. No stream is reused after cancellation.
pub async fn pump<A, B>(
    mut client: A,
    mut upstream: B,
    owner_revoked: CancellationToken,
    allocation_revoked: CancellationToken,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    ensure!(
        !owner_revoked.is_cancelled() && !allocation_revoked.is_cancelled(),
        "duplex admission revoked"
    );
    crate::asyncrt::select! {
        _ = owner_revoked.cancelled() => anyhow::bail!("duplex activation retired"),
        _ = allocation_revoked.cancelled() => anyhow::bail!("duplex allocation retired"),
        result = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
            result.context("duplex copy failed")?;
            Ok(())
        }
    }
}

#[cfg(all(test, not(celld_internal_tests)))]
#[path = "native_duplex_tests.rs"]
mod tests;
