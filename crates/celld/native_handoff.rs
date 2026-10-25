use crate::bucket::Bucket;
use crate::ownership_store::BucketOwnership;
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

#[derive(Debug)]
pub(crate) struct CooperativeRetirementRequired;

impl std::fmt::Display for CooperativeRetirementRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("cooperative-retirement-required")
    }
}

impl std::error::Error for CooperativeRetirementRequired {}

pub(crate) const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
static OWNERSHIP: OnceLock<Arc<BucketOwnership>> = OnceLock::new();

#[cfg(all(test, not(celld_internal_tests)))]
#[path = "native_handoff_tests.rs"]
pub(crate) mod tests;

// the process uses the actor's existing ownership adapter, never another lease.
pub fn install(ownership: Arc<BucketOwnership>) -> anyhow::Result<()> {
    OWNERSHIP
        .set(ownership)
        .map_err(|_| anyhow!("native ownership already installed"))
}

pub(crate) fn ownership() -> Option<Arc<BucketOwnership>> {
    OWNERSHIP.get().cloned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EncodedOwner", into = "EncodedOwner")]
pub(crate) struct OwnerWire {
    pub node: String,
    pub epoch: u64,
    pub native: Option<Protection>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedOwner {
    node: String,
    epoch: EncodedEpoch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native: Option<Protection>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum EncodedEpoch {
    Legacy(u64),
    Protected(ProtectedEpoch),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedEpoch {
    native_handoff: u8,
    value: u64,
}

impl From<OwnerWire> for EncodedOwner {
    fn from(owner: OwnerWire) -> Self {
        // an old u64 reader must fail before it can acquire a guard and strip protection.
        let epoch = if owner.native.is_some() {
            EncodedEpoch::Protected(ProtectedEpoch {
                native_handoff: 1,
                value: owner.epoch,
            })
        } else {
            EncodedEpoch::Legacy(owner.epoch)
        };
        Self {
            node: owner.node,
            epoch,
            native: owner.native,
        }
    }
}

impl TryFrom<EncodedOwner> for OwnerWire {
    type Error = &'static str;

    fn try_from(owner: EncodedOwner) -> Result<Self, Self::Error> {
        let epoch = match (&owner.epoch, &owner.native) {
            (EncodedEpoch::Legacy(epoch), None) => *epoch,
            (EncodedEpoch::Protected(tag), Some(native))
                if tag.native_handoff == 1 && native.version == 1 && tag.value == native.epoch =>
            {
                tag.value
            }
            _ => return Err("owner epoch encoding and native protection disagree"),
        };
        Ok(Self {
            node: owner.node,
            epoch,
            native: owner.native,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Protection {
    pub version: u8,
    pub node: String,
    pub generation: String,
    pub epoch: u64,
    // empty only until the successor binds its own journal before its first reservation.
    pub journal: String,
    // immutable linked history is retained even after this owner starts new work.
    pub head: Option<String>,
    pub closed: Option<String>,
    pub restore: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub epoch: u64,
    pub txid: u64,
    pub digest: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DestroyedAttempt {
    pub id: String,
    pub attempt: String,
    pub fingerprint: Option<String>,
    pub container_id: Option<String>,
    pub image: Option<String>,
    pub engine_image: Option<String>,
    pub platform: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Closure {
    pub version: u8,
    pub scope: String,
    pub node: String,
    pub generation: String,
    pub epoch: u64,
    pub journal: String,
    pub previous: Option<String>,
    pub checkpoint: Checkpoint,
    pub attempts: Vec<DestroyedAttempt>,
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn owner_key(scope: &str) -> String {
    format!("cells/{scope}/own.json")
}

fn closure_key(scope: &str, hash: &str) -> anyhow::Result<String> {
    anyhow::ensure!(valid_digest(hash), "invalid native closure digest");
    Ok(format!("cells/{scope}/native-closures/{hash}.json"))
}

fn checkpoint_key(scope: &str, hash: &str) -> anyhow::Result<String> {
    anyhow::ensure!(valid_digest(hash), "invalid native checkpoint digest");
    Ok(format!("cells/{scope}/native-checkpoints/{hash}.ltx"))
}

pub(crate) async fn read_owner(
    bucket: &Bucket,
    scope: &str,
) -> anyhow::Result<Option<(OwnerWire, String)>> {
    let Some((body, etag)) = bucket.get(&owner_key(scope)).await? else {
        return Ok(None);
    };
    let owner: OwnerWire = serde_json::from_slice(&body).context("invalid native owner record")?;
    if let Some(native) = &owner.native {
        anyhow::ensure!(
            native.version == 1
                && native.epoch == owner.epoch
                && !native.node.is_empty()
                && !native.generation.is_empty()
                && (valid_digest(&native.journal)
                    || (native.journal.is_empty() && native.head.is_some()))
                && (owner.node.is_empty() || owner.node == native.node),
            "native owner identity mismatch"
        );
        anyhow::ensure!(
            native.closed.is_none() || (owner.node.is_empty() && native.closed == native.head),
            "native owner closure mismatch"
        );
    }
    Ok(Some((owner, etag)))
}

// readback is mandatory after an ambiguous write, including an immutable create.
async fn put_immutable(bucket: &Bucket, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
    if matches!(bucket.put_cas(key, body.clone(), None).await, Ok(Some(_))) {
        return Ok(());
    }
    let (found, _) = bucket
        .get(key)
        .await?
        .context("native immutable publication did not settle")?;
    anyhow::ensure!(
        found.as_ref() == body.as_slice(),
        "native immutable publication conflicts"
    );
    Ok(())
}

pub(crate) async fn replace_owner(
    bucket: &Bucket,
    scope: &str,
    etag: &str,
    owner: &OwnerWire,
) -> anyhow::Result<()> {
    let body = serde_json::to_vec(owner)?;
    if matches!(
        bucket.put_cas(&owner_key(scope), body, Some(etag)).await,
        Ok(Some(_))
    ) {
        return Ok(());
    }
    let (found, _) = read_owner(bucket, scope)
        .await?
        .context("native owner disappeared during publication")?;
    anyhow::ensure!(found == *owner, "native owner publication lost authority");
    Ok(())
}

pub(crate) async fn load_closure(
    bucket: &Bucket,
    scope: &str,
    hash: &str,
) -> anyhow::Result<Closure> {
    let (body, _) = bucket
        .get(&closure_key(scope, hash)?)
        .await?
        .context("native closure is missing")?;
    anyhow::ensure!(digest(&body) == hash, "native closure digest mismatch");
    let closure: Closure = serde_json::from_slice(&body).context("invalid native closure")?;
    anyhow::ensure!(
        closure.version == 1
            && closure.scope == scope
            && closure.epoch > 0
            && closure.checkpoint.epoch == closure.epoch
            && closure.checkpoint.txid > 0
            && !closure.node.is_empty()
            && !closure.generation.is_empty(),
        "native closure identity mismatch"
    );
    let mut ids = BTreeSet::new();
    for attempt in &closure.attempts {
        anyhow::ensure!(
            !attempt.id.is_empty()
                && valid_digest(&attempt.attempt)
                && ids.insert(&attempt.id)
                && attempt.fingerprint.as_deref().is_none_or(valid_digest)
                && attempt.container_id.as_deref().is_none_or(valid_digest),
            "invalid closed native attempt"
        );
    }
    Ok(closure)
}

pub(crate) fn certify_release(owner: &OwnerWire, closure: &Closure) -> anyhow::Result<()> {
    let native = owner
        .native
        .as_ref()
        .context("native protection is missing")?;
    anyhow::ensure!(
        !closure.scope.is_empty()
            && closure.node == native.node
            && closure.generation == native.generation
            && closure.epoch == owner.epoch
            && closure.checkpoint.epoch == owner.epoch
            && closure.previous == native.head
            && closure.journal == native.journal,
        "native closure does not certify this owner"
    );
    Ok(())
}

pub(crate) async fn claim_native(
    bucket: &Bucket,
    scope: &str,
    owner: &OwnerWire,
    node: &str,
    generation: &str,
    epoch: u64,
    recovered_journal: Option<&str>,
) -> anyhow::Result<Option<Protection>> {
    let Some(native) = &owner.native else {
        return Ok(None);
    };
    anyhow::ensure!(
        epoch > owner.epoch && !generation.is_empty(),
        "native writer epoch or process is invalid"
    );
    let mut next = native.clone();
    if owner.node.is_empty() {
        let hash = native
            .closed
            .as_deref()
            .ok_or(CooperativeRetirementRequired)?;
        let closure = load_closure(bucket, scope, hash).await?;
        anyhow::ensure!(
            closure.node == native.node
                && closure.generation == native.generation
                && closure.epoch == owner.epoch,
            "released native proof belongs to another owner"
        );
        load_checkpoint(bucket, scope, &closure.checkpoint).await?;
        next.restore = Some(hash.to_string());
        next.journal.clear();
    } else {
        // lease expiry is not physical writer exclusion, even if node-log recovery finished.
        anyhow::ensure!(
            owner.node == node
                && (native.generation == generation
                    || (native.journal.is_empty() && native.head.is_some())
                    || recovered_journal
                        .is_some_and(|journal| !journal.is_empty() && journal == native.journal)),
            CooperativeRetirementRequired
        );
    }
    next.node = node.to_string();
    next.generation = generation.to_string();
    next.epoch = epoch;
    next.closed = None;
    Ok(Some(next))
}

pub(crate) async fn publish_checkpoint(
    bucket: &Bucket,
    scope: &str,
    epoch: u64,
    txid: u64,
    bytes: &[u8],
) -> anyhow::Result<Checkpoint> {
    anyhow::ensure!(
        epoch > 0 && txid > 0 && !bytes.is_empty(),
        "empty native control checkpoint"
    );
    let checkpoint = Checkpoint {
        epoch,
        txid,
        digest: digest(bytes),
        bytes: bytes.len() as u64,
    };
    put_immutable(
        bucket,
        &checkpoint_key(scope, &checkpoint.digest)?,
        bytes.to_vec(),
    )
    .await?;
    Ok(checkpoint)
}

pub(crate) async fn load_checkpoint(
    bucket: &Bucket,
    scope: &str,
    checkpoint: &Checkpoint,
) -> anyhow::Result<Vec<u8>> {
    let (body, _) = bucket
        .get(&checkpoint_key(scope, &checkpoint.digest)?)
        .await?
        .context("native control checkpoint is missing")?;
    anyhow::ensure!(
        body.len() as u64 == checkpoint.bytes && digest(&body) == checkpoint.digest,
        "native control checkpoint integrity failure"
    );
    Ok(body.to_vec())
}

impl BucketOwnership {
    pub(crate) async fn native_owner(&self, scope: &str) -> anyhow::Result<Option<Protection>> {
        Ok(read_owner(&self.bucket_client(), scope)
            .await?
            .and_then(|(owner, _)| owner.native))
    }

    /// Local dormant retirement may consume an older attachment only while
    /// this process remains the exact shared owner of the newer epoch.
    pub(crate) async fn dormant_native_owner(
        &self,
        scope: &str,
        epoch: u64,
    ) -> anyhow::Result<Option<Protection>> {
        let Some((owner, _)) = read_owner(&self.bucket_client(), scope).await? else {
            return Ok(None);
        };
        let Some(native) = owner.native else {
            return Ok(None);
        };
        anyhow::ensure!(
            owner.node == self.node_name()
                && owner.epoch == epoch
                && native.node == owner.node
                && native.epoch == epoch
                && Some(native.generation.as_str()) == self.process_generation()
                && native.closed.is_none(),
            "dormant native retirement authority changed"
        );
        if let Some(hash) = &native.restore {
            anyhow::ensure!(
                native.journal.is_empty() && native.head.as_ref() == Some(hash),
                "pending native restore is not untouched inherited state"
            );
        }
        Ok(Some(native))
    }

    pub(crate) async fn protect_native(
        &self,
        scope: &str,
        epoch: u64,
        journal: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(valid_digest(journal), "native journal identity is invalid");
        let bucket = self.bucket_client();
        let (mut owner, etag) = read_owner(&bucket, scope)
            .await?
            .context("native allocation has no owner")?;
        let generation = self
            .process_generation()
            .context("native allocation has no process generation")?;
        anyhow::ensure!(
            owner.node == self.node_name() && owner.epoch == epoch,
            "native allocation owner changed"
        );
        if let Some(native) = &mut owner.native {
            anyhow::ensure!(
                native.generation == generation
                    && native.closed.is_none()
                    && native.restore.is_none(),
                "native allocation authority or checkpoint is not settled"
            );
            if native.journal.is_empty() {
                native.journal = journal.to_string();
                return replace_owner(&bucket, scope, &etag, &owner).await;
            }
            anyhow::ensure!(
                native.journal == journal,
                "native allocation journal is not the protected journal"
            );
            return Ok(());
        }
        owner.native = Some(Protection {
            version: 1,
            node: owner.node.clone(),
            generation: generation.to_string(),
            epoch,
            journal: journal.to_string(),
            head: None,
            closed: None,
            restore: None,
        });
        replace_owner(&bucket, scope, &etag, &owner).await
    }

    pub(crate) async fn finish_native_restore(
        &self,
        scope: &str,
        epoch: u64,
        hash: &str,
    ) -> anyhow::Result<()> {
        let bucket = self.bucket_client();
        let (mut owner, etag) = read_owner(&bucket, scope)
            .await?
            .context("restored native owner is missing")?;
        anyhow::ensure!(
            owner.node == self.node_name() && owner.epoch == epoch,
            "restored native owner changed"
        );
        let native = owner
            .native
            .as_mut()
            .context("restored native protection is missing")?;
        anyhow::ensure!(
            Some(native.generation.as_str()) == self.process_generation()
                && native.head.as_deref() == Some(hash)
                && native.closed.is_none()
                && native
                    .restore
                    .as_deref()
                    .is_none_or(|pending| pending == hash),
            "restored native lineage changed"
        );
        native.restore = None;
        replace_owner(&bucket, scope, &etag, &owner).await
    }

    pub(crate) async fn release_inherited_native(
        &self,
        scope: &str,
        epoch: u64,
    ) -> anyhow::Result<Option<celld_logic::CasOutcome>> {
        let bucket = self.bucket_client();
        let (mut owner, etag) = read_owner(&bucket, scope)
            .await?
            .context("native release owner is missing")?;
        if owner.node != self.node_name() || owner.epoch != epoch {
            return Ok(Some(celld_logic::CasOutcome::Rejected));
        }
        let Some(native) = &owner.native else {
            return Ok(None);
        };
        let Some(hash) = native.restore.as_deref() else {
            return Ok(None);
        };
        anyhow::ensure!(
            Some(native.generation.as_str()) == self.process_generation()
                && native.journal.is_empty()
                && native.closed.is_none()
                && native.head.as_deref() == Some(hash),
            "native inherited release is not an untouched pending restore"
        );
        let inherited = load_closure(&bucket, scope, hash).await?;
        anyhow::ensure!(
            inherited.epoch < epoch,
            "native inherited release lineage is not monotone"
        );
        // no actor or allocation can pass the shared pending-restore gate. carry
        // its exact checkpoint into this cold epoch, without opening that gate.
        let bytes = load_checkpoint(&bucket, scope, &inherited.checkpoint).await?;
        let checkpoint =
            publish_checkpoint(&bucket, scope, epoch, inherited.checkpoint.txid, &bytes).await?;
        owner.native.as_mut().expect("checked above").restore = None;
        // clearing the restore gate and releasing are one cas. if a concurrent
        // restore completes first, this guard loses and cannot discard its work.
        self.commit_native_release(scope, owner, etag, checkpoint, Vec::new())
            .await
            .map(Some)
    }

    pub(crate) async fn release_native(
        &self,
        scope: &str,
        epoch: u64,
        checkpoint: Checkpoint,
        attempts: Vec<DestroyedAttempt>,
    ) -> anyhow::Result<celld_logic::CasOutcome> {
        let bucket = self.bucket_client();
        let (owner, etag) = read_owner(&bucket, scope)
            .await?
            .context("native release owner is missing")?;
        if owner.node != self.node_name() || owner.epoch != epoch {
            return Ok(celld_logic::CasOutcome::Rejected);
        }
        self.commit_native_release(scope, owner, etag, checkpoint, attempts)
            .await
    }

    async fn commit_native_release(
        &self,
        scope: &str,
        mut owner: OwnerWire,
        etag: String,
        checkpoint: Checkpoint,
        attempts: Vec<DestroyedAttempt>,
    ) -> anyhow::Result<celld_logic::CasOutcome> {
        let bucket = self.bucket_client();
        let epoch = owner.epoch;
        let native = owner
            .native
            .as_ref()
            .context("native release protection is missing")?;
        anyhow::ensure!(
            Some(native.generation.as_str()) == self.process_generation()
                && native.restore.is_none(),
            "native release process or restore changed"
        );
        load_checkpoint(&bucket, scope, &checkpoint).await?;
        let closure = Closure {
            version: 1,
            scope: scope.to_string(),
            node: native.node.clone(),
            generation: native.generation.clone(),
            epoch,
            journal: native.journal.clone(),
            previous: native.head.clone(),
            checkpoint,
            attempts,
        };
        certify_release(&owner, &closure)?;
        let body = serde_json::to_vec(&closure)?;
        let hash = digest(&body);
        put_immutable(&bucket, &closure_key(scope, &hash)?, body).await?;
        owner.node.clear();
        let native = owner.native.as_mut().expect("checked above");
        native.head = Some(hash.clone());
        native.closed = Some(hash);
        replace_owner(&bucket, scope, &etag, &owner).await?;
        Ok(celld_logic::CasOutcome::Applied)
    }

    pub(crate) async fn remote_attempt(
        &self,
        scope: &str,
        epoch: u64,
        id: &str,
    ) -> anyhow::Result<Option<DestroyedAttempt>> {
        let bucket = self.bucket_client();
        let (owner, _) = read_owner(&bucket, scope)
            .await?
            .context("native inspection owner is missing")?;
        anyhow::ensure!(
            owner.node == self.node_name() && owner.epoch == epoch,
            "native inspection owner changed"
        );
        let Some(native) = owner.native else {
            return Ok(None);
        };
        anyhow::ensure!(
            Some(native.generation.as_str()) == self.process_generation()
                && native.restore.is_none()
                && native.closed.is_none(),
            "native inspection checkpoint is not verified"
        );
        let mut head = native.head;
        let mut seen = BTreeSet::new();
        let mut later_epoch = epoch;
        while let Some(hash) = head {
            anyhow::ensure!(seen.insert(hash.clone()), "native closure lineage cycles");
            let closure = load_closure(&bucket, scope, &hash).await?;
            anyhow::ensure!(
                closure.epoch < later_epoch,
                "native closure lineage is not monotone"
            );
            later_epoch = closure.epoch;
            if let Some(attempt) = closure
                .attempts
                .into_iter()
                .find(|attempt| attempt.id == id)
            {
                return Ok(Some(attempt));
            }
            head = closure.previous;
        }
        Ok(None)
    }
}
