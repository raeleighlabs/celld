use super::*;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const DEADLINE: Duration = Duration::from_secs(30);
const ATTEMPT_LABEL: &str = "celld.allocation.attempt";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationOptions {
    pub id: String,
    pub image: String,
    pub engine_image: String,
    pub platform: String,
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub enable_internet: bool,
}

pub enum AllocationRequest {
    Start(AllocationOptions),
    Inspect(String),
    Destroy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationObservation {
    pub engine_image: String,
    pub platform: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationView {
    pub id: String,
    pub image: Option<String>,
    pub engine_image: Option<String>,
    pub platform: Option<String>,
    pub container_id: Option<String>,
    pub status: String,
    pub observed: Option<AllocationObservation>,
    pub reason: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u8,
    node: String,
    scope: String,
    pub(super) id: String,
    attempt: String,
    name: String,
    fingerprint: Option<String>,
    spec: ContainerSpec,
    image: Option<String>,
    engine_image: Option<String>,
    platform: Option<String>,
    container_id: Option<String>,
    create_dispatched: bool,
    create_confirmed: bool,
    #[serde(default)]
    create_rejected: bool,
    destroy_requested: bool,
    status: String,
    reason: Option<String>,
}

impl Record {
    fn view(&self, observed: Option<AllocationObservation>) -> AllocationView {
        AllocationView {
            id: self.id.clone(),
            image: self.image.clone(),
            engine_image: self.engine_image.clone(),
            platform: self.platform.clone(),
            container_id: self.container_id.clone(),
            status: self.status.clone(),
            observed,
            reason: self.reason.clone(),
        }
    }

    fn validate(&self, node: &str, scope: &str, id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1 && self.node == node && self.scope == scope && self.id == id,
            "allocation journal identity mismatch"
        );
        valid_id(&self.id)?;
        anyhow::ensure!(hex_value(&self.attempt, 64), "invalid allocation attempt");
        anyhow::ensure!(
            self.name == attempt_name(node, scope, id, &self.attempt),
            "invalid allocation name"
        );
        anyhow::ensure!(
            matches!(
                self.status.as_str(),
                "reserved"
                    | "creating"
                    | "created"
                    | "starting"
                    | "running"
                    | "exited"
                    | "failed"
                    | "unknown"
                    | "cleanupPending"
                    | "destroyed"
            ),
            "invalid allocation status"
        );
        if let Some(fingerprint) = &self.fingerprint {
            anyhow::ensure!(hex_value(fingerprint, 64), "invalid allocation fingerprint");
            valid_image(self.image.as_deref().unwrap_or(""), "celld-image:")?;
            valid_image(self.engine_image.as_deref().unwrap_or(""), "sha256:")?;
            valid_platform(self.platform.as_deref().unwrap_or(""))?;
        } else {
            anyhow::ensure!(
                self.status == "destroyed"
                    && !self.create_dispatched
                    && self.container_id.is_none(),
                "invalid allocation tombstone"
            );
        }
        if let Some(id) = &self.container_id {
            anyhow::ensure!(
                hex_value(id, 64),
                "invalid container id in allocation journal"
            );
        }
        anyhow::ensure!(
            !self.create_confirmed || (self.create_dispatched && self.container_id.is_some()),
            "invalid create confirmation"
        );
        anyhow::ensure!(
            self.status != "destroyed"
                || !self.create_dispatched
                || self.create_confirmed
                || self.create_rejected,
            "unsettled create cannot be destroyed"
        );
        anyhow::ensure!(
            !self.create_rejected
                || (self.create_dispatched
                    && !self.create_confirmed
                    && self.container_id.is_none()),
            "invalid create rejection"
        );
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_value(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn valid_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id.as_bytes()[0].is_ascii_alphanumeric()
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
        "allocation id must be a bounded identifier"
    );
    Ok(())
}

fn valid_image(image: &str, prefix: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        image
            .strip_prefix(prefix)
            .is_some_and(|value| hex_value(value, 64)),
        "allocation image must be immutable"
    );
    Ok(())
}

fn valid_platform(platform: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(platform, "linux/amd64" | "linux/arm64"),
        "unsupported allocation platform"
    );
    Ok(())
}

impl AllocationOptions {
    fn normalise(&mut self) -> anyhow::Result<()> {
        valid_id(&self.id)?;
        valid_image(&self.image, "celld-image:")?;
        valid_image(&self.engine_image, "sha256:")?;
        valid_platform(&self.platform)?;
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= 65536,
            "allocation options exceed 64 KiB"
        );
        self.env.sort();
        for (index, (name, value)) in self.env.iter().enumerate() {
            anyhow::ensure!(
                !name.is_empty() && !name.contains(['=', '\0']) && !value.contains('\0'),
                "invalid allocation environment"
            );
            anyhow::ensure!(
                index == 0 || self.env[index - 1].0 != *name,
                "duplicate allocation environment name"
            );
        }
        if let Some(entrypoint) = &self.entrypoint {
            anyhow::ensure!(
                entrypoint.iter().all(|value| !value.contains('\0')),
                "invalid allocation entrypoint"
            );
        }
        Ok(())
    }
}

fn attempt_name(node: &str, scope: &str, id: &str, attempt: &str) -> String {
    let bytes = serde_json::to_vec(&(node, scope, id, attempt)).expect("string tuple serialises");
    format!("celld-allocation-{:x}", Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    node: String,
    key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyCleanup {
    pub(super) epoch: u64,
    pub(super) serial: u64,
    pub(super) run: u64,
}

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(super) enum LegacyAdmission {
    Execute,
    EmptyDestroy,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyRecord {
    pub(super) scope: String,
    pub(super) spec: ContainerSpec,
    pub(super) target: Option<String>,
    pub(super) phase: String,
    #[serde(default)]
    pub(super) cleanup: Option<LegacyCleanup>,
}

impl LegacyRecord {
    fn validate(&self, scope: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.scope == scope, "legacy scope identity mismatch");
        anyhow::ensure!(
            matches!(
                self.phase.as_str(),
                "idle" | "preparing" | "creating" | "starting" | "running" | "deleting"
            ),
            "invalid legacy phase"
        );
        anyhow::ensure!(
            self.target.as_deref().is_none_or(|id| hex_value(id, 64)),
            "invalid legacy target"
        );
        anyhow::ensure!(
            match self.phase.as_str() {
                "idle" | "creating" => self.target.is_none(),
                "starting" | "running" | "deleting" => self.target.is_some(),
                _ => true,
            },
            "legacy phase and target disagree"
        );
        Ok(())
    }
}

pub(super) struct Journal {
    connection: Mutex<Connection>,
    path: PathBuf,
    marker_path: PathBuf,
    marker: Vec<u8>,
    inode: (u64, u64),
    node: String,
    key: Vec<u8>,
    _lock: File,
}

impl Journal {
    // This host journal binds SQLite to real inode identities and an OS flock.
    // Its lock and fsync operations must use the same physical filesystem.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn open(dir: &Path, node: &str) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let lock_path = dir.join("container-allocations.lock");
        let old_lock = lock_path.try_exists()?;
        let database_exists = dir.join("container-allocations.sqlite").try_exists()?;
        let marker_exists = dir.join("container-allocations.expected").try_exists()?;
        anyhow::ensure!(
            (!old_lock && !database_exists && !marker_exists)
                || (old_lock && database_exists && marker_exists),
            "allocation initialisation evidence exists but expected state is missing"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!old_lock)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        if !old_lock {
            lock.sync_all()?;
            File::open(dir)?.sync_all()?;
        }
        // the node's local journal has one executor, including during engine recreation.
        anyhow::ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "allocation journal is already owned by another engine"
        );
        let path = dir.join("container-allocations.sqlite");
        let marker_path = dir.join("container-allocations.expected");
        let exists = path.try_exists()?;
        let expected = marker_path.try_exists()?;
        anyhow::ensure!(
            exists == expected && exists == database_exists && expected == marker_exists,
            "allocation journal or expected-state marker is missing or changed"
        );
        let marker = if expected {
            std::fs::read(&marker_path)?
        } else {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|_| anyhow!("allocation randomness unavailable"))?;
            let bytes = serde_json::to_vec(&Marker {
                version: 1,
                node: node.to_owned(),
                key: encode_hex(&key),
            })?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&marker_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            File::open(dir)?.sync_all()?;
            bytes
        };
        let decoded: Marker =
            serde_json::from_slice(&marker).context("invalid allocation marker")?;
        anyhow::ensure!(
            decoded.version == 1 && decoded.node == node && hex_value(&decoded.key, 64),
            "allocation marker identity mismatch"
        );
        if !exists {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .sync_all()?;
        }
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;")?;
        if !exists {
            connection.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE identity (version INTEGER PRIMARY KEY CHECK(version=1), node TEXT NOT NULL, root BLOB NOT NULL);
                CREATE TABLE scopes (scope TEXT PRIMARY KEY, mode TEXT NOT NULL);
                CREATE TABLE legacy_owned (scope TEXT PRIMARY KEY, body BLOB NOT NULL);
                CREATE TABLE attempts (scope TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, mac BLOB NOT NULL, PRIMARY KEY(scope, id));
                COMMIT;")?;
            connection.execute("INSERT INTO identity VALUES (1, ?1, X'')", [node])?;
            File::open(dir)?.sync_all()?;
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        anyhow::ensure!(integrity == "ok", "allocation journal is corrupt");
        let identity: (u8, String) =
            connection.query_row("SELECT version, node FROM identity", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        anyhow::ensure!(
            identity == (1, node.to_string()),
            "allocation journal identity mismatch"
        );
        let metadata = std::fs::metadata(&path)?;
        let journal = Self {
            connection: Mutex::new(connection),
            path,
            marker_path,
            marker,
            inode: (metadata.dev(), metadata.ino()),
            node: node.to_string(),
            key: crate::engine_api::decode_durable_object_id(&decoded.key)
                .ok_or_else(|| anyhow!("invalid allocation marker key"))?
                .to_vec(),
            _lock: lock,
        };
        if !exists {
            journal.seal(&journal.connection.lock().unwrap())?;
        }
        let legacy_records = journal.legacy_records(&journal.connection.lock().unwrap())?;
        for mut record in legacy_records {
            if record.phase == "preparing" {
                record.phase = if record.target.is_some() {
                    "running"
                } else {
                    "idle"
                }
                .to_string();
                journal.save_legacy(&mut record)?;
            }
        }
        for mut record in journal.all()? {
            if record.status == "reserved" {
                record.status = "failed".to_string();
                record.reason = Some("interruptedBeforeCreate".to_string());
                journal.save(&mut record)?;
            }
        }
        Ok(journal)
    }

    #[allow(clippy::disallowed_methods)] // Compare the live inode to the held OS lock.
    pub(super) fn check(&self) -> anyhow::Result<()> {
        let metadata = std::fs::metadata(&self.path).context("allocation journal is missing")?;
        let lock = self._lock.metadata()?;
        let expected_lock =
            std::fs::metadata(self.path.with_file_name("container-allocations.lock"))?;
        anyhow::ensure!(
            (lock.dev(), lock.ino()) == (expected_lock.dev(), expected_lock.ino()),
            "allocation journal lock was replaced"
        );
        anyhow::ensure!(
            (metadata.dev(), metadata.ino()) == self.inode
                && std::fs::read(&self.marker_path)? == self.marker,
            "allocation journal was replaced"
        );
        Ok(())
    }

    fn mac(&self, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts a 32-byte key");
        mac.update(domain);
        mac.update(bytes);
        mac.finalize().into_bytes().to_vec()
    }

    fn snapshot_mac(&self, connection: &Connection) -> anyhow::Result<Vec<u8>> {
        let mut statement = connection.prepare("SELECT 'scope', scope, mode, X'', X'' FROM scopes UNION ALL SELECT 'attempt', scope, id, body, mac FROM attempts UNION ALL SELECT 'legacy', scope, '', body, X'' FROM legacy_owned ORDER BY 1, 2, 3")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut hash = Sha256::new();
        for row in rows {
            hash.update(serde_json::to_vec(&row?)?);
            hash.update(b"\n");
        }
        Ok(self.mac(b"allocation-journal-v1", &hash.finalize()))
    }

    fn seal(&self, connection: &Connection) -> anyhow::Result<()> {
        let root = self.snapshot_mac(connection)?;
        anyhow::ensure!(
            connection.execute("UPDATE identity SET root=?1 WHERE version=1", [root])? == 1,
            "allocation journal identity missing"
        );
        Ok(())
    }

    fn verify_seal(&self, connection: &Connection) -> anyhow::Result<()> {
        let root: Vec<u8> =
            connection.query_row("SELECT root FROM identity WHERE version=1", [], |row| {
                row.get(0)
            })?;
        anyhow::ensure!(
            root == self.snapshot_mac(connection)?,
            "allocation journal records are missing or corrupt"
        );
        Ok(())
    }

    fn decode(
        &self,
        scope: String,
        id: String,
        body: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<Record> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts a 32-byte key");
        mac.update(b"allocation-record-v1");
        mac.update(&body);
        mac.verify_slice(&signature)
            .map_err(|_| anyhow!("allocation record integrity failure"))?;
        let record: Record = serde_json::from_slice(&body).context("invalid allocation record")?;
        record.validate(&self.node, &scope, &id)?;
        Ok(record)
    }

    pub(super) fn identity(&self) -> anyhow::Result<String> {
        self.check()?;
        Ok(crate::native_handoff::digest(&self.marker))
    }

    pub(super) fn closed_attempts(
        &self,
        scope: &str,
    ) -> anyhow::Result<Vec<crate::native_handoff::DestroyedAttempt>> {
        self.check()?;
        let connection = self.connection.lock().unwrap();
        self.records(&connection)?
            .into_iter()
            .filter(|record| record.scope == scope)
            .map(|record| {
                anyhow::ensure!(
                    record.status == "destroyed",
                    "native allocation remains unresolved at handoff"
                );
                Ok(crate::native_handoff::DestroyedAttempt {
                    id: record.id,
                    attempt: record.attempt,
                    fingerprint: record.fingerprint,
                    container_id: record.container_id,
                    image: record.image,
                    engine_image: record.engine_image,
                    platform: record.platform,
                })
            })
            .collect()
    }

    fn records(&self, connection: &Connection) -> anyhow::Result<Vec<Record>> {
        self.verify_seal(connection)?;
        let mut statement = connection.prepare("SELECT scope, id, body, mac FROM attempts")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (scope, id, body, mac) = row?;
            let record = self.decode(scope, id, body, mac)?;
            anyhow::ensure!(
                Self::mode(connection, &record.scope)?.as_deref() == Some("native"),
                "allocation scope record is missing"
            );
            anyhow::ensure!(
                record.status == "destroyed"
                    || !records
                        .iter()
                        .any(|other: &Record| other.scope == record.scope
                            && other.status != "destroyed"),
                "overlapping allocation records"
            );
            records.push(record);
        }
        Ok(records)
    }

    pub(super) fn commitments(&self) -> anyhow::Result<Vec<ContainerSpec>> {
        self.check()?;
        let connection = self.connection.lock().unwrap();
        // one sealed snapshot includes both pending and confirmed ownership, once per scope.
        let mut scopes = std::collections::BTreeMap::new();
        for record in self.records(&connection)? {
            if record.status != "destroyed" {
                scopes.insert(record.scope, record.spec);
            }
        }
        for record in self.legacy_records(&connection)? {
            if record.phase != "idle" {
                anyhow::ensure!(
                    scopes.insert(record.scope, record.spec).is_none(),
                    "overlapping container commitments"
                );
            }
        }
        Ok(scopes.into_values().collect())
    }

    pub(super) fn legacy_pending(&self, scope: &str) -> anyhow::Result<bool> {
        Ok(self.legacy_record(scope)?.is_some_and(|record| {
            record.cleanup.is_some() || !matches!(record.phase.as_str(), "idle" | "running")
        }))
    }

    pub(super) fn validate_inventory(&self, entry: &Value) -> anyhow::Result<()> {
        let labels = &entry["Labels"];
        let scope = labels["celld.cell"]
            .as_str()
            .ok_or_else(|| anyhow!("allocation inventory scope missing"))?;
        let id = labels["celld.allocation.id"]
            .as_str()
            .ok_or_else(|| anyhow!("allocation inventory id missing"))?;
        let record = self
            .get(scope, id)?
            .ok_or_else(|| anyhow!("allocation inventory has no expected record"))?;
        anyhow::ensure!(
            labels["celld.node"].as_str() == Some(self.node.as_str())
                && labels[ATTEMPT_LABEL].as_str() == Some(record.attempt.as_str())
                && labels["celld.class"].as_str() == Some(record.spec.class_name.as_str())
                && record
                    .container_id
                    .as_deref()
                    .is_none_or(|id| entry["Id"].as_str() == Some(id))
                && record.status != "destroyed",
            "allocation inventory ownership mismatch"
        );
        Ok(())
    }

    pub(super) fn all(&self) -> anyhow::Result<Vec<Record>> {
        self.check()?;
        self.records(&self.connection.lock().unwrap())
    }

    pub(super) fn active(&self, scope: &str) -> anyhow::Result<Option<Record>> {
        Ok(self
            .all()?
            .into_iter()
            .find(|record| record.scope == scope && record.status != "destroyed"))
    }

    fn get(&self, scope: &str, id: &str) -> anyhow::Result<Option<Record>> {
        Ok(self
            .all()?
            .into_iter()
            .find(|record| record.scope == scope && record.id == id))
    }

    fn mode(connection: &Connection, scope: &str) -> anyhow::Result<Option<String>> {
        let mode: Option<String> = connection
            .query_row("SELECT mode FROM scopes WHERE scope=?1", [scope], |row| {
                row.get(0)
            })
            .optional()?;
        anyhow::ensure!(
            mode.as_deref()
                .is_none_or(|mode| matches!(mode, "native" | "legacy")),
            "invalid allocation scope mode"
        );
        Ok(mode)
    }

    pub(super) fn native_scope(&self, scope: &str) -> anyhow::Result<bool> {
        self.check()?;
        let connection = self.connection.lock().unwrap();
        self.records(&connection)?;
        Ok(Self::mode(&connection, scope)?.as_deref() == Some("native"))
    }

    pub(super) fn claim_legacy(&self, scope: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.legacy_pending(scope)?,
            "legacy operation outcome remains unresolved"
        );
        self.check()?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        self.records(&tx)?;
        anyhow::ensure!(
            Self::mode(&tx, scope)?.as_deref() != Some("native"),
            "legacy start is refused for an allocation scope"
        );
        tx.execute(
            "INSERT OR IGNORE INTO scopes VALUES (?1, 'legacy')",
            [scope],
        )?;
        self.seal(&tx)?;
        tx.commit()?;
        Ok(())
    }

    fn legacy_records(&self, connection: &Connection) -> anyhow::Result<Vec<LegacyRecord>> {
        self.verify_seal(connection)?;
        let mut statement = connection.prepare("SELECT scope, body FROM legacy_owned")?;
        let mut records = Vec::new();
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })? {
            let (scope, body) = row?;
            let record: LegacyRecord = serde_json::from_slice(&body)?;
            record.validate(&scope)?;
            anyhow::ensure!(
                Self::mode(connection, &scope)?.as_deref() == Some("legacy"),
                "legacy ownership mode missing"
            );
            records.push(record);
        }
        Ok(records)
    }

    pub(super) fn legacy_record(&self, scope: &str) -> anyhow::Result<Option<LegacyRecord>> {
        self.check()?;
        Ok(self
            .legacy_records(&self.connection.lock().unwrap())?
            .into_iter()
            .find(|record| record.scope == scope))
    }

    pub(super) fn save_legacy(&self, record: &mut LegacyRecord) -> anyhow::Result<()> {
        self.check()?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        self.save_legacy_in(&tx, record)?;
        tx.commit()?;
        Ok(())
    }

    fn save_legacy_in(
        &self,
        connection: &Connection,
        record: &mut LegacyRecord,
    ) -> anyhow::Result<()> {
        record.validate(&record.scope)?;
        self.records(connection)?;
        if let Some(current) = self
            .legacy_records(connection)?
            .into_iter()
            .find(|old| old.scope == record.scope)
        {
            // synchronous cleanup requests must survive progress saved from an older snapshot.
            record.cleanup = current.cleanup.or(record.cleanup.take());
        }
        if record.phase == "idle" {
            // only a confirmed target teardown or a definite pre-create failure settles intent.
            record.cleanup = None;
        }
        anyhow::ensure!(
            Self::mode(connection, &record.scope)?.as_deref() != Some("native"),
            "legacy operation refused for native scope"
        );
        connection.execute(
            "INSERT OR IGNORE INTO scopes VALUES (?1, 'legacy')",
            [&record.scope],
        )?;
        connection.execute("INSERT INTO legacy_owned VALUES (?1, ?2) ON CONFLICT(scope) DO UPDATE SET body=excluded.body", params![record.scope, serde_json::to_vec(record)?])?;
        self.seal(connection)
    }

    pub(super) fn request_legacy_cleanup(
        &self,
        scope: &str,
        owner: LegacyCleanup,
    ) -> anyhow::Result<()> {
        self.check()?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        anyhow::ensure!(
            Self::mode(&tx, scope)?.as_deref() != Some("native"),
            "legacy cleanup refused for native scope"
        );
        if let Some(mut record) = self
            .legacy_records(&tx)?
            .into_iter()
            .find(|record| record.scope == scope)
        {
            if record.phase != "idle" {
                // retain the phase and target, especially an unacknowledged create.
                record.cleanup.get_or_insert(owner);
                tx.execute(
                    "UPDATE legacy_owned SET body=?2 WHERE scope=?1",
                    params![scope, serde_json::to_vec(&record)?],
                )?;
                self.seal(&tx)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn begin_legacy_operation(
        &self,
        cell: &CellContainer,
        operation: &LegacyOperation,
    ) -> anyhow::Result<LegacyAdmission> {
        self.check()?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        // Absence is authoritative only in one fully validated, sealed snapshot.
        // The caller holds the registry and per-cell lifecycle admission locks.
        let attempts = self.records(&tx)?;
        let legacy = self
            .legacy_records(&tx)?
            .into_iter()
            .find(|record| record.scope == cell.scope);
        let mode = Self::mode(&tx, &cell.scope)?;
        anyhow::ensure!(
            mode.as_deref() != Some("native"),
            "legacy operation refused for native scope"
        );
        if matches!(operation, LegacyOperation::Destroy { .. }) && mode.is_none() {
            anyhow::ensure!(
                legacy.is_none() && !attempts.iter().any(|record| record.scope == cell.scope),
                "unclaimed scope has container operation evidence"
            );
            tx.commit()?;
            return Ok(LegacyAdmission::EmptyDestroy);
        }
        let mut record = legacy.unwrap_or(LegacyRecord {
            scope: cell.scope.clone(),
            spec: (*cell.spec).clone(),
            target: None,
            phase: "idle".to_string(),
            cleanup: None,
        });
        anyhow::ensure!(
            record.spec.class_name == cell.spec.class_name,
            "legacy class mismatch"
        );
        if matches!(operation, LegacyOperation::Start { .. }) {
            anyhow::ensure!(
                record.cleanup.is_none() && matches!(record.phase.as_str(), "idle" | "running"),
                "legacy operation outcome remains unresolved"
            );
            if record.target.is_none() {
                record.spec = (*cell.spec).clone();
            }
            record.phase = "preparing".to_string();
        } else {
            anyhow::ensure!(
                record.phase != "creating",
                "legacy create outcome remains unresolved"
            );
            record.phase = if record.target.is_some() {
                "deleting"
            } else {
                "idle"
            }
            .to_string();
        }
        self.save_legacy_in(&tx, &mut record)?;
        tx.commit()?;
        Ok(LegacyAdmission::Execute)
    }

    pub(super) fn finish_legacy_preparation(&self, scope: &str) -> anyhow::Result<()> {
        let Some(mut record) = self.legacy_record(scope)? else {
            return Ok(());
        };
        if record.phase == "preparing" {
            record.phase = if record.target.is_some() {
                "running"
            } else {
                "idle"
            }
            .to_string();
            self.save_legacy(&mut record)?;
        }
        Ok(())
    }

    pub(super) fn record_legacy(&self, scope: &str, class: &str, id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(hex_value(id, 64), "legacy create returned an invalid id");
        let mut record = self
            .legacy_record(scope)?
            .ok_or_else(|| anyhow!("legacy create intent missing"))?;
        anyhow::ensure!(
            record.phase == "creating"
                && record.target.is_none()
                && record.spec.class_name == class,
            "legacy create intent mismatch"
        );
        record.target = Some(id.to_string());
        record.phase = "starting".to_string();
        self.save_legacy(&mut record)
    }

    pub(super) fn owns_legacy(&self, scope: &str, class: &str, id: &str) -> anyhow::Result<bool> {
        Ok(self.legacy_record(scope)?.is_some_and(|record| {
            record.spec.class_name == class && record.target.as_deref() == Some(id)
        }))
    }

    fn put(&self, connection: &Connection, record: &Record) -> anyhow::Result<()> {
        record.validate(&self.node, &record.scope, &record.id)?;
        let body = serde_json::to_vec(record)?;
        let mac = self.mac(b"allocation-record-v1", &body);
        connection.execute("INSERT INTO attempts VALUES (?1, ?2, ?3, ?4) ON CONFLICT(scope, id) DO UPDATE SET body=excluded.body, mac=excluded.mac",
            params![record.scope, record.id, body, mac])?;
        Ok(())
    }

    fn save(&self, record: &mut Record) -> anyhow::Result<()> {
        self.check()?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        let current = self
            .records(&tx)?
            .into_iter()
            .find(|old| old.scope == record.scope && old.id == record.id)
            .ok_or_else(|| anyhow!("allocation record is missing"))?;
        record.destroy_requested |= current.destroy_requested;
        if record.destroy_requested && !matches!(record.status.as_str(), "destroyed" | "unknown") {
            record.status = "cleanupPending".to_string();
        }
        self.put(&tx, record)?;
        self.seal(&tx)?;
        tx.commit()?;
        Ok(())
    }

    fn reserve(
        &self,
        cell: &CellContainer,
        options: Option<&AllocationOptions>,
        id: &str,
        policy: &Value,
    ) -> anyhow::Result<bool> {
        valid_id(id)?;
        self.check()?;
        let fingerprint = options
            .map(|options| serde_json::to_vec(&(options, &*cell.spec, policy)))
            .transpose()?
            .map(|bytes| encode_hex(&self.mac(b"allocation-request-v1", &bytes)));
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        anyhow::ensure!(
            Self::mode(&tx, &cell.scope)?.as_deref() != Some("legacy"),
            "allocation API requires a scope not previously started by the legacy API"
        );
        let records = self.records(&tx)?;
        if let Some(record) = records
            .iter()
            .find(|record| record.scope == cell.scope && record.id == id)
        {
            if options.is_some() {
                anyhow::ensure!(record.fingerprint == fingerprint, "allocation id was already used with different inputs or destroyed before start");
            }
            if options.is_none() && record.status != "destroyed" {
                let mut record = record.clone();
                record.destroy_requested = true;
                record.status = "cleanupPending".to_string();
                self.put(&tx, &record)?;
                self.seal(&tx)?;
                tx.commit()?;
            }
            return Ok(false);
        }
        if options.is_some() {
            anyhow::ensure!(
                !records
                    .iter()
                    .any(|record| record.scope == cell.scope && record.status != "destroyed"),
                "another allocation remains unresolved"
            );
        }
        let mut attempt = [0u8; 32];
        getrandom::fill(&mut attempt).map_err(|_| anyhow!("allocation randomness unavailable"))?;
        let attempt = encode_hex(&attempt);
        let record = Record {
            version: 1,
            node: self.node.clone(),
            scope: cell.scope.clone(),
            id: id.to_string(),
            name: attempt_name(&self.node, &cell.scope, id, &attempt),
            attempt,
            fingerprint,
            spec: (*cell.spec).clone(),
            image: options.map(|o| o.image.clone()),
            engine_image: options.map(|o| o.engine_image.clone()),
            platform: options.map(|o| o.platform.clone()),
            container_id: None,
            create_dispatched: false,
            create_confirmed: false,
            create_rejected: false,
            destroy_requested: options.is_none(),
            status: if options.is_some() {
                "reserved"
            } else {
                "destroyed"
            }
            .to_string(),
            reason: None,
        };
        tx.execute(
            "INSERT OR IGNORE INTO scopes VALUES (?1, 'native')",
            [&cell.scope],
        )?;
        self.put(&tx, &record)?;
        self.seal(&tx)?;
        tx.commit()?;
        Ok(true)
    }
}

impl ContainerEngine {
    pub(crate) fn native_journal_identity(&self) -> anyhow::Result<String> {
        self.allocations.identity()
    }

    pub fn native_scope(&self, scope: &str) -> anyhow::Result<bool> {
        self.allocations.native_scope(scope)
    }

    pub fn with_legacy_cell<T>(
        &self,
        scope: &str,
        use_cell: impl FnOnce(&CellContainer) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let cells = self.cells.lock().unwrap();
        let cell = cells
            .get(scope)
            .ok_or_else(|| anyhow!("container is detached"))?;
        self.refuse_native_legacy(cell)?;
        use_cell(cell)
    }

    pub fn with_allocation_event_cell<T>(
        &self,
        scope: &str,
        epoch: Option<u64>,
        use_cell: impl FnOnce(&CellContainer) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let cells = self.cells.lock().unwrap();
        let cell = cells
            .get(scope)
            .ok_or_else(|| anyhow!("allocation cell is detached"))?;
        self.authorise_allocation_epoch(cell, epoch)?;
        use_cell(cell)
    }

    pub fn refuse_native_legacy(&self, cell: &CellContainer) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.allocations.native_scope(&cell.scope)?,
            "legacy operation is unavailable for native allocations; use the attempt-specific API"
        );
        Ok(())
    }

    pub(super) fn request_allocation_cleanup(
        &self,
        cell: &CellContainer,
        id: &str,
    ) -> anyhow::Result<()> {
        self.allocations.reserve(cell, None, id, &Value::Null)?;
        Ok(())
    }

    pub fn authorise_allocation_epoch(
        &self,
        cell: &CellContainer,
        epoch: Option<u64>,
    ) -> anyhow::Result<()> {
        let state = cell.state.lock().unwrap();
        anyhow::ensure!(
            state.activation_serial != 0
                && state.allocation_admitted
                && !state.activation_pending
                && epoch == Some(state.activation_epoch),
            "allocation event epoch is stale, missing or pending"
        );
        Ok(())
    }

    pub fn legacy_start_admission(&self, cell: &CellContainer) -> anyhow::Result<()> {
        let _cells = self.cells.lock().unwrap();
        let state = cell.state.lock().unwrap();
        anyhow::ensure!(
            state.allocation_admitted && !state.activation_pending,
            "legacy admission closed by ownership release or pending activation"
        );
        self.allocations.claim_legacy(&cell.scope)
    }

    pub fn allocation_request_from_event(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        request: AllocationRequest,
        epoch: Option<u64>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>> {
        let epoch = epoch.ok_or_else(|| anyhow!("allocation event epoch is missing"))?;
        self.allocation_request_inner(cell, request, Some(epoch))
    }

    pub fn allocation_request(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        request: AllocationRequest,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>> {
        self.allocation_request_inner(cell, request, None)
    }

    // fleet admission is owned before its first await. the shared marker precedes
    // reservation, and the exact activation is checked again after publication.
    fn allocation_request_inner(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        request: AllocationRequest,
        epoch: Option<u64>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>> {
        let ownership = if self.bucket.is_some() {
            Some(
                crate::native_handoff::ownership()
                    .context("native shared ownership is not configured")?,
            )
        } else {
            None
        };
        #[cfg(test)]
        let ownership = self
            .native_ownership_for_test
            .lock()
            .unwrap()
            .clone()
            .or(ownership);
        let Some(ownership) = ownership else {
            return self.allocation_request_admitted(cell, request, epoch);
        };
        if epoch.is_none() && !matches!(&request, AllocationRequest::Start(_)) {
            return self.allocation_request_admitted(cell, request, epoch);
        }
        anyhow::ensure!(
            ownership.node_name() == self.node,
            "native ownership adapter belongs to another node"
        );
        let (serial, owner_epoch) = {
            let _cells = self.cells.lock().unwrap();
            if let Some(epoch) = epoch {
                self.authorise_allocation_epoch(&cell, Some(epoch))?;
            }
            let state = cell.state.lock().unwrap();
            (state.activation_serial, state.activation_epoch)
        };
        let shared_permit = self
            .allocation_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("native shared admission queue is full"))?;
        let engine = self.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        asyncrt::spawn(async move {
            let result = asyncrt::timeout(crate::native_handoff::DEADLINE, async {
                let id = match &request {
                    AllocationRequest::Start(options) => {
                        ownership
                            .protect_native(
                                &cell.scope,
                                owner_epoch,
                                &engine.native_journal_identity()?,
                            )
                            .await?;
                        &options.id
                    }
                    AllocationRequest::Destroy(id) => {
                        ownership
                            .protect_native(
                                &cell.scope,
                                owner_epoch,
                                &engine.native_journal_identity()?,
                            )
                            .await?;
                        id
                    }
                    AllocationRequest::Inspect(id) => id,
                };
                let remote = ownership
                    .remote_attempt(&cell.scope, owner_epoch, id)
                    .await?;
                {
                    let _cells = engine.cells.lock().unwrap();
                    engine.authorise_allocation_epoch(&cell, Some(owner_epoch))?;
                    anyhow::ensure!(
                        cell.state.lock().unwrap().activation_serial == serial,
                        "native allocation activation changed during shared admission"
                    );
                }
                if let Some(remote) = remote {
                    anyhow::ensure!(
                        !matches!(&request, AllocationRequest::Start(_)),
                        "certified remote allocation id cannot be reused"
                    );
                    return Ok(AllocationView {
                        id: remote.id,
                        image: remote.image,
                        engine_image: remote.engine_image,
                        platform: remote.platform,
                        container_id: remote.container_id,
                        status: "destroyed".to_string(),
                        observed: None,
                        reason: None,
                    });
                }
                // the admitted helper repeats its checks while holding the registry lock.
                drop(shared_permit);
                engine
                    .allocation_request_admitted_serial(cell, request, epoch, Some(serial))?
                    .await
                    .map_err(|_| anyhow!("native allocation owner stopped"))?
            })
            .await
            .map_err(|_| anyhow!("native shared admission deadline exceeded"))
            .and_then(|result| result);
            let _ = sender.send(result);
        })
        .detach();
        Ok(receiver)
    }

    fn allocation_request_admitted(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        request: AllocationRequest,
        epoch: Option<u64>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>> {
        self.allocation_request_admitted_serial(cell, request, epoch, None)
    }

    // local reservation remains synchronous and owns cleanup before dispatch.
    fn allocation_request_admitted_serial(
        self: &Arc<Self>,
        cell: Arc<CellContainer>,
        mut request: AllocationRequest,
        epoch: Option<u64>,
        expected_serial: Option<u64>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<AllocationView>>> {
        let mut permit = None;
        let policy = json!({ "runtime": self.runtime, "dns": self.dns });
        let (fresh, activation_serial) = {
            let cells = self.cells.lock().unwrap();
            anyhow::ensure!(
                cells
                    .get(&cell.scope)
                    .is_some_and(|current| Arc::ptr_eq(current, &cell)),
                "allocation cell handle is no longer attached"
            );
            // attach holds the same registry lock while changing the activation.
            if let Some(epoch) = epoch {
                self.authorise_allocation_epoch(&cell, Some(epoch))?;
            }
            let activation_serial = cell.state.lock().unwrap().activation_serial;
            anyhow::ensure!(
                expected_serial.is_none_or(|serial| serial == activation_serial),
                "native allocation activation changed before reservation"
            );
            let fresh = match &mut request {
                AllocationRequest::Start(options) => {
                    options.normalise()?;
                    permit = Some(
                        self.allocation_slots
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| anyhow!("allocation operation queue is full"))?,
                    );
                    let mut state = cell.state.lock().unwrap();
                    anyhow::ensure!(
                        state.allocation_admitted && !state.activation_pending,
                        "allocation admission closed by ownership release or pending activation"
                    );
                    let fresh =
                        self.allocations
                            .reserve(&cell, Some(options), &options.id, &policy)?;
                    if let Some(cancel) = state.allocation_sweeper.take() {
                        cancel.cancel();
                    }
                    state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
                    fresh
                }
                AllocationRequest::Destroy(id) => {
                    self.allocations.reserve(&cell, None, id, &policy)?
                }
                AllocationRequest::Inspect(id) => {
                    valid_id(id)?;
                    false
                }
            };
            (fresh, activation_serial)
        };
        // destroy intent is durable even if admission or the execution deadline refuses work.
        let permit = match permit {
            Some(permit) => permit,
            None => self
                .allocation_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow!("allocation operation queue is full"))?,
        };
        let engine = self.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        asyncrt::spawn(async move {
            let _permit = permit;
            let _guard =
                match asyncrt::timeout(engine.allocation_wait, engine.lifecycle.lock()).await {
                    Ok(guard) => guard,
                    Err(_) => {
                        let _ = sender
                            .send(Err(anyhow!("allocation operation queue deadline exceeded")));
                        return;
                    }
                };
            let result = match request {
                AllocationRequest::Start(options) => {
                    if cell.state.lock().unwrap().activation_serial != activation_serial && !fresh {
                        Err(anyhow!("stale allocation replay has no cleanup authority"))
                    } else if cell.state.lock().unwrap().activation_serial != activation_serial {
                        match engine.request_allocation_cleanup(&cell, &options.id) {
                            Ok(()) => engine.destroy_allocation_locked(&cell, &options.id).await,
                            Err(error) => Err(error),
                        }
                    } else {
                        engine.start_allocation_locked(&cell, options, fresh).await
                    }
                }
                AllocationRequest::Inspect(id) => match engine.allocations.get(&cell.scope, &id) {
                    Ok(Some(record)) => engine.observe_allocation(&cell, record).await,
                    Ok(None) => Err(anyhow!("allocation id is unknown")),
                    Err(error) => Err(error),
                },
                AllocationRequest::Destroy(id) => {
                    engine.destroy_allocation_locked(&cell, &id).await
                }
            };
            let _ = sender.send(result);
        })
        .detach();
        Ok(receiver)
    }

    pub(super) async fn allocation_call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<crate::docker::Reply> {
        // a timeout is uncertainty, not cancellation of a daemon operation.
        asyncrt::timeout(
            self.allocation_wait,
            self.docker.call_bounded(method, path, body, 1024 * 1024),
        )
        .await
        .map_err(|_| anyhow!("allocation Docker deadline exceeded"))?
        .map_err(|_| anyhow!("allocation Docker transport unavailable"))
    }

    async fn verify_image(
        &self,
        image: &str,
        engine_image: &str,
        platform: &str,
    ) -> anyhow::Result<()> {
        let reply = self
            .allocation_call("GET", &format!("/images/{image}/json"), None)
            .await?;
        anyhow::ensure!(reply.status.is_success(), "allocation image unavailable");
        let info = reply
            .json()
            .map_err(|_| anyhow!("invalid image inspection"))?;
        anyhow::ensure!(
            info.get("Id").and_then(Value::as_str) == Some(engine_image),
            "allocation engine image mismatch"
        );
        let observed = format!(
            "{}/{}",
            info["Os"].as_str().unwrap_or(""),
            info["Architecture"].as_str().unwrap_or("")
        );
        anyhow::ensure!(observed == platform, "allocation platform mismatch");
        Ok(())
    }

    async fn start_allocation_locked(
        &self,
        cell: &Arc<CellContainer>,
        options: AllocationOptions,
        fresh: bool,
    ) -> anyhow::Result<AllocationView> {
        let mut record = self
            .allocations
            .get(&cell.scope, &options.id)?
            .ok_or_else(|| anyhow!("allocation reservation is missing"))?;
        if record.destroy_requested && record.status != "destroyed" {
            return self.destroy_allocation_locked(cell, &record.id).await;
        }
        if !fresh || record.status != "reserved" {
            return self.observe_allocation(cell, record).await;
        }
        if self.require_verified_fence().is_err() {
            record.status = "failed".to_string();
            record.reason = Some("fenceNotVerified".to_string());
            self.allocations.save(&mut record)?;
            return Ok(record.view(None));
        }
        let preparation = async {
            let legacy = self
                .allocation_call("GET", &format!("/containers/{}/json", cell.name), None)
                .await?;
            anyhow::ensure!(
                legacy.status.as_u16() == 404,
                "legacy container absence is not confirmed"
            );
            self.verify_image(&options.image, &options.engine_image, &options.platform)
                .await?;
            self.verify_image(
                &options.engine_image,
                &options.engine_image,
                &options.platform,
            )
            .await?;

            asyncrt::timeout(DEADLINE, self.enforce_instance_ceiling(cell))
                .await
                .map_err(|_| anyhow!("allocation capacity deadline exceeded"))??;
            asyncrt::timeout(DEADLINE, self.networks())
                .await
                .map_err(|_| anyhow!("allocation network deadline exceeded"))?
        }
        .await;
        let (open, internal) = match preparation {
            Ok(networks) => networks,
            Err(_) => {
                record.status = "failed".to_string();
                record.reason = Some("preparationFailed".to_string());
                self.allocations.save(&mut record)?;
                return Ok(record.view(None));
            }
        };
        record = self
            .allocations
            .get(&cell.scope, &options.id)?
            .ok_or_else(|| anyhow!("allocation reservation missing"))?;
        if record.destroy_requested {
            return self.destroy_allocation_locked(cell, &record.id).await;
        }
        let mut body = self.create_body(
            cell,
            StartParams {
                entrypoint: options.entrypoint,
                env: options.env,
                enable_internet: options.enable_internet,
                labels: Vec::new(),
            },
            &options.engine_image,
            &open,
            &internal,
        );
        body["Labels"][ATTEMPT_LABEL] = json!(record.attempt);
        body["Labels"]["celld.allocation.id"] = json!(record.id);
        record.status = "creating".to_string();
        record.create_dispatched = true;
        self.allocations.save(&mut record)?;
        let created = self
            .allocation_call(
                "POST",
                &format!("/containers/create?name={}", record.name),
                Some(body),
            )
            .await;
        // docker's complete no-such-image response proves this create was rejected.
        // malformed responses, conflicts and server failures remain uncertain.
        if created.as_ref().is_ok_and(|reply| {
            reply.status.as_u16() == 404
                && reply
                    .json()
                    .ok()
                    .is_some_and(|body| body["message"].is_string())
        }) {
            record.create_rejected = true;
            record.status = "failed".to_string();
            record.reason = Some("createRejected".to_string());
            self.allocations.save(&mut record)?;
            if record.destroy_requested {
                return self.destroy_allocation_locked(cell, &record.id).await;
            }
            return Ok(record.view(None));
        }
        let id = created
            .ok()
            .filter(|reply| reply.status.is_success())
            .and_then(|reply| reply.json().ok())
            .and_then(|body| body["Id"].as_str().map(str::to_string))
            .filter(|id| hex_value(id, 64));
        let Some(id) = id else {
            return self.unknown(record, "createOutcomeUnknown");
        };
        record.container_id = Some(id.clone());
        record.create_confirmed = true;
        record.status = "created".to_string();
        self.allocations.save(&mut record)?;
        record = self
            .allocations
            .get(&cell.scope, &options.id)?
            .ok_or_else(|| anyhow!("allocation reservation missing"))?;
        if record.destroy_requested {
            return self.destroy_allocation_locked(cell, &record.id).await;
        }
        if !matches!(self.owned_container(&record).await, Ok(Some(_))) {
            return self.unknown(record, "createdContainerUnverified");
        }
        record.status = "starting".to_string();
        self.allocations.save(&mut record)?;
        if record.destroy_requested {
            return self.destroy_allocation_locked(cell, &record.id).await;
        }
        let started = self
            .allocation_call("POST", &format!("/containers/{id}/start"), None)
            .await;
        if !started.is_ok_and(|reply| reply.status.is_success()) {
            return self.unknown(record, "startOutcomeUnknown");
        }
        self.observe_allocation(cell, record).await
    }

    fn unknown(&self, mut record: Record, reason: &str) -> anyhow::Result<AllocationView> {
        if let Some(cell) = self.cell(&record.scope) {
            let mut state = cell.state.lock().unwrap();
            state.running = false;
            state.address = Address::None;
        }
        record.status = "unknown".to_string();
        record.reason = Some(reason.to_string());
        self.allocations.save(&mut record)?;
        Ok(record.view(None))
    }

    async fn owned_container(&self, record: &Record) -> anyhow::Result<Option<Value>> {
        let target = record.container_id.as_deref().unwrap_or(&record.name);
        let reply = self
            .allocation_call("GET", &format!("/containers/{target}/json"), None)
            .await?;
        if reply.status.as_u16() == 404 {
            return Ok(None);
        }
        anyhow::ensure!(
            reply.status.is_success(),
            "allocation inspection unavailable"
        );
        let info = reply
            .json()
            .map_err(|_| anyhow!("invalid allocation inspection"))?;
        let id = info["Id"].as_str().unwrap_or("");
        anyhow::ensure!(
            hex_value(id, 64)
                && record
                    .container_id
                    .as_deref()
                    .is_none_or(|expected| expected == id),
            "allocation container id mismatch"
        );
        let labels = &info["Config"]["Labels"];
        for (key, expected) in [
            ("celld.node", &record.node),
            ("celld.cell", &record.scope),
            ("celld.class", &record.spec.class_name),
            (ATTEMPT_LABEL, &record.attempt),
            ("celld.allocation.id", &record.id),
        ] {
            anyhow::ensure!(
                labels[key].as_str() == Some(expected.as_str()),
                "allocation ownership mismatch"
            );
        }
        anyhow::ensure!(
            info["Name"].as_str() == Some(format!("/{}", record.name).as_str()),
            "allocation name mismatch"
        );
        anyhow::ensure!(
            info["Image"].as_str() == record.engine_image.as_deref(),
            "allocation selected image mismatch"
        );
        Ok(Some(info))
    }

    pub(super) async fn observe_allocation(
        &self,
        cell: &Arc<CellContainer>,
        mut record: Record,
    ) -> anyhow::Result<AllocationView> {
        if matches!(record.status.as_str(), "destroyed" | "failed" | "reserved") {
            return Ok(record.view(None));
        }
        let info = match self.owned_container(&record).await {
            Ok(Some(info)) => info,
            Ok(None) => return self.unknown(record, "containerNotObserved"),
            Err(_) => return self.unknown(record, "containerUnverified"),
        };
        record.container_id = info["Id"].as_str().map(str::to_string);
        let engine_image = record
            .engine_image
            .as_deref()
            .ok_or_else(|| anyhow!("allocation image missing"))?;
        let platform = record
            .platform
            .as_deref()
            .ok_or_else(|| anyhow!("allocation platform missing"))?;
        if self
            .verify_image(engine_image, engine_image, platform)
            .await
            .is_err()
        {
            return self.unknown(record, "observedImageUnverified");
        }
        let (Some(status), Some(running)) = (
            info["State"]["Status"].as_str(),
            info["State"]["Running"].as_bool(),
        ) else {
            return self.unknown(record, "containerStateUnverified");
        };
        if !matches!(
            status,
            "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead"
        ) {
            return self.unknown(record, "containerStateUnverified");
        }
        let status = status.to_string();
        let observation = AllocationObservation {
            engine_image: engine_image.to_string(),
            platform: platform.to_string(),
            status,
        };
        if !record.create_confirmed {
            record.status = "unknown".to_string();
            record.reason = Some("createOutcomeUnknown".to_string());
        } else if record.destroy_requested {
            record.status = "cleanupPending".to_string();
        } else {
            record.status = if running { "running" } else { "exited" }.to_string();
            record.reason = None;
        }
        self.allocations.save(&mut record)?;
        if record.create_confirmed && record.status == "running" {
            let adopted = !cell.running()
                || cell.state.lock().unwrap().allocation_container != record.container_id;
            let run = if adopted {
                cell.begin_run()
            } else {
                cell.current_run()
            };
            {
                let mut state = cell.state.lock().unwrap();
                state.allocation_container = record.container_id.clone();
                state.running = true;
                state.address = address_of(&info);
            }
            if adopted {
                self.watch_exit(cell, run);
            }
        } else {
            let mut state = cell.state.lock().unwrap();
            state.running = false;
            state.address = Address::None;
        }
        Ok(record.view(Some(observation)))
    }

    pub(super) async fn destroy_allocation_locked(
        &self,
        cell: &Arc<CellContainer>,
        id: &str,
    ) -> anyhow::Result<AllocationView> {
        let mut record = self
            .allocations
            .get(&cell.scope, id)?
            .ok_or_else(|| anyhow!("allocation id is unknown"))?;
        if record.status == "destroyed" {
            return Ok(record.view(None));
        }
        record.status = "cleanupPending".to_string();
        record.destroy_requested = true;
        self.allocations.save(&mut record)?;
        {
            let mut state = cell.state.lock().unwrap();
            state.running = false;
            state.address = Address::None;
            if let Some(cancel) = state.allocation_sweeper.take() {
                cancel.cancel();
            }
            state.inactivity_epoch = state.inactivity_epoch.wrapping_add(1);
        }
        if record.create_dispatched && !record.create_rejected {
            let info = match self.owned_container(&record).await {
                Ok(info) => info,
                Err(_) => return self.unknown(record, "cleanupTargetUnverified"),
            };
            if let Some(info) = info {
                let id = info["Id"]
                    .as_str()
                    .ok_or_else(|| anyhow!("allocation container id missing"))?;
                record.container_id = Some(id.to_string());
                self.allocations.save(&mut record)?;
                let deleted = self
                    .allocation_call(
                        "DELETE",
                        &format!("/containers/{id}?force=true&v=true"),
                        None,
                    )
                    .await;
                if !deleted
                    .is_ok_and(|reply| reply.status.is_success() || reply.status.as_u16() == 404)
                {
                    return self.unknown(record, "deleteOutcomeUnknown");
                }
            }
            // even a later 404 cannot settle an unacknowledged create request.
            if !record.create_confirmed {
                return self.unknown(record, "createOutcomeUnknown");
            }
        }
        record.status = "destroyed".to_string();
        record.reason = None;
        self.allocations.save(&mut record)?;
        let run = {
            let mut state = cell.state.lock().unwrap();
            state.running = false;
            state.address = Address::None;
            state.allocation_container = None;
            state.run
        };
        cell.exit.send_replace(Some((run, Ok(137))));
        Ok(record.view(None))
    }
}

#[cfg(all(test, not(celld_internal_tests)))]
#[path = "container_allocation_tests.rs"]
mod tests;
