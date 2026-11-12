use super::AllocationOptions;
use super::Record;
use crate::container::ContainerEngine;
use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

pub(super) const EXECUTABLE: &str = "/.grapefuit-sandbox/gate";
pub(super) const RELEASE: &str = "/.grapefuit-sandbox/release";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Phase {
    Waiting,
    ReleasePending,
    Released,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Gate {
    directory: PathBuf,
    owner: u32,
    token: String,
    executable_sha256: String,
    argv: Vec<String>,
    pub(super) phase: Phase,
    directory_identity: Option<(u64, u64)>,
    executable_identity: Option<(u64, u64)>,
    release_identity: Option<(u64, u64)>,
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn argv(image: &Value, override_argv: &Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    fn array(value: &Value) -> anyhow::Result<Vec<String>> {
        if value.is_null() {
            return Ok(Vec::new());
        }
        value
            .as_array()
            .ok_or_else(|| anyhow!("invalid image argv"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.contains('\0'))
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("invalid image argv element"))
            })
            .collect()
    }
    let command = array(&image["Config"]["Cmd"])?;
    let result = match override_argv {
        Some(override_argv) if !override_argv.is_empty() => override_argv.clone(),
        Some(_) => command,
        None => {
            let mut entrypoint = array(&image["Config"]["Entrypoint"])?;
            entrypoint.extend(command);
            entrypoint
        }
    };
    anyhow::ensure!(
        !result.is_empty() && !result[0].is_empty() && serde_json::to_vec(&result)?.len() <= 65536,
        "sandbox command missing or too large"
    );
    Ok(result)
}

fn static_executable(bytes: &[u8], platform: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.len() >= 64 && &bytes[..6] == b"\x7fELF\x02\x01",
        "gate must be a static ELF64 executable"
    );
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let machine = match platform {
        "linux/amd64" => 62,
        "linux/arm64" => 183,
        _ => 0,
    };
    anyhow::ensure!(
        u16_at(16) == 2 && u16_at(18) == machine && machine != 0,
        "gate architecture or ELF executable type mismatch"
    );
    let start = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into()?))?;
    let size = u16_at(54) as usize;
    let count = u16_at(56) as usize;
    anyhow::ensure!(size >= 56 && count > 0, "invalid gate ELF program headers");
    for index in 0..count {
        let offset = index
            .checked_mul(size)
            .and_then(|offset| start.checked_add(offset))
            .filter(|offset| offset.checked_add(56).is_some_and(|end| end <= bytes.len()))
            .ok_or_else(|| anyhow!("invalid gate ELF header range"))?;
        let kind = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
        anyhow::ensure!(
            !matches!(kind, 2 | 3),
            "gate must not use an image dynamic loader"
        );
    }
    Ok(())
}

impl Gate {
    pub(super) fn validate(
        &self,
        attempt: &str,
        dispatched: bool,
        confirmed: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.token == attempt
                && super::hex_value(&self.executable_sha256, 64)
                && self.directory.is_absolute()
                && self.directory.file_name().and_then(|name| name.to_str()) == Some(attempt)
                && !self.argv.is_empty()
                && !self.argv[0].is_empty()
                && self.argv.iter().all(|value| !value.contains('\0'))
                && serde_json::to_vec(&self.argv)?.len() <= 65536,
            "invalid sandbox gate ownership"
        );
        anyhow::ensure!(
            !dispatched
                || (self.directory_identity.is_some()
                    && self.executable_identity.is_some()
                    && self.release_identity.is_some()),
            "sandbox gate file identities missing"
        );
        anyhow::ensure!(
            (self.executable_identity.is_none() || self.directory_identity.is_some())
                && (self.release_identity.is_none() || self.executable_identity.is_some())
                && (self.phase == Phase::Waiting || (dispatched && confirmed)),
            "invalid sandbox gate creation or release phase"
        );
        Ok(())
    }

    #[allow(clippy::disallowed_methods)] // Gate files are explicitly owned by the allocation journal.
    pub(super) fn verify_root(&self, journal_directory: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.directory
                == std::fs::canonicalize(journal_directory)?
                    .join("sandbox-gates")
                    .join(&self.token),
            "sandbox gate directory ownership mismatch"
        );
        anyhow::ensure!(
            std::fs::metadata(journal_directory)?.uid() == self.owner,
            "sandbox gate owner mismatch"
        );
        Ok(())
    }

    fn executable(&self) -> PathBuf {
        self.directory.join("gate")
    }
    fn release(&self) -> PathBuf {
        self.directory.join("release")
    }

    fn command(&self) -> Vec<String> {
        let mut command = vec![
            EXECUTABLE.to_string(),
            "--release".to_string(),
            RELEASE.to_string(),
            "--token".to_string(),
            self.token.clone(),
            "--".to_string(),
        ];
        command.extend(self.argv.clone());
        command
    }

    fn mounts(&self) -> Value {
        json!([
            {"Type":"bind", "Source":self.executable(), "Target":EXECUTABLE, "ReadOnly":true,
                "BindOptions":{"NonRecursive":true}},
            {"Type":"bind", "Source":self.release(), "Target":RELEASE, "ReadOnly":true,
                "BindOptions":{"NonRecursive":true}}
        ])
    }

    pub(super) fn apply(&self, body: &mut Value) -> anyhow::Result<()> {
        self.verify_files()?;
        anyhow::ensure!(
            self.phase == Phase::Waiting && !self.opened()?,
            "sandbox gate already released"
        );
        body["Entrypoint"] = json!(self.command());
        body["Cmd"] = json!([]);
        body["Healthcheck"] = json!({"Test":["NONE"]});
        body["HostConfig"]["Init"] = json!(false);
        body["HostConfig"]["RestartPolicy"] = json!({"Name":"no", "MaximumRetryCount":0});
        body["HostConfig"]["Mounts"] = self.mounts();
        Ok(())
    }

    #[allow(clippy::disallowed_methods)] // Read-only host checks bind durable identities to individual regular files.
    fn checked_file(
        &self,
        path: &Path,
        expected: Option<(u64, u64)>,
        mode: u32,
    ) -> anyhow::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == self.owner
                && metadata.mode() & 0o7777 == mode
                && Some(identity(&metadata)) == expected,
            "sandbox gate file identity or mode mismatch"
        );
        Ok(file)
    }

    #[allow(clippy::disallowed_methods)] // Directory metadata is needed to refuse symlink or replaced ownership.
    fn verify_directory(&self) -> anyhow::Result<()> {
        let metadata = std::fs::symlink_metadata(&self.directory)?;
        anyhow::ensure!(
            metadata.is_dir()
                && metadata.mode() & 0o7777 == 0o700
                && metadata.uid() == self.owner
                && Some(identity(&metadata)) == self.directory_identity,
            "sandbox gate directory replaced or unavailable"
        );
        Ok(())
    }

    pub(super) fn verify_files(&self) -> anyhow::Result<()> {
        self.verify_directory()?;
        let mut file = self.checked_file(&self.executable(), self.executable_identity, 0o555)?;
        anyhow::ensure!(
            file.metadata()?.len() <= 16 * 1024 * 1024,
            "gate executable exceeds limit"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "gate executable exceeds limit"
        );
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == self.executable_sha256,
            "gate executable changed"
        );
        self.opened()?;
        Ok(())
    }

    pub(super) fn opened(&self) -> anyhow::Result<bool> {
        let mut file = self.checked_file(&self.release(), self.release_identity, 0o644)?;
        anyhow::ensure!(
            file.metadata()?.len() == 66,
            "sandbox release file must be bounded to 66 bytes"
        );
        let mut bytes = [0u8; 67];
        let length = file.read(&mut bytes)?;
        anyhow::ensure!(
            length == 66
                && &bytes[1..65] == self.token.as_bytes()
                && bytes[65] == b'\n'
                && matches!(bytes[0], b'0' | b'1'),
            "invalid sandbox release file"
        );
        Ok(bytes[0] == b'1')
    }

    pub(super) fn verify_config(&self, info: &Value) -> anyhow::Result<()> {
        self.verify_files()?;
        anyhow::ensure!(
            info["Config"]["Entrypoint"] == json!(self.command())
                && (info["Config"]["Cmd"].is_null()
                    || info["Config"]["Cmd"].as_array().is_some_and(Vec::is_empty))
                && info["Config"]["Healthcheck"]["Test"] == json!(["NONE"])
                && info["HostConfig"]["Init"] == false
                && info["HostConfig"]["RestartPolicy"]["Name"] == "no"
                && info["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] == 0,
            "sandbox gate command or healthcheck mismatch"
        );
        anyhow::ensure!(
            info["HostConfig"]["Mounts"] == self.mounts(),
            "sandbox gate mount specification mismatch"
        );
        let mounts = info["Mounts"]
            .as_array()
            .ok_or_else(|| anyhow!("sandbox gate mounts missing"))?;
        anyhow::ensure!(mounts.len() == 2, "sandbox unexpected bind or volume");
        for (target, source) in [(EXECUTABLE, self.executable()), (RELEASE, self.release())] {
            anyhow::ensure!(
                mounts
                    .iter()
                    .filter(|mount| mount["Type"] == "bind"
                        && mount["Destination"] == target
                        && mount["Source"].as_str() == source.to_str()
                        && mount["RW"] == false
                        && mount["Propagation"] == "rprivate")
                    .count()
                    == 1,
                "sandbox gate bind mismatch"
            );
        }
        let opened = self.opened()?;
        anyhow::ensure!(
            match self.phase {
                Phase::Waiting => !opened,
                Phase::ReleasePending => true,
                Phase::Released => opened,
            },
            "sandbox release state disagrees with journal"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::disallowed_methods)] // Compare kernel-resolved mount targets and executable with owned host inodes.
    pub(super) fn verify_live(&self, info: &Value) -> anyhow::Result<()> {
        let pid = info["State"]["Pid"]
            .as_u64()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| anyhow!("gate PID missing"))?;
        for (target, expected) in [
            (EXECUTABLE, self.executable_identity),
            (RELEASE, self.release_identity),
        ] {
            let metadata = std::fs::metadata(format!("/proc/{pid}/root{target}"))?;
            anyhow::ensure!(
                metadata.is_file() && Some(identity(&metadata)) == expected,
                "sandbox live gate bind identity mismatch"
            );
        }
        if !self.opened()? {
            let executable = std::fs::metadata(format!("/proc/{pid}/exe"))?;
            anyhow::ensure!(
                Some(identity(&executable)) == self.executable_identity,
                "trusted gate is not the waiting process"
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn verify_live(&self, _: &Value) -> anyhow::Result<()> {
        anyhow::bail!("sandbox gate requires Linux")
    }

    #[allow(clippy::disallowed_methods)] // Only one byte of the allocation-owned, inode-pinned release file is changed.
    fn release_gate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.phase == Phase::ReleasePending,
            "sandbox release was not durably authorised"
        );
        self.verify_files()?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.release())?;
        anyhow::ensure!(
            Some(identity(&file.metadata()?)) == self.release_identity,
            "sandbox release inode changed"
        );
        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"1")?;
        file.sync_all()?;
        anyhow::ensure!(self.opened()?, "sandbox release not observed");
        Ok(())
    }

    #[allow(clippy::disallowed_methods)] // Called only after exact native removal, never while a gate can execute.
    pub(super) fn cleanup(&self, journal_directory: &Path) -> anyhow::Result<()> {
        self.verify_root(journal_directory)?;
        match std::fs::symlink_metadata(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                File::open(
                    self.directory
                        .parent()
                        .ok_or_else(|| anyhow!("gate parent missing"))?,
                )?
                .sync_all()?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(_) => self.verify_directory()?,
        }
        let entries: Vec<_> = std::fs::read_dir(&self.directory)?.collect::<Result<_, _>>()?;
        anyhow::ensure!(
            entries
                .iter()
                .all(|entry| matches!(entry.file_name().to_str(), Some("gate" | "release"))),
            "sandbox gate directory has unowned files"
        );
        for (path, expected) in [
            (self.executable(), self.executable_identity),
            (self.release(), self.release_identity),
        ] {
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(metadata) => anyhow::ensure!(
                    metadata.is_file()
                        && metadata.nlink() == 1
                        && Some(identity(&metadata)) == expected,
                    "sandbox cleanup file ownership mismatch"
                ),
            }
        }
        for path in [self.executable(), self.release()] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        File::open(&self.directory)?.sync_all()?;
        std::fs::remove_dir(&self.directory)?;
        File::open(
            self.directory
                .parent()
                .ok_or_else(|| anyhow!("gate parent missing"))?,
        )?
        .sync_all()?;
        Ok(())
    }
}

impl ContainerEngine {
    #[allow(clippy::disallowed_methods)] // Allocate gate resources through the existing sealed ownership record before Docker dispatch.
    pub(super) async fn prepare_sandbox_gate(
        &self,
        record: &mut Record,
        options: &AllocationOptions,
    ) -> anyhow::Result<()> {
        let reply = self
            .allocation_call(
                "GET",
                &format!("/images/{}/json", options.engine_image),
                None,
            )
            .await?;
        anyhow::ensure!(
            reply.status.is_success(),
            "sandbox command image unavailable"
        );
        let command = argv(&reply.json()?, &options.entrypoint)?;
        let source = std::env::var_os("CELLD_SANDBOX_GATE_PATH")
            .ok_or_else(|| anyhow!("CELLD_SANDBOX_GATE_PATH is required"))?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(source)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.len() <= 16 * 1024 * 1024
                && metadata.mode() & 0o022 == 0,
            "installed gate must be a bounded operator-owned executable"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "gate executable exceeds limit"
        );
        static_executable(&bytes, &options.platform)?;
        let parent = std::fs::canonicalize(
            self.allocations
                .path
                .parent()
                .ok_or_else(|| anyhow!("journal parent missing"))?,
        )?;
        let owner = std::fs::metadata(&parent)?.uid();
        anyhow::ensure!(
            file.metadata()?.uid() == 0 || file.metadata()?.uid() == owner,
            "installed gate is not owned by root or the journal operator"
        );
        anyhow::ensure!(
            std::fs::metadata(&parent)?.mode() & 0o022 == 0,
            "journal directory is writable by other users"
        );
        let root = parent.join("sandbox-gates");
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
                File::open(&parent)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&root)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.mode() & 0o7777 == 0o700 && metadata.uid() == owner,
            "sandbox gate root is not private"
        );
        let gate = Gate {
            directory: root.join(&record.attempt),
            owner,
            token: record.attempt.clone(),
            executable_sha256: format!("{:x}", Sha256::digest(&bytes)),
            argv: command,
            phase: Phase::Waiting,
            directory_identity: None,
            executable_identity: None,
            release_identity: None,
        };
        record.gate = Some(gate.clone());
        self.allocations.save(record)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&gate.directory)?;
        std::fs::set_permissions(&gate.directory, std::fs::Permissions::from_mode(0o700))?;
        File::open(&root)?.sync_all()?;
        let mut gate = gate;
        gate.directory_identity = Some(identity(&std::fs::symlink_metadata(&gate.directory)?));
        record.gate = Some(gate.clone());
        self.allocations.save(record)?;
        let mut binary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o555)
            .open(gate.executable())?;
        binary.write_all(&bytes)?;
        binary.set_permissions(std::fs::Permissions::from_mode(0o555))?;
        binary.sync_all()?;
        gate.executable_identity = Some(identity(&binary.metadata()?));
        record.gate = Some(gate.clone());
        self.allocations.save(record)?;
        let mut release = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(gate.release())?;
        release.write_all(format!("0{}\n", gate.token).as_bytes())?;
        release.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        release.sync_all()?;
        gate.release_identity = Some(identity(&release.metadata()?));
        File::open(&gate.directory)?.sync_all()?;
        record.gate = Some(gate);
        self.allocations.save(record)?;
        Ok(())
    }

    pub(super) fn release_sandbox_gate(
        &self,
        record: &mut Record,
        info: &Value,
    ) -> anyhow::Result<()> {
        let current = self
            .allocations
            .get(&record.scope, &record.id)?
            .ok_or_else(|| anyhow!("gate allocation missing"))?;
        anyhow::ensure!(
            !current.destroy_requested && current.create_confirmed,
            "sandbox release admission closed"
        );
        *record = current;
        let gate = record
            .gate
            .as_ref()
            .ok_or_else(|| anyhow!("sandbox gate missing"))?;
        let sandbox = record
            .sandbox
            .as_ref()
            .ok_or_else(|| anyhow!("sandbox controls missing"))?;
        let policy = record
            .sandbox_seccomp
            .as_ref()
            .ok_or_else(|| anyhow!("sandbox seccomp missing"))?;
        sandbox.verify(info, gate, policy)?;
        if gate.phase == Phase::Released {
            return Ok(());
        }
        record
            .gate
            .as_mut()
            .ok_or_else(|| anyhow!("sandbox gate missing"))?
            .phase = Phase::ReleasePending;
        self.allocations.save(record)?;
        anyhow::ensure!(
            !record.destroy_requested,
            "sandbox release closed by cleanup"
        );
        record
            .gate
            .as_ref()
            .ok_or_else(|| anyhow!("sandbox gate missing"))?
            .release_gate()?;
        record
            .gate
            .as_mut()
            .ok_or_else(|| anyhow!("sandbox gate missing"))?
            .phase = Phase::Released;
        self.allocations.save(record)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn image_and_override_command_semantics() {
        let image = json!({"Config":{"Entrypoint":["image-entry","flag"],"Cmd":["image-command"]}});
        assert_eq!(
            argv(&image, &None).unwrap(),
            ["image-entry", "flag", "image-command"]
        );
        assert_eq!(
            argv(&image, &Some(vec!["override".into()])).unwrap(),
            ["override"]
        );
        assert_eq!(argv(&image, &Some(vec![])).unwrap(), ["image-command"]);
        assert!(argv(&json!({"Config":{}}), &None).is_err());
    }

    fn fixture() -> (tempfile::TempDir, Gate) {
        let root = tempfile::tempdir().unwrap();
        let token = "a".repeat(64);
        let directory = root.path().join("sandbox-gates").join(&token);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = b"owned gate fixture";
        std::fs::write(directory.join("gate"), bytes).unwrap();
        std::fs::set_permissions(
            directory.join("gate"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        std::fs::write(directory.join("release"), format!("0{token}\n")).unwrap();
        std::fs::set_permissions(
            directory.join("release"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let gate = Gate {
            owner: std::fs::metadata(root.path()).unwrap().uid(),
            token,
            executable_sha256: format!("{:x}", Sha256::digest(bytes)),
            argv: vec!["/app".into()],
            phase: Phase::Waiting,
            directory_identity: Some(identity(&std::fs::metadata(&directory).unwrap())),
            executable_identity: Some(identity(
                &std::fs::metadata(directory.join("gate")).unwrap(),
            )),
            release_identity: Some(identity(
                &std::fs::metadata(directory.join("release")).unwrap(),
            )),
            directory,
        };
        (root, gate)
    }

    fn inspection(gate: &Gate) -> Value {
        let mut body = json!({"HostConfig":{}});
        gate.apply(&mut body).unwrap();
        json!({"Config": {"Entrypoint":body["Entrypoint"],"Cmd":body["Cmd"],"Healthcheck":body["Healthcheck"]},
            "HostConfig":body["HostConfig"],
            "Mounts":[{"Type":"bind","Source":gate.executable(),"Destination":EXECUTABLE,"RW":false,"Propagation":"rprivate"},
                {"Type":"bind","Source":gate.release(),"Destination":RELEASE,"RW":false,"Propagation":"rprivate"}]})
    }

    #[test]
    fn release_requires_durable_approval_and_reconciles_pending_write() {
        let (_root, mut gate) = fixture();
        let info = inspection(&gate);
        gate.verify_config(&info).unwrap();
        assert!(gate.release_gate().is_err());
        assert!(!gate.opened().unwrap());
        gate.phase = Phase::ReleasePending;
        gate.release_gate().unwrap();
        assert!(gate.opened().unwrap());
        gate.verify_config(&info).unwrap();
        gate.release_gate().unwrap();
        gate.phase = Phase::Released;
        gate.verify_config(&info).unwrap();
        gate.phase = Phase::Waiting;
        assert!(gate.verify_config(&info).is_err());
    }

    #[test]
    fn journal_phase_matches_release_file() {
        let (_root, mut gate) = fixture();
        let info = inspection(&gate);
        for opened in [false, true] {
            std::fs::write(
                gate.release(),
                format!("{}{}\n", if opened { '1' } else { '0' }, gate.token),
            )
            .unwrap();
            for (phase, valid) in [
                (Phase::Waiting, !opened),
                (Phase::ReleasePending, true),
                (Phase::Released, opened),
            ] {
                gate.phase = phase;
                assert_eq!(gate.verify_config(&info).is_ok(), valid);
            }
        }
    }

    #[test]
    fn control_and_file_drift_refuses_reuse_and_preserves_cleanup_ownership() {
        let (root, gate) = fixture();
        let mut info = inspection(&gate);
        info["Config"]["Healthcheck"]["Test"] = json!(["CMD", "/untrusted"]);
        assert!(gate.verify_config(&info).is_err());
        let mut info = inspection(&gate);
        info["Mounts"][0]["RW"] = json!(true);
        assert!(gate.verify_config(&info).is_err());
        std::fs::write(gate.release(), "corrupt").unwrap();
        assert!(gate.opened().is_err());
        gate.cleanup(root.path()).unwrap();
        gate.cleanup(root.path()).unwrap();
        assert!(!gate.directory.exists());
    }

    #[test]
    fn cleanup_does_not_remove_replaced_or_unowned_files() {
        let (root, gate) = fixture();
        std::fs::write(gate.directory.join("unowned"), "keep").unwrap();
        assert!(gate.cleanup(root.path()).is_err());
        assert!(gate.executable().exists());
        std::fs::remove_file(gate.directory.join("unowned")).unwrap();
        std::fs::rename(gate.release(), root.path().join("old-release")).unwrap();
        std::fs::write(gate.release(), format!("0{}\n", gate.token)).unwrap();
        assert!(gate.cleanup(root.path()).is_err());
        assert!(gate.executable().exists());
    }

    #[test]
    fn static_gate_cannot_load_an_image_interpreter() {
        let mut bytes = vec![0u8; 128];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        static_executable(&bytes, "linux/amd64").unwrap();
        assert!(static_executable(&bytes, "linux/arm64").is_err());
        bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
        assert!(static_executable(&bytes, "linux/amd64").is_err());
    }
}
