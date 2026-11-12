use super::gate::Gate;
use super::seccomp::Policy;
use crate::container::ContainerEngine;
use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sandbox {
    pub version: u8,
    pub profile: String,
    pub enforcement: String,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub pids_limit: u64,
    pub shm_bytes: u64,
}

const GENERATED: [&str; 3] = ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"];

pub(super) fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<Sandbox>>, D::Error> {
    Box::<Sandbox>::deserialize(deserializer).map(Some)
}

fn empty(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn verify_image_volumes(info: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        info["Config"].is_object()
            && (info["Config"]["Volumes"].is_null()
                || info["Config"]["Volumes"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)),
        "sandbox refuses image-declared VOLUME or missing image configuration"
    );
    Ok(())
}

impl Sandbox {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        let tuple = match self.profile.as_str() {
            "small" => (250, 268435456, 67108864),
            "medium" => (500, 536870912, 134217728),
            "large" => (1000, 1073741824, 268435456),
            _ => anyhow::bail!("unknown sandbox profile"),
        };
        anyhow::ensure!(
            self.version == 1
                && self.enforcement == "overlay2-xfs-v1"
                && (self.cpu_millis, self.memory_bytes, self.disk_bytes) == tuple
                && self.pids_limit == 128
                && self.shm_bytes == 8388608,
            "sandbox profile constants mismatch"
        );
        Ok(())
    }

    pub(super) fn apply(&self, body: &mut Value) -> anyhow::Result<()> {
        self.validate()?;
        let host = &mut body["HostConfig"];
        anyhow::ensure!(
            empty(&host["Binds"]),
            "sandbox refuses external resolver binds"
        );
        anyhow::ensure!(
            host["Runtime"].is_null() || host["Runtime"] == "runc",
            "sandbox requires runc"
        );
        host["Runtime"] = json!("runc");
        host["IpcMode"] = json!("private");
        host["NanoCpus"] = json!(self.cpu_millis * 1_000_000);
        host["Memory"] = json!(self.memory_bytes);
        host["MemorySwap"] = json!(self.memory_bytes);
        host["PidsLimit"] = json!(self.pids_limit);
        host["ShmSize"] = json!(self.shm_bytes);
        host["StorageOpt"] = json!({"size": self.disk_bytes.to_string()});
        host["LogConfig"] = json!({"Type": "none", "Config": {}});
        host["ReadonlyPaths"] = json!([
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf"
        ]);
        Ok(())
    }

    pub(super) fn verify(&self, info: &Value, gate: &Gate, policy: &Policy) -> anyhow::Result<()> {
        self.validate()?;
        let host = &info["HostConfig"];
        policy.verify_host(host)?;
        for (key, expected) in [
            ("NanoCpus", self.cpu_millis * 1_000_000),
            ("Memory", self.memory_bytes),
            ("MemorySwap", self.memory_bytes),
            ("PidsLimit", self.pids_limit),
            ("ShmSize", self.shm_bytes),
        ] {
            anyhow::ensure!(
                host[key].as_u64() == Some(expected),
                "sandbox resource mismatch: {key}"
            );
        }
        anyhow::ensure!(
            host["StorageOpt"] == json!({"size": self.disk_bytes.to_string()})
                && host["LogConfig"]["Type"] == "none"
                && info["LogPath"].as_str().is_some_and(str::is_empty),
            "sandbox disk controls mismatch"
        );
        for key in [
            "Binds",
            "VolumesFrom",
            "Tmpfs",
            "Devices",
            "DeviceRequests",
            "CapAdd",
        ] {
            anyhow::ensure!(empty(&host[key]), "sandbox unexpected host setting: {key}");
        }
        anyhow::ensure!(
            host["Runtime"] == "runc"
                && host["Privileged"] == false
                && host["CapDrop"] == json!(["ALL"])
                && host["SecurityOpt"]
                    .as_array()
                    .is_some_and(|opts| opts.iter().any(|v| v == "no-new-privileges"))
                && matches!(host["IpcMode"].as_str(), Some("private" | ""))
                && host["PidMode"].as_str() == Some("")
                && host["UsernsMode"].as_str() == Some(""),
            "sandbox isolation mismatch"
        );
        gate.verify_config(info)?;
        verify_image_volumes(info)?;
        for path in GENERATED {
            anyhow::ensure!(
                host["ReadonlyPaths"]
                    .as_array()
                    .is_some_and(|paths| paths.iter().any(|p| p == path)),
                "sandbox generated file is not read-only"
            );
        }
        anyhow::ensure!(
            info["GraphDriver"]["Name"] == "overlay2",
            "sandbox requires classic overlay2"
        );
        let upper = info["GraphDriver"]["Data"]["UpperDir"]
            .as_str()
            .ok_or_else(|| anyhow!("sandbox upperdir missing"))?;
        let work = info["GraphDriver"]["Data"]["WorkDir"]
            .as_str()
            .ok_or_else(|| anyhow!("sandbox workdir missing"))?;
        anyhow::ensure!(
            verify_quota(upper, self.disk_bytes)? == verify_quota(work, self.disk_bytes)?,
            "sandbox overlay workdir and upperdir project mismatch"
        );
        if info["State"]["Running"] == true {
            super::seccomp::verify_live(info)?;
            verify_live_mounts(info, upper, work, self.shm_bytes)?;
            gate.verify_live(info)?;
        }
        Ok(())
    }
}

impl ContainerEngine {
    pub(super) async fn qualify_sandbox(
        &self,
        image: &str,
        sandbox: &Sandbox,
    ) -> anyhow::Result<()> {
        sandbox.validate()?;
        anyhow::ensure!(cfg!(target_os = "linux"), "sandbox requires Linux");
        let reply = self.allocation_call("GET", "/info", None).await?;
        anyhow::ensure!(
            reply.status.is_success(),
            "sandbox daemon inspection unavailable"
        );
        let info = reply.json()?;
        super::seccomp::verify_daemon(&info)?;
        anyhow::ensure!(
            info["Driver"] == "overlay2",
            "sandbox requires classic overlay2"
        );
        for capability in ["MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"] {
            anyhow::ensure!(
                info[capability] == true,
                "sandbox daemon capability missing: {capability}"
            );
        }
        let status = info["DriverStatus"]
            .as_array()
            .ok_or_else(|| anyhow!("sandbox driver status missing"))?;
        anyhow::ensure!(
            status
                .iter()
                .any(|pair| pair == &json!(["Backing Filesystem", "xfs"])),
            "sandbox requires XFS backing"
        );
        let root = info["DockerRootDir"]
            .as_str()
            .ok_or_else(|| anyhow!("sandbox Docker root missing"))?;
        qualified_mount(root)?;
        let reply = self
            .allocation_call("GET", &format!("/images/{image}/json"), None)
            .await?;
        anyhow::ensure!(reply.status.is_success(), "sandbox image unavailable");
        verify_image_volumes(&reply.json()?)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::disallowed_methods)] // Host qualification reads the kernel's mount inventory.
fn qualified_mount(path: &str) -> anyhow::Result<String> {
    let path = std::fs::canonicalize(path)?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut candidates = Vec::new();
    for line in mounts.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left: Vec<_> = left.split_whitespace().collect();
        let right: Vec<_> = right.split_whitespace().collect();
        anyhow::ensure!(
            left.len() >= 6 && right.len() >= 3,
            "invalid mount inventory"
        );
        if !left[4].contains('\\') && path.starts_with(left[4]) {
            candidates.push((left[4].len(), right[0], right[1], right[2]));
        }
    }
    let (_, fs, device, options) = candidates
        .into_iter()
        .max_by_key(|entry| entry.0)
        .ok_or_else(|| anyhow!("sandbox backing mount missing"))?;
    anyhow::ensure!(
        fs == "xfs"
            && options
                .split(',')
                .any(|opt| matches!(opt, "prjquota" | "pquota"))
            && !options.split(',').any(|opt| opt == "pqnoenforce")
            && !device.contains('\\'),
        "sandbox requires enforcing XFS project quotas"
    );
    Ok(device.to_owned())
}

#[cfg(not(target_os = "linux"))]
fn qualified_mount(_: &str) -> anyhow::Result<String> {
    anyhow::bail!("sandbox requires Linux")
}

#[cfg(target_os = "linux")]
#[allow(clippy::disallowed_methods)] // Query the owned upperdir using Linux's read-only quota UAPI.
fn verify_quota(path: &str, bytes: u64) -> anyhow::Result<u32> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    #[derive(Default)]
    struct Fsxattr {
        flags: u32,
        extsize: u32,
        nextents: u32,
        project: u32,
        cowextsize: u32,
        pad: [u8; 8],
    }
    let device = std::ffi::CString::new(qualified_mount(path)?)?;
    let file = std::fs::File::open(path)?;
    let mut attr = Fsxattr::default();
    // SAFETY: FS_IOC_FSGETXATTR writes the Linux UAPI repr(C) fsxattr into a live,
    // correctly sized buffer. The descriptor remains owned for the whole call.
    let result =
        unsafe { libc::ioctl(file.as_raw_fd(), 0x801c581f_u64 as libc::c_ulong, &mut attr) };
    anyhow::ensure!(
        result == 0 && attr.project != 0 && attr.flags & 0x200 != 0,
        "sandbox upperdir project inheritance missing"
    );
    // SAFETY: zero is valid for all fields of Linux's integer-only dqblk.
    let mut quota: libc::dqblk = unsafe { std::mem::zeroed() };
    // SAFETY: Q_GETQUOTA for PRJQUOTA writes a dqblk. Both pointers are live and
    // correctly sized. This read-only command does not alter host quota state.
    let result = unsafe {
        libc::quotactl(
            0x80000702_u32 as libc::c_int,
            device.as_ptr(),
            attr.project as libc::c_int,
            (&mut quota as *mut libc::dqblk).cast(),
        )
    };
    anyhow::ensure!(
        result == 0
            && quota.dqb_valid & 1 != 0
            && quota.dqb_bhardlimit.checked_mul(1024) == Some(bytes),
        "sandbox upperdir quota mismatch or unavailable"
    );
    Ok(attr.project)
}

#[cfg(not(target_os = "linux"))]
fn verify_quota(_: &str, _: u64) -> anyhow::Result<u32> {
    anyhow::bail!("sandbox requires Linux")
}

#[cfg(any(target_os = "linux", test))]
struct LiveMount<'a> {
    id: u64,
    parent: u64,
    device: &'a str,
    root: &'a str,
    target: &'a str,
    writable: bool,
    filesystem: &'a str,
    source: &'a str,
    super_options: &'a str,
}

#[cfg(any(target_os = "linux", test))]
fn parse_live_mounts(text: &str) -> anyhow::Result<std::collections::BTreeMap<u64, LiveMount<'_>>> {
    let mut mounts = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| anyhow!("invalid live mount"))?;
        let left: Vec<_> = left.split_whitespace().collect();
        let right: Vec<_> = right.split_whitespace().collect();
        anyhow::ensure!(left.len() >= 6 && right.len() == 3, "invalid live mount");
        let access: Vec<_> = left[5]
            .split(',')
            .filter(|option| matches!(*option, "ro" | "rw"))
            .collect();
        anyhow::ensure!(access.len() == 1, "invalid live mount access mode");
        let mount = LiveMount {
            id: left[0].parse()?,
            parent: left[1].parse()?,
            device: left[2],
            root: left[3],
            target: left[4],
            writable: access[0] == "rw",
            filesystem: right[0],
            source: right[1],
            super_options: right[2],
        };
        anyhow::ensure!(
            mount.id > 0 && mount.parent > 0,
            "invalid live mount identity"
        );
        anyhow::ensure!(
            mounts.insert(mount.id, mount).is_none(),
            "duplicate live mount identity"
        );
    }
    Ok(mounts)
}

#[cfg(any(target_os = "linux", test))]
fn visible_mount_id(fdinfo: &str) -> anyhow::Result<u64> {
    let mut id = None;
    for line in fdinfo.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            anyhow::ensure!(id.is_none(), "duplicate descriptor mount identity");
            id = Some(value.trim().parse::<u64>()?);
        }
    }
    id.filter(|id| *id > 0)
        .ok_or_else(|| anyhow!("descriptor mount identity missing"))
}

#[cfg(any(target_os = "linux", test))]
fn verify_generated_mount(
    mounts: &std::collections::BTreeMap<u64, LiveMount<'_>>,
    target: &str,
    visible_id: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(GENERATED.contains(&target), "unexpected generated file");
    let visible = mounts
        .get(&visible_id)
        .filter(|mount| mount.target == target && !mount.writable)
        .ok_or_else(|| anyhow!("sandbox visible generated mount missing or writable"))?;
    let mut remaining: std::collections::BTreeSet<_> = mounts
        .values()
        .filter(|mount| mount.target == target)
        .map(|mount| mount.id)
        .collect();
    let mut current = visible;
    loop {
        anyhow::ensure!(
            remaining.remove(&current.id),
            "sandbox generated mount cycle"
        );
        anyhow::ensure!(
            current.device == visible.device
                && current.root == visible.root
                && current.filesystem == visible.filesystem
                && current.source == visible.source,
            "sandbox generated mount backing mismatch"
        );
        let parent = mounts
            .get(&current.parent)
            .ok_or_else(|| anyhow!("sandbox generated mount parent missing"))?;
        if parent.target != target {
            anyhow::ensure!(
                parent.target == "/"
                    || target
                        .strip_prefix(parent.target)
                        .is_some_and(|suffix| suffix.starts_with('/')),
                "sandbox generated mount parent is not an ancestor"
            );
            break;
        }
        current = parent;
    }
    anyhow::ensure!(
        remaining.is_empty(),
        "sandbox generated mount branch or disconnected duplicate"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::disallowed_methods)] // Read the owned container's kernel namespace and pin its visible generated files.
fn verify_live_mounts(info: &Value, upper: &str, work: &str, shm_bytes: u64) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let pid = info["State"]["Pid"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| anyhow!("sandbox live PID missing"))?;
    let id = info["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("sandbox id missing"))?;
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    anyhow::ensure!(cgroup.contains(id), "sandbox PID ownership unverified");
    let mut generated_files = Vec::new();
    for target in GENERATED {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(format!("/proc/{pid}/root{target}"))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "sandbox generated file is not regular"
        );
        generated_files.push((target, file));
    }
    let mountinfo = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
    let mounts = parse_live_mounts(&mountinfo)?;
    // Covered writable mounts are allowed only beneath the descriptor-proven read-only top.
    for (target, file) in &generated_files {
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        verify_generated_mount(&mounts, target, visible_mount_id(&fdinfo)?)?;
    }
    let mut gate_mounts = std::collections::BTreeSet::new();
    let mut root = false;
    let mut shm = false;
    for mount in mounts.values() {
        let target = mount.target;
        let writable = mount.writable;
        if target == "/" {
            anyhow::ensure!(
                !root
                    && writable
                    && mount.filesystem == "overlay"
                    && mount
                        .super_options
                        .split(',')
                        .any(|option| option == format!("upperdir={upper}"))
                    && mount
                        .super_options
                        .split(',')
                        .any(|option| option == format!("workdir={work}")),
                "sandbox live root mismatch"
            );
            root = true;
        } else if GENERATED.contains(&target) {
            continue;
        } else if matches!(target, super::gate::EXECUTABLE | super::gate::RELEASE) {
            anyhow::ensure!(
                !writable && gate_mounts.insert(target),
                "sandbox gate mount writable or duplicated"
            );
        } else if target == "/dev/shm" {
            anyhow::ensure!(
                !shm && mount.filesystem == "tmpfs"
                    && mount
                        .super_options
                        .split(',')
                        .any(|option| option == format!("size={}", shm_bytes)
                            || option == format!("size={}k", shm_bytes / 1024)),
                "sandbox shared memory mount mismatch"
            );
            shm = true;
        } else if writable {
            anyhow::ensure!(
                matches!(mount.filesystem, "tmpfs" | "proc" | "devpts" | "mqueue"),
                "sandbox unexpected writable disk-backed mount"
            );
        }
    }
    anyhow::ensure!(
        root && shm && gate_mounts.len() == 2,
        "sandbox live mount inventory incomplete"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_live_mounts(_: &Value, _: &str, _: &str, _: u64) -> anyhow::Result<()> {
    anyhow::bail!("sandbox requires Linux")
}

#[cfg(test)]
mod tests {
    use super::super::AllocationOptions;
    use super::*;

    fn small() -> Sandbox {
        serde_json::from_value(json!({"version":1,"profile":"small","enforcement":"overlay2-xfs-v1",
            "cpuMillis":250,"memoryBytes":268435456,"diskBytes":67108864,"pidsLimit":128,"shmBytes":8388608})).unwrap()
    }

    fn generated_mountinfo() -> &'static str {
        concat!(
            "540 503 0:55 / / rw,relatime - overlay overlay rw,upperdir=/upper,workdir=/work\n",
            "551 540 7:0 /containers/owned/resolv.conf /etc/resolv.conf rw,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
            "552 540 7:0 /containers/owned/hostname /etc/hostname rw,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
            "553 540 7:0 /containers/owned/hosts /etc/hosts rw,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
            "509 553 7:0 /containers/owned/hosts /etc/hosts ro,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
            "510 552 7:0 /containers/owned/hostname /etc/hostname ro,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
            "511 551 7:0 /containers/owned/resolv.conf /etc/resolv.conf ro,relatime - xfs /dev/loop0 rw,attr2,inode64,logbufs=8,logbsize=32k,prjquota\n",
        )
    }

    #[test]
    fn generated_files_accept_captured_runc_stacks_independent_of_order() {
        let captured = generated_mountinfo();
        let reversed = captured.lines().rev().collect::<Vec<_>>().join("\n");
        for text in [captured, reversed.as_str()] {
            let mounts = parse_live_mounts(text).unwrap();
            assert_eq!(
                mounts[&540].super_options,
                "rw,upperdir=/upper,workdir=/work"
            );
            for (target, id) in [
                ("/etc/hosts", 509),
                ("/etc/hostname", 510),
                ("/etc/resolv.conf", 511),
            ] {
                verify_generated_mount(&mounts, target, id).unwrap();
            }
        }
    }

    #[test]
    fn generated_files_accept_single_readonly_bind_and_longer_linear_stack() {
        let direct = generated_mountinfo()
            .lines()
            .filter(|line| !line.starts_with("553 "))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("509 553 ", "509 540 ");
        verify_generated_mount(&parse_live_mounts(&direct).unwrap(), "/etc/hosts", 509).unwrap();
        let extra = generated_mountinfo()
            .lines()
            .find(|line| line.starts_with("509 "))
            .unwrap()
            .replacen("509 553 ", "700 509 ", 1);
        let stacked = format!("{}{extra}\n", generated_mountinfo());
        let mounts = parse_live_mounts(&stacked).unwrap();
        verify_generated_mount(&mounts, "/etc/hosts", 700).unwrap();
        assert!(verify_generated_mount(&mounts, "/etc/hosts", 509).is_err());
    }

    #[test]
    fn generated_files_require_the_actual_visible_readonly_mount_identity() {
        let mounts = parse_live_mounts(generated_mountinfo()).unwrap();
        for id in [0, 540, 553, 999, 510] {
            assert!(verify_generated_mount(&mounts, "/etc/hosts", id).is_err());
        }
        let missing = generated_mountinfo()
            .lines()
            .filter(|line| !line.starts_with("509 "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            verify_generated_mount(&parse_live_mounts(&missing).unwrap(), "/etc/hosts", 509)
                .is_err()
        );
        assert!(verify_generated_mount(&mounts, "/other", 509).is_err());
    }

    #[test]
    fn generated_files_refuse_writable_tops_backing_drift_cycles_and_missing_parents() {
        for (before, after) in [
            ("/etc/hosts ro,", "/etc/hosts rw,"),
            ("553 540 7:0", "553 540 7:1"),
            ("553 540 ", "553 509 "),
            ("553 540 ", "553 999 "),
            ("/owned/hosts /etc/hosts rw,", "/other/hosts /etc/hosts rw,"),
            (
                "/etc/hosts rw,relatime - xfs",
                "/etc/hosts rw,relatime - ext4",
            ),
            (
                "/etc/hosts rw,relatime - xfs /dev/loop0",
                "/etc/hosts rw,relatime - xfs /dev/loop1",
            ),
            ("0:55 / / rw,", "0:55 / /unrelated rw,"),
        ] {
            let changed = generated_mountinfo().replace(before, after);
            assert_ne!(changed, generated_mountinfo());
            let mounts = parse_live_mounts(&changed).unwrap();
            assert!(
                verify_generated_mount(&mounts, "/etc/hosts", 509).is_err(),
                "accepted generated mount drift: {before} -> {after}"
            );
        }
    }

    #[test]
    fn generated_files_refuse_branches_and_disconnected_duplicates() {
        let visible = generated_mountinfo()
            .lines()
            .find(|line| line.starts_with("509 "))
            .unwrap();
        for parent in [553, 540, 999] {
            let extra = visible.replacen("509 553 ", &format!("700 {parent} "), 1);
            let changed = format!("{}{extra}\n", generated_mountinfo());
            assert!(verify_generated_mount(
                &parse_live_mounts(&changed).unwrap(),
                "/etc/hosts",
                509
            )
            .is_err());
        }
    }

    #[test]
    fn mount_inventory_refuses_duplicate_ids_and_malformed_records() {
        let duplicate = format!("{}{}", generated_mountinfo(), generated_mountinfo());
        assert!(parse_live_mounts(&duplicate).is_err());
        for text in [
            "509 553 7:0 /owned /etc/hosts ro - xfs /dev/loop0",
            "509 553 7:0 /owned /etc/hosts ro xfs /dev/loop0 rw",
            "bad 553 7:0 /owned /etc/hosts ro - xfs /dev/loop0 rw",
            "509 bad 7:0 /owned /etc/hosts ro - xfs /dev/loop0 rw",
            "0 553 7:0 /owned /etc/hosts ro - xfs /dev/loop0 rw",
            "509 0 7:0 /owned /etc/hosts ro - xfs /dev/loop0 rw",
            "509 553 7:0 /owned /etc/hosts ro,rw - xfs /dev/loop0 rw",
            "509 553 7:0 /owned /etc/hosts relatime - xfs /dev/loop0 rw",
        ] {
            assert!(
                parse_live_mounts(text).is_err(),
                "accepted malformed mount: {text}"
            );
        }
    }

    #[test]
    fn descriptor_mount_identity_requires_one_positive_decimal_id() {
        assert_eq!(
            visible_mount_id("pos:\t0\nflags:\t0104000\nmnt_id:\t509\nino:\t23\n").unwrap(),
            509
        );
        for text in [
            "pos:\t0\nino:\t509\n",
            "mnt_id:\t0\n",
            "mnt_id:\n",
            "mnt_id:\tbad\n",
            "mnt_id:\t-509\n",
            "mnt_id:\t509\nmnt_id:\t509\n",
            "mnt_id:\t509 510\n",
        ] {
            assert!(
                visible_mount_id(text).is_err(),
                "accepted invalid fdinfo: {text}"
            );
        }
    }

    #[test]
    fn exact_profiles_and_host_controls() {
        let small = small();
        small.validate().unwrap();
        let mut changed = small.clone();
        changed.disk_bytes += 1;
        assert!(changed.validate().is_err());
        let mut body = json!({"HostConfig": {}});
        small.apply(&mut body).unwrap();
        assert_eq!(body["HostConfig"]["NanoCpus"], 250000000);
        assert_eq!(body["HostConfig"]["MemorySwap"], 268435456);
        assert_eq!(body["HostConfig"]["StorageOpt"], json!({"size":"67108864"}));
        assert_eq!(body["HostConfig"]["LogConfig"]["Type"], "none");
        assert_eq!(body["HostConfig"]["ShmSize"], 8388608);
        for path in GENERATED {
            assert!(body["HostConfig"]["ReadonlyPaths"]
                .as_array()
                .unwrap()
                .contains(&json!(path)));
        }
        let mut object = serde_json::to_value(&small).unwrap();
        object["extra"] = json!(true);
        assert!(serde_json::from_value::<Sandbox>(object).is_err());
    }

    #[test]
    fn binds_and_non_runc_are_refused() {
        for host in [
            json!({"Binds":["/tmp:/tmp:rw"]}),
            json!({"Runtime":"runsc"}),
        ] {
            assert!(small().apply(&mut json!({"HostConfig": host})).is_err());
        }
    }

    #[test]
    fn image_volumes_are_refused_including_anonymous_volumes() {
        for image in [
            json!({"Config":{"Volumes":{"/state":{}}}}),
            json!({"Config":{"Volumes":{"/":{}}}}),
            json!({}),
        ] {
            assert!(verify_image_volumes(&image).is_err());
        }
        verify_image_volumes(&json!({"Config":{"Volumes":null}})).unwrap();
        verify_image_volumes(&json!({"Config":{"Volumes":{}}})).unwrap();
    }

    #[test]
    fn legacy_wire_is_unchanged_and_null_is_refused() {
        let legacy = json!({"id":"a","image":format!("celld-image:{}", "a".repeat(64)),
            "engineImage":format!("sha256:{}", "b".repeat(64)), "platform":"linux/amd64",
            "entrypoint":null,"env":[],"enableInternet":false});
        let options: AllocationOptions = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(serde_json::to_value(options).unwrap(), legacy);
        let mut present = legacy;
        present["sandbox"] = Value::Null;
        assert!(serde_json::from_value::<AllocationOptions>(present.clone()).is_err());
        present["sandbox"] = serde_json::to_value(small()).unwrap();
        let mut options: AllocationOptions = serde_json::from_value(present.clone()).unwrap();
        assert_eq!(serde_json::to_value(&options).unwrap(), present);
        options.normalise().unwrap();
        options.sandbox.as_mut().unwrap().pids_limit = 129;
        assert!(options.normalise().is_err());
    }
}
