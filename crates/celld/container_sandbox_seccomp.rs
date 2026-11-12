use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

const BASELINE: &str = "4b8214fc4971e06172938a1f1554ccff6647ee80";
const BASELINE_SHA256: &str = "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6";
const READ_ONLY_IOCTL: [u64; 3] = [0x801c581f, 0x80086601, 0x80046601];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Policy {
    version: u8,
    baseline_commit: String,
    baseline_sha256: String,
    profile: Value,
}

impl Policy {
    pub(super) fn new() -> anyhow::Result<Self> {
        let mut profile: Value =
            serde_json::from_str(include_str!("sandbox-seccomp-default.json"))?;
        anyhow::ensure!(
            profile["defaultAction"] == "SCMP_ACT_ERRNO" && profile["defaultErrnoRet"] == 1,
            "sandbox seccomp baseline must deny by default"
        );
        let rules = profile["syscalls"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("seccomp rules missing"))?;
        for rule in rules.iter_mut() {
            let names = rule["names"]
                .as_array_mut()
                .ok_or_else(|| anyhow!("seccomp syscall names missing"))?;
            names.retain(|name| name != "ioctl");
        }
        rules.retain(|rule| {
            rule["names"]
                .as_array()
                .is_some_and(|names| !names.is_empty())
        });
        for request in READ_ONLY_IOCTL {
            rules.push(json!({"names":["ioctl"],"action":"SCMP_ACT_ALLOW",
                "args":[{"index":1,"value":request,"op":"SCMP_CMP_EQ"}]}));
        }
        Ok(Self {
            version: 1,
            baseline_commit: BASELINE.to_string(),
            baseline_sha256: BASELINE_SHA256.to_string(),
            profile,
        })
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(*self == Self::new()?, "sandbox seccomp enforcement drift");
        Ok(())
    }

    pub(super) fn apply(&self, body: &mut Value) -> anyhow::Result<()> {
        self.validate()?;
        body["HostConfig"]["SecurityOpt"] = json!([
            "no-new-privileges",
            format!("seccomp={}", serde_json::to_string(&self.profile)?)
        ]);
        Ok(())
    }

    pub(super) fn verify_host(&self, host: &Value) -> anyhow::Result<()> {
        self.validate()?;
        let opts = host["SecurityOpt"]
            .as_array()
            .ok_or_else(|| anyhow!("sandbox security options missing"))?;
        anyhow::ensure!(
            opts.len() == 2
                && opts
                    .iter()
                    .filter(|opt| opt.as_str() == Some("no-new-privileges"))
                    .count()
                    == 1,
            "sandbox security options drift"
        );
        let profiles: Vec<_> = opts
            .iter()
            .filter_map(|opt| opt.as_str().and_then(|opt| opt.strip_prefix("seccomp=")))
            .collect();
        anyhow::ensure!(
            profiles.len() == 1 && serde_json::from_str::<Value>(profiles[0])? == self.profile,
            "sandbox explicit Docker seccomp policy mismatch"
        );
        Ok(())
    }
}

pub(super) fn verify_daemon(info: &Value) -> anyhow::Result<()> {
    let options = info["SecurityOptions"]
        .as_array()
        .ok_or_else(|| anyhow!("Docker seccomp capability missing"))?;
    let seccomp: Vec<_> = options
        .iter()
        .filter_map(Value::as_str)
        .filter(|option| option.starts_with("name=seccomp"))
        .collect();
    anyhow::ensure!(seccomp.len() == 1 && seccomp[0] == "name=seccomp,profile=builtin",
        "sandbox requires Docker seccomp support with the built-in default, not a custom daemon policy");
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::disallowed_methods)] // Read kernel evidence for the Docker-wide filter before opening the gate.
pub(super) fn verify_live(info: &Value) -> anyhow::Result<()> {
    let pid = info["State"]["Pid"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| anyhow!("sandbox seccomp PID missing"))?;
    verify_status(&std::fs::read_to_string(format!("/proc/{pid}/status"))?)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn verify_live(_: &Value) -> anyhow::Result<()> {
    anyhow::bail!("sandbox seccomp requires Linux")
}

#[cfg(any(target_os = "linux", test))]
fn verify_status(status: &str) -> anyhow::Result<()> {
    fn field<'a>(status: &'a str, key: &str) -> anyhow::Result<&'a str> {
        let values: Vec<_> = status
            .lines()
            .filter_map(|line| line.strip_prefix(key).map(str::trim))
            .collect();
        anyhow::ensure!(
            values.len() == 1,
            "sandbox kernel security field missing or duplicated"
        );
        Ok(values[0])
    }
    anyhow::ensure!(
        field(status, "Seccomp:")? == "2"
            && field(status, "NoNewPrivs:")? == "1"
            && field(status, "Seccomp_filters:")?.parse::<u64>()? >= 1,
        "sandbox kernel seccomp or no-new-privileges missing"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_three_read_only_ioctl_encodings_are_allowed() {
        let policy = Policy::new().unwrap();
        let rules: Vec<_> = policy.profile["syscalls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| {
                rule["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == "ioctl")
            })
            .collect();
        assert_eq!(rules.len(), 3);
        for (rule, request) in rules.iter().zip(READ_ONLY_IOCTL) {
            assert_eq!(
                **rule,
                json!({"names":["ioctl"],"action":"SCMP_ACT_ALLOW",
                "args":[{"index":1,"value":request,"op":"SCMP_CMP_EQ"}]})
            );
        }
        for request in [
            0x401c5820_u64,
            0xc01c5820,
            0x40086602,
            0x40046602,
            0xc0086602,
            0x100000000 | 0x401c5820,
            0xffffffff40086602,
        ] {
            assert!(!READ_ONLY_IOCTL.contains(&request));
        }
        let baseline: Value =
            serde_json::from_str(include_str!("sandbox-seccomp-default.json")).unwrap();
        let mut expected = baseline.clone();
        expected["syscalls"][0]["names"]
            .as_array_mut()
            .unwrap()
            .retain(|name| name != "ioctl");
        let mut actual = policy.profile.clone();
        actual["syscalls"]
            .as_array_mut()
            .unwrap()
            .truncate(baseline["syscalls"].as_array().unwrap().len());
        assert_eq!(
            actual, expected,
            "non-ioctl default seccomp rules must remain unchanged"
        );
        assert!(policy.profile["archMap"].as_array().unwrap().iter().any(|arch|
            arch == &json!({"architecture":"SCMP_ARCH_X86_64","subArchitectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"]})));
        assert!(policy.profile["archMap"].as_array().unwrap().iter().any(|arch|
            arch == &json!({"architecture":"SCMP_ARCH_AARCH64","subArchitectures":["SCMP_ARCH_ARM"]})));
    }

    #[test]
    fn full_persisted_and_inspected_policy_must_match() {
        let policy = Policy::new().unwrap();
        let retained: Policy =
            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
        retained.validate().unwrap();
        let mut body = json!({"HostConfig":{}});
        retained.apply(&mut body).unwrap();
        retained.verify_host(&body["HostConfig"]).unwrap();
        for value in [
            "seccomp=unconfined",
            "seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\"}",
            "apparmor=unconfined",
        ] {
            let mut changed = body.clone();
            changed["HostConfig"]["SecurityOpt"][1] = json!(value);
            assert!(retained.verify_host(&changed["HostConfig"]).is_err());
        }
        let mut changed = retained;
        changed.profile["defaultAction"] = json!("SCMP_ACT_ALLOW");
        assert!(changed.validate().is_err());
        let mut changed = policy.clone();
        changed.profile["syscalls"]
            .as_array_mut()
            .unwrap()
            .push(json!({"names":["ioctl"],"action":"SCMP_ACT_ALLOW"}));
        assert!(changed.validate().is_err());
        let mut changed = policy.clone();
        changed.baseline_commit = "0".repeat(40);
        assert!(changed.validate().is_err());
        assert!(policy
            .verify_host(&json!({"SecurityOpt":["no-new-privileges"]}))
            .is_err());
    }

    #[test]
    fn kernel_filter_evidence_is_fail_closed() {
        verify_status("Seccomp:\t2\nNoNewPrivs:\t1\nSeccomp_filters:\t1\n").unwrap();
        for status in [
            "",
            "Seccomp:\t0\nNoNewPrivs:\t1\nSeccomp_filters:\t1\n",
            "Seccomp:\t2\nNoNewPrivs:\t0\nSeccomp_filters:\t1\n",
            "Seccomp:\t2\nNoNewPrivs:\t1\nSeccomp_filters:\t0\n",
        ] {
            assert!(verify_status(status).is_err());
        }
    }

    #[test]
    fn daemon_without_seccomp_or_with_custom_default_is_refused() {
        verify_daemon(&json!({"SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]}))
            .unwrap();
        for info in [
            json!({}),
            json!({"SecurityOptions":[]}),
            json!({"SecurityOptions":["name=seccomp,profile=/custom.json"]}),
            json!({"SecurityOptions":["name=seccomp,profile=builtin","name=seccomp,profile=unconfined"]}),
        ] {
            assert!(verify_daemon(&info).is_err());
        }
    }
}
