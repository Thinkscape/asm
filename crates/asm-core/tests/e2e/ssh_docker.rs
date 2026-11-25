//! Opt-in: the host scripts on Debian in Docker, driven through the production ssh path
//! (`cargo test -p asm-core --test e2e ssh_host_scripts_on_linux -- --ignored --nocapture`).

use super::*;
use asm_core::ffi::{LeaseInfo, SourceKind, SshCleanupState, SshTargetDraft, SshTargetState, SshTargetUser};
use asm_core::manager::ssh::{OpenSshRemote, RemoteAuth, RemoteError, RemoteOutput, SshRemote, list_host_users};
use asm_core::store::SshTargetRecord;
use std::process::{Child, ChildStdin};
use std::time::{SystemTime, UNIX_EPOCH};

/// Base images and their sudo package: classic sudo on Debian, sudo-rs on Ubuntu 26.04.
const BASES: [(&str, &str); 3] = [("debian:12", "sudo"), ("debian:13", "sudo"), ("ubuntu:26.04", "sudo-rs")];

fn docker(args: &[&str], stdin: Option<&[u8]>) -> Out {
    let mut child = Command::new("docker")
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run docker");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// `docker rm -f` on drop.
struct Container(String);

impl Container {
    /// `docker exec <c> <args...>`.
    fn exec(&self, args: &[&str]) -> Out {
        let mut all = vec!["exec", self.0.as_str()];
        all.extend_from_slice(args);
        docker(&all, None)
    }

    /// `docker exec <c> sh -c <script>`.
    fn sh(&self, script: &str) -> Out {
        self.exec(&["sh", "-c", script])
    }

    /// `sh -c <script>` that must exit 0; its trimmed stdout.
    fn ok(&self, script: &str) -> String {
        let out = self.sh(script);
        assert_eq!(out.code, 0, "{script}: {}{}", out.stdout, out.stderr);
        out.stdout.trim().to_owned()
    }

    /// Replace `path` in place (owner and mode stay) with `data`.
    fn write(&self, path: &str, data: &str) {
        let script = format!("cat > '{path}'");
        let out = docker(&["exec", "-i", &self.0, "sh", "-c", &script], Some(data.as_bytes()));
        assert_eq!(out.code, 0, "writing {path}: {}", out.stderr);
    }

    fn running(&self, pattern: &str) -> bool {
        self.exec(&["pgrep", "-f", pattern]).code == 0
    }

    /// The host's own sweep, `asm-end-lease --sweep`.
    fn sweep(&self) {
        self.ok("systemctl start asm-end-lease.service");
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0])
            .stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// Local child processes: SIGTERM (which `asm ssh request` forwards to ssh), then SIGKILL.
#[derive(Default)]
struct Children(Vec<Child>);

impl Children {
    fn add(&mut self, child: Child) -> usize {
        self.0.push(child);
        self.0.len() - 1
    }

    fn get(&mut self, i: usize) -> &mut Child {
        &mut self.0[i]
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = Command::new("/bin/kill").arg(child.id().to_string()).status();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        for child in &mut self.0 {
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Stops every `asm ssh agent` that logged its start to the log file.
struct Agents(PathBuf);

impl Drop for Agents {
    fn drop(&mut self) {
        let log = std::fs::read_to_string(&self.0).unwrap_or_default();
        for pid in log.lines().filter(|l| l.contains("started for"))
            .filter_map(|l| Some(l.split("asm ssh-agent[").nth(1)?.split(']').next()?.to_owned()))
        {
            let _ = Command::new("/bin/kill").arg(pid).stderr(Stdio::null()).status();
        }
    }
}

/// A remote that never reaches any host.
struct Unreachable;

impl SshRemote for Unreachable {
    fn run(&self, _: &SshTargetRecord, _: &RemoteAuth, _: &str, _: Duration)
        -> std::result::Result<RemoteOutput, RemoteError>
    {
        Err(RemoteError::Unreachable("test".into()))
    }
}

fn wait_for(description: &str, secs: u64, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out after {secs} s waiting for {description}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Sleep until `at` plus `extra` seconds (Unix time).
fn sleep_until(at: u64, extra: u64) {
    let now = unix(SystemTime::now());
    if at + extra > now {
        std::thread::sleep(Duration::from_secs(at + extra - now));
    }
    std::thread::sleep(Duration::from_millis(200));
}

fn ssh_lease(m: &Manager, reason: &str) -> Option<LeaseInfo> {
    m.list_leases().into_iter().find(|l| l.source_kind == SourceKind::Ssh && l.reason == reason)
}

fn lease_id(m: &Manager, reason: &str) -> String {
    let mut id = None;
    wait_for(&format!("SSH lease {reason}"), 30, || {
        id = ssh_lease(m, reason).map(|l| l.lease_id);
        id.is_some()
    });
    id.unwrap()
}

fn expires_at(m: &Manager, reason: &str) -> u64 {
    unix(ssh_lease(m, reason).and_then(|l| l.expires_at).expect("SSH lease end"))
}

/// The cleanup state and detail of `lin` in lease `reason`.
fn cleanup(m: &Manager, reason: &str) -> (Option<SshCleanupState>, String) {
    let lease = ssh_lease(m, reason).expect("SSH lease");
    let target = lease.ssh.expect("SSH detail").targets.into_iter().find(|t| t.name == "lin").expect("lin");
    (target.cleanup, target.cleanup_detail)
}

fn wait_cleanup(m: &Manager, reason: &str, secs: u64, ok: impl Fn(Option<SshCleanupState>, &str) -> bool)
    -> (Option<SshCleanupState>, String)
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let seen = cleanup(m, reason);
        if ok(seen.0, &seen.1) {
            eprintln!("{reason} cleanup: {:?}: {}", seen.0, seen.1);
            return seen;
        }
        assert!(Instant::now() < deadline, "{reason} cleanup after {secs} s: {seen:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_exit(child: &mut Child, what: &str, secs: u64) {
    wait_for(&format!("{what} to exit"), secs, || !matches!(child.try_wait(), Ok(None)));
}

fn keygen(path: &Path) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(path)
        .stdin(Stdio::null())
        .status().unwrap();
    assert!(status.success(), "ssh-keygen failed");
}

fn output(mut c: Command, stdin: Option<&str>) -> Out {
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("spawn");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    }
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// `/usr/bin/ssh -F <config> <args...>`.
fn ssh(config: &Path, args: &[&str]) -> Command {
    let mut c = Command::new("/usr/bin/ssh");
    c.arg("-F").arg(config).args(args);
    c
}

/// The paired CLI; every run logs agent starts to `agent_log`.
struct Cli<'a> {
    env: &'a Env,
    agent_log: String,
}

impl Cli<'_> {
    fn command(&self, args: &[&str], extra: &[(&str, &str)]) -> Command {
        let mut env = vec![("ASM_SSH_AGENT_LOG", self.agent_log.as_str())];
        env.extend_from_slice(extra);
        self.env.command(args, &env)
    }

    fn run(&self, args: &[&str]) -> Out {
        output(self.command(args, &[]), None)
    }

    /// Runs in the background with stdout and stderr in `<dir>/<name>.out` / `.err`.
    fn spawn(&self, args: &[&str], dir: &Path, name: &str) -> Child {
        let mut c = self.command(args, &[]);
        c.stdin(Stdio::null())
            .stdout(std::fs::File::create(dir.join(format!("{name}.out"))).unwrap())
            .stderr(std::fs::File::create(dir.join(format!("{name}.err"))).unwrap());
        c.spawn().expect("spawn asm")
    }

    fn lease_config(&self, lease_id: &str) -> PathBuf {
        self.env.config.join("asm/ssh").join(lease_id).join("config")
    }
}

#[test]
#[ignore = "needs Docker; run with --ignored"]
fn ssh_host_scripts_on_linux() {
    let bin_dir = workspace().join("dist/bin");
    if !bin_dir.join("iron-proxy").is_file() {
        eprintln!("skipping: missing prerequisite {}; run `just proxy`", bin_dir.join("iron-proxy").display());
        return;
    }
    let cli = build_cli();
    for (base, sudo) in BASES {
        eprintln!("== {base} ({sudo})");
        host_scripts_on(base, sudo, &cli, &bin_dir);
    }
}

fn host_scripts_on(base: &str, sudo: &str, cli: &Path, bin_dir: &Path) {
    // ---- Setup ----
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh-target");
    let image = format!("asm-ssh-target:{}", base.replace(':', "-"));
    let built = docker(&["build", "-q", "--build-arg", &format!("BASE={base}"), "--build-arg", &format!("SUDO={sudo}"),
        "-t", &image, fixture.to_str().unwrap()], None);
    assert_eq!(built.code, 0, "docker build {image}: {}", built.stderr);
    let started = docker(&["run", "-d", "--privileged", "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "--tmpfs", "/run", "--tmpfs", "/run/lock", "-p", "127.0.0.1::22", &image], None);
    assert_eq!(started.code, 0, "docker run {image}: {}", started.stderr);
    let c = Container(started.stdout.trim().to_owned());
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let out = c.exec(&["systemctl", "is-active", "ssh.service"]);
        if out.stdout.trim() == "active" {
            break;
        }
        if Instant::now() > deadline {
            eprintln!("skipping: systemd did not start in Docker: ssh.service is {:?} {}", out.stdout.trim(), out.stderr.trim());
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let mapped = docker(&["port", &c.0, "22"], None);
    let port: u16 = mapped.stdout.lines().next().and_then(|l| l.rsplit(':').next())
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("docker port: {}{}", mapped.stdout, mapped.stderr));
    let host_key = c.ok("cat /etc/ssh/ssh_host_ed25519_key.pub")
        .split_whitespace().take(2).collect::<Vec<_>>().join(" ");

    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    keygen(&t.join("operator"));
    let operator_pub = std::fs::read_to_string(t.join("operator.pub")).unwrap();
    c.ok("umask 077 && mkdir -p /root/.ssh && chmod 700 /root/.ssh && : > /root/.ssh/authorized_keys \
          && chmod 600 /root/.ssh/authorized_keys");
    c.write("/root/.ssh/authorized_keys", &operator_pub);
    let root_keys = c.ok("sha256sum /root/.ssh/authorized_keys");

    let ssh_config = t.join("ssh_config");
    std::fs::write(&ssh_config, format!(
        "Host lin-target\n  HostName 127.0.0.1\n  Port {port}\n  User root\n  IdentityFile \"{}\"\n  \
         IdentitiesOnly yes\n  IdentityAgent none\n",
        t.join("operator").display(),
    )).unwrap();
    // The test's own operator logins pin the host key; the manager's pass their own options.
    let operator_known_hosts = t.join("operator_known_hosts");
    std::fs::write(&operator_known_hosts, format!("[127.0.0.1]:{port} {host_key}\n")).unwrap();
    let operator_ssh = |args: &[&str]| {
        let mut c = ssh(&ssh_config, &["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]);
        c.arg("-o").arg(format!("UserKnownHostsFile={}", operator_known_hosts.display()));
        c.args(args);
        c
    };

    let ports = free_ports(5);
    let approver = Arc::new(AutoApprover {
        manager: OnceLock::new(), approvals: AtomicUsize::new(0), busy: Mutex::new(()),
    });
    let manager = Manager::start_with(
        t.join("data"), bin_dir.to_path_buf(), Arc::new(Observer(approver.clone())),
        StartOptions {
            resume_key: Some([23; 32]),
            values_root: Some(t.join("values")),
            settings: vec![
                (keys::API_BIND.into(), json!("127.0.0.1")), (keys::API_PORT.into(), json!(0)),
                (keys::PROXY_BIND.into(), json!("127.0.0.1")),
                (keys::PROXY_PORT.into(), json!(ports[0])),
                (keys::PROXY_HTTP_PORT.into(), json!(ports[1])),
                (keys::PROXY_HTTPS_PORT.into(), json!(ports[2])),
                (keys::PROXY_MGMT_PORT.into(), json!(ports[3])),
                (keys::PROXY_METRICS_PORT.into(), json!(ports[4])),
                (keys::PROXY_HINTS.into(), json!(["127.0.0.1"])),
            ],
        },
    ).expect("start isolated manager");
    approver.manager.set(manager.clone()).ok().unwrap();
    let shutdown = ShutdownManager(manager);
    let manager = &shutdown.0;
    let remote = || Arc::new(OpenSshRemote::new(manager.core().dirs.ssh_known_hosts(), Some(ssh_config.clone())));
    manager.core().install_ssh_remote(remote());

    let env = Env { cli: cli.to_path_buf(), config: t.join("config"), secrets: t.join("secrets") };
    let code = manager.create_pairing_code("ssh docker e2e".into(), Some(3600), Some(1), vec!["127.0.0.1/8".into()])
        .unwrap();
    let paired = env.run(&["pair", &manager.general_settings().listening_on, &code.code], None);
    assert_eq!(paired.code, 0, "pairing failed: {}", paired.stderr);
    let agent_log = t.join("agent.log");
    let _agents = Agents(agent_log.clone());
    let asm = Cli { env: &env, agent_log: agent_log.to_str().unwrap().to_owned() };
    let mut children = Children::default();

    // Users agents may log in as: a plain account, one that can become root and a daemon
    // account without a login shell.
    c.ok("useradd -m -s /bin/bash deploy && useradd -m -s /bin/bash -G sudo ops");
    let listed = list_host_users("lin-target", "root", std::slice::from_ref(&host_key), Some(&ssh_config),
        &{ let d = t.join("users-run"); std::fs::create_dir(&d).unwrap(); d }).expect("list the host's users");
    let user = |name: &str| listed.iter().find(|u| u.name == name).unwrap_or_else(|| panic!("{name}: {listed:?}"));
    assert_eq!((user("deploy").system, user("deploy").login_shell, user("deploy").admin.as_deref()), (false, true, None));
    assert_eq!(user("ops").admin.as_deref(), Some("in group sudo"));
    assert_eq!((user("www-data").system, user("www-data").login_shell), (true, false));
    for absent in ["root", "nobody", "asm-ops"] {
        assert!(listed.iter().all(|u| u.name != absent), "{absent} listed: {listed:?}");
    }
    let users: Vec<SshTargetUser> = ["deploy", "ops", "www-data"].iter()
        .map(|name| SshTargetUser { name: (*name).into(), admin: user(name).admin.clone() }).collect();

    let units = vec!["asm-test.service".to_owned()];
    let target = manager.save_ssh_target(SshTargetDraft {
        id: None, expected_revision: None, name: "lin".into(), destination: "lin-target".into(),
        agent_hostname: "127.0.0.1".into(), agent_port: port, privileged_login: "root".into(),
        allow_privileged: true, host_keys: vec![host_key.clone()], log_units: units.clone(),
        restart_units: units, max_duration_secs: 60, users,
    }).expect("save SSH target");
    let tid = target.id.clone();

    // ---- 1. A foreign account is refused. ----
    c.ok("useradd --system asm-ops");
    let refused = manager.enroll_ssh_target(tid.clone(), target.revision).expect_err("enrolled over a foreign asm-ops");
    assert!(refused.to_string().contains("user-exists"), "{refused}");
    c.ok("test ! -e /var/lib/asm-ssh && test ! -e /usr/lib/asm-ssh");
    c.ok("userdel asm-ops");

    // ---- 1b. Other ways sshd could let someone in as an asm account are refused. ----
    c.ok("ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/other-ca && echo 'TrustedUserCAKeys /etc/ssh/other-ca.pub' > /etc/ssh/sshd_config.d/asm-test-ca.conf");
    let revision = manager.list_ssh_targets().unwrap().into_iter().find(|i| i.id == tid).unwrap().revision;
    let refused = manager.enroll_ssh_target(tid.clone(), revision).expect_err("enrolled with a host-wide user CA");
    assert!(refused.to_string().contains("auth-path") && refused.to_string().contains("TrustedUserCAKeys"), "{refused}");
    c.ok("test ! -e /var/lib/asm-ssh && test ! -e /usr/lib/asm-ssh");
    c.ok("printf 'Match User asm-ops,asm-priv\\n    TrustedUserCAKeys none\\n' >> /etc/ssh/sshd_config.d/asm-test-ca.conf");

    // ---- 2. Enroll. ----
    let revision = manager.list_ssh_targets().unwrap().into_iter().find(|i| i.id == tid).unwrap().revision;
    let enrolled = manager.enroll_ssh_target(tid.clone(), revision).expect("enroll");
    assert_eq!(enrolled.state, SshTargetState::Enrolled, "{:?}", enrolled.error);
    let marker = format!(" asm-ca-{tid}$");
    assert_eq!(c.ok(&format!("grep -c '{marker}' /var/lib/asm-ops/.ssh/authorized_keys")), "2");
    assert_eq!(c.ok("stat -c %U /var/lib/asm-ops/.ssh/authorized_keys /var/lib/asm-priv/.ssh/authorized_keys"),
        "root\nroot");
    assert_eq!(c.ok("id -Gn asm-ops"), "asm-ops");
    assert_eq!(c.ok("id -Gn asm-priv"), "asm-priv");
    assert_eq!(c.ok("systemctl is-active asm-end-lease.timer"), "active");
    let sudo = c.ok("sudo -l -U asm-ops");
    assert!(sudo.contains("asm-logs asm-test.service *"), "{sudo}");
    assert!(sudo.contains("restart asm-test.service"), "{sudo}");
    assert_eq!(c.ok("sha256sum /root/.ssh/authorized_keys"), root_keys);
    let priv_rules = c.ok("sudo -l -U asm-priv");
    assert!(priv_rules.contains("(root, deploy, ops, www-data) NOPASSWD: ALL"), "{priv_rules}");
    assert_eq!(c.ok("sed -n 's/^user=//p' /var/lib/asm-ssh/manifest | cut -d: -f1,3"), "deploy:0\nops:1\nwww-data:0");
    assert_eq!(c.ok("sed -n 's/^user=www-data://p' /var/lib/asm-ssh/manifest"), "33:0");
    assert_eq!(c.ok(&format!("grep -c '{marker}' /var/lib/asm-priv/.ssh/authorized_keys")), "2");

    // ---- 3. Privileged command, sftp, and plain ssh through the Include. ----
    let r1 = asm.run(&["ssh", "request", "lin", "r1", "--privileged", "--", "id", "-u"]);
    assert_eq!((r1.code, r1.stdout.trim()), (0, "0"), "{}", r1.stderr);
    let r1_config = asm.lease_config(&lease_id(manager, "r1"));
    let mut sftp = Command::new("/usr/bin/sftp");
    sftp.arg("-F").arg(&r1_config).args(["-b", "-", "lin"]);
    let sftp = output(sftp, Some("pwd\n"));
    assert_eq!(sftp.code, 0, "{}{}", sftp.stdout, sftp.stderr);
    assert!(sftp.stdout.contains("Remote working directory: /root"), "{}", sftp.stdout);
    let home = t.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let installed = output(asm.command(&["ssh", "install"], &[("HOME", home.to_str().unwrap())]), None);
    assert_eq!(installed.code, 0, "{}{}", installed.stdout, installed.stderr);
    let home_config = home.join(".ssh/config");
    for name in ["lin", "127.0.0.1"] {
        let out = output(ssh(&home_config, &[name, "id", "-u"]), None);
        assert_eq!((out.code, out.stdout.trim()), (0, "0"), "ssh {name} through the Include: {}", out.stderr);
    }

    // ---- 3b. Access as other users, and a user whose rights changed. ----
    // www-data has no login shell and no home directory here: /bin/sh, starting in /.
    for (reason, name, session) in [("u1", "deploy", "deploy /home/deploy /bin/bash"), ("u2", "www-data", "www-data / /bin/sh")] {
        let out = asm.run(&["ssh", "request", "lin", reason, "--as", name, "--", "echo $(id -un) $(pwd) $SHELL"]);
        assert_eq!((out.code, out.stdout.trim()), (0, session), "{name}: {}", out.stderr);
        assert!(!out.stderr.contains("can't cd"), "{name}: {}", out.stderr);
    }
    let refused = asm.run(&["ssh", "request", "lin", "u3", "--as", "games", "--", "id", "-un"]);
    assert_eq!(refused.code, 2, "{}", refused.stderr);
    assert!(refused.stderr.contains("does not allow access as games"), "{}", refused.stderr);
    // deploy joins sudo after enrollment: its logins are refused until the target is
    // enrolled again, which refuses it too.
    c.ok("usermod -aG sudo deploy");
    let drift = asm.run(&["ssh", "request", "lin", "u1", "--as", "deploy", "--", "id", "-un"]);
    assert_eq!(drift.code, 126, "{}{}", drift.stdout, drift.stderr);
    assert!(drift.stderr.contains("deploy can now become root (in group sudo)"), "{}", drift.stderr);
    let changed = manager.enroll_ssh_target(tid.clone(), revision).expect_err("enrolled a user that became root");
    assert!(changed.to_string().contains("deploy can now become root (in group sudo)"), "{changed}");
    // Enrolling ended the target's leases; their cleanup finishes before enrolling again
    // (until the cleanup thread lets go of the target, enrolling asks to try again).
    for reason in ["r1", "u1", "u2"] {
        wait_cleanup(manager, reason, 60, |state, _| matches!(state, Some(SshCleanupState::Done)));
    }
    c.ok("gpasswd -d deploy sudo >/dev/null");
    let mut again = None;
    wait_for("the target to be free to enroll", 30, || match manager.enroll_ssh_target(tid.clone(), revision) {
        Err(e) if e.to_string().contains("try again in a moment") => false,
        other => {
            again = Some(other);
            true
        }
    });
    let again = again.unwrap().expect("enroll again");
    assert_eq!(again.state, SshTargetState::Enrolled, "{:?}", again.error);

    // ---- 4. Logs. ----
    let r2 = asm.run(&["ssh", "request", "lin", "r2", "--grant", "logs:asm-test.service", "--",
        "logs", "asm-test.service", "5"]);
    assert_eq!(r2.code, 0, "{}{}", r2.stdout, r2.stderr);
    let r2b = asm.run(&["ssh", "request", "lin", "r2b", "--grant", "logs:asm-test.service", "--",
        "logs", "ssh.service", "5"]);
    assert_eq!(r2b.code, 126, "{}{}", r2b.stdout, r2b.stderr);
    assert!(r2b.stderr.contains("not granted"), "{}", r2b.stderr);

    // ---- 5. Restart. ----
    let r3 = asm.run(&["ssh", "request", "lin", "r3", "--grant", "restart:asm-test.service", "--",
        "restart", "asm-test.service"]);
    assert_eq!(r3.code, 0, "{}{}", r3.stdout, r3.stderr);
    let r3_config = asm.lease_config(&lease_id(manager, "r3"));
    let out = output(ssh(&r3_config, &["lin", "restart", "ssh.service"]), None);
    assert_eq!(out.code, 126, "{}{}", out.stdout, out.stderr);
    assert!(out.stderr.contains("not granted"), "{}", out.stderr);

    // ---- 6. Ending a live session without touching anything else. ----
    assert_eq!(docker(&["exec", "-d", &c.0, "sleep", "7777"], None).code, 0);
    let mut operator = operator_ssh(&["lin-target", "sleep", "6666"]);
    operator.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let operator = children.add(operator.spawn().unwrap());
    let r4 = children.add(asm.spawn(&["ssh", "request", "lin", "r4", "--privileged", "--new-lease", "--",
        "sleep", "600"], t, "r4"));
    wait_for("sleep 600 (r4) in the container", 30, || c.running("sleep 600"));
    let r4_id = lease_id(manager, "r4");
    manager.revoke_lease(r4_id.clone()).unwrap();
    wait_exit(children.get(r4), "r4", 20);
    wait_cleanup(manager, "r4", 20, |s, d| s == Some(SshCleanupState::Done) && d == "host reported: ended 1 sessions");
    assert!(c.ok("cat /run/asm-ssh/ended").contains(&r4_id));
    assert_eq!(c.exec(&["pgrep", "-xf", "sleep 7777"]).code, 0, "the decoy was killed");
    assert!(matches!(children.get(operator).try_wait(), Ok(None)), "the operator's session was ended");
    let _ = children.get(operator).kill();
    let _ = children.get(operator).wait();

    // ---- 7. Host backstop without the Mac. ----
    wait_for("r4's sleep 600 to be gone", 20, || !c.running("sleep 600"));
    let r5 = children.add(asm.spawn(&["ssh", "request", "lin", "r5", "--privileged", "--new-lease", "--",
        "sleep", "600"], t, "r5"));
    wait_for("sleep 600 (r5) in the container", 30, || c.running("sleep 600"));
    manager.core().install_ssh_remote(Arc::new(Unreachable));
    sleep_until(expires_at(manager, "r5"), 2);
    c.sweep();
    wait_exit(children.get(r5), "r5", 20);
    wait_cleanup(manager, "r5", 20, |s, _| s == Some(SshCleanupState::Retrying));
    manager.core().install_ssh_remote(remote());

    // ---- 8. Extension and terminal warning. ----
    let r6 = asm.run(&["ssh", "request", "lin", "r6", "--privileged", "--new-lease"]);
    assert_eq!(r6.code, 0, "{}{}", r6.stdout, r6.stderr);
    assert!(r6.stdout.starts_with("ssh lease "), "{}", r6.stdout);
    let r6_id = lease_id(manager, "r6");
    let r6_end = expires_at(manager, "r6");
    let r6_out = t.join("r6.out");
    let mut session = ssh(&asm.lease_config(&r6_id), &["-tt", "lin", "sleep 601"]);
    session.stdin(Stdio::piped())
        .stdout(std::fs::File::create(&r6_out).unwrap())
        .stderr(std::fs::File::create(t.join("r6.err")).unwrap());
    let mut session = session.spawn().unwrap();
    // Keep the terminal's input open, so the session is not ended by an EOF.
    let _session_stdin: Option<ChildStdin> = session.stdin.take();
    let session = children.add(session);
    wait_for("sleep 601 in the container", 30, || c.running("sleep 601"));
    c.sweep();
    wait_for("the terminal warning", 5, || std::fs::read_to_string(&r6_out)
        .is_ok_and(|o| o.contains("asm: this SSH lease ends at")));
    // The extension must end well after the original end, so the sweep between the two
    // ends has a margin.
    sleep_until(r6_end.saturating_sub(45), 0);
    let extended = asm.run(&["ssh", "extend", &r6_id, "longer"]);
    assert_eq!(extended.code, 0, "{}{}", extended.stdout, extended.stderr);
    assert!(extended.stdout.contains("lin: confirmed"), "{}", extended.stdout);
    let r6_new_end = expires_at(manager, "r6");
    assert!(r6_new_end > r6_end + 5, "{r6_new_end} vs {r6_end}");
    assert_eq!(c.ok(&format!("cat /run/asm-ssh/leases/{r6_id}")), r6_new_end.to_string());
    sleep_until(r6_end, 2);
    c.sweep();
    std::thread::sleep(Duration::from_secs(2));
    assert!(matches!(children.get(session).try_wait(), Ok(None)), "the extended session ended at the old end");
    sleep_until(r6_new_end, 2);
    c.sweep();
    wait_exit(children.get(session), "the r6 session", 20);

    // ---- 9. Cleanup never falls back to the operator's key. ----
    let ops_keys = "/var/lib/asm-ops/.ssh/authorized_keys";
    let original = c.ok(&format!("cat {ops_keys}"));
    let without_cleanup: String = original.lines()
        .filter(|l| !l.contains(&format!("\"asm-{tid}-cleanup\"")))
        .map(|l| format!("{l}\n")).collect();
    assert_eq!(without_cleanup.lines().count(), 1, "{original}");
    let operator_line = operator_pub.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    c.write(ops_keys, &format!("{without_cleanup}{operator_line} operator-test\n"));
    wait_for("r6's sleep 601 to be gone", 20, || !c.running("sleep 601"));
    let r7 = children.add(asm.spawn(&["ssh", "request", "lin", "r7", "--privileged", "--new-lease", "--",
        "sleep", "600"], t, "r7"));
    wait_for("sleep 600 (r7) in the container", 30, || c.running("sleep 600"));
    let r7_id = lease_id(manager, "r7");
    manager.revoke_lease(r7_id).unwrap();
    wait_cleanup(manager, "r7", 20,
        |s, d| s == Some(SshCleanupState::Retrying) && d.contains("Permission denied"));
    c.write(ops_keys, &without_cleanup);

    // ---- 10. Remove. ----
    manager.unenroll_ssh_target(tid.clone()).expect("remove asm from the host");
    let info = manager.list_ssh_targets().unwrap().into_iter().find(|i| i.id == tid).unwrap();
    assert_eq!(info.state, SshTargetState::NotEnrolled, "{:?}", info.error);
    let (state, detail) = cleanup(manager, "r7");
    eprintln!("r7 cleanup: {state:?}: {detail}");
    assert_eq!(state, Some(SshCleanupState::Done), "{detail}");
    assert!(detail.starts_with("host reported: asm removed"), "{detail}");
    wait_exit(children.get(r7), "r7", 20);
    for user in ["asm-ops", "asm-priv"] {
        assert_ne!(c.exec(&["getent", "passwd", user]).code, 0, "{user} still exists");
    }
    for path in ["/etc/sudoers.d/asm-ssh", "/usr/lib/asm-ssh", "/var/lib/asm-ssh", "/var/lib/asm-ops",
        "/var/lib/asm-priv", "/etc/systemd/system/asm-end-lease.timer"]
    {
        assert_ne!(c.exec(&["test", "-e", path]).code, 0, "{path} still exists");
    }
    assert_eq!(c.ok("sha256sum /root/.ssh/authorized_keys"), root_keys);
    let out = output(operator_ssh(&["lin-target", "true"]), None);
    assert_eq!(out.code, 0, "the operator's own login: {}", out.stderr);
    for reason in ["r4", "r5"] {
        let (state, detail) = cleanup(manager, reason);
        eprintln!("{reason} cleanup after removal: {state:?}: {detail}");
    }
}
