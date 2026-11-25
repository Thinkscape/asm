use super::*;
use asm_core::manager::ssh::{HostCheck, Route, certificate_config, check_destination, fetch_host_keys, ssh_options};

/// Stops the test sshd.
struct Processes {
    sshd: Option<std::process::Child>,
}

impl Drop for Processes {
    fn drop(&mut self) {
        if let Some(mut sshd) = self.sshd.take() {
            let _ = sshd.kill();
            let _ = sshd.wait();
        }
    }
}

fn user() -> String {
    std::env::var("USER").expect("USER is set")
}

fn keygen(path: &Path) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(path)
        .stdin(Stdio::null())
        .status().unwrap();
    assert!(status.success(), "ssh-keygen failed");
}

/// An unprivileged sshd on 127.0.0.1 with `dir/hostkey` that trusts `ca` for `principal`
/// logging in as `$USER`, and the keys in `dir/authorized_keys` when that file exists.
/// `Err` carries the reason sshd did not come up.
fn start_sshd(dir: &Path, port: u16, ca: &str, principal: &str) -> std::result::Result<std::process::Child, String> {
    std::fs::write(dir.join("ca.pub"), format!("{ca}\n")).unwrap();
    std::fs::create_dir_all(dir.join("principals")).unwrap();
    std::fs::write(dir.join("principals").join(user()), format!("{principal}\n")).unwrap();
    let config = dir.join("sshd_config");
    std::fs::write(&config, format!(
        "ListenAddress 127.0.0.1\nPort {port}\nHostKey {d}/hostkey\nPidFile {d}/sshd.pid\nUsePAM no\n\
         StrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile {d}/authorized_keys\n\
         TrustedUserCAKeys {d}/ca.pub\nAuthorizedPrincipalsFile {d}/principals/%u\nLogLevel VERBOSE\n",
        d = dir.display(),
    )).unwrap();
    let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
    let mut child = Command::new("/usr/sbin/sshd")
        .arg("-D").arg("-e").arg("-f").arg(&config)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(log)
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let log = std::fs::read_to_string(dir.join("sshd.log")).unwrap_or_default();
            return Err(format!("sshd exited ({status}): {log}"));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(child);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sshd did not start listening".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The host key was accepted (no verification failure) and authentication was refused.
fn assert_reached_pinned_host(what: &str, out: std::process::Output, sshd_dir: &Path) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let sshd_log = std::fs::read_to_string(sshd_dir.join("sshd.log")).unwrap_or_default();
    assert_eq!(out.status.code(), Some(255), "{what}: {stderr}\nsshd: {sshd_log}");
    assert!(stderr.contains("Permission denied"), "{what}: {stderr}\nsshd: {sshd_log}");
    assert!(!stderr.contains("Host key verification failed"), "{what}: {stderr}");
}

/// Both ways the manager runs ssh (operator options and a certificate run's config)
/// verify the target against the pinned host key under `HostKeyAlias`, with a data
/// path that contains a space.
#[test]
fn ssh_configs_reach_a_pinned_host() {
    let tmp = tempfile::tempdir().unwrap();
    let sshd_dir = tmp.path().join("sshd");
    std::fs::create_dir_all(&sshd_dir).unwrap();
    keygen(&sshd_dir.join("hostkey"));
    keygen(&sshd_dir.join("ca"));
    let host_key = std::fs::read_to_string(sshd_dir.join("hostkey.pub")).unwrap()
        .split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let ca = std::fs::read_to_string(sshd_dir.join("ca.pub")).unwrap().trim().to_owned();
    let port = free_ports(1)[0];
    let mut processes = Processes { sshd: None };
    match start_sshd(&sshd_dir, port, &ca, "asm-0123abcd-privileged") {
        Ok(child) => processes.sshd = Some(child),
        Err(why) => {
            eprintln!("skipping: macOS would not run an unprivileged sshd: {why}");
            return;
        }
    }

    let pin_dir = tmp.path().join("pin dir");
    std::fs::create_dir_all(&pin_dir).unwrap();
    let known_hosts = pin_dir.join("known_hosts");
    std::fs::write(&known_hosts, format!("asm-target-0123abcd {host_key}\n")).unwrap();

    // Operator options: the test's own options come first, so they win and keep the
    // operator's agent and keys out.
    let out = Command::new("/usr/bin/ssh")
        .args(["-o", "IdentityAgent=none", "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no"])
        .args(ssh_options(&known_hosts, "0123abcd").unwrap())
        .arg("-l").arg(user())
        .arg("--").arg(format!("ssh://127.0.0.1:{port}")).arg("true")
        .stdin(Stdio::null())
        .output().unwrap();
    assert_reached_pinned_host("operator options", out, &sshd_dir);

    // Certificate config: a throwaway key whose "certificate" is its plain public key.
    let run_dir = tmp.path().join("run dir");
    std::fs::create_dir_all(&run_dir).unwrap();
    keygen(&run_dir.join("id"));
    std::fs::copy(run_dir.join("id.pub"), run_dir.join("id-cert.pub")).unwrap();
    let route = Route { hostname: "127.0.0.1".into(), port, ..Route::default() };
    let config = certificate_config(&route, &known_hosts, "0123abcd", "asm-ops", &run_dir, None).unwrap();
    std::fs::write(run_dir.join("config"), config).unwrap();
    let out = Command::new("/usr/bin/ssh")
        .arg("-F").arg(run_dir.join("config")).args(["-T", "asm-target", "true"])
        .stdin(Stdio::null())
        .output().unwrap();
    assert_reached_pinned_host("certificate config", out, &sshd_dir);
}

/// With no known_hosts entry, asm fetches the host key through the ssh route without
/// logging in, and an address where nothing listens gives a clear error.
#[test]
fn host_keys_are_fetched_without_known_hosts_or_a_login() {
    let tmp = tempfile::tempdir().unwrap();
    let sshd_dir = tmp.path().join("sshd");
    std::fs::create_dir_all(&sshd_dir).unwrap();
    keygen(&sshd_dir.join("hostkey"));
    keygen(&sshd_dir.join("ca"));
    let host_key = std::fs::read_to_string(sshd_dir.join("hostkey.pub")).unwrap()
        .split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let ca = std::fs::read_to_string(sshd_dir.join("ca.pub")).unwrap().trim().to_owned();
    let [port, closed] = free_ports(2)[..] else { unreachable!() };
    let mut processes = Processes { sshd: None };
    match start_sshd(&sshd_dir, port, &ca, "asm-0123abcd-privileged") {
        Ok(child) => processes.sshd = Some(child),
        Err(why) => {
            eprintln!("skipping: macOS would not run an unprivileged sshd: {why}");
            return;
        }
    }
    let config = tmp.path().join("ssh config");
    std::fs::write(&config, format!(
        "Host lin-host\n  HostName 127.0.0.1\n  Port {port}\n  User {u}\nHost closed-host\n  HostName 127.0.0.1\n  Port {closed}\n",
        u = user(),
    )).unwrap();
    let run_dir = |name: &str| {
        let dir = tmp.path().join(format!("run-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };

    assert_eq!(fetch_host_keys("lin-host", Some(&config), &run_dir("open")).unwrap(), [host_key]);
    let sshd_log = std::fs::read_to_string(sshd_dir.join("sshd.log")).unwrap_or_default();
    assert!(!sshd_log.contains("Accepted"), "a fetch logged in: {sshd_log}");

    let err = fetch_host_keys("closed-host", Some(&config), &run_dir("closed")).unwrap_err();
    assert!(err.message.starts_with("could not get the host keys of closed-host: "), "{}", err.message);
    assert!(err.message.contains("refused"), "{}", err.message);
}

/// The check before a target is saved logs in as enrollment will: with the right pinned
/// key it reaches the login (and sudo), with a wrong one it reports the keys the host
/// offers, and a login the host refuses is an error.
#[test]
fn host_checks_tell_a_changed_key_from_a_refused_login() {
    let tmp = tempfile::tempdir().unwrap();
    let sshd_dir = tmp.path().join("sshd");
    std::fs::create_dir_all(&sshd_dir).unwrap();
    for name in ["hostkey", "ca", "other-hostkey"] {
        keygen(&sshd_dir.join(name));
    }
    for name in ["operator", "stranger"] {
        keygen(&tmp.path().join(name));
    }
    let public = |path: PathBuf| std::fs::read_to_string(path).unwrap()
        .split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let host_key = public(sshd_dir.join("hostkey.pub"));
    let other_key = public(sshd_dir.join("other-hostkey.pub"));
    std::fs::copy(tmp.path().join("operator.pub"), sshd_dir.join("authorized_keys")).unwrap();
    let ca = public(sshd_dir.join("ca.pub"));
    let port = free_ports(1)[0];
    let mut processes = Processes { sshd: None };
    match start_sshd(&sshd_dir, port, &ca, "asm-0123abcd-privileged") {
        Ok(child) => processes.sshd = Some(child),
        Err(why) => {
            eprintln!("skipping: macOS would not run an unprivileged sshd: {why}");
            return;
        }
    }
    let config = tmp.path().join("ssh config");
    let mut text = String::new();
    for (host, key) in [("lin-host", "operator"), ("stranger-host", "stranger")] {
        text.push_str(&format!(
            "Host {host}\n  HostName 127.0.0.1\n  Port {port}\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  IdentityAgent none\n",
            tmp.path().join(key).display(),
        ));
    }
    std::fs::write(&config, text).unwrap();
    let run_dir = |name: &str| {
        let dir = tmp.path().join(format!("run-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };
    let me = user();

    // `$USER` is not root, so the check also runs `sudo -n`: either it works here, or the
    // error names sudo, which the host only reaches after the key and the login.
    match check_destination("lin-host", &me, std::slice::from_ref(&host_key), Some(&config), &run_dir("ok")) {
        Ok(HostCheck::Verified) => {}
        Err(e) => assert!(e.message.contains("needs passwordless sudo"), "{}", e.message),
        Ok(other) => panic!("unexpected {other:?}"),
    }
    assert_eq!(check_destination("lin-host", &me, &[other_key], Some(&config), &run_dir("changed")).unwrap(),
        HostCheck::KeyMismatch(vec![host_key.clone()]));
    let err = check_destination("stranger-host", &me, &[host_key], Some(&config), &run_dir("stranger")).unwrap_err();
    assert!(err.message.starts_with(&format!("asm could not log in to stranger-host as {me} with your ssh setup: ")),
        "{}", err.message);
}

/// A jump host goes through asm's own ssh config: it is checked against the operator's
/// known_hosts even when their config would accept new hosts, never added to it, and a
/// failure names it. Once known, fetches and checks work through it.
#[test]
fn jump_hosts_are_checked_but_never_added_to_known_hosts() {
    let tmp = tempfile::tempdir().unwrap();
    let sshd_dir = tmp.path().join("sshd");
    std::fs::create_dir_all(&sshd_dir).unwrap();
    keygen(&sshd_dir.join("hostkey"));
    keygen(&sshd_dir.join("ca"));
    keygen(&tmp.path().join("operator"));
    let public = |path: PathBuf| std::fs::read_to_string(path).unwrap()
        .split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let host_key = public(sshd_dir.join("hostkey.pub"));
    std::fs::copy(tmp.path().join("operator.pub"), sshd_dir.join("authorized_keys")).unwrap();
    let port = free_ports(1)[0];
    let mut processes = Processes { sshd: None };
    match start_sshd(&sshd_dir, port, &public(sshd_dir.join("ca.pub")), "asm-0123abcd-privileged") {
        Ok(child) => processes.sshd = Some(child),
        Err(why) => {
            eprintln!("skipping: macOS would not run an unprivileged sshd: {why}");
            return;
        }
    }
    // The operator's own known_hosts for the jump host starts empty, and their config would
    // accept it as new.
    let operator_known_hosts = tmp.path().join("operator_known_hosts");
    std::fs::write(&operator_known_hosts, "").unwrap();
    let identity = format!("  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  IdentityAgent none\n",
        tmp.path().join("operator").display());
    let config = tmp.path().join("ssh config");
    std::fs::write(&config, format!(
        "Host jump\n  HostName 127.0.0.1\n  Port {port}\n{identity}  UserKnownHostsFile \"{}\"\n  StrictHostKeyChecking accept-new\n\
         Host via-jump\n  HostName 127.0.0.1\n  Port {port}\n  ProxyJump jump\n{identity}",
        operator_known_hosts.display(),
    )).unwrap();
    let run_dir = |name: &str| {
        let dir = tmp.path().join(format!("run-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };
    let me = user();

    let err = fetch_host_keys("via-jump", Some(&config), &run_dir("fetch-unknown")).unwrap_err();
    assert!(err.message.contains("a jump host failed its host key check"), "{}", err.message);
    let err = check_destination("via-jump", &me, std::slice::from_ref(&host_key), Some(&config), &run_dir("check-unknown"))
        .unwrap_err();
    assert!(err.message.contains("a jump host failed its host key check"), "{}", err.message);
    assert_eq!(std::fs::read_to_string(&operator_known_hosts).unwrap(), "", "the jump host was added");

    let known = format!("[127.0.0.1]:{port} {host_key}\n");
    std::fs::write(&operator_known_hosts, &known).unwrap();
    assert_eq!(fetch_host_keys("via-jump", Some(&config), &run_dir("fetch-known")).unwrap(), [host_key.clone()]);
    match check_destination("via-jump", &me, std::slice::from_ref(&host_key), Some(&config), &run_dir("check-known")) {
        Ok(HostCheck::Verified) => {}
        Err(e) => assert!(e.message.contains("needs passwordless sudo"), "{}", e.message),
        Ok(other) => panic!("unexpected {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&operator_known_hosts).unwrap(), known, "known_hosts changed");
}
