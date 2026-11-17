//! Process inspection for the supervisor: finding iron-proxy processes left over by
//! earlier manager instances (by executable name and `--config` argument), and naming the
//! process that listens on a port.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const LSOF: &str = "/usr/sbin/lsof";

/// Executable path of `pid`, canonicalised; `None` when it is gone or not ours to inspect.
pub fn process_path(pid: libc::pid_t) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is valid for `len` bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let p = PathBuf::from(String::from_utf8(buf).ok()?);
    Some(std::fs::canonicalize(&p).unwrap_or(p))
}

/// Every pid on the system.
fn all_pids() -> Vec<libc::pid_t> {
    // SAFETY: a null buffer asks for the current count.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    // Room for processes started between the two calls.
    let mut pids = vec![0 as libc::pid_t; n as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
    // SAFETY: the buffer holds `bytes` bytes.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if n <= 0 {
        return Vec::new();
    }
    pids.truncate(n as usize);
    pids.retain(|&p| p > 0);
    pids
}

/// The argument vector of `pid` (`KERN_PROCARGS2`); `None` when it cannot be read.
pub fn process_args(pid: libc::pid_t) -> Option<Vec<String>> {
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `argmax` is valid for `size` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut argmax).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || argmax <= 0 {
        return None;
    }
    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buf` is valid for `size` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);
    parse_procargs2(&buf)
}

/// Parse a `KERN_PROCARGS2` buffer: `argc` (native-endian i32), the executable path, NUL
/// padding, then `argc` NUL-terminated arguments (the environment follows; ignored).
pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    if argc < 0 {
        return None;
    }
    let rest = &buf[4..];
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end;
    while rest.get(pos) == Some(&0) {
        pos += 1;
    }
    let mut args = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let tail = rest.get(pos..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        args.push(String::from_utf8_lossy(&tail[..end]).into_owned());
        pos += end + 1;
    }
    Some(args)
}

/// Whether `args` (argv, program name first) passes `config` to `--config`/`-config`.
pub fn args_use_config(args: &[String], config: &Path) -> bool {
    let wanted = canonical(config);
    let same = |v: &str| canonical(Path::new(v)) == wanted;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let flag = a.strip_prefix("--").or_else(|| a.strip_prefix('-'));
        let Some(flag) = flag else { continue };
        if flag == "config" {
            if it.next().is_some_and(|v| same(v)) {
                return true;
            }
        } else if let Some(v) = flag.strip_prefix("config=")
            && same(v)
        {
            return true;
        }
    }
    false
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn is_iron_proxy(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "iron-proxy")
}

/// Whether `pid` is an iron-proxy of this data directory: `binary` itself, or any
/// `iron-proxy` executable started with `--config <config>`.
pub fn is_own_proxy(pid: libc::pid_t, binary: &Path, config: &Path) -> bool {
    let Some(path) = process_path(pid) else {
        return false;
    };
    if !is_iron_proxy(&path) {
        return false;
    }
    path == canonical(binary) || process_args(pid).is_some_and(|a| args_use_config(&a, config))
}

/// Running iron-proxy processes started with `--config <config>`, except `exclude`.
pub fn find_proxies_for_config(config: &Path, exclude: Option<u32>) -> Vec<libc::pid_t> {
    let me = std::process::id();
    all_pids()
        .into_iter()
        .filter(|&p| p as u32 != me && Some(p as u32) != exclude)
        .filter(|&p| process_path(p).is_some_and(|path| is_iron_proxy(&path)))
        .filter(|&p| process_args(p).is_some_and(|a| args_use_config(&a, config)))
        .collect()
}

/// SIGTERM `pid`, SIGKILL after `grace`; true when it is gone afterwards.
pub fn terminate(pid: libc::pid_t, grace: Duration) -> bool {
    if pid <= 1 {
        return false;
    }
    // SAFETY: plain syscall on a pid the caller identified.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = Instant::now() + grace;
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if alive(pid) {
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(1);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    !alive(pid)
}

/// The process still exists and is not a zombie (zombies have no executable path).
fn alive(pid: libc::pid_t) -> bool {
    process_path(pid).is_some()
}

/// Process listening on TCP `port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortHolder {
    pub pid: libc::pid_t,
    /// Program name as started (`argv[0]` base name), else the kernel's command name.
    pub name: String,
}

/// Who listens on TCP `port` (`lsof`); `None` when nobody visible to this user does.
pub fn port_holder(port: u16) -> Option<PortHolder> {
    let out = Command::new(LSOF)
        .args(["-nP", "+c0", "-sTCP:LISTEN", "-Fpc"])
        .arg(format!("-iTCP:{port}"))
        .env_clear()
        .output()
        .ok()?;
    let mut holder = parse_lsof(&String::from_utf8_lossy(&out.stdout))?;
    if let Some(name) = process_args(holder.pid)
        .and_then(|a| a.into_iter().next())
        .and_then(|a0| {
            Path::new(&a0)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .filter(|n| !n.is_empty())
    {
        holder.name = name;
    }
    Some(holder)
}

/// First process of `lsof -F` output (`p<pid>` then `c<command>` lines).
pub fn parse_lsof(out: &str) -> Option<PortHolder> {
    let mut pid = None;
    for line in out.lines() {
        if let Some(p) = line.strip_prefix('p') {
            if pid.is_some() {
                break;
            }
            pid = p.trim().parse().ok();
        } else if let (Some(c), Some(pid)) = (line.strip_prefix('c'), pid) {
            return Some(PortHolder {
                pid,
                name: c.to_string(),
            });
        }
    }
    pid.map(|pid| PortHolder {
        pid,
        name: "unknown process".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(argc: i32, exec: &str, args: &[&str], env: &[&str]) -> Vec<u8> {
        let mut b = argc.to_ne_bytes().to_vec();
        b.extend_from_slice(exec.as_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        for a in args.iter().chain(env) {
            b.extend_from_slice(a.as_bytes());
            b.push(0);
        }
        b
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_procargs2() {
        let buf = procargs(
            3,
            "/Applications/A.app/Contents/MacOS/iron-proxy",
            &["iron-proxy", "--config", "/data/proxy/iron-proxy.yaml"],
            &["HOME=/Users/x"],
        );
        assert_eq!(
            parse_procargs2(&buf).unwrap(),
            strings(&["iron-proxy", "--config", "/data/proxy/iron-proxy.yaml"])
        );
        // Truncated argument list.
        assert_eq!(parse_procargs2(&buf[..buf.len() - 40]), None);
        assert_eq!(parse_procargs2(&[1, 0]), None);
    }

    #[test]
    fn reads_own_args() {
        let args = process_args(std::process::id() as libc::pid_t).unwrap();
        assert!(!args.is_empty());
    }

    #[test]
    fn matches_config_argument() {
        let cfg = Path::new("/data dir/proxy/iron-proxy.yaml");
        let yes = [
            &["iron-proxy", "--config", "/data dir/proxy/iron-proxy.yaml"][..],
            &[
                "/x/iron-proxy",
                "-config",
                "/data dir/proxy/iron-proxy.yaml",
            ],
            &["iron-proxy", "--config=/data dir/proxy/iron-proxy.yaml"],
            &[
                "iron-proxy",
                "-ssh",
                "-config=/data dir/proxy/iron-proxy.yaml",
            ],
        ];
        for a in yes {
            assert!(args_use_config(&strings(a), cfg), "{a:?}");
        }
        let no = [
            &["iron-proxy", "--config", "/other/iron-proxy.yaml"][..],
            &["iron-proxy", "--config"],
            &["iron-proxy", "/data dir/proxy/iron-proxy.yaml"],
            &["--config", "/data dir/proxy/iron-proxy.yaml"][..1],
            &["iron-proxy", "--configx", "/data dir/proxy/iron-proxy.yaml"],
        ];
        for a in no {
            assert!(!args_use_config(&strings(a), cfg), "{a:?}");
        }
    }

    #[test]
    fn parses_lsof_output() {
        let out = "p4242\ncPython\nf5\np99\ncother\n";
        assert_eq!(
            parse_lsof(out),
            Some(PortHolder {
                pid: 4242,
                name: "Python".into()
            })
        );
        assert_eq!(parse_lsof(""), None);
        assert_eq!(parse_lsof("p7\n").unwrap().pid, 7);
    }

    #[test]
    fn finds_the_listener_of_a_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let Some(h) = port_holder(port) else {
            eprintln!("lsof unavailable; skipped");
            return;
        };
        assert_eq!(h.pid as u32, std::process::id());
    }
}
