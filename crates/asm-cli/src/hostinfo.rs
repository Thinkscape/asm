//! Facts about this machine (sent when pairing) and the agent label.

use asm_proto::rules::is_bidi_control;
use asm_proto::wire::HostInfo;
use std::ffi::CStr;
use std::path::PathBuf;

/// Drop control and bidi characters (the manager rejects them) and trim.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Collect [`HostInfo`] for this machine.
pub fn collect() -> HostInfo {
    HostInfo {
        hostname: clean(&hostname()),
        os: std::env::consts::OS.to_owned(),
        os_version: clean(&os_version()),
        kernel: clean(&uname_release()),
        arch: std::env::consts::ARCH.to_owned(),
        username: clean(&username()),
        addresses: addresses(),
        asm_version: env!("CARGO_PKG_VERSION").to_owned(),
        container: in_container(),
    }
}

pub(crate) fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success
    // (the final byte stays 0 because we pass len - 1).
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) };
    if rc != 0 {
        return String::new();
    }
    CStr::from_bytes_until_nul(&buf)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn uname_release() -> String {
    // SAFETY: utsname is plain old data; uname fills it with NUL-terminated strings.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return String::new();
        }
        CStr::from_ptr(u.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(target_os = "macos")]
fn os_version() -> String {
    std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_default()
}

#[cfg(not(target_os = "macos"))]
fn os_version() -> String {
    let text = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    parse_os_release(&text)
}

/// `PRETTY_NAME`, else `NAME VERSION_ID`, from os-release text.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn parse_os_release(text: &str) -> String {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let v = l.strip_prefix(key)?.strip_prefix('=')?;
            Some(v.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
        })
    };
    if let Some(p) = get("PRETTY_NAME").filter(|p| !p.is_empty()) {
        return p;
    }
    match (get("NAME"), get("VERSION_ID")) {
        (Some(n), Some(v)) => format!("{n} {v}"),
        (Some(n), None) => n,
        _ => String::new(),
    }
}

/// The passwd entry (name, home, login shell) of the effective user.
fn passwd_entry() -> Option<(String, PathBuf, String)> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getpwuid_r writes into our buffers only; pointers are checked before use.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        let rc = libc::getpwuid_r(
            libc::geteuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() || pw.pw_name.is_null() {
            return None;
        }
        let name = CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned();
        let home = if pw.pw_dir.is_null() {
            PathBuf::new()
        } else {
            PathBuf::from(std::ffi::OsStr::from_bytes(
                CStr::from_ptr(pw.pw_dir).to_bytes(),
            ))
        };
        let shell = if pw.pw_shell.is_null() {
            String::new()
        } else {
            CStr::from_ptr(pw.pw_shell).to_string_lossy().into_owned()
        };
        Some((name, home, shell))
    }
}

/// Home directory from the passwd database.
pub fn passwd_home() -> Option<PathBuf> {
    passwd_entry().map(|(_, h, _)| h).filter(|h| h.is_absolute())
}

/// Login shell from the passwd database.
pub fn passwd_shell() -> Option<String> {
    passwd_entry().map(|(_, _, s)| s).filter(|s| s.starts_with('/'))
}

fn username() -> String {
    passwd_entry()
        .map(|(n, _, _)| n)
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_default()
}

/// Non-loopback interface addresses (IPv6 link-local excluded), de-duplicated.
fn addresses() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // SAFETY: getifaddrs allocates a list we walk read-only and free with freeifaddrs;
    // sockaddr pointers are cast according to their sa_family.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || (ifa.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint) != 0 {
                continue;
            }
            let ip: std::net::IpAddr = match (*ifa.ifa_addr).sa_family as libc::c_int {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).into()
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr).into()
                }
                _ => continue,
            };
            let skip = ip.is_loopback()
                || ip.is_unspecified()
                || matches!(ip, std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
            let s = ip.to_string();
            if !skip && !out.contains(&s) {
                out.push(s);
            }
        }
        libc::freeifaddrs(head);
    }
    out
}

/// Docker (`/.dockerenv`), Podman (`/run/.containerenv`) or a container cgroup.
fn in_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    ["/proc/1/cgroup", "/proc/self/cgroup"].iter().any(|p| {
        std::fs::read_to_string(p).is_ok_and(|t| {
            [
                "docker",
                "kubepods",
                "containerd",
                "libpod",
                "podman",
                "lxc",
            ]
            .iter()
            .any(|k| t.contains(k))
        })
    })
}

/// [`asm_proto::wire::machine_hint`] of this machine's id; `None` without one (e.g. a
/// container without `/etc/machine-id`).
pub fn machine_hint() -> Option<String> {
    machine_id().map(|id| asm_proto::wire::machine_hint(&id))
}

/// `/etc/machine-id`, else `/var/lib/dbus/machine-id`.
#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| {
            let id = std::fs::read_to_string(p).ok()?;
            let id = id.trim();
            (!id.is_empty() && id != "uninitialized").then(|| id.to_owned())
        })
}

/// The hardware UUID (`IOPlatformUUID`, uppercase with dashes) from `gethostuuid`, else
/// from `ioreg`.
#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    let mut id = [0u8; 16];
    let wait = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: id is the 16-byte uuid_t gethostuuid writes; wait is a valid timespec.
    if unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) } == 0 && id != [0; 16] {
        let h = asm_proto::crypto::hex_encode(&id).to_ascii_uppercase();
        return Some(format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        ));
    }
    ioreg_platform_uuid()
}

/// `IOPlatformUUID` as printed by `ioreg -rd1 -c IOPlatformExpertDevice`.
#[cfg(target_os = "macos")]
fn ioreg_platform_uuid() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let v = l.split_once("\"IOPlatformUUID\" = \"")?.1;
        let v = v.split('"').next()?.trim();
        (!v.is_empty()).then(|| v.to_owned())
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn machine_id() -> Option<String> {
    None
}

/// The agent label: `$ASM_AGENT`, else the parent process name, else empty.
pub fn agent_label() -> String {
    if let Ok(a) = std::env::var("ASM_AGENT") {
        let a = clean(&a);
        if !a.is_empty() {
            return a;
        }
    }
    clean(&parent_name())
}

#[cfg(target_os = "linux")]
fn parent_name() -> String {
    // SAFETY: getppid has no preconditions.
    let ppid = unsafe { libc::getppid() };
    std::fs::read_to_string(format!("/proc/{ppid}/comm"))
        .map(|s| s.trim_end().to_owned())
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn parent_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: getppid has no preconditions; proc_name writes at most buf.len() bytes.
    let n = unsafe {
        let ppid = libc::getppid();
        libc::proc_name(ppid, buf.as_mut_ptr().cast(), buf.len() as u32)
    };
    if n <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..n as usize]).into_owned()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn parent_name() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_parsing() {
        assert_eq!(
            parse_os_release("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"),
            "Ubuntu 24.04.1 LTS"
        );
        assert_eq!(
            parse_os_release("NAME=Alpine Linux\nVERSION_ID=3.20.0\n"),
            "Alpine Linux 3.20.0"
        );
        assert_eq!(parse_os_release(""), "");
    }

    #[test]
    fn host_info_is_valid() {
        let h = collect();
        h.validate().unwrap();
        assert!(!h.hostname.is_empty());
        assert!(!h.kernel.is_empty());
        assert!(h.addresses.iter().all(|a| a != "127.0.0.1" && a != "::1"));
    }

    #[test]
    fn cleaning_drops_controls() {
        assert_eq!(clean(" claude\n"), "claude");
        assert_eq!(clean("a\u{202E}b"), "ab");
    }

    #[test]
    fn machine_hint_is_stable_hex() {
        let Some(h) = machine_hint() else { return };
        assert_eq!(h.len(), 64);
        assert_eq!(machine_hint(), Some(h));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn gethostuuid_matches_ioreg() {
        if let Some(ioreg) = ioreg_platform_uuid() {
            assert_eq!(machine_id(), Some(ioreg));
        }
    }
}
