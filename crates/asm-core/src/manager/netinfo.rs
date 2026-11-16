//! The Mac's own hostnames and addresses (suggestions for proxy hostname hints).

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let s = CStr::from_bytes_until_nul(&buf)
        .ok()?
        .to_str()
        .ok()?
        .trim()
        .to_ascii_lowercase();
    (!s.is_empty()).then_some(s)
}

/// Non-loopback, non-link-local interface addresses (IPv4 first).
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we walk read-only and free with freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                        if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                            out.push(IpAddr::V4(ip));
                        }
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                        if !ip.is_loopback() && !link_local && !ip.is_unspecified() {
                            out.push(IpAddr::V6(ip));
                        }
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out.sort_by_key(|ip| ip.is_ipv6());
    out.dedup();
    out
}

/// Hostname, `<hostname>.local` and interface addresses, de-duplicated.
pub fn local_names() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(h) = hostname() {
        let short = h.trim_end_matches(".local").to_string();
        out.push(format!("{short}.local"));
        if !short.is_empty() && short != h {
            out.push(short);
        } else if h != format!("{short}.local") {
            out.push(h);
        }
    }
    out.extend(local_addresses().into_iter().map(|ip| ip.to_string()));
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}
