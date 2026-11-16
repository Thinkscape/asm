//! The Mac's own hostnames, addresses and subnets (suggestions for proxy hostname hints
//! and pairing-code networks), and IP network (CIDR) parsing and matching.

use std::ffi::CStr;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{CoreError, Result};

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

/// The Bonjour local host name (System Settings → Sharing), without `.local`.
fn bonjour_name() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "LocalHostName"])
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

/// Size of `sockaddr_in6`, the largest socket address read here.
const SOCKADDR_MAX: usize = 28;

/// The address bytes of an `AF_INET` / `AF_INET6` socket address. Netmasks come back
/// truncated to `sa_len` bytes (and sometimes with family 0), so `family` is the one of
/// the interface address and the missing tail reads as zero.
///
/// SAFETY: `sa` must point to a socket address valid for its `sa_len` bytes.
unsafe fn sockaddr_ip(sa: *const libc::sockaddr, family: i32) -> Option<IpAddr> {
    let mut buf = [0u8; SOCKADDR_MAX];
    // SAFETY: the caller guarantees `sa_len` readable bytes; at most SOCKADDR_MAX are copied.
    unsafe {
        let len = usize::from((*sa).sa_len).min(SOCKADDR_MAX);
        std::ptr::copy_nonoverlapping(sa.cast::<u8>(), buf.as_mut_ptr(), len);
    }
    match family {
        libc::AF_INET => {
            let b: [u8; 4] = buf[4..8].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        libc::AF_INET6 => {
            let b: [u8; 16] = buf[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Non-loopback, non-link-local interface addresses with their prefix length (when the
/// interface reports a netmask).
fn interfaces() -> Vec<(IpAddr, Option<u8>)> {
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
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let family = i32::from((*ifa.ifa_addr).sa_family);
            let Some(ip) = sockaddr_ip(ifa.ifa_addr, family) else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() || is_link_local(ip) {
                continue;
            }
            let prefix = (!ifa.ifa_netmask.is_null())
                .then(|| sockaddr_ip(ifa.ifa_netmask, family))
                .flatten()
                .map(|mask| match mask {
                    IpAddr::V4(m) => u32::from(m).leading_ones() as u8,
                    IpAddr::V6(m) => u128::from(m).leading_ones() as u8,
                });
            out.push((ip, prefix));
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Non-loopback, non-link-local interface addresses (IPv4 first).
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = interfaces().into_iter().map(|(ip, _)| ip).collect();
    out.sort_by_key(|ip| ip.is_ipv6());
    out.dedup();
    out
}

/// Hostname, the Bonjour name (`<LocalHostName>.local`) and interface addresses,
/// de-duplicated. The hostname may already be a DNS name (`mac.home.arpa`), so `.local`
/// is never appended to it.
pub fn local_names() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(h) = hostname() {
        out.push(h);
    }
    if let Some(bonjour) = bonjour_name() {
        out.push(format!("{}.local", bonjour.to_ascii_lowercase()));
    }
    out.extend(local_addresses().into_iter().map(|ip| ip.to_string()));
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

/// Tailscale's address ranges: its interface addresses are host routes (/32, /128), so
/// the tailnet range is suggested instead.
const TAILSCALE_V4: &str = "100.64.0.0/10";
const TAILSCALE_V6: &str = "fd7a:115c:a1e0::/48";

/// The networks this Mac is attached to, from its interface addresses and netmasks
/// (`192.168.1.0/24`, `fd12:3456::/64`), IPv4 first, de-duplicated. Host routes are
/// skipped, except that a Tailscale address suggests the tailnet range.
pub fn local_subnets() -> Vec<String> {
    let tailscale = [TAILSCALE_V4, TAILSCALE_V6].map(|s| Cidr::parse(s).expect("valid"));
    let mut nets: Vec<Cidr> = Vec::new();
    for (ip, prefix) in interfaces() {
        if let Some(t) = tailscale.iter().find(|t| t.contains(ip)) {
            nets.push(*t);
            continue;
        }
        let full = if ip.is_ipv4() { 32 } else { 128 };
        match prefix {
            Some(p) if p > 0 && p < full => nets.push(Cidr::new(ip, p)),
            _ => {}
        }
    }
    nets.sort_by_key(|n| n.addr.is_ipv6());
    let mut out: Vec<String> = Vec::new();
    for n in nets {
        let s = n.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// An IP network: `10.0.0.0/8`, `fd00::/8`; a bare address is a /32 or /128. Host bits
/// are cleared and IPv4-mapped IPv6 networks (`::ffff:10.0.0.0/104`) become IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn new(ip: IpAddr, prefix: u8) -> Self {
        let (ip, prefix) = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
                _ => (ip, prefix),
            },
            IpAddr::V4(_) => (ip, prefix),
        };
        Cidr {
            addr: mask(ip, prefix),
            prefix,
        }
    }

    /// `None` for anything but `<address>` or `<address>/<prefix length>`.
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = ip.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse::<u8>().ok().filter(|&p| p <= max)?
            }
            Some(_) => return None,
        };
        Some(Self::new(ip, prefix))
    }

    /// Whether `ip` (IPv4-mapped IPv6 counts as IPv4) lies in this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & m))
        }
        IpAddr::V6(v6) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & m))
        }
    }
}

/// One allow-list entry, normalised (`10.1.2.3/8` → `10.0.0.0/8`, `10.0.0.1` →
/// `10.0.0.1/32`); `invalid` names the entry.
pub fn check_network(entry: &str) -> Result<String> {
    Cidr::parse(entry).map(|c| c.to_string()).ok_or_else(|| {
        CoreError::invalid(format!(
            "invalid network \"{}\": use an address or a CIDR range such as 10.0.0.0/8 or fd00::/8",
            entry.trim()
        ))
    })
}

/// A pairing code's allow-list: entries trimmed, empty ones dropped, each normalised by
/// [`check_network`], duplicates removed. `[]` allows any address.
pub fn parse_networks(entries: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for entry in entries.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
        let net = check_network(entry)?;
        if !out.contains(&net) {
            out.push(net);
        }
    }
    Ok(out)
}

/// Whether `peer` may use a code limited to `networks` (`[]` = any address). An
/// unparseable stored entry matches nothing.
pub fn network_allows(networks: &[String], peer: Option<IpAddr>) -> bool {
    if networks.is_empty() {
        return true;
    }
    let Some(peer) = peer else { return false };
    networks
        .iter()
        .filter_map(|n| Cidr::parse(n))
        .any(|n| n.contains(peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_normalises() {
        let p = |s: &str| Cidr::parse(s).map(|c| c.to_string());
        assert_eq!(p("10.0.0.0/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(p(" 10.1.2.3/8 ").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(p("100.64.0.0/10").as_deref(), Some("100.64.0.0/10"));
        assert_eq!(p("192.168.1.7").as_deref(), Some("192.168.1.7/32"));
        assert_eq!(p("0.0.0.0/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(p("fd00::/8").as_deref(), Some("fd00::/8"));
        assert_eq!(p("FD12:3456::1/64").as_deref(), Some("fd12:3456::/64"));
        assert_eq!(p("::1").as_deref(), Some("::1/128"));
        assert_eq!(p("::ffff:10.0.0.0/104").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(p("::ffff:192.0.2.1").as_deref(), Some("192.0.2.1/32"));
        for bad in [
            "",
            "/8",
            "10.0.0.0/",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0/8",
            "10.0.0.0/+8",
            "10.0.0.0/8/8",
            "host.example",
            "10.0.0.0 /8",
            "10.0.0.0/0008",
        ] {
            assert_eq!(p(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn matches_v4_v6_and_mapped() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains(ip("10.255.0.1")));
        assert!(!net.contains(ip("11.0.0.1")));
        assert!(
            net.contains(ip("::ffff:10.1.2.3")),
            "mapped peer counts as IPv4"
        );
        assert!(!net.contains(ip("fd00::1")));

        let host = Cidr::parse("192.0.2.5").unwrap();
        assert!(host.contains(ip("192.0.2.5")));
        assert!(!host.contains(ip("192.0.2.6")));

        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")));

        let mapped = Cidr::parse("::ffff:127.0.0.0/104").unwrap();
        assert!(mapped.contains(ip("127.0.0.1")));
        assert!(mapped.contains(ip("::ffff:127.0.0.1")));

        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("8.8.8.8")));
        assert!(!all.contains(ip("::1")));
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2001:db8::1")));
    }

    #[test]
    fn allow_lists() {
        let nets = parse_networks(&[
            " 10.0.0.0/8".into(),
            String::new(),
            "10.1.0.0/8".into(),
            "fd00::/8 ".into(),
        ])
        .unwrap();
        assert_eq!(nets, ["10.0.0.0/8", "fd00::/8"]);
        let err = parse_networks(&["10.0.0.0/8".into(), "10.0.0.0/40".into()]).unwrap_err();
        assert_eq!(err.code, asm_proto::ErrorCode::Invalid);
        assert!(err.message.contains("\"10.0.0.0/40\""), "{}", err.message);

        assert!(network_allows(&[], None));
        assert!(network_allows(&[], Some(ip("8.8.8.8"))));
        assert!(network_allows(&nets, Some(ip("10.9.9.9"))));
        assert!(network_allows(&nets, Some(ip("::ffff:10.9.9.9"))));
        assert!(network_allows(&nets, Some(ip("fdaa::1"))));
        assert!(!network_allows(&nets, Some(ip("127.0.0.1"))));
        assert!(!network_allows(&nets, None));
    }

    #[test]
    fn subnets_are_networks() {
        for s in local_subnets() {
            let c = Cidr::parse(&s).unwrap_or_else(|| panic!("{s}"));
            assert_eq!(c.to_string(), s);
        }
    }
}
