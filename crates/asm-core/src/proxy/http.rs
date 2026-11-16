//! Minimal blocking HTTP/1.1 client for iron-proxy's loopback management and health
//! listeners (`Connection: close`, no TLS, no redirects).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct Response {
    pub status: u16,
    pub body: String,
}

pub fn request(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    timeout: Duration,
) -> std::io::Result<Response> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: 0\r\n"
    );
    if let Some(t) = bearer {
        req.push_str("Authorization: Bearer ");
        req.push_str(t);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.take(1 << 20).read_to_end(&mut raw)?;
    parse(&raw).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed HTTP response")
    })
}

fn parse(raw: &[u8]) -> Option<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status_line = head.lines().next()?;
    let mut parts = status_line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    Some(Response {
        status,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_body() {
        let r = parse(b"HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\n\r\n{\"error\":\"x\"}").unwrap();
        assert_eq!(r.status, 422);
        assert_eq!(r.body, "{\"error\":\"x\"}");
        assert!(parse(b"garbage").is_none());
    }
}
