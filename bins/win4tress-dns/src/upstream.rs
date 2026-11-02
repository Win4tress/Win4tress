//! Asking upstream: the system's DNS servers over UDP (TCP when the answer
//! is truncated), one after another; or a DNS-over-HTTPS server on a kept
//! connection that closes after a minute idle. Each UDP query goes out from a
//! fresh port with a random id, and an answer must match both and the
//! question, against spoofing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use w4_dns::wire;

/// Per server, before trying the next.
const UDP_TIMEOUT: Duration = Duration::from_millis(1500);
const TCP_TIMEOUT: Duration = Duration::from_secs(4);
const DOH_TIMEOUT: Duration = Duration::from_secs(5);
/// A DoH connection unused this long is closed.
pub const DOH_IDLE: Duration = Duration::from_secs(60);
const MAX_ANSWER: usize = 65_535;

/// Whether `answer` is the answer to `query` (same id and question).
fn matches(query: &[u8], answer: &[u8]) -> bool {
    let (Ok(q), Ok(a)) = (wire::parse_query(query), wire::parse_answer(answer)) else {
        return false;
    };
    a.id == q.id && a.question.as_ref() == Some(&q.question)
}

async fn udp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = match server.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    socket.connect(server).await.map_err(|e| e.to_string())?;
    let id = w4_sys::random::u16();
    let sent = wire::with_id(query, id);
    socket.send(&sent).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + UDP_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = match tokio::time::timeout(left, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("{server}: {e}")),
            Err(_) => return Err(format!("{server}: no answer")),
        };
        if matches(&sent, &buf[..n]) {
            return Ok(buf[..n].to_vec());
        }
        // Someone else's packet, or a spoof: keep waiting.
    }
}

async fn tcp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let work = async {
        let mut s = TcpStream::connect(server)
            .await
            .map_err(|e| e.to_string())?;
        let id = w4_sys::random::u16();
        let sent = wire::with_id(query, id);
        let len = u16::try_from(sent.len()).map_err(|_| "query too large")?;
        s.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        s.write_all(&sent).await.map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let mut answer = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut answer).await.map_err(|e| e.to_string())?;
        if !matches(&sent, &answer) {
            return Err("answer doesn't match the question".to_string());
        }
        Ok(answer)
    };
    tokio::time::timeout(TCP_TIMEOUT, work)
        .await
        .map_err(|_| format!("{server}: TCP timed out"))?
}

/// The system servers, in order, until one answers; the answer carries the
/// query's id. Returns the server that answered.
pub async fn system(servers: &[IpAddr], query: &[u8]) -> Result<(Vec<u8>, IpAddr), String> {
    let original_id = wire::parse_query(query)?.id;
    let mut last = "no DNS servers to ask".to_string();
    for ip in servers {
        let server = SocketAddr::new(*ip, 53);
        let answer = match udp(server, query).await {
            Ok(a) if wire::parse_answer(&a).is_ok_and(|p| p.truncated) => tcp(server, query).await,
            other => other,
        };
        match answer {
            Ok(a) => return Ok((wire::with_id(&a, original_id), *ip)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// DNS over HTTPS (RFC 8484), POST, on one kept connection.
pub struct Doh {
    host: String,
    path: String,
    session: Mutex<Option<(std::sync::Arc<w4_sys::http::Session>, Instant)>>,
}

impl Doh {
    pub fn new(url: &str) -> Result<Doh, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or("DoH needs an https:// address")?;
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/dns-query"),
        };
        Ok(Doh {
            host: host.to_ascii_lowercase(),
            path: path.to_string(),
            session: Mutex::new(None),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    fn session(&self) -> Result<std::sync::Arc<w4_sys::http::Session>, String> {
        let mut slot = self.session.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((s, used)) = slot.as_mut() {
            *used = Instant::now();
            return Ok(std::sync::Arc::clone(s));
        }
        let s = std::sync::Arc::new(w4_sys::http::Session::open(&self.host, DOH_TIMEOUT)?);
        *slot = Some((std::sync::Arc::clone(&s), Instant::now()));
        Ok(s)
    }

    fn forget(&self) {
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Closes the connection when it's been idle a minute.
    pub fn close_if_idle(&self) {
        let mut slot = self.session.lock().unwrap_or_else(|p| p.into_inner());
        if slot
            .as_ref()
            .is_some_and(|(_, used)| used.elapsed() >= DOH_IDLE)
        {
            *slot = None;
            tracing::debug!(host = %self.host, "DoH connection closed (idle)");
        }
    }

    fn post(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        let headers = [
            ("Content-Type", "application/dns-message"),
            ("Accept", "application/dns-message"),
        ];
        let r = self
            .session()?
            .send("POST", &self.path, &headers, Some(body), MAX_ANSWER)?;
        if r.status != 200 {
            return Err(format!("{} answered HTTP {}", self.host, r.status));
        }
        Ok(r.body)
    }

    /// Asks over HTTPS (id 0, as RFC 8484 suggests); retries once on a fresh
    /// connection if the kept one went stale.
    pub fn ask(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let original_id = wire::parse_query(query)?.id;
        let body = wire::with_id(query, 0);
        let answer = self.post(&body).or_else(|e| {
            tracing::debug!("DoH retry after: {e}");
            self.forget();
            self.post(&body)
        })?;
        let parsed = wire::parse_answer(&answer)?;
        let asked = wire::parse_query(query)?.question;
        if parsed.question.as_ref() != Some(&asked) {
            return Err(format!("{} answered another question", self.host));
        }
        Ok(wire::with_id(&answer, original_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_addresses_split() {
        let d = Doh::new("https://Cloudflare-DNS.com/dns-query").unwrap();
        assert_eq!(
            (d.host(), d.path.as_str()),
            ("cloudflare-dns.com", "/dns-query")
        );
        assert_eq!(Doh::new("https://dns.example").unwrap().path, "/dns-query");
        assert!(Doh::new("http://dns.example/dns-query").is_err());
    }

    #[test]
    fn answers_must_match_the_question() {
        let q = wire::query(7, "example.com", wire::TYPE_A).unwrap();
        let p = wire::parse_query(&q).unwrap();
        let good = wire::error(&q, &p, wire::RCODE_SERVFAIL);
        assert!(matches(&q, &good));
        let other = wire::query(7, "example.org", wire::TYPE_A).unwrap();
        let po = wire::parse_query(&other).unwrap();
        assert!(!matches(
            &q,
            &wire::error(&other, &po, wire::RCODE_SERVFAIL)
        ));
        assert!(!matches(&q, &wire::with_id(&good, 8)));
    }
}
