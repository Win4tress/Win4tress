//! Listening on loopback only (SPEC §13): `127.0.0.1:53` and `[::1]:53`, UDP
//! and TCP. Each query is answered on its own task; UDP answers too large for
//! the asker come back truncated so it retries over TCP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use w4_dns::wire;

use crate::resolve::Resolver;

/// Queries being answered at once, beyond which new ones wait.
const IN_FLIGHT: usize = 1_024;
const TCP_IDLE: Duration = Duration::from_secs(10);

pub fn addresses(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
    ]
}

/// Binds every address; an address in use (another DNS server: Hyper-V's
/// Internet Connection Sharing, WSL, an ad blocker on this PC) is an error that
/// says so.
pub async fn bind(port: u16) -> Result<(Vec<UdpSocket>, Vec<TcpListener>), String> {
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for addr in addresses(port) {
        let in_use = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                format!("{addr} is already in use by another DNS server on this PC")
            } else {
                format!("{addr}: {e}")
            }
        };
        udp.push(UdpSocket::bind(addr).await.map_err(in_use)?);
        tcp.push(TcpListener::bind(addr).await.map_err(in_use)?);
    }
    Ok((udp, tcp))
}

pub async fn serve_udp(socket: UdpSocket, resolver: Arc<Resolver>, shutdown: CancellationToken) {
    let socket = Arc::new(socket);
    let limit = Arc::new(Semaphore::new(IN_FLIGHT));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = socket.recv_from(&mut buf) => match r {
                Ok(x) => x,
                // Windows reports an earlier answer's ICMP "port unreachable"
                // here (WSAECONNRESET); it isn't this socket's failure.
                Err(e) => {
                    tracing::debug!("UDP receive: {e}");
                    continue;
                }
            },
        };
        let query = buf[..n].to_vec();
        let Ok(permit) = Arc::clone(&limit).acquire_owned().await else {
            break;
        };
        let socket = Arc::clone(&socket);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            if let Some(mut answer) = resolver.answer(&query).await {
                if let Ok(q) = wire::parse_query(&query) {
                    let max = usize::from(q.edns_size.unwrap_or(512).max(512));
                    if answer.len() > max {
                        answer = wire::truncated(&query, &q);
                    }
                }
                let _ = socket.send_to(&answer, from).await;
            }
            drop(permit);
        });
    }
}

pub async fn serve_tcp(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    shutdown: CancellationToken,
) {
    loop {
        let (mut stream, _) = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("TCP accept: {e}");
                    continue;
                }
            },
        };
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len)).await {
                    Ok(Ok(_)) => {}
                    _ => break,
                }
                let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut query).await.is_err() {
                    break;
                }
                let Some(answer) = resolver.answer(&query).await else {
                    break;
                };
                let Ok(n) = u16::try_from(answer.len()) else {
                    break;
                };
                if stream.write_all(&n.to_be_bytes()).await.is_err()
                    || stream.write_all(&answer).await.is_err()
                {
                    break;
                }
            }
        });
    }
}
