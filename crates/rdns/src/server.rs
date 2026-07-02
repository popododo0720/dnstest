//! UDP and TCP transports.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info};

use dns_proto::message::{Flags, Message, RCODE_FORMERR, rcode_name, type_name};
use dns_resolver::Resolver;

/// Idle time after which a TCP connection is dropped.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time budget for reading the body of one TCP query.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run_udp(socket: UdpSocket, resolver: Arc<Resolver>) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Some(reply) = process(&data, peer, &resolver, "udp").await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

pub async fn run_tcp(listener: TcpListener, resolver: Arc<Resolver>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _ = serve_tcp_conn(stream, peer, resolver).await;
        });
    }
}

/// Parse one query and produce the reply bytes. Returns None when the input
/// is too mangled to answer at all.
async fn process(
    data: &[u8],
    peer: SocketAddr,
    resolver: &Resolver,
    proto: &str,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    match Message::parse(data) {
        Ok(query) => {
            let resp = resolver.handle(&query).await;
            log_query(proto, peer, &query, &resp, started);
            let limit = if proto == "udp" {
                // Without EDNS the classic 512-byte limit applies (RFC 1035);
                // with it, the client's advertised size, kept within reason.
                query
                    .edns
                    .as_ref()
                    .map(|e| (e.udp_payload as usize).clamp(512, 4096))
                    .unwrap_or(512)
            } else {
                u16::MAX as usize
            };
            Some(resp.encode_limited(limit))
        }
        Err(e) => {
            debug!("{proto} {peer}: unparseable query ({e})");
            // Echo the id back with FORMERR if there is enough to salvage one.
            let id = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            let resp = Message::new(
                id,
                Flags { qr: true, rcode: RCODE_FORMERR, ..Flags::default() },
            );
            Some(resp.encode())
        }
    }
}

async fn serve_tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    resolver: Arc<Resolver>,
) -> std::io::Result<()> {
    loop {
        // RFC 7766: each message is prefixed with a two-byte length.
        let mut len_buf = [0u8; 2];
        match timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Err(_) => return Ok(()),     // idle
            Ok(Err(_)) => return Ok(()), // closed
            Ok(Ok(_)) => {}
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(());
        }
        let mut data = vec![0u8; len];
        match timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut data)).await {
            Err(_) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => {}
        }

        let Some(reply) = process(&data, peer, &resolver, "tcp").await else {
            return Ok(());
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
}

fn log_query(proto: &str, peer: SocketAddr, query: &Message, resp: &Message, started: Instant) {
    if let Some(q) = query.questions.first() {
        info!(
            "{proto} {peer} {} {} -> {} ({} answer{}, {:?})",
            q.qname,
            type_name(q.qtype),
            rcode_name(resp.flags.rcode),
            resp.answers.len(),
            if resp.answers.len() == 1 { "" } else { "s" },
            started.elapsed(),
        );
    } else {
        info!("{proto} {peer} <no question> -> {}", rcode_name(resp.flags.rcode));
    }
}
