//! UDP and TCP transports.
//!
//! Performance model: N UDP sockets share the port via SO_REUSEPORT (the
//! kernel spreads clients across them) and each socket gets one worker task.
//! Queries answerable from zones or cache are resolved and sent inline in the
//! worker loop — no per-query task, no allocation beyond the response buffer.
//! Only queries that need upstream traffic are spawned off.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dns_guard::{Acl, RateLimiter};
use dns_metrics::Metrics;
use dns_proto::message::{Flags, Message, RCODE_FORMERR, rcode_name, type_name};
use dns_resolver::{Outcome, Resolver};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ServerCtx {
    pub resolver: Arc<Resolver>,
    pub metrics: Arc<Metrics>,
    pub acl: Acl,
    pub limiter: Option<RateLimiter>,
    pub query_log: bool,
}

/// N kernel-load-balanced sockets bound to the same address.
pub fn reuseport_udp_sockets(addr: SocketAddr, n: usize) -> std::io::Result<Vec<UdpSocket>> {
    (0..n.max(1))
        .map(|_| {
            let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            UdpSocket::from_std(sock.into())
        })
        .collect()
}

pub async fn run_udp_worker(socket: UdpSocket, ctx: Arc<ServerCtx>) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        Metrics::inc(&ctx.metrics.queries_udp);
        if let Some(limiter) = &ctx.limiter {
            if !limiter.allow(peer.ip()) {
                // Drop, do not answer: a rate-limited reply is still
                // amplification for a spoofed source.
                Metrics::inc(&ctx.metrics.rate_limited);
                continue;
            }
        }

        let started = Instant::now();
        let query = match Message::parse(&buf[..n]) {
            Ok(q) => q,
            Err(e) => {
                debug!("udp {peer}: unparseable query ({e})");
                if let Some(reply) = formerr_reply(&buf[..n]) {
                    ctx.metrics.observe_rcode(RCODE_FORMERR);
                    let _ = socket.send_to(&reply, peer).await;
                }
                continue;
            }
        };

        let allowed = ctx.acl.is_allowed(peer.ip());
        match ctx.resolver.resolve_local(&query, allowed) {
            // Fast path: answered from zones/cache, sent inline.
            Outcome::Done(resp) => {
                finish_udp(&ctx, &socket, peer, &query, resp, started).await;
            }
            // Slow path: upstream traffic needed, hand off to a task.
            Outcome::Pending(pending) => {
                let ctx = ctx.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let resp = ctx.resolver.resolve_pending(pending).await;
                    finish_udp(&ctx, &socket, peer, &query, resp, started).await;
                });
            }
        }
    }
}

async fn finish_udp(
    ctx: &ServerCtx,
    socket: &UdpSocket,
    peer: SocketAddr,
    query: &Message,
    resp: Message,
    started: Instant,
) {
    // Without EDNS the classic 512-byte limit applies (RFC 1035); with it,
    // the client's advertised size, kept within reason.
    let limit = query
        .edns
        .as_ref()
        .map(|e| (e.udp_payload as usize).clamp(512, 4096))
        .unwrap_or(512);
    let wire = resp.encode_limited(limit);
    observe(ctx, "udp", peer, query, &resp, started);
    let _ = socket.send_to(&wire, peer).await;
}

pub async fn run_tcp(listener: TcpListener, ctx: Arc<ServerCtx>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = serve_tcp_conn(stream, peer, ctx).await;
        });
    }
}

async fn serve_tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ServerCtx>,
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

        Metrics::inc(&ctx.metrics.queries_tcp);
        if let Some(limiter) = &ctx.limiter {
            if !limiter.allow(peer.ip()) {
                Metrics::inc(&ctx.metrics.rate_limited);
                return Ok(());
            }
        }

        let started = Instant::now();
        let reply = match Message::parse(&data) {
            Ok(query) => {
                let allowed = ctx.acl.is_allowed(peer.ip());
                let resp = ctx.resolver.handle(&query, allowed).await;
                observe(&ctx, "tcp", peer, &query, &resp, started);
                resp.encode_limited(u16::MAX as usize)
            }
            Err(e) => {
                debug!("tcp {peer}: unparseable query ({e})");
                match formerr_reply(&data) {
                    Some(r) => r,
                    None => return Ok(()),
                }
            }
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
}

/// Echo the id back with FORMERR if there is enough to salvage one.
fn formerr_reply(data: &[u8]) -> Option<Vec<u8>> {
    let id = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
    let resp = Message::new(id, Flags { qr: true, rcode: RCODE_FORMERR, ..Flags::default() });
    Some(resp.encode())
}

fn observe(
    ctx: &ServerCtx,
    proto: &str,
    peer: SocketAddr,
    query: &Message,
    resp: &Message,
    started: Instant,
) {
    ctx.metrics.observe_rcode(resp.flags.rcode);
    ctx.metrics.observe_latency(started.elapsed());
    if !ctx.query_log {
        return;
    }
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
    }
}
