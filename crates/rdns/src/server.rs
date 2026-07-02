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

use std::collections::HashMap;

use dns_guard::{Acl, RateLimiter};
use dns_metrics::Metrics;
use dns_proto::message::{
    Flags, Message, OPCODE_NOTIFY, RCODE_FORMERR, RCODE_NOTIMP, RCODE_REFUSED, TYPE_AXFR,
    rcode_name, type_name,
};
use dns_proto::message::{RData, TYPE_IXFR};
use dns_proto::name::DnsName;
use dns_resolver::{Outcome, Resolver};
use dns_tsig::{KeyRing, TsigError, verify as tsig_verify};
use dns_xfr::{Journal, Secondary};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info};

/// Seconds since the Unix epoch, for TSIG time checks.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ServerCtx {
    pub resolver: Arc<Resolver>,
    pub metrics: Arc<Metrics>,
    pub acl: Acl,
    pub limiter: Option<RateLimiter>,
    pub query_log: bool,
    /// Networks allowed to AXFR our zones.
    pub transfer_acl: Acl,
    /// Secondary zones by origin, for routing incoming NOTIFYs.
    pub secondaries: HashMap<DnsName, Arc<Secondary>>,
    /// Change history for incremental (IXFR) transfers.
    pub journal: Arc<Journal>,
    /// TSIG keys accepted on transfers.
    pub tsig_keys: KeyRing,
    /// When set, AXFR/IXFR must carry a valid TSIG signed by this key.
    pub require_tsig: Option<DnsName>,
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

        // RFC 1996: a NOTIFY for one of our secondary zones kicks its
        // refresh loop; everything else with that opcode is refused.
        if query.flags.opcode == OPCODE_NOTIFY {
            Metrics::inc(&ctx.metrics.notify_received);
            let mut resp = Message::response_to(&query);
            resp.flags.opcode = OPCODE_NOTIFY;
            resp.flags.aa = true;
            match query.questions.first().and_then(|q| ctx.secondaries.get(&q.qname)) {
                Some(sec) => sec.kick.notify_one(),
                None => resp.flags.rcode = RCODE_REFUSED,
            }
            let _ = socket.send_to(&resp.encode(), peer).await;
            continue;
        }

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
        tokio::spawn(serve_tcp_conn(stream, peer, ctx));
    }
}

/// DNS-over-TLS (RFC 7858): TLS handshake, then the same framed DNS loop.
pub async fn run_dot(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    ctx: Arc<ServerCtx>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    let _ = serve_stream(tls, peer, ctx, "dot").await;
                }
                Err(e) => debug!("dot {peer}: tls handshake failed: {e}"),
            }
        });
    }
}

/// DNS-over-HTTPS (RFC 8484): TLS with ALPN, then HTTP/2 (`h2`) or HTTP/1.1
/// depending on what the client negotiated. GET/POST /dns-query.
pub async fn run_doh(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    ctx: Arc<ServerCtx>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    debug!("doh {peer}: tls handshake failed: {e}");
                    return;
                }
            };
            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            if is_h2 {
                let _ = serve_doh_h2(tls, peer, ctx).await;
            } else {
                let _ = serve_doh_conn(tls, peer, ctx).await;
            }
        });
    }
}

/// HTTP/2 DoH via the `h2` crate: one DNS query per stream (RFC 8484).
async fn serve_doh_h2<S: AsyncRead + AsyncWrite + Unpin>(
    tls: S,
    peer: SocketAddr,
    ctx: Arc<ServerCtx>,
) -> Result<(), h2::Error> {
    let mut conn = h2::server::handshake(tls).await?;
    while let Some(request) = conn.accept().await {
        let (req, mut respond) = match request {
            Ok(rs) => rs,
            Err(e) => {
                debug!("doh/h2 {peer}: stream error: {e}");
                break;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle_h2_request(req, &mut respond, &ctx, peer).await;
        });
    }
    Ok(())
}

async fn handle_h2_request(
    req: http::Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<bytes::Bytes>,
    ctx: &ServerCtx,
    peer: SocketAddr,
) -> Result<(), h2::Error> {
    // Reconstruct the request head as "METHOD target" for the shared DoH
    // parser, then collect the POST body from the stream.
    let method = req.method().clone();
    let path_and_query =
        req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
    let head = format!("{method} {path_and_query} HTTP/2");

    let mut body = Vec::new();
    let mut recv = req.into_body();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
        if body.len() > 65535 {
            break;
        }
    }

    Metrics::inc(&ctx.metrics.queries_tcp);
    match dns_tls::parse_doh(&head, &body) {
        Some(r) => {
            let started = Instant::now();
            let dns = handle_query_bytes(ctx, &r.dns, peer, "doh", started).await;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/dns-message")
                .header("content-length", dns.len().to_string())
                .header("cache-control", "max-age=0")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false)?;
            stream.send_data(bytes::Bytes::from(dns), true)?;
        }
        None => {
            let response = http::Response::builder().status(404).body(()).unwrap();
            respond.send_response(response, true)?;
        }
    }
    Ok(())
}

async fn serve_doh_conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    ctx: Arc<ServerCtx>,
) -> std::io::Result<()> {
    // Read the HTTP request head, then the body per Content-Length.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = match timeout(TCP_READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 8192 {
            let _ = stream.write_all(&dns_tls::http_error("431 Request Header Fields Too Large")).await;
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    if content_length > 65535 {
        let _ = stream.write_all(&dns_tls::http_error("413 Payload Too Large")).await;
        return Ok(());
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    Metrics::inc(&ctx.metrics.queries_tcp);
    let response = match dns_tls::parse_doh(&head, &body) {
        Some(req) => {
            let started = Instant::now();
            let dns = handle_query_bytes(&ctx, &req.dns, peer, "doh", started).await;
            dns_tls::doh_response(&dns)
        }
        None => dns_tls::http_error("404 Not Found"),
    };
    stream.write_all(&response).await?;
    Ok(())
}

/// Drive one DNS/TCP connection over any byte stream (plain TCP or, for DoT,
/// a TLS stream), using RFC 7766 length-prefixed framing.
async fn serve_tcp_conn(stream: TcpStream, peer: SocketAddr, ctx: Arc<ServerCtx>) {
    let _ = serve_stream(stream, peer, ctx, "tcp").await;
}

pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    ctx: Arc<ServerCtx>,
    proto: &str,
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

        // Zone transfers stream multiple framed messages directly.
        if let Ok(query) = Message::parse(&data) {
            if is_transfer(&query) {
                let frames = transfer_out(&ctx, peer, &query, &data);
                for frame in frames {
                    stream.write_all(&frame).await?;
                }
                continue;
            }
        }

        let started = Instant::now();
        let reply = handle_query_bytes(&ctx, &data, peer, proto, started).await;
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
}

/// Resolve one query given its wire bytes and return the response wire.
/// Shared by TCP, DoT, and DoH (transfers are handled separately).
pub async fn handle_query_bytes(
    ctx: &ServerCtx,
    data: &[u8],
    peer: SocketAddr,
    proto: &str,
    started: Instant,
) -> Vec<u8> {
    match Message::parse(data) {
        Ok(query) => {
            let allowed = ctx.acl.is_allowed(peer.ip());
            let resp = ctx.resolver.handle(&query, allowed).await;
            observe(ctx, proto, peer, &query, &resp, started);
            // DoT/DoH have no 512-byte limit; TCP framing carries the rest.
            resp.encode_limited(u16::MAX as usize)
        }
        Err(e) => {
            debug!("{proto} {peer}: unparseable query ({e})");
            formerr_reply(data).unwrap_or_default()
        }
    }
}

fn is_transfer(query: &Message) -> bool {
    query.flags.opcode == 0
        && query.questions.len() == 1
        && matches!(query.questions[0].qtype, TYPE_AXFR | TYPE_IXFR)
}

/// Serve an AXFR or IXFR, enforcing the transfer ACL and (when configured)
/// TSIG. On refusal, returns a single framed error message.
fn transfer_out(ctx: &ServerCtx, peer: SocketAddr, query: &Message, raw: &[u8]) -> Vec<Vec<u8>> {
    let refuse = |rcode: u8| {
        let mut resp = Message::response_to(query);
        resp.flags.rcode = rcode;
        frame_one(&resp.encode())
    };

    if !ctx.transfer_acl.is_allowed(peer.ip()) {
        return refuse(RCODE_REFUSED);
    }

    // TSIG enforcement / verification.
    let request_mac = match verify_transfer_tsig(ctx, query, raw) {
        Ok(mac) => mac,
        Err(rcode) => return refuse(rcode),
    };

    let qname = &query.questions[0].qname;
    let zones = ctx.resolver.zones();
    let Some(zone) = zones.iter().find(|z| z.origin == *qname) else {
        return refuse(RCODE_NOTIMP);
    };

    let frames = if query.questions[0].qtype == TYPE_IXFR {
        let client_serial = query
            .authorities
            .iter()
            .find_map(|r| match &r.rdata {
                RData::Soa(soa) => Some(soa.serial),
                _ => None,
            })
            .unwrap_or(0);
        Metrics::inc(&ctx.metrics.axfr_out);
        info!("{peer} IXFR {qname} from serial {client_serial}");
        dns_xfr::ixfr_messages(zone, query, client_serial, &ctx.journal)
    } else {
        Metrics::inc(&ctx.metrics.axfr_out);
        info!("{peer} AXFR {qname}");
        dns_xfr::axfr_messages(zone, query)
    };

    // Sign each transfer message when the request was signed (RFC 8945 §5.3:
    // every message in a signed transfer carries a TSIG chained on the prior
    // MAC; the first uses the request MAC).
    match (&request_mac, ctx.require_tsig.as_ref()) {
        (Some(mac), _) => sign_transfer_frames(ctx, query, frames, mac),
        _ => frames,
    }
}

/// Verify TSIG on a transfer request. Returns the request MAC when signed,
/// None when unsigned and TSIG is not required, or an rcode on failure.
fn verify_transfer_tsig(
    ctx: &ServerCtx,
    query: &Message,
    raw: &[u8],
) -> Result<Option<Vec<u8>>, u8> {
    if query.tsig.is_none() {
        return if ctx.require_tsig.is_some() {
            Err(dns_proto::message::RCODE_NOTAUTH) // TSIG required but absent
        } else {
            Ok(None)
        };
    }
    match tsig_verify(query, raw, &ctx.tsig_keys, unix_now(), None) {
        Ok(mac) => {
            // If a specific key is required, enforce it.
            if let Some(required) = &ctx.require_tsig {
                if query.tsig.as_ref().map(|t| &t.key_name) != Some(required) {
                    return Err(dns_proto::message::RCODE_NOTAUTH);
                }
            }
            Ok(Some(mac))
        }
        Err(TsigError::BadTime) | Err(TsigError::BadSig) | Err(TsigError::BadKey)
        | Err(TsigError::Missing) => Err(dns_proto::message::RCODE_NOTAUTH),
    }
}

/// Re-sign transfer frames with TSIG, chaining each MAC onto the previous.
fn sign_transfer_frames(
    ctx: &ServerCtx,
    query: &Message,
    frames: Vec<Vec<u8>>,
    request_mac: &[u8],
) -> Vec<Vec<u8>> {
    let Some(tsig) = &query.tsig else { return frames };
    let Some(key) = ctx.tsig_keys.get(&tsig.key_name) else { return frames };
    let now = unix_now();
    let mut prior = request_mac.to_vec();
    let mut out = Vec::with_capacity(frames.len());
    for frame in frames {
        // Each frame is length-prefixed; re-parse the message to re-sign it.
        let Ok(msg) = Message::parse(&frame[2..]) else {
            out.push(frame);
            continue;
        };
        let signed = dns_tsig::sign_response(&msg, key, &prior, now);
        // The MAC we just produced chains into the next message.
        if let Ok(parsed) = Message::parse(&signed) {
            if let Some(t) = parsed.tsig {
                prior = t.mac;
            }
        }
        out.push(frame_one(&signed).pop().unwrap());
    }
    out
}

fn frame_one(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    vec![framed]
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
