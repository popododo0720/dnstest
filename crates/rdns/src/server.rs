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
    /// TSIG keys accepted on transfers and updates.
    pub tsig_keys: KeyRing,
    /// When set, AXFR/IXFR must carry a valid TSIG signed by this key.
    pub require_tsig: Option<DnsName>,
    /// Everything needed to accept and commit RFC 2136 dynamic updates.
    pub updates: Option<UpdateCtx>,
    /// DNS Cookie secret (RFC 7873); None disables cookies.
    pub cookie_key: Option<dns_guard::cookie::CookieKey>,
    /// Require a valid cookie on UDP (anti-amplification): cookieless queries
    /// get a BADCOOKIE challenge instead of a full answer.
    pub require_cookie: bool,
}

/// Configuration for dynamic updates (RFC 2136), shared with zone persistence.
pub struct UpdateCtx {
    pub acl: Acl,
    /// Require a valid TSIG by this key name (None = IP ACL only).
    pub require_tsig: Option<DnsName>,
    pub zone_dir: Option<std::path::PathBuf>,
    pub notify_targets: Vec<SocketAddr>,
    /// DNSSEC signers + origins + validity + NSEC3 for re-signing after edits.
    pub dnssec: Option<(
        Arc<Vec<dns_dnssec::DnssecKey>>,
        Vec<DnsName>,
        u64,
        Option<dns_dnssec::nsec3::Nsec3Params>,
    )>,
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

        // RFC 2136 dynamic update.
        if query.flags.opcode == dns_proto::message::OPCODE_UPDATE {
            let resp = handle_update(&ctx, peer, &query, &buf[..n]).await;
            let _ = socket.send_to(&resp.encode(), peer).await;
            continue;
        }

        // RFC 7873 cookie enforcement (UDP anti-amplification): answer a
        // cookieless/invalid-cookie query with a BADCOOKIE challenge only.
        if let Some(resp) = cookie_challenge(&ctx, &query, peer.ip()) {
            let _ = socket.send_to(&resp.encode(), peer).await;
            continue;
        }

        let allowed = ctx.acl.is_allowed(peer.ip());
        match ctx.resolver.resolve_local(&query, allowed, peer.ip()) {
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

/// Attach a fresh server cookie to a response echoing the client's cookie
/// (RFC 7873). No-op when cookies are disabled or the client sent none.
fn attach_cookie(ctx: &ServerCtx, resp: &mut Message, query: &Message, ip: std::net::IpAddr) {
    use dns_proto::message::EDNS_COOKIE;
    let (Some(key), Some(qedns)) = (&ctx.cookie_key, &query.edns) else { return };
    let Some(client) = qedns.get_option(EDNS_COOKIE).and_then(cookie_client) else { return };
    let opt = key.build(&client, ip, unix_now() as u32);
    let edns = resp.edns.get_or_insert_with(dns_proto::message::Edns::ours);
    edns.set_option(EDNS_COOKIE, &opt);
}

fn cookie_client(cookie: &[u8]) -> Option<[u8; 8]> {
    dns_guard::cookie::CookieKey::client_cookie(cookie)
}

/// If cookie enforcement is on and a UDP query lacks a valid cookie, build a
/// BADCOOKIE challenge (RFC 7873 §5.2.3): the client must retry with the
/// returned server cookie. Returns None when the query may be answered.
fn cookie_challenge(ctx: &ServerCtx, query: &Message, ip: std::net::IpAddr) -> Option<Message> {
    use dns_guard::cookie::CookieStatus;
    use dns_proto::message::EDNS_COOKIE;
    if !ctx.require_cookie {
        return None;
    }
    let key = ctx.cookie_key.as_ref()?;
    let cookie = query.edns.as_ref().and_then(|e| e.get_option(EDNS_COOKIE)).unwrap_or(&[]);
    let now = unix_now() as u32;
    match key.verify(cookie, ip, now) {
        CookieStatus::Valid | CookieStatus::Stale => None,
        _ => {
            // Challenge: echo a server cookie with extended rcode BADCOOKIE (23).
            let mut resp = Message::response_to(query);
            resp.flags.rcode = 23 & 0x0F; // low nibble in the header
            let edns = resp.edns.get_or_insert_with(dns_proto::message::Edns::ours);
            edns.ext_rcode = 23 >> 4; // high bits in the OPT ttl
            if let Some(client) = cookie_client(cookie) {
                edns.set_option(EDNS_COOKIE, &key.build(&client, ip, now));
            }
            Some(resp)
        }
    }
}

/// DNSSEC records (RRSIG/NSEC/NSEC3/DNSKEY/DS) are only sent to clients that
/// requested them with the DO bit (RFC 3225). Recursion/validation fetches
/// them regardless, so strip them for non-DO clients.
fn strip_dnssec_unless_do(resp: &mut Message, query: &Message) {
    use dns_proto::message::{TYPE_DNSKEY, TYPE_DS, TYPE_NSEC, TYPE_NSEC3, TYPE_NSEC3PARAM, TYPE_RRSIG};
    let do_bit = query.edns.as_ref().is_some_and(|e| e.do_bit);
    if do_bit {
        return;
    }
    let is_dnssec = |t: u16| {
        matches!(t, TYPE_RRSIG | TYPE_NSEC | TYPE_NSEC3 | TYPE_NSEC3PARAM | TYPE_DNSKEY | TYPE_DS)
    };
    // Keep DNSKEY/DS when explicitly queried; otherwise these are meta records.
    let qtype = query.questions.first().map(|q| q.qtype);
    resp.answers.retain(|r| !is_dnssec(r.rtype()) || Some(r.rtype()) == qtype);
    resp.authorities.retain(|r| !is_dnssec(r.rtype()));
    resp.additionals.retain(|r| !is_dnssec(r.rtype()));
}

async fn finish_udp(
    ctx: &ServerCtx,
    socket: &UdpSocket,
    peer: SocketAddr,
    query: &Message,
    mut resp: Message,
    started: Instant,
) {
    strip_dnssec_unless_do(&mut resp, query);
    attach_cookie(ctx, &mut resp, query, peer.ip());
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

/// DNS-over-QUIC (RFC 9250): each query is a bidirectional stream carrying a
/// 2-byte length-prefixed DNS message; the response is written back framed.
pub async fn run_doq(endpoint: quinn::Endpoint, ctx: Arc<ServerCtx>) -> std::io::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!("doq: connection failed: {e}");
                    return;
                }
            };
            let peer = conn.remote_address();
            // Each accepted bidi stream is one query/response exchange.
            loop {
                match conn.accept_bi().await {
                    Ok((send, recv)) => {
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            let _ = serve_doq_stream(send, recv, peer, ctx).await;
                        });
                    }
                    Err(_) => break, // connection closed
                }
            }
        });
    }
    Ok(())
}

async fn serve_doq_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    ctx: Arc<ServerCtx>,
) -> std::io::Result<()> {
    // RFC 9250 §4.2: the message is length-prefixed, and the client closes its
    // send side after the query.
    let data = match recv.read_to_end(65535).await {
        Ok(d) if d.len() >= 2 => d,
        _ => return Ok(()),
    };
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let body = data.get(2..2 + len).unwrap_or(&data[2..]);

    Metrics::inc(&ctx.metrics.queries_tcp);
    let started = Instant::now();
    let reply = handle_query_bytes(&ctx, body, peer, "doq", started).await;
    let mut framed = Vec::with_capacity(reply.len() + 2);
    framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
    framed.extend_from_slice(&reply);
    let _ = send.write_all(&framed).await;
    let _ = send.finish();
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

        // Zone transfers and dynamic updates are handled specially.
        if let Ok(query) = Message::parse(&data) {
            if is_transfer(&query) {
                let frames = transfer_out(&ctx, peer, &query, &data);
                for frame in frames {
                    stream.write_all(&frame).await?;
                }
                continue;
            }
            if query.flags.opcode == dns_proto::message::OPCODE_UPDATE {
                let resp = handle_update(&ctx, peer, &query, &data).await;
                let wire = resp.encode();
                stream.write_all(&(wire.len() as u16).to_be_bytes()).await?;
                stream.write_all(&wire).await?;
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
            let mut resp = ctx.resolver.handle(&query, allowed, peer.ip()).await;
            strip_dnssec_unless_do(&mut resp, &query);
            attach_cookie(ctx, &mut resp, &query, peer.ip());
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

/// Handle an RFC 2136 dynamic update: ACL + TSIG gate, apply to the zone, then
/// persist / re-sign / NOTIFY on success.
async fn handle_update(
    ctx: &ServerCtx,
    peer: SocketAddr,
    query: &Message,
    raw: &[u8],
) -> Message {
    use dns_proto::message::{OPCODE_UPDATE, RCODE_NOERROR, RCODE_NOTAUTH, RCODE_REFUSED};

    let mut resp = Message::response_to(query);
    resp.flags.opcode = OPCODE_UPDATE;

    let Some(up) = &ctx.updates else {
        resp.flags.rcode = RCODE_REFUSED; // updates disabled
        return resp;
    };
    if !up.acl.is_allowed(peer.ip()) {
        resp.flags.rcode = RCODE_REFUSED;
        return resp;
    }
    // TSIG: required when configured, otherwise verified if present.
    if up.require_tsig.is_some() || query.tsig.is_some() {
        match tsig_verify(query, raw, &ctx.tsig_keys, unix_now(), None) {
            Ok(_) => {
                if let Some(req) = &up.require_tsig {
                    if query.tsig.as_ref().map(|t| &t.key_name) != Some(req) {
                        resp.flags.rcode = RCODE_NOTAUTH;
                        return resp;
                    }
                }
            }
            Err(_) => {
                resp.flags.rcode = RCODE_NOTAUTH;
                return resp;
            }
        }
    }

    // RFC 2136: the Zone section is the single question (type SOA).
    let Some(zone_q) = query.questions.first() else {
        resp.flags.rcode = dns_proto::message::RCODE_FORMERR;
        return resp;
    };
    let zones = ctx.resolver.zones();
    let Some(old) = zones.iter().find(|z| z.origin == zone_q.qname) else {
        resp.flags.rcode = RCODE_NOTAUTH; // not authoritative for this zone
        return resp;
    };

    let mut new_zone = old.clone();
    let rcode = new_zone.apply_update(&query.answers, &query.authorities);
    if rcode != RCODE_NOERROR {
        resp.flags.rcode = rcode;
        return resp;
    }
    new_zone.bump_serial();

    // Commit: swap the zone in, journal the delta, persist, re-sign, notify.
    ctx.journal.record(old, &new_zone);
    let origin = new_zone.origin.clone();
    ctx.resolver.upsert_zone(new_zone.clone());
    Metrics::inc(&ctx.metrics.zone_reloads);

    if let Some(dir) = &up.zone_dir {
        let stem = origin.to_string();
        let path = dir.join(format!("{}.zone", stem.trim_end_matches('.')));
        if let Err(e) = std::fs::write(&path, new_zone.to_zonefile()) {
            debug!("update: cannot persist {}: {e}", path.display());
        }
    }
    if let Some((keys, origins, validity, nsec3)) = &up.dnssec {
        if origins.contains(&origin) {
            ctx.resolver.resign(keys, origins, unix_now(), *validity, nsec3.clone());
        }
    }
    for &target in &up.notify_targets {
        let origin = origin.clone();
        tokio::spawn(async move {
            let _ = dns_xfr::send_notify(target, &origin).await;
        });
    }
    info!("update: {peer} modified zone {origin} -> serial bumped");
    resp
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
