//! Upstream forwarding: UDP with TCP fallback, response validation, and a
//! failover pool over multiple upstream resolvers.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use dns_metrics::Metrics;
use dns_proto::message::{CLASS_IN, Edns, Flags, Message, Question};
use dns_proto::name::DnsName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_ATTEMPTS: usize = 2;

#[derive(Debug)]
pub enum ForwardError {
    Io(std::io::Error),
    Timeout,
    NoUpstream,
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardError::Io(e) => write!(f, "i/o error: {e}"),
            ForwardError::Timeout => write!(f, "upstream timed out"),
            ForwardError::NoUpstream => write!(f, "no upstream configured"),
        }
    }
}

impl std::error::Error for ForwardError {}

impl From<std::io::Error> for ForwardError {
    fn from(e: std::io::Error) -> Self {
        ForwardError::Io(e)
    }
}

/// A set of upstream resolvers. Queries go to the preferred upstream first;
/// on failure the next one is tried and, when it answers, becomes preferred.
pub struct UpstreamPool {
    addrs: Vec<SocketAddr>,
    preferred: AtomicUsize,
}

impl UpstreamPool {
    pub fn new(addrs: Vec<SocketAddr>) -> Option<Self> {
        if addrs.is_empty() {
            None
        } else {
            Some(UpstreamPool { addrs, preferred: AtomicUsize::new(0) })
        }
    }

    pub async fn query(
        &self,
        qname: &DnsName,
        qtype: u16,
        metrics: &Metrics,
    ) -> Result<Message, ForwardError> {
        let start = self.preferred.load(Relaxed);
        let mut last = ForwardError::NoUpstream;
        for i in 0..self.addrs.len() {
            let idx = (start + i) % self.addrs.len();
            Metrics::inc(&metrics.upstream_queries);
            match forward_query(self.addrs[idx], qname, qtype).await {
                Ok(m) => {
                    if i > 0 {
                        self.preferred.store(idx, Relaxed);
                        Metrics::inc(&metrics.upstream_failovers);
                        warn!("failed over to upstream {}", self.addrs[idx]);
                    }
                    return Ok(m);
                }
                Err(e) => {
                    Metrics::inc(&metrics.upstream_failures);
                    debug!("upstream {} failed: {e}", self.addrs[idx]);
                    last = e;
                }
            }
        }
        Err(last)
    }
}

async fn forward_query(
    upstream: SocketAddr,
    qname: &DnsName,
    qtype: u16,
) -> Result<Message, ForwardError> {
    let mut query = Message::new(random_id(), Flags { rd: true, ..Flags::default() });
    query
        .questions
        .push(Question { qname: qname.clone(), qtype, qclass: CLASS_IN });
    query.edns = Some(Edns::ours());
    let wire = query.encode();

    let mut last_err = ForwardError::Timeout;
    for _ in 0..UPSTREAM_ATTEMPTS {
        match udp_exchange(upstream, &wire, &query).await {
            Ok(m) if m.flags.tc => {
                debug!("upstream response truncated, retrying over TCP");
                return tcp_exchange(upstream, &wire, &query).await;
            }
            Ok(m) => return Ok(m),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// True if `m` is a plausible reply to `query` (id, QR bit and question echo
/// all match) — the standard defense against stale and spoofed datagrams.
fn is_reply_to(m: &Message, query: &Message) -> bool {
    m.id == query.id
        && m.flags.qr
        && m.questions.first().is_some_and(|got| {
            let want = &query.questions[0];
            got.qname == want.qname && got.qtype == want.qtype
        })
}

async fn udp_exchange(
    upstream: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<Message, ForwardError> {
    let bind_addr: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(upstream).await?;
    sock.send(wire).await?;

    let mut buf = [0u8; 2048];
    timeout(UPSTREAM_TIMEOUT, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if let Ok(m) = Message::parse(&buf[..n]) {
                if is_reply_to(&m, query) {
                    return Ok(m);
                }
            }
            // Mismatched datagram (late or spoofed): keep waiting.
        }
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
}

async fn tcp_exchange(
    upstream: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<Message, ForwardError> {
    timeout(UPSTREAM_TIMEOUT * 2, async {
        let mut stream = TcpStream::connect(upstream).await?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(wire);
        stream.write_all(&framed).await?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        let m = Message::parse(&data)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad reply"))?;
        if !is_reply_to(&m, query) {
            return Err(ForwardError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "reply does not match query",
            )));
        }
        Ok(m)
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
}

/// Unpredictable-enough query ids without a crypto dependency: an xorshift64
/// stream seeded once from /dev/urandom.
fn random_id() -> u16 {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    let state = STATE.get_or_init(|| {
        use std::io::Read;
        let mut bytes = [0u8; 8];
        let seed = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map(|_| u64::from_le_bytes(bytes))
            .unwrap_or_else(|_| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0)
                    ^ (std::process::id() as u64) << 32
            });
        Mutex::new(seed | 1)
    });
    let mut s = state.lock().unwrap();
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    (*s & 0xFFFF) as u16
}
