//! Query resolution: authoritative zones first, then the cache, then the
//! upstream forwarder.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

use dns_cache::{Cache, Key};
use dns_proto::message::{
    CLASS_ANY, CLASS_IN, Edns, Flags, Message, Question, RCODE_FORMERR, RCODE_NOTIMP,
    RCODE_REFUSED, RCODE_SERVFAIL, Record, TYPE_SOA,
};
use dns_proto::name::DnsName;
use dns_zone::Zone;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_ATTEMPTS: usize = 2;

pub struct Resolver {
    zones: Vec<Zone>,
    upstream: Option<SocketAddr>,
    cache: Cache,
}

impl Resolver {
    pub fn new(zones: Vec<Zone>, upstream: Option<SocketAddr>, cache_size: usize) -> Self {
        Resolver { zones, upstream, cache: Cache::new(cache_size) }
    }

    fn find_zone(&self, name: &DnsName) -> Option<&Zone> {
        self.zones
            .iter()
            .filter(|z| name.ends_with(&z.origin))
            .max_by_key(|z| z.origin.label_count())
    }

    pub async fn handle(&self, query: &Message) -> Message {
        let mut resp = Message::response_to(query);

        // RFC 6891: unknown EDNS version gets BADVERS (extended rcode 16 =
        // ext_rcode 1, header rcode 0).
        if let Some(e) = &query.edns {
            if e.version > 0 {
                if let Some(re) = &mut resp.edns {
                    re.ext_rcode = 1;
                }
                return resp;
            }
        }
        if query.flags.opcode != 0 {
            resp.flags.rcode = RCODE_NOTIMP;
            return resp;
        }
        if query.questions.len() != 1 {
            resp.flags.rcode = RCODE_FORMERR;
            return resp;
        }
        let q = &query.questions[0];
        if q.qclass != CLASS_IN && q.qclass != CLASS_ANY {
            resp.flags.rcode = RCODE_NOTIMP;
            return resp;
        }
        resp.flags.ra = self.upstream.is_some();

        // Authoritative data wins over forwarding.
        if let Some(zone) = self.find_zone(&q.qname) {
            resp.flags.aa = true;
            let result = zone.lookup(&q.qname, q.qtype);
            resp.flags.rcode = result.rcode;
            resp.answers = result.answers;
            if result.negative {
                resp.authorities.push(zone.soa.clone());
            }
            // A CNAME chain that leaves the zone: keep resolving upstream if
            // the client asked for recursion.
            if let Some(target) = result.offsite {
                if query.flags.rd && self.upstream.is_some() {
                    match self.resolve_external(&target, q.qtype).await {
                        Ok((rcode, mut answers, mut authorities)) => {
                            if answers.is_empty() {
                                resp.authorities.append(&mut authorities);
                            }
                            resp.answers.append(&mut answers);
                            resp.flags.rcode = rcode;
                        }
                        Err(e) => {
                            warn!("offsite CNAME {target} resolution failed: {e}");
                            resp.flags.rcode = RCODE_SERVFAIL;
                        }
                    }
                }
                // Without RD the client gets the bare CNAME and follows it.
            }
            return resp;
        }

        if !query.flags.rd || self.upstream.is_none() {
            resp.flags.rcode = RCODE_REFUSED;
            return resp;
        }
        match self.resolve_external(&q.qname, q.qtype).await {
            Ok((rcode, answers, authorities)) => {
                resp.flags.rcode = rcode;
                resp.answers = answers;
                resp.authorities = authorities;
            }
            Err(e) => {
                warn!("upstream lookup {} {} failed: {e}", q.qname, q.qtype);
                resp.flags.rcode = RCODE_SERVFAIL;
            }
        }
        resp
    }

    /// Cache-through lookup against the upstream resolver.
    async fn resolve_external(
        &self,
        qname: &DnsName,
        qtype: u16,
    ) -> Result<(u8, Vec<Record>, Vec<Record>), ForwardError> {
        let key = Key { qname: qname.clone(), qtype };
        if let Some(hit) = self.cache.get(&key) {
            debug!("cache hit for {qname}");
            return Ok(hit);
        }
        let upstream = self.upstream.ok_or(ForwardError::NoUpstream)?;
        let msg = forward_query(upstream, qname, qtype).await?;
        // Keep only the SOA from the authority section — it is what negative
        // caching and NXDOMAIN responses need; NS referrals are upstream noise.
        let authorities: Vec<Record> =
            msg.authorities.iter().filter(|r| r.rtype() == TYPE_SOA).cloned().collect();
        self.cache
            .insert(key, msg.flags.rcode, msg.answers.clone(), authorities.clone());
        Ok((msg.flags.rcode, msg.answers, authorities))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use dns_proto::message::{RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A};
    use dns_zone::parse_zone_file;

    const ZONE: &str = "\
$ORIGIN example.lab.
$TTL 300
@    IN SOA ns1 h 1 2 3 4 300
@    IN NS  ns1
ns1  IN A   10.0.0.1
www  IN A   10.0.0.10
";

    fn resolver() -> Resolver {
        Resolver::new(vec![parse_zone_file(ZONE).unwrap()], None, 16)
    }

    fn query(name: &str, qtype: u16) -> Message {
        let mut m = Message::new(7, Flags { rd: true, ..Flags::default() });
        m.questions.push(Question {
            qname: DnsName::parse_str(name).unwrap(),
            qtype,
            qclass: CLASS_IN,
        });
        m
    }

    #[tokio::test]
    async fn authoritative_answer() {
        let r = resolver();
        let resp = r.handle(&query("www.example.lab", TYPE_A)).await;
        assert_eq!(resp.flags.rcode, RCODE_NOERROR);
        assert!(resp.flags.aa);
        assert!(!resp.flags.ra);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn nxdomain_carries_soa() {
        let r = resolver();
        let resp = r.handle(&query("missing.example.lab", TYPE_A)).await;
        assert_eq!(resp.flags.rcode, RCODE_NXDOMAIN);
        assert_eq!(resp.authorities.len(), 1);
        assert_eq!(resp.authorities[0].rtype(), TYPE_SOA);
    }

    #[tokio::test]
    async fn refuses_outside_zone_without_upstream() {
        let r = resolver();
        let resp = r.handle(&query("google.com", TYPE_A)).await;
        assert_eq!(resp.flags.rcode, RCODE_REFUSED);
    }

    #[tokio::test]
    async fn notimp_for_weird_opcode() {
        let r = resolver();
        let mut q = query("www.example.lab", TYPE_A);
        q.flags.opcode = 2; // STATUS
        let resp = r.handle(&q).await;
        assert_eq!(resp.flags.rcode, RCODE_NOTIMP);
    }
}
