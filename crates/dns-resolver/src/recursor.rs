//! Iterative recursive resolver (RFC 1034 §4.3.2): resolves a name from the
//! root down, following NS referrals and glue, with no upstream forwarder.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dns_metrics::Metrics;
use dns_proto::message::{
    CLASS_IN, Edns, Flags, Message, Question, RData, TYPE_A, TYPE_CNAME, TYPE_NS,
};
use dns_proto::name::DnsName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::upstream::ForwardError;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound on referral hops before giving up (loop / very deep delegation guard).
const MAX_REFERRALS: usize = 30;
/// Bound on CNAME redirections within one resolution.
const MAX_CNAMES: usize = 12;
/// Bound on nested resolutions to resolve a glueless NS name.
const MAX_GLUELESS_DEPTH: usize = 6;

/// The IANA root name servers (A records), used as resolution seeds.
const ROOT_HINTS: [&str; 13] = [
    "198.41.0.4",    // a
    "199.9.14.201",  // b
    "192.33.4.12",   // c
    "199.7.91.13",   // d
    "192.203.230.10",// e
    "192.5.5.241",   // f
    "192.112.36.4",  // g
    "198.97.190.53", // h
    "192.36.148.17", // i
    "192.58.128.30", // j
    "193.0.14.129",  // k
    "199.7.83.42",   // l
    "202.12.27.33",  // m
];

pub struct Recursor {
    roots: Vec<SocketAddr>,
}

impl Default for Recursor {
    fn default() -> Self {
        Self::new()
    }
}

impl Recursor {
    pub fn new() -> Self {
        let roots = ROOT_HINTS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 53))
            .collect();
        Recursor { roots }
    }

    /// Resolve (qname, qtype) iteratively from the root.
    pub async fn resolve(
        &self,
        qname: &DnsName,
        qtype: u16,
        metrics: &Metrics,
    ) -> Result<Message, ForwardError> {
        self.resolve_depth(qname, qtype, metrics, 0).await
    }

    fn resolve_depth<'a>(
        &'a self,
        qname: &'a DnsName,
        qtype: u16,
        metrics: &'a Metrics,
        glueless_depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Message, ForwardError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut cnames = 0;
            let full_labels = qname.label_count();
            let mut servers = self.roots.clone();
            // Labels of the zone we are currently talking to (root = 0). The
            // next query reveals exactly one more label (QNAME minimization,
            // RFC 9156) until we reach the full name.
            let mut zone_depth = 0usize;
            let mut minimize = true;

            for _ in 0..MAX_REFERRALS {
                let keep = if minimize { (zone_depth + 1).min(full_labels) } else { full_labels };
                let is_full = keep == full_labels;
                let min_name = suffix(qname, keep);
                // Intermediate steps probe with NS (privacy); the last with the
                // real type.
                let step_type = if is_full { qtype } else { TYPE_NS };

                let resp = match self.query_servers(&servers, &min_name, step_type, metrics).await {
                    Some(r) => r,
                    None => return Err(ForwardError::Timeout),
                };

                // Referral (NS in authority for a name at/under min_name)?
                let ns_owner = resp
                    .authorities
                    .iter()
                    .find(|r| r.rtype() == TYPE_NS)
                    .map(|r| r.name.clone());
                let ns_names: Vec<DnsName> = resp
                    .authorities
                    .iter()
                    .filter(|r| r.rtype() == TYPE_NS)
                    .filter_map(|r| match &r.rdata {
                        RData::Ns(n) => Some(n.clone()),
                        _ => None,
                    })
                    .collect();

                // A real answer only counts on the full-name query.
                if is_full {
                    let has_answer = resp
                        .answers
                        .iter()
                        .any(|r| r.name == *qname && (r.rtype() == qtype || r.rtype() == TYPE_CNAME));
                    if has_answer {
                        if qtype != TYPE_CNAME {
                            if let Some(target) = resp
                                .answers
                                .iter()
                                .find(|r| r.name == *qname && r.rtype() == TYPE_CNAME)
                                .and_then(|r| match &r.rdata {
                                    RData::Cname(t) => Some(t.clone()),
                                    _ => None,
                                })
                            {
                                let resolved = resp.answers.iter().any(|r| r.rtype() == qtype);
                                if !resolved {
                                    cnames += 1;
                                    if cnames > MAX_CNAMES {
                                        return Err(ForwardError::Timeout);
                                    }
                                    let mut chased = self
                                        .resolve_depth(&target, qtype, metrics, glueless_depth)
                                        .await?;
                                    let mut answers = resp.answers.clone();
                                    answers.append(&mut chased.answers);
                                    chased.answers = answers;
                                    chased.questions = vec![Question {
                                        qname: qname.clone(),
                                        qtype,
                                        qclass: CLASS_IN,
                                    }];
                                    return Ok(chased);
                                }
                            }
                        }
                        return Ok(finalize(resp, qname, qtype));
                    }
                    if ns_names.is_empty() {
                        return Ok(finalize(resp, qname, qtype)); // authoritative negative
                    }
                }

                if !ns_names.is_empty() {
                    // Descend into the delegation. The new zone cut is the NS
                    // owner's depth (or at least one deeper than now).
                    let new_depth = ns_owner.map(|n| n.label_count()).unwrap_or(keep);
                    zone_depth = new_depth.max(zone_depth + 1);
                    servers = match self.referral_addrs(&resp, &ns_names, glueless_depth, metrics).await
                    {
                        Some(s) => s,
                        None => return Err(ForwardError::Timeout),
                    };
                    continue;
                }

                // No referral and not a final answer: a minimized intermediate
                // query. NXDOMAIN here may be an empty-non-terminal false
                // negative (RFC 9156 §4) — fall back to the full name; a
                // NODATA means the ENT exists, so reveal one more label.
                if resp.flags.rcode == dns_proto::message::RCODE_NXDOMAIN {
                    minimize = false;
                    continue;
                }
                zone_depth += 1;
                if zone_depth >= full_labels {
                    minimize = false; // next query is the full name
                }
            }
            Err(ForwardError::Timeout)
        })
    }

    /// Resolve the addresses to talk to for a referral, using glue or, when
    /// glueless, resolving an NS name's A record.
    async fn referral_addrs(
        &self,
        resp: &Message,
        ns_names: &[DnsName],
        glueless_depth: usize,
        metrics: &Metrics,
    ) -> Option<Vec<SocketAddr>> {
        let mut next: Vec<SocketAddr> = resp
            .additionals
            .iter()
            .filter(|r| ns_names.contains(&r.name))
            .filter_map(|r| match &r.rdata {
                RData::A(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                RData::Aaaa(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                _ => None,
            })
            .collect();
        if next.is_empty() {
            if glueless_depth >= MAX_GLUELESS_DEPTH {
                return None;
            }
            for ns in ns_names {
                if let Ok(m) = self.resolve_depth(ns, TYPE_A, metrics, glueless_depth + 1).await {
                    next.extend(m.answers.iter().filter_map(|r| match &r.rdata {
                        RData::A(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                        _ => None,
                    }));
                    if !next.is_empty() {
                        break;
                    }
                }
            }
        }
        (!next.is_empty()).then_some(next)
    }

    /// Try each server in turn until one answers.
    async fn query_servers(
        &self,
        servers: &[SocketAddr],
        qname: &DnsName,
        qtype: u16,
        metrics: &Metrics,
    ) -> Option<Message> {
        for &server in servers.iter().take(4) {
            Metrics::inc(&metrics.upstream_queries);
            match query_one(server, qname, qtype).await {
                Ok(m) => return Some(m),
                Err(_) => {
                    Metrics::inc(&metrics.upstream_failures);
                    continue;
                }
            }
        }
        None
    }
}

/// A single non-recursive (RD=0) query to one authoritative server, with DO
/// set so DNSSEC records come back for the validator; TCP fallback on TC.
async fn query_one(server: SocketAddr, qname: &DnsName, qtype: u16) -> Result<Message, ForwardError> {
    let mut q = Message::new(query_id(), Flags { rd: false, cd: true, ..Flags::default() });
    q.questions.push(Question { qname: qname.clone(), qtype, qclass: CLASS_IN });
    let mut edns = Edns::ours();
    edns.do_bit = true;
    q.edns = Some(edns);
    let wire = q.encode();

    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).await.map_err(ForwardError::Io)?;
    sock.connect(server).await.map_err(ForwardError::Io)?;
    sock.send(&wire).await.map_err(ForwardError::Io)?;

    let mut buf = [0u8; 4096];
    let msg = timeout(QUERY_TIMEOUT, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if let Ok(m) = Message::parse(&buf[..n]) {
                if m.id == q.id && m.flags.qr {
                    return Ok::<Message, std::io::Error>(m);
                }
            }
        }
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
    .map_err(ForwardError::Io)?;

    if msg.flags.tc {
        return query_one_tcp(server, &wire, q.id).await;
    }
    Ok(msg)
}

async fn query_one_tcp(server: SocketAddr, wire: &[u8], id: u16) -> Result<Message, ForwardError> {
    timeout(QUERY_TIMEOUT * 2, async {
        let mut stream = TcpStream::connect(server).await?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(wire);
        stream.write_all(&framed).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        Message::parse(&data)
            .ok()
            .filter(|m| m.id == id && m.flags.qr)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad tcp reply"))
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
    .map_err(ForwardError::Io)
}

/// Present the resolved message as an answer to the original client: set the
/// question and RA, clear AA (we are not authoritative).
fn finalize(mut resp: Message, qname: &DnsName, qtype: u16) -> Message {
    // Present as our answer to the client: our question, RA set, AA cleared.
    // The rcode is kept as delivered by the authoritative server.
    resp.questions = vec![Question { qname: qname.clone(), qtype, qclass: CLASS_IN }];
    resp.flags.aa = false;
    resp.flags.ra = true;
    resp
}

/// The last `keep` labels of `name` (its `keep`-label suffix), for QNAME
/// minimization. `keep >= label_count` returns the whole name.
fn suffix(name: &DnsName, keep: usize) -> DnsName {
    let labels = name.labels();
    if keep >= labels.len() {
        return name.clone();
    }
    let start = labels.len() - keep;
    DnsName::from_labels(labels[start..].to_vec()).unwrap_or_else(|_| name.clone())
}

fn query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static CTR: AtomicU16 = AtomicU16::new(0xACE1);
    let mut x = CTR.fetch_add(0x9E37, Ordering::Relaxed);
    x ^= x >> 7;
    x
}
