//! Iterative recursive resolver (RFC 1034 §4.3.2): resolves a name from the
//! root down, following NS referrals and glue, with no upstream forwarder.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
/// Hard bound on total nested resolutions (glueless NS + CNAME chase)
/// per resolution — prevents stack growth from CNAME loops or deep chains.
const MAX_DEPTH: usize = 24;

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

/// How long a learned delegation (zone → name-server addresses) is reused
/// before re-fetching it from the parent.
const DELEGATION_TTL: Duration = Duration::from_secs(600);

pub struct Recursor {
    roots: Vec<SocketAddr>,
    /// Learned delegations so a cache miss starts from the deepest known zone
    /// cut instead of the root (zone → addresses, with an expiry).
    delegations: RwLock<HashMap<DnsName, (Vec<SocketAddr>, Instant)>>,
    /// Answer cache keyed on (name, type) — crucial for validation, which
    /// re-fetches DNSKEY/DS for the whole chain of trust.
    answers: RwLock<HashMap<(DnsName, u16), (Message, Instant)>>,
    metrics: Arc<Metrics>,
}

impl Recursor {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        let roots = ROOT_HINTS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 53))
            .collect();
        Recursor {
            roots,
            delegations: RwLock::new(HashMap::new()),
            answers: RwLock::new(HashMap::new()),
            metrics,
        }
    }

    /// The deepest cached delegation that is an ancestor of `qname`, if fresh.
    /// `min_skip` skips that many leading labels: a DS query must be answered
    /// by the *parent* zone, so it starts one label up (min_skip = 1) to avoid
    /// landing on the child's own servers, which do not hold their DS.
    fn cached_start(&self, qname: &DnsName, min_skip: usize) -> Option<(DnsName, Vec<SocketAddr>)> {
        let map = self.delegations.read().unwrap();
        let now = Instant::now();
        let labels = qname.labels();
        for skip in min_skip..labels.len() {
            if let Ok(cand) = DnsName::from_labels(labels[skip..].to_vec()) {
                if let Some((servers, exp)) = map.get(&cand) {
                    if *exp > now {
                        return Some((cand, servers.clone()));
                    }
                }
            }
        }
        None
    }

    fn cache_delegation(&self, zone: DnsName, servers: Vec<SocketAddr>) {
        if servers.is_empty() || zone.is_root() {
            return;
        }
        let mut map = self.delegations.write().unwrap();
        if map.len() > 100_000 {
            let now = Instant::now();
            map.retain(|_, (_, exp)| *exp > now);
        }
        map.insert(zone, (servers, Instant::now() + DELEGATION_TTL));
    }

    /// Resolve (qname, qtype) iteratively from the root, with an answer cache
    /// so repeated lookups (notably DNSSEC DNSKEY/DS chains) are cheap.
    pub async fn resolve(&self, qname: &DnsName, qtype: u16) -> Result<Message, ForwardError> {
        let key = (qname.clone(), qtype);
        {
            let cache = self.answers.read().unwrap();
            if let Some((msg, exp)) = cache.get(&key) {
                if *exp > Instant::now() {
                    Metrics::inc(&self.metrics.cache_hits);
                    return Ok(msg.clone());
                }
            }
        }
        let msg = self.resolve_depth(qname, qtype, 0).await?;
        // Cache positive/negative answers for the min answer TTL (bounded).
        let ttl = msg
            .answers
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(300)
            .clamp(5, 3600);
        let mut cache = self.answers.write().unwrap();
        if cache.len() > 100_000 {
            let now = Instant::now();
            cache.retain(|_, (_, exp)| *exp > now);
        }
        cache.insert(key, (msg.clone(), Instant::now() + Duration::from_secs(ttl as u64)));
        Ok(msg)
    }

    fn resolve_depth<'a>(
        &'a self,
        qname: &'a DnsName,
        qtype: u16,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Message, ForwardError>> + Send + 'a>>
    {
        Box::pin(async move {
            if depth > MAX_DEPTH {
                return Err(ForwardError::Timeout);
            }
            let full_labels = qname.label_count();
            // Start from the deepest cached delegation when we have one,
            // otherwise the root. `current_zone` is the zone the current
            // servers are authoritative for (bailiwick anchor).
            // A DS query is answered by the parent zone; never start from a
            // cached delegation for the exact name (the child lacks its DS).
            let min_skip = if qtype == dns_proto::message::TYPE_DS { 1 } else { 0 };
            let (mut servers, mut current_zone, mut zone_depth) =
                match self.cached_start(qname, min_skip) {
                    Some((zone, s)) => {
                        let d = zone.label_count();
                        (s, zone, d)
                    }
                    None => (self.roots.clone(), DnsName::root(), 0usize),
                };
            // The next query reveals exactly one more label than the zone cut
            // (QNAME minimization, RFC 9156) until we reach the full name.
            let mut minimize = true;

            for _ in 0..MAX_REFERRALS {
                let keep = if minimize { (zone_depth + 1).min(full_labels) } else { full_labels };
                let is_full = keep == full_labels;
                let min_name = suffix(qname, keep);
                // Intermediate steps probe with NS (privacy); the last with the
                // real type.
                let step_type = if is_full { qtype } else { TYPE_NS };

                let resp = match self.query_servers(&servers, &min_name, step_type).await {
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
                                    let mut chased = self
                                        .resolve_depth(&target, qtype, depth + 1)
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
                    let new_zone = ns_owner.clone().unwrap_or_else(|| min_name.clone());
                    // DS lives in the PARENT zone (RFC 4034 §5): once the
                    // referral is for the exact queried name, we have reached
                    // the parent — do not descend into the child, answer from
                    // the parent's response (which carries the DS or the
                    // NSEC/NSEC3 proving its absence).
                    if qtype == dns_proto::message::TYPE_DS && new_zone == *qname {
                        return Ok(finalize(resp, qname, qtype));
                    }
                    // Bailiwick (RFC 5452 / cache-poisoning defense): a valid
                    // referral must be *within* the zone we asked and strictly
                    // deeper. Reject out-of-zone or non-progressing delegations.
                    if !new_zone.ends_with(&current_zone)
                        || new_zone.label_count() <= current_zone.label_count()
                    {
                        if minimize && !is_full {
                            minimize = false; // retry this step with the full name
                            continue;
                        }
                        return Ok(finalize(resp, qname, qtype));
                    }
                    // Glue is trusted only when in-bailiwick of the zone we
                    // just queried (`current_zone`) — a server may legitimately
                    // supply glue for any name within its own zone (e.g. root
                    // gives gtld-servers.net glue for .com). Out-of-bailiwick
                    // glue is discarded and the NS name resolved from scratch.
                    servers = match self
                        .referral_addrs(&resp, &ns_names, &current_zone, depth)
                        .await
                    {
                        Some(s) => s,
                        None => return Err(ForwardError::Timeout),
                    };
                    self.cache_delegation(new_zone.clone(), servers.clone());
                    zone_depth = new_zone.label_count().max(zone_depth + 1);
                    current_zone = new_zone;
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

    /// Addresses to talk to for a referral into `zone`. Glue is trusted only
    /// when the NS name is in-bailiwick (a subdomain of `zone`); out-of-
    /// bailiwick NS names are resolved from scratch to avoid poisoned glue.
    async fn referral_addrs(
        &self,
        resp: &Message,
        ns_names: &[DnsName],
        zone: &DnsName,
        depth: usize,
    ) -> Option<Vec<SocketAddr>> {
        let mut next: Vec<SocketAddr> = resp
            .additionals
            .iter()
            .filter(|r| ns_names.contains(&r.name) && r.name.ends_with(zone))
            .filter_map(|r| match &r.rdata {
                RData::A(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                RData::Aaaa(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                _ => None,
            })
            .collect();
        if next.is_empty() {
            if depth >= MAX_DEPTH {
                return None;
            }
            for ns in ns_names {
                if let Ok(m) = self.resolve_depth(ns, TYPE_A, depth + 1).await {
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
    ) -> Option<Message> {
        for &server in servers.iter().take(4) {
            Metrics::inc(&self.metrics.upstream_queries);
            match query_one(server, qname, qtype).await {
                Ok(m) => return Some(m),
                Err(_) => {
                    Metrics::inc(&self.metrics.upstream_failures);
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
