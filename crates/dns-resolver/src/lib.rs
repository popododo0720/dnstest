//! Query resolution: authoritative zones first, then the cache, then the
//! upstream pool.
//!
//! The hot path is split in two so transports can answer most queries without
//! spawning a task: [`Resolver::resolve_local`] is synchronous and handles
//! everything answerable from zones and cache; only queries that genuinely
//! need upstream traffic return [`Outcome::Pending`] and go through the
//! asynchronous [`Resolver::resolve_pending`].

mod flight;
mod upstream;

pub use upstream::ForwardError;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use dns_cache::{Cache, Key};
use dns_metrics::Metrics;
use dns_proto::message::{
    CLASS_ANY, CLASS_IN, Message, RCODE_FORMERR, RCODE_NOTIMP, RCODE_REFUSED, RCODE_SERVFAIL,
    Record, TYPE_SOA,
};
use dns_proto::name::DnsName;
use dns_zone::Zone;
use tracing::warn;

use crate::flight::{Role, Singleflight};
use crate::upstream::UpstreamPool;

pub struct Resolver {
    zones: RwLock<Arc<Vec<Zone>>>,
    pool: Option<UpstreamPool>,
    cache: Cache,
    flight: Singleflight,
    metrics: Arc<Metrics>,
}

/// Result of the synchronous resolution attempt.
pub enum Outcome {
    Done(Message),
    Pending(Pending),
}

/// A response that still needs upstream traffic to complete.
pub struct Pending {
    resp: Message,
    target: DnsName,
    qtype: u16,
    /// true: append to an authoritative CNAME chain; false: fill the whole
    /// response.
    append: bool,
}

impl Resolver {
    pub fn new(
        zones: Vec<Zone>,
        upstreams: Vec<SocketAddr>,
        cache_size: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        Resolver {
            zones: RwLock::new(Arc::new(zones)),
            pool: UpstreamPool::new(upstreams),
            cache: Cache::new(cache_size),
            flight: Singleflight::default(),
            metrics,
        }
    }

    /// Current zone set (cheap snapshot for readers).
    pub fn zones(&self) -> Arc<Vec<Zone>> {
        self.zones.read().unwrap().clone()
    }

    /// Atomically replace the zone set (API edits, SIGHUP reload).
    pub fn set_zones(&self, zones: Vec<Zone>) {
        *self.zones.write().unwrap() = Arc::new(zones);
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Full resolution; convenience for transports that do not use the
    /// sync/async split.
    pub async fn handle(&self, query: &Message, recursion_allowed: bool) -> Message {
        match self.resolve_local(query, recursion_allowed) {
            Outcome::Done(m) => m,
            Outcome::Pending(p) => self.resolve_pending(p).await,
        }
    }

    /// Synchronous fast path: validation, authoritative zones, and cache.
    pub fn resolve_local(&self, query: &Message, recursion_allowed: bool) -> Outcome {
        let mut resp = Message::response_to(query);

        // RFC 6891: unknown EDNS version gets BADVERS (extended rcode 16 =
        // ext_rcode 1, header rcode 0).
        if let Some(e) = &query.edns {
            if e.version > 0 {
                if let Some(re) = &mut resp.edns {
                    re.ext_rcode = 1;
                }
                return Outcome::Done(resp);
            }
        }
        if query.flags.opcode != 0 {
            resp.flags.rcode = RCODE_NOTIMP;
            return Outcome::Done(resp);
        }
        if query.questions.len() != 1 {
            resp.flags.rcode = RCODE_FORMERR;
            return Outcome::Done(resp);
        }
        let q = &query.questions[0];
        if q.qclass != CLASS_IN && q.qclass != CLASS_ANY {
            resp.flags.rcode = RCODE_NOTIMP;
            return Outcome::Done(resp);
        }
        resp.flags.ra = self.pool.is_some() && recursion_allowed;

        // Authoritative data wins over forwarding.
        let zones = self.zones();
        if let Some(zone) = find_zone(&zones, &q.qname) {
            resp.flags.aa = true;
            let result = zone.lookup(&q.qname, q.qtype);
            resp.flags.rcode = result.rcode;
            resp.answers = result.answers;
            if result.negative {
                resp.authorities.push(zone.soa.clone());
            }
            // A CNAME chain that leaves the zone: keep resolving if the
            // client asked for recursion and is allowed to use it.
            if let Some(target) = result.offsite {
                if query.flags.rd && self.pool.is_some() && recursion_allowed {
                    let key = Key { qname: target.clone(), qtype: q.qtype };
                    if let Some(hit) = self.cache_get(&key) {
                        merge(&mut resp, hit, true);
                        return Outcome::Done(resp);
                    }
                    return Outcome::Pending(Pending {
                        resp,
                        target,
                        qtype: q.qtype,
                        append: true,
                    });
                }
                // Without recursion the client gets the bare CNAME.
            }
            return Outcome::Done(resp);
        }

        if !query.flags.rd || self.pool.is_none() {
            resp.flags.rcode = RCODE_REFUSED;
            return Outcome::Done(resp);
        }
        if !recursion_allowed {
            Metrics::inc(&self.metrics.recursion_refused);
            resp.flags.rcode = RCODE_REFUSED;
            return Outcome::Done(resp);
        }
        let key = Key { qname: q.qname.clone(), qtype: q.qtype };
        if let Some(hit) = self.cache_get(&key) {
            merge(&mut resp, hit, false);
            return Outcome::Done(resp);
        }
        Outcome::Pending(Pending { resp, target: q.qname.clone(), qtype: q.qtype, append: false })
    }

    /// Complete a pending response with upstream traffic.
    pub async fn resolve_pending(&self, mut p: Pending) -> Message {
        match self.resolve_external(&p.target, p.qtype).await {
            Ok(hit) => merge(&mut p.resp, hit, p.append),
            Err(e) => {
                warn!("upstream lookup {} type{} failed: {e}", p.target, p.qtype);
                p.resp.flags.rcode = RCODE_SERVFAIL;
            }
        }
        p.resp
    }

    fn cache_get(&self, key: &Key) -> Option<(u8, Vec<Record>, Vec<Record>)> {
        let hit = self.cache.get(key);
        if hit.is_some() {
            Metrics::inc(&self.metrics.cache_hits);
        }
        hit
    }

    /// Cache-through, singleflight-deduplicated upstream lookup.
    async fn resolve_external(
        &self,
        qname: &DnsName,
        qtype: u16,
    ) -> Result<(u8, Vec<Record>, Vec<Record>), ForwardError> {
        let key = Key { qname: qname.clone(), qtype };
        for _ in 0..3 {
            if let Some(hit) = self.cache_get(&key) {
                return Ok(hit);
            }
            match self.flight.begin(&key) {
                Role::Leader(_guard) => {
                    Metrics::inc(&self.metrics.cache_misses);
                    let pool = self.pool.as_ref().ok_or(ForwardError::NoUpstream)?;
                    let msg = pool.query(qname, qtype, &self.metrics).await?;
                    // Keep only the SOA from the authority section — it is
                    // what negative answers need; referral NS sets are noise.
                    let authorities: Vec<Record> = msg
                        .authorities
                        .iter()
                        .filter(|r| r.rtype() == TYPE_SOA)
                        .cloned()
                        .collect();
                    self.cache.insert(
                        key,
                        msg.flags.rcode,
                        msg.answers.clone(),
                        authorities.clone(),
                    );
                    return Ok((msg.flags.rcode, msg.answers, authorities));
                }
                Role::Follower(mut rx) => {
                    Metrics::inc(&self.metrics.singleflight_merged);
                    // Completion signal; an error means the leader already
                    // finished and dropped the sender. Either way: re-check.
                    let _ = rx.wait_for(|done| *done).await;
                }
            }
        }
        // Leaders kept failing with uncacheable results; go direct.
        let pool = self.pool.as_ref().ok_or(ForwardError::NoUpstream)?;
        let msg = pool.query(qname, qtype, &self.metrics).await?;
        Ok((msg.flags.rcode, msg.answers, Vec::new()))
    }
}

fn find_zone<'a>(zones: &'a [Zone], name: &DnsName) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|z| name.ends_with(&z.origin))
        .max_by_key(|z| z.origin.label_count())
}

/// Fold a lookup result into a response. `append` keeps existing answers (the
/// authoritative part of a CNAME chain) and only adds authority records when
/// the tail produced no answers.
fn merge(resp: &mut Message, hit: (u8, Vec<Record>, Vec<Record>), append: bool) {
    let (rcode, mut answers, mut authorities) = hit;
    resp.flags.rcode = rcode;
    if append {
        if answers.is_empty() {
            resp.authorities.append(&mut authorities);
        }
        resp.answers.append(&mut answers);
    } else {
        resp.answers = answers;
        resp.authorities = authorities;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_proto::message::{Flags, Question, RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A};
    use dns_zone::parse_zone_file;

    const ZONE: &str = "\
$ORIGIN example.lab.
$TTL 300
@    IN SOA ns1 h 1 2 3 4 300
@    IN NS  ns1
ns1  IN A   10.0.0.1
www  IN A   10.0.0.10
";

    fn resolver(upstreams: Vec<SocketAddr>) -> Resolver {
        Resolver::new(
            vec![parse_zone_file(ZONE).unwrap()],
            upstreams,
            16,
            Arc::new(Metrics::new()),
        )
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
    async fn authoritative_answer_is_synchronous() {
        let r = resolver(vec![]);
        let Outcome::Done(resp) = r.resolve_local(&query("www.example.lab", TYPE_A), true) else {
            panic!("zone answers must not need upstream")
        };
        assert_eq!(resp.flags.rcode, RCODE_NOERROR);
        assert!(resp.flags.aa);
        assert!(!resp.flags.ra);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn nxdomain_carries_soa() {
        let r = resolver(vec![]);
        let resp = r.handle(&query("missing.example.lab", TYPE_A), true).await;
        assert_eq!(resp.flags.rcode, RCODE_NXDOMAIN);
        assert_eq!(resp.authorities.len(), 1);
        assert_eq!(resp.authorities[0].rtype(), TYPE_SOA);
    }

    #[tokio::test]
    async fn refuses_outside_zone_without_upstream() {
        let r = resolver(vec![]);
        let resp = r.handle(&query("google.com", TYPE_A), true).await;
        assert_eq!(resp.flags.rcode, RCODE_REFUSED);
    }

    #[tokio::test]
    async fn acl_denied_recursion_is_refused_but_zones_still_answer() {
        let r = resolver(vec!["192.0.2.1:53".parse().unwrap()]);
        let refused = r.handle(&query("google.com", TYPE_A), false).await;
        assert_eq!(refused.flags.rcode, RCODE_REFUSED);
        assert!(!refused.flags.ra);

        let zoned = r.handle(&query("www.example.lab", TYPE_A), false).await;
        assert_eq!(zoned.flags.rcode, RCODE_NOERROR);
        assert_eq!(zoned.answers.len(), 1);
    }

    #[tokio::test]
    async fn zone_hot_swap() {
        let r = resolver(vec![]);
        let updated = "\
$ORIGIN example.lab.
$TTL 300
@    IN SOA ns1 h 2 2 3 4 300
www  IN A   10.9.9.9
";
        r.set_zones(vec![parse_zone_file(updated).unwrap()]);
        let resp = r.handle(&query("www.example.lab", TYPE_A), true).await;
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata.text(), "10.9.9.9");
    }
}
