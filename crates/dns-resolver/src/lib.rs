//! Query resolution: authoritative zones first, then the cache, then the
//! upstream pool.
//!
//! The hot path is split in two so transports can answer most queries without
//! spawning a task: [`Resolver::resolve_local`] is synchronous and handles
//! everything answerable from zones and cache; only queries that genuinely
//! need upstream traffic return [`Outcome::Pending`] and go through the
//! asynchronous [`Resolver::resolve_pending`].

mod flight;
mod rpz;
mod upstream;
mod validator;

pub use rpz::{Rpz, RpzAction};
pub use upstream::ForwardError;
pub use validator::{Security, TrustAnchor, Validator};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use dns_cache::{Cache, Key};
use dns_dnssec::SignedZone;
use dns_metrics::Metrics;
use dns_proto::message::{
    CLASS_ANY, CLASS_CH, CLASS_IN, Message, RCODE_FORMERR, RCODE_NOTIMP, RCODE_NXDOMAIN,
    Question, RCODE_REFUSED, RCODE_SERVFAIL, RData, Record, TYPE_A, TYPE_AAAA, TYPE_ANY,
    TYPE_AXFR, TYPE_DNSKEY, TYPE_IXFR, TYPE_NSEC3PARAM, TYPE_SOA, TYPE_TXT,
};
use dns_proto::name::DnsName;
use dns_zone::Zone;
use tracing::warn;

use crate::flight::{Role, Singleflight};
use crate::upstream::UpstreamPool;

pub struct Resolver {
    zones: RwLock<Arc<Vec<Zone>>>,
    pool: Option<UpstreamPool>,
    /// Conditional forwarding: (zone, upstreams), longest suffix wins.
    forwards: Vec<(DnsName, UpstreamPool)>,
    rpz: RwLock<Arc<Rpz>>,
    /// DNSSEC-signed material by zone origin (empty when unsigned).
    signed: RwLock<Arc<HashMap<DnsName, Arc<SignedZone>>>>,
    /// Validating-resolver engine (set when DNSSEC validation is enabled).
    validator: Option<Validator>,
    cache: Cache,
    flight: Singleflight,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
pub struct ResolverOptions {
    pub zones: Vec<Zone>,
    pub upstreams: Vec<SocketAddr>,
    pub forwards: Vec<(DnsName, Vec<SocketAddr>)>,
    pub cache_size: usize,
    pub rpz: Rpz,
    pub signed: HashMap<DnsName, Arc<SignedZone>>,
    /// Enable DNSSEC validation of forwarded answers (root trust anchor).
    pub validate: bool,
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
    pub fn new(opts: ResolverOptions, metrics: Arc<Metrics>) -> Self {
        Resolver {
            zones: RwLock::new(Arc::new(opts.zones)),
            pool: UpstreamPool::new(opts.upstreams),
            forwards: opts
                .forwards
                .into_iter()
                .filter_map(|(zone, ups)| UpstreamPool::new(ups).map(|p| (zone, p)))
                .collect(),
            rpz: RwLock::new(Arc::new(opts.rpz)),
            signed: RwLock::new(Arc::new(opts.signed)),
            validator: opts.validate.then(Validator::with_root),
            cache: Cache::new(opts.cache_size.max(1)),
            flight: Singleflight::default(),
            metrics,
        }
    }

    /// Replace the DNSSEC-signed material (re-sign on reload).
    pub fn set_signed(&self, signed: HashMap<DnsName, Arc<SignedZone>>) {
        *self.signed.write().unwrap() = Arc::new(signed);
    }

    /// (Re)sign the given origins with `keys` over the current zone data.
    /// Called at startup, on SIGHUP, and after API edits so RRSIGs stay fresh.
    pub fn resign(
        &self,
        keys: &[dns_dnssec::DnssecKey],
        origins: &[DnsName],
        now: u64,
        validity_secs: u64,
        nsec3: Option<dns_dnssec::nsec3::Nsec3Params>,
    ) {
        let zones = self.zones();
        let mut map = HashMap::new();
        for origin in origins {
            if let Some(zone) = zones.iter().find(|z| z.origin == *origin) {
                map.insert(
                    origin.clone(),
                    Arc::new(SignedZone::sign(zone, keys, now, validity_secs, nsec3.clone())),
                );
            }
        }
        self.set_signed(map);
    }

    fn signed_zones(&self) -> Arc<HashMap<DnsName, Arc<SignedZone>>> {
        self.signed.read().unwrap().clone()
    }

    /// The upstream pool responsible for `name`: the most specific forward
    /// zone, falling back to the default resolvers.
    fn pool_for(&self, name: &DnsName) -> Option<&UpstreamPool> {
        self.forwards
            .iter()
            .filter(|(zone, _)| name.ends_with(zone))
            .max_by_key(|(zone, _)| zone.label_count())
            .map(|(_, pool)| pool)
            .or(self.pool.as_ref())
    }

    /// Replace or add a single zone (secondary transfers).
    pub fn upsert_zone(&self, zone: Zone) {
        let mut zones = self.zones().as_ref().clone();
        match zones.iter().position(|z| z.origin == zone.origin) {
            Some(i) => zones[i] = zone,
            None => zones.push(zone),
        }
        self.set_zones(zones);
    }

    pub fn set_rpz(&self, rpz: Rpz) {
        *self.rpz.write().unwrap() = Arc::new(rpz);
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
        // CHAOS class: answer version.bind like BIND does, refuse the rest.
        if q.qclass == CLASS_CH {
            return Outcome::Done(chaos_answer(resp, q));
        }
        if q.qclass != CLASS_IN && q.qclass != CLASS_ANY {
            resp.flags.rcode = RCODE_NOTIMP;
            return Outcome::Done(resp);
        }
        // Zone transfers are TCP-only and handled at the transport layer.
        if q.qtype == TYPE_AXFR || q.qtype == TYPE_IXFR {
            resp.flags.rcode = RCODE_NOTIMP;
            return Outcome::Done(resp);
        }
        resp.flags.ra =
            (self.pool.is_some() || !self.forwards.is_empty()) && recursion_allowed;

        // Authoritative data wins over forwarding.
        let zones = self.zones();
        if let Some(zone) = find_zone(&zones, &q.qname) {
            resp.flags.aa = true;
            // DNSSEC is engaged only when the client set the DO bit (RFC 6840).
            let signed = self.signed_zones();
            let dnssec = query
                .edns
                .as_ref()
                .filter(|e| e.do_bit)
                .and_then(|_| signed.get(&zone.origin))
                .cloned();

            // Apex DNSKEY is synthesized from the signing key, not zone data.
            if q.qtype == TYPE_DNSKEY && q.qname == zone.origin {
                if let Some(sz) = &dnssec {
                    let (rrset, rrsigs) = sz.dnskey_records();
                    resp.answers.extend(rrset.iter().cloned());
                    resp.answers.extend(rrsigs.iter().cloned());
                    return Outcome::Done(resp);
                }
            }
            // NSEC3PARAM is likewise synthesized from the signing config.
            if q.qtype == TYPE_NSEC3PARAM && q.qname == zone.origin {
                if let Some(sz) = &dnssec {
                    if let Some(rec) = sz.nsec3param() {
                        resp.answers.push(rec.clone());
                        resp.answers.extend(sz.rrsigs_for(&zone.origin, TYPE_NSEC3PARAM).iter().cloned());
                        return Outcome::Done(resp);
                    }
                }
            }

            let result = zone.lookup(&q.qname, q.qtype);
            resp.flags.rcode = result.rcode;
            resp.answers = result.answers;
            if result.negative {
                resp.authorities.push(zone.soa.clone());
            }
            if let Some(sz) = &dnssec {
                attach_dnssec(&mut resp, q, zone, sz, result.negative);
            }
            // A CNAME chain that leaves the zone: keep resolving if the
            // client asked for recursion and is allowed to use it.
            if let Some(target) = result.offsite {
                if query.flags.rd && self.pool_for(&target).is_some() && recursion_allowed {
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

        // Response policy: applies to anything we would resolve for clients.
        let rpz = self.rpz.read().unwrap().clone();
        if let Some(action) = rpz.lookup(&q.qname) {
            Metrics::inc(&self.metrics.rpz_blocked);
            match action {
                RpzAction::Block => resp.flags.rcode = RCODE_NXDOMAIN,
                RpzAction::Redirect(ip) => {
                    let rdata = match (ip, q.qtype) {
                        (std::net::IpAddr::V4(v4), TYPE_A | TYPE_ANY) => Some(RData::A(v4)),
                        (std::net::IpAddr::V6(v6), TYPE_AAAA | TYPE_ANY) => Some(RData::Aaaa(v6)),
                        _ => None, // sinkhole family does not match qtype: NODATA
                    };
                    if let Some(rdata) = rdata {
                        resp.answers.push(Record {
                            name: q.qname.clone(),
                            class: CLASS_IN,
                            ttl: 60,
                            rdata,
                        });
                    }
                }
            }
            return Outcome::Done(resp);
        }

        if !query.flags.rd || self.pool_for(&q.qname).is_none() {
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
            Ok((rcode, answers, authorities, secure)) => {
                // AD is set from the DNSSEC status (RFC 6840 §5.7) via merge.
                merge(&mut p.resp, dns_cache::Hit { rcode, answers, authorities, secure }, p.append);
            }
            Err(ForwardError::Bogus) => {
                Metrics::inc(&self.metrics.upstream_failures);
                warn!("bogus DNSSEC answer for {} — returning SERVFAIL", p.target);
                p.resp.flags.rcode = RCODE_SERVFAIL;
            }
            Err(e) => {
                // All upstreams down: serve stale cache data if we have any
                // (RFC 8767) before giving up with SERVFAIL.
                let key = Key { qname: p.target.clone(), qtype: p.qtype };
                if let Some(hit) = self.cache.get_stale(&key) {
                    Metrics::inc(&self.metrics.served_stale);
                    warn!("upstreams failed for {}, serving stale data", p.target);
                    merge(&mut p.resp, hit, p.append);
                } else {
                    warn!("upstream lookup {} type{} failed: {e}", p.target, p.qtype);
                    p.resp.flags.rcode = RCODE_SERVFAIL;
                }
            }
        }
        p.resp
    }

    fn cache_get(&self, key: &Key) -> Option<dns_cache::Hit> {
        let hit = self.cache.get(key);
        if hit.is_some() {
            Metrics::inc(&self.metrics.cache_hits);
        }
        hit
    }

    /// Cache-through, singleflight-deduplicated upstream lookup. The `bool` is
    /// the DNSSEC security status (true = Secure) when validation is enabled.
    async fn resolve_external(
        &self,
        qname: &DnsName,
        qtype: u16,
    ) -> Result<(u8, Vec<Record>, Vec<Record>, bool), ForwardError> {
        let key = Key { qname: qname.clone(), qtype };
        for _ in 0..3 {
            if let Some(hit) = self.cache_get(&key) {
                return Ok((hit.rcode, hit.answers, hit.authorities, hit.secure));
            }
            match self.flight.begin(&key) {
                Role::Leader(_guard) => {
                    Metrics::inc(&self.metrics.cache_misses);
                    let pool = self.pool_for(qname).ok_or(ForwardError::NoUpstream)?;

                    // With validation on, fetch with DO=1 and check the chain.
                    let (msg, secure) = match &self.validator {
                        Some(v) => {
                            let m = pool.query_dnssec(qname, qtype, &self.metrics).await?;
                            match v.validate(pool, &self.metrics, &m).await {
                                Security::Bogus => return Err(ForwardError::Bogus),
                                Security::Secure => (m, true),
                                Security::Insecure => (m, false),
                            }
                        }
                        None => (pool.query(qname, qtype, &self.metrics).await?, false),
                    };

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
                        secure,
                    );
                    return Ok((msg.flags.rcode, msg.answers, authorities, secure));
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
        let pool = self.pool_for(qname).ok_or(ForwardError::NoUpstream)?;
        let msg = pool.query(qname, qtype, &self.metrics).await?;
        Ok((msg.flags.rcode, msg.answers, Vec::new(), false))
    }
}

/// `version.bind CH TXT` compatibility; everything else in CHAOS is refused.
fn chaos_answer(mut resp: Message, q: &dns_proto::message::Question) -> Message {
    let is_version = ["version.bind", "version.server"]
        .iter()
        .any(|n| DnsName::parse_str(n).is_ok_and(|n| n == q.qname));
    if is_version && (q.qtype == TYPE_TXT || q.qtype == TYPE_ANY) {
        resp.answers.push(Record {
            name: q.qname.clone(),
            class: CLASS_CH,
            ttl: 0,
            rdata: RData::Txt(vec![
                format!("rdns {}", env!("CARGO_PKG_VERSION")).into_bytes(),
            ]),
        });
    } else {
        resp.flags.rcode = RCODE_REFUSED;
    }
    resp
}

/// Attach DNSSEC records to an authoritative response (RFC 4035 §3.1):
/// RRSIGs beside every answer rrset, and NSEC + RRSIG proving denial.
fn attach_dnssec(resp: &mut Message, q: &Question, zone: &Zone, sz: &SignedZone, negative: bool) {
    // Sign each answer rrset (group by owner+type to sign once per set).
    let mut signed_sets: Vec<(DnsName, u16)> = Vec::new();
    let owners_types: Vec<(DnsName, u16)> =
        resp.answers.iter().map(|r| (r.name.clone(), r.rtype())).collect();
    for (owner, rtype) in owners_types {
        if signed_sets.contains(&(owner.clone(), rtype)) {
            continue;
        }
        resp.answers.extend(sz.rrsigs_for(&owner, rtype).iter().cloned());
        signed_sets.push((owner, rtype));
    }

    if negative {
        // Sign the SOA that lookup put in the authority section.
        resp.authorities.extend(sz.rrsigs_for(&zone.origin, TYPE_SOA).iter().cloned());
        // NSEC or NSEC3 authenticated denial (RFC 4035 / 5155).
        let nxdomain = resp.flags.rcode == RCODE_NXDOMAIN;
        resp.authorities.extend(sz.denial_records(&q.qname, nxdomain));
    }
}

fn find_zone<'a>(zones: &'a [Zone], name: &DnsName) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|z| name.ends_with(&z.origin))
        .max_by_key(|z| z.origin.label_count())
}

/// Fold a cached/looked-up result into a response and carry its DNSSEC
/// validated status to the AD bit. `append` keeps existing answers (the
/// authoritative part of a CNAME chain) and only adds authority records when
/// the tail produced no answers.
fn merge(resp: &mut Message, hit: dns_cache::Hit, append: bool) {
    let dns_cache::Hit { rcode, mut answers, mut authorities, secure } = hit;
    resp.flags.rcode = rcode;
    if append {
        if answers.is_empty() {
            resp.authorities.append(&mut authorities);
        }
        resp.answers.append(&mut answers);
        // The whole chain is authenticated only if both halves are.
        resp.flags.ad = resp.flags.ad && secure;
    } else {
        resp.answers = answers;
        resp.authorities = authorities;
        resp.flags.ad = secure;
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
            ResolverOptions {
                zones: vec![parse_zone_file(ZONE).unwrap()],
                upstreams,
                cache_size: 16,
                ..ResolverOptions::default()
            },
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
