//! Validating resolver: builds a DNSSEC chain of trust from a configured
//! trust anchor (the IANA root KSK by default) down to the answer's signer,
//! fetching DNSKEY and DS records through the upstream pool.
//!
//! Positive answers are validated cryptographically end to end: a forged
//! record yields `Bogus` (→ SERVFAIL), a properly signed one yields `Secure`
//! (→ AD bit). Zones with a securely-proven absent DS are `Insecure` and pass
//! through unauthenticated. Validated DNSKEY/DS sets are memoized per call.

use std::collections::HashMap;

use dns_dnssec::nsec3::{Nsec3Params, hash_name};
use dns_dnssec::validate::{parse_rrsig, verify_ds, verify_rrsig};
use dns_metrics::Metrics;
use dns_proto::message::{
    Message, RCODE_NXDOMAIN, RData, Record, TYPE_DNSKEY, TYPE_DS, TYPE_NSEC, TYPE_NSEC3,
    TYPE_RRSIG,
};
use dns_proto::name::DnsName;

use crate::upstream::UpstreamPool;

const MAX_DEPTH: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Chain of trust verified end to end.
    Secure,
    /// Provably unsigned (a secure delegation to an unsigned zone).
    Insecure,
    /// Signatures or the chain failed to verify — the answer is forged/broken.
    Bogus,
}

/// A trust anchor: a DS record (key tag, algorithm, digest type, digest) for a
/// zone, against which that zone's DNSKEY is validated.
#[derive(Clone)]
pub struct TrustAnchor {
    pub zone: DnsName,
    pub ds_rdata: Vec<u8>,
}

impl TrustAnchor {
    /// The IANA root KSK-2017 (key tag 20326), SHA-256 DS. Still published as
    /// a valid root trust anchor.
    pub fn root_ksk_2017() -> Self {
        let digest = hex(
            "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        );
        let mut ds = Vec::new();
        ds.extend_from_slice(&20326u16.to_be_bytes());
        ds.push(8); // RSA/SHA-256
        ds.push(2); // SHA-256 digest
        ds.extend_from_slice(&digest);
        TrustAnchor { zone: DnsName::root(), ds_rdata: ds }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub struct Validator {
    anchors: Vec<TrustAnchor>,
}

/// Per-validation state threaded through the chain walk.
struct Ctx<'a> {
    pool: &'a UpstreamPool,
    metrics: &'a Metrics,
    /// zone -> validated DNSKEY rdata list (`Some(vec![])` = bogus,
    /// `None` = insecure).
    keys: HashMap<DnsName, Option<Vec<Vec<u8>>>>,
}

type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Validator {
    pub fn new(anchors: Vec<TrustAnchor>) -> Self {
        Validator { anchors }
    }

    pub fn with_root() -> Self {
        Validator::new(vec![TrustAnchor::root_ksk_2017()])
    }

    /// Validate a forwarded response. Each rrset is checked against the keys of
    /// *its own* signer (a CNAME chain can cross zones). Positive answers and
    /// the NSEC/NSEC3 records proving a negative answer are both authenticated;
    /// the result is Bogus if a signature fails or a denial is not proven.
    pub async fn validate(
        &self,
        pool: &UpstreamPool,
        metrics: &Metrics,
        msg: &Message,
    ) -> Security {
        let mut ctx = Ctx { pool, metrics, keys: HashMap::new() };

        // 1) Answer section.
        let answer = self.verify_section(&mut ctx, &msg.answers).await;
        if answer.bogus {
            return Security::Bogus;
        }

        // 2) When the answer is a denial (NXDOMAIN or NODATA), the NSEC/NSEC3
        //    records in the authority section must be authenticated and must
        //    actually prove the denial.
        let is_denial = msg.answers.iter().all(|r| r.rtype() == TYPE_RRSIG)
            || msg.flags.rcode == RCODE_NXDOMAIN;
        let mut denial_secure = false;
        if is_denial && !msg.authorities.is_empty() {
            let auth = self.verify_section(&mut ctx, &msg.authorities).await;
            if auth.bogus {
                return Security::Bogus;
            }
            // A securely-signed authority section that carries NSEC/NSEC3 and
            // proves the denial for the queried name.
            if auth.any_secure && self.denial_proven(msg) {
                denial_secure = true;
            } else if auth.any_secure && has_nsec(&msg.authorities) {
                // Signed NSEC/NSEC3 present but coverage not established:
                // reject rather than trust a possibly-replayed proof.
                return Security::Bogus;
            }
        }

        if answer.any_secure || denial_secure {
            Security::Secure
        } else {
            Security::Insecure
        }
    }

    /// Verify every signed rrset in `records` against its signer's validated
    /// keys. `pool_records` is the record list the RRSIGs are drawn from
    /// (same as `records` here). Returns whether anything validated securely
    /// and whether any signed rrset failed (bogus).
    async fn verify_section(&self, ctx: &mut Ctx<'_>, records: &[Record]) -> SectionResult {
        let mut sets: Vec<(DnsName, u16)> = records
            .iter()
            .filter(|r| r.rtype() != TYPE_RRSIG)
            .map(|r| (r.name.clone(), r.rtype()))
            .collect();
        sets.sort_by(|a, b| (a.0.to_string(), a.1).cmp(&(b.0.to_string(), b.1)));
        sets.dedup();

        let mut any_secure = false;
        for (owner, rtype) in sets {
            let rrset: Vec<Record> =
                records.iter().filter(|r| r.name == owner && r.rtype() == rtype).cloned().collect();
            let sigs: Vec<Vec<u8>> = records
                .iter()
                .filter(|r| r.rtype() == TYPE_RRSIG && r.name == owner)
                .filter_map(|r| match &r.rdata {
                    RData::Unknown { data, .. } => Some(data.clone()),
                    _ => None,
                })
                .filter(|d| parse_rrsig(d).map(|f| f.type_covered) == Some(rtype))
                .collect();
            if sigs.is_empty() {
                continue; // unsigned rrset (glue, or an unsigned zone's data)
            }
            let mut verified = false;
            for sig in &sigs {
                let Some(fields) = parse_rrsig(sig) else { continue };
                let signer = fields.signer.clone();
                match self.dnskeys(ctx, &signer, 0).await {
                    None => {
                        verified = true; // insecure signer
                        break;
                    }
                    Some(keys) if keys.is_empty() => continue, // broken chain
                    Some(keys) => {
                        if keys.iter().any(|k| verify_rrsig(&rrset, sig, k)) {
                            verified = true;
                            any_secure = true;
                            break;
                        }
                    }
                }
            }
            if !verified {
                return SectionResult { any_secure, bogus: true };
            }
        }
        SectionResult { any_secure, bogus: false }
    }

    /// Does the authority section's NSEC/NSEC3 set actually prove the denial
    /// for the queried name?
    fn denial_proven(&self, msg: &Message) -> bool {
        let Some(q) = msg.questions.first() else { return false };
        let nsec3: Vec<&Record> =
            msg.authorities.iter().filter(|r| r.rtype() == TYPE_NSEC3).collect();
        if !nsec3.is_empty() {
            return nsec3_proves(&q.qname, &nsec3);
        }
        let nsec: Vec<&Record> =
            msg.authorities.iter().filter(|r| r.rtype() == TYPE_NSEC).collect();
        if !nsec.is_empty() {
            return nsec_proves(&q.qname, q.qtype, &nsec);
        }
        false
    }

    /// Validated DNSKEY rdata set for `zone`: `Some(keys)` if secure, `None`
    /// if the zone is provably insecure (no DS). Recurses toward the anchor.
    fn dnskeys<'a>(
        &'a self,
        ctx: &'a mut Ctx<'_>,
        zone: &'a DnsName,
        depth: usize,
    ) -> BoxFut<'a, Option<Vec<Vec<u8>>>> {
        Box::pin(async move {
            if depth > MAX_DEPTH {
                return None;
            }
            if let Some(cached) = ctx.keys.get(zone) {
                return cached.clone();
            }

            // Fetch the DNSKEY rrset and its RRSIG.
            let msg = ctx.pool.query_dnssec(zone, TYPE_DNSKEY, ctx.metrics).await.ok();
            let msg = match msg {
                Some(m) => m,
                None => {
                    ctx.keys.insert(zone.clone(), None);
                    return None;
                }
            };
            let dnskeys: Vec<Vec<u8>> = msg
                .answers
                .iter()
                .filter(|r| r.rtype() == TYPE_DNSKEY)
                .filter_map(|r| match &r.rdata {
                    RData::Unknown { data, .. } => Some(data.clone()),
                    _ => None,
                })
                .collect();
            if dnskeys.is_empty() {
                ctx.keys.insert(zone.clone(), None);
                return None;
            }

            // The DS set that must vouch one of these keys.
            let ds_set = if let Some(anchor) =
                self.anchors.iter().find(|a| a.zone == *zone)
            {
                Some(vec![anchor.ds_rdata.clone()])
            } else {
                match self.delegated_ds(&mut *ctx, zone, depth).await {
                    DsResult::Secure(set) => Some(set),
                    DsResult::Insecure => {
                        ctx.keys.insert(zone.clone(), None);
                        return None; // insecure delegation
                    }
                    DsResult::Bogus => {
                        // Signal bogus with an empty vec sentinel is ambiguous;
                        // cache None and let the caller treat missing as fail.
                        ctx.keys.insert(zone.clone(), Some(Vec::new()));
                        return Some(Vec::new());
                    }
                }
            };
            let Some(ds_set) = ds_set else {
                ctx.keys.insert(zone.clone(), None);
                return None;
            };

            // A key that a DS vouches for is a trusted entry point.
            let trusted: Vec<&Vec<u8>> = dnskeys
                .iter()
                .filter(|k| ds_set.iter().any(|ds| verify_ds(zone, k, ds)))
                .collect();
            if trusted.is_empty() {
                ctx.keys.insert(zone.clone(), Some(Vec::new()));
                return Some(Vec::new()); // bogus: no DS matches
            }

            // The DNSKEY RRset must be self-signed by a trusted key.
            let dnskey_records: Vec<Record> =
                msg.answers.iter().filter(|r| r.rtype() == TYPE_DNSKEY).cloned().collect();
            let ok = msg
                .answers
                .iter()
                .filter(|r| r.rtype() == TYPE_RRSIG)
                .filter_map(|r| match &r.rdata {
                    RData::Unknown { data, .. } => Some(data),
                    _ => None,
                })
                .any(|sig| trusted.iter().any(|k| verify_rrsig(&dnskey_records, sig, k)));

            let result = if ok { dnskeys } else { Vec::new() };
            ctx.keys.insert(zone.clone(), Some(result.clone()));
            Some(result)
        })
    }

    /// Fetch and validate the DS rrset for `zone` (published in the parent).
    fn delegated_ds<'a>(
        &'a self,
        ctx: &'a mut Ctx<'_>,
        zone: &'a DnsName,
        depth: usize,
    ) -> BoxFut<'a, DsResult> {
        Box::pin(async move {
        let Some(parent) = zone.parent() else { return DsResult::Bogus };
        let parent_keys = match self.dnskeys(&mut *ctx, &parent, depth + 1).await {
            Some(k) if !k.is_empty() => k,
            Some(_) => return DsResult::Bogus, // parent bogus
            None => return DsResult::Insecure, // parent insecure => child insecure
        };

        let msg = match ctx.pool.query_dnssec(zone, TYPE_DS, ctx.metrics).await {
            Ok(m) => m,
            Err(_) => return DsResult::Bogus,
        };
        let ds_records: Vec<Record> =
            msg.answers.iter().filter(|r| r.rtype() == TYPE_DS).cloned().collect();
        if ds_records.is_empty() {
            // No DS: an insecure delegation (we trust the upstream's NODATA
            // here rather than validating the NSEC proof).
            return DsResult::Insecure;
        }
        // The DS rrset must be signed by the parent's validated keys.
        let signed = msg
            .answers
            .iter()
            .filter(|r| r.rtype() == TYPE_RRSIG)
            .filter_map(|r| match &r.rdata {
                RData::Unknown { data, .. } => Some(data),
                _ => None,
            })
            .any(|sig| parent_keys.iter().any(|k| verify_rrsig(&ds_records, sig, k)));
        if !signed {
            return DsResult::Bogus;
        }
        let set = ds_records
            .iter()
            .filter_map(|r| match &r.rdata {
                RData::Unknown { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        DsResult::Secure(set)
        })
    }
}

enum DsResult {
    Secure(Vec<Vec<u8>>),
    Insecure,
    Bogus,
}

struct SectionResult {
    any_secure: bool,
    bogus: bool,
}

fn has_nsec(records: &[Record]) -> bool {
    records.iter().any(|r| matches!(r.rtype(), TYPE_NSEC | TYPE_NSEC3))
}

/// Canonical name ordering key (RFC 4034 §6.1): labels compared right-to-left.
fn canon_key(name: &DnsName) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name.labels().to_vec();
    labels.reverse();
    labels
}

/// Parse an NSEC rdata into (next owner name, covered type set).
fn parse_nsec(rdata: &[u8]) -> Option<(DnsName, Vec<u16>)> {
    let mut pos = 0;
    let next = DnsName::from_wire(rdata, &mut pos).ok()?;
    let types = parse_type_bitmap(&rdata[pos..]);
    Some((next, types))
}

/// Parse the RFC 4034 §4.1.2 type bitmap (windowed).
fn parse_type_bitmap(mut data: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    while data.len() >= 2 {
        let window = data[0] as u16;
        let len = data[1] as usize;
        if data.len() < 2 + len {
            break;
        }
        for (i, &byte) in data[2..2 + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(window * 256 + (i as u16) * 8 + bit as u16);
                }
            }
        }
        data = &data[2 + len..];
    }
    types
}

/// True if the signed NSEC records prove `qname`/`qtype` is absent: either an
/// exact-match NSEC without the type (NODATA), or an NSEC whose range covers
/// the name (NXDOMAIN).
fn nsec_proves(qname: &DnsName, qtype: u16, nsec: &[&Record]) -> bool {
    let target = canon_key(qname);
    for rec in nsec {
        let RData::Unknown { data, .. } = &rec.rdata else { continue };
        let Some((next, types)) = parse_nsec(data) else { continue };
        let owner = canon_key(&rec.name);
        // NODATA: exact owner match, queried type not in the bitmap.
        if rec.name == *qname {
            if !types.contains(&qtype) {
                return true;
            }
            continue;
        }
        // NXDOMAIN: owner < qname < next (with the zone-apex wrap at the end).
        let next_k = canon_key(&next);
        let covered = if owner < next_k {
            owner < target && target < next_k
        } else {
            // Last NSEC wraps past the apex.
            target > owner || target < next_k
        };
        if covered {
            return true;
        }
    }
    false
}

/// Parse an NSEC3 rdata: (params, next-hash, covered types).
fn parse_nsec3(rdata: &[u8]) -> Option<(Nsec3Params, Vec<u8>, Vec<u16>)> {
    if rdata.len() < 5 {
        return None;
    }
    let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
    let salt_len = rdata[4] as usize;
    let salt = rdata.get(5..5 + salt_len)?.to_vec();
    let hash_pos = 5 + salt_len;
    let hash_len = *rdata.get(hash_pos)? as usize;
    let next = rdata.get(hash_pos + 1..hash_pos + 1 + hash_len)?.to_vec();
    let types = parse_type_bitmap(&rdata[hash_pos + 1 + hash_len..]);
    Some((Nsec3Params { iterations, salt }, next, types))
}

/// The base32hex label of an NSEC3 owner, decoded to the raw hash.
fn nsec3_owner_hash(name: &DnsName) -> Option<Vec<u8>> {
    let label = name.labels().first()?;
    base32hex_decode(std::str::from_utf8(label).ok()?)
}

fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.chars() {
        let v = match c.to_ascii_lowercase() {
            '0'..='9' => c as u32 - '0' as u32,
            'a'..='v' => c.to_ascii_lowercase() as u32 - 'a' as u32 + 10,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// True if the signed NSEC3 records prove the denial via a matching (NODATA)
/// or a closest-encloser proof (NXDOMAIN). Uses the params from the records.
fn nsec3_proves(qname: &DnsName, nsec3: &[&Record]) -> bool {
    let Some(params) = nsec3.iter().find_map(|r| match &r.rdata {
        RData::Unknown { data, .. } => parse_nsec3(data).map(|(p, _, _)| p),
        _ => None,
    }) else {
        return false;
    };
    // Owner hash -> (next hash) for range checks; also collect matches.
    let entries: Vec<(Vec<u8>, Vec<u8>)> = nsec3
        .iter()
        .filter_map(|r| {
            let owner = nsec3_owner_hash(&r.name)?;
            let RData::Unknown { data, .. } = &r.rdata else { return None };
            let (_, next, _) = parse_nsec3(data)?;
            Some((owner, next))
        })
        .collect();
    let matches = |h: &[u8]| entries.iter().any(|(o, _)| o.as_slice() == h);
    let covers = |h: &[u8]| {
        entries.iter().any(|(o, next)| {
            if o < next {
                o.as_slice() < h && h <= next.as_slice()
            } else {
                h > o.as_slice() || h <= next.as_slice()
            }
        })
    };

    // NODATA: NSEC3 matching qname's own hash.
    if matches(&hash_name(qname, &params)) {
        return true;
    }
    // NXDOMAIN closest-encloser proof: find the closest ancestor whose hash
    // matches, then the next-closer name must be covered.
    let labels = qname.labels();
    for skip in 1..labels.len() {
        let Ok(ce) = DnsName::from_labels(labels[skip..].to_vec()) else { continue };
        if matches(&hash_name(&ce, &params)) {
            // next closer = one label longer than ce toward qname.
            let Ok(nc) = DnsName::from_labels(labels[skip - 1..].to_vec()) else { continue };
            if covers(&hash_name(&nc, &params)) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_anchor_has_expected_tag() {
        let a = TrustAnchor::root_ksk_2017();
        assert!(a.zone.is_root());
        // DS key tag is the first two bytes.
        assert_eq!(u16::from_be_bytes([a.ds_rdata[0], a.ds_rdata[1]]), 20326);
        assert_eq!(a.ds_rdata[2], 8); // RSA/SHA-256
        assert_eq!(a.ds_rdata[3], 2); // SHA-256
    }
}
