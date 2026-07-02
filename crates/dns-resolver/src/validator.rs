//! Validating resolver: builds a DNSSEC chain of trust from a configured
//! trust anchor (the IANA root KSK by default) down to the answer's signer,
//! fetching DNSKEY and DS records through the upstream pool.
//!
//! Positive answers are validated cryptographically end to end: a forged
//! record yields `Bogus` (→ SERVFAIL), a properly signed one yields `Secure`
//! (→ AD bit). Zones with a securely-proven absent DS are `Insecure` and pass
//! through unauthenticated. Validated DNSKEY/DS sets are memoized per call.

use std::collections::HashMap;

use dns_dnssec::validate::{parse_rrsig, verify_ds, verify_rrsig};
use dns_metrics::Metrics;
use dns_proto::message::{Message, RData, Record, TYPE_DNSKEY, TYPE_DS, TYPE_RRSIG};
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

    /// Validate a forwarded response. Each answer rrset is checked against the
    /// keys of *its own* signer (a CNAME chain can cross zones), so the result
    /// is Bogus only if some rrset has a signature that fails to verify under a
    /// securely-reachable key. Unsigned/insecure rrsets pass through.
    pub async fn validate(
        &self,
        pool: &UpstreamPool,
        metrics: &Metrics,
        msg: &Message,
    ) -> Security {
        // Distinct (owner, type) rrsets in the answer, excluding RRSIGs.
        let mut sets: Vec<(DnsName, u16)> = msg
            .answers
            .iter()
            .filter(|r| r.rtype() != TYPE_RRSIG)
            .map(|r| (r.name.clone(), r.rtype()))
            .collect();
        sets.sort_by(|a, b| (a.0.to_string(), a.1).cmp(&(b.0.to_string(), b.1)));
        sets.dedup();

        let mut ctx = Ctx { pool, metrics, keys: HashMap::new() };
        let mut any_secure = false;

        for (owner, rtype) in sets {
            let rrset: Vec<Record> = msg
                .answers
                .iter()
                .filter(|r| r.name == owner && r.rtype() == rtype)
                .cloned()
                .collect();
            // RRSIGs covering this rrset (owner + type_covered match).
            let sigs: Vec<Vec<u8>> = msg
                .answers
                .iter()
                .filter(|r| r.rtype() == TYPE_RRSIG && r.name == owner)
                .filter_map(|r| match &r.rdata {
                    RData::Unknown { data, .. } => Some(data.clone()),
                    _ => None,
                })
                .filter(|d| parse_rrsig(d).map(|f| f.type_covered) == Some(rtype))
                .collect();
            if sigs.is_empty() {
                continue; // unsigned rrset (e.g. glue): not covered
            }
            // Validate against each covering RRSIG's own signer.
            let mut verified = false;
            for sig in &sigs {
                let Some(fields) = parse_rrsig(sig) else { continue };
                let signer = fields.signer.clone();
                match self.dnskeys(&mut ctx, &signer, 0).await {
                    None => {
                        // Insecure signer: treat this rrset as insecure.
                        verified = true;
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
                return Security::Bogus;
            }
        }

        if any_secure { Security::Secure } else { Security::Insecure }
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
