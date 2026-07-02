//! DNSSEC online signing with Ed25519 (algorithm 15, RFC 8080).
//!
//! A [`DnssecKey`] is a single combined signing key (KSK+ZSK, flags 257). At
//! [`SignedZone::sign`] time every RRset gets a precomputed RRSIG, an NSEC
//! chain is built for authenticated denial, and the apex DNSKEY is signed.
//! Serving then only looks signatures up — no per-query crypto.
//!
//! DNSKEY/RRSIG/NSEC/DS records are represented as [`RData::Unknown`] with
//! correctly-formed rdata: their embedded names must NOT be downcased (RFC
//! 6840 §5.1), which is exactly what verbatim rdata gives us.

use std::collections::HashMap;

use dns_proto::message::{CLASS_IN, RData, Record, TYPE_DNSKEY, TYPE_NSEC, TYPE_RRSIG};
use dns_proto::name::DnsName;
use dns_zone::Zone;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub const ALG_ED25519: u8 = 15;
const DNSKEY_FLAGS_KSK: u16 = 257;
const DIGEST_SHA256: u8 = 2;

pub struct DnssecKey {
    key_pair: Ed25519KeyPair,
    public: Vec<u8>,
    signer: DnsName,
    key_tag: u16,
}

impl DnssecKey {
    /// Fresh key; returns the 32-byte seed to persist (store it secretly).
    pub fn generate(signer: DnsName) -> Result<(Self, [u8; 32]), String> {
        let rng = SystemRandom::new();
        let seed = ring::rand::generate::<[u8; 32]>(&rng)
            .map_err(|_| "rng failure")?
            .expose();
        Ok((Self::from_seed(&seed, signer)?, seed))
    }

    pub fn from_seed(seed: &[u8; 32], signer: DnsName) -> Result<Self, String> {
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| "invalid Ed25519 seed")?;
        let public = key_pair.public_key().as_ref().to_vec();
        let key_tag = key_tag(&dnskey_rdata(DNSKEY_FLAGS_KSK, &public));
        Ok(DnssecKey { key_pair, public, signer, key_tag })
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    fn dnskey_record(&self, ttl: u32) -> Record {
        Record {
            name: self.signer.clone(),
            class: CLASS_IN,
            ttl,
            rdata: RData::Unknown {
                rtype: TYPE_DNSKEY,
                data: dnskey_rdata(DNSKEY_FLAGS_KSK, &self.public),
            },
        }
    }

    /// Human-readable DS presentation (SHA-256) for uploading to the parent.
    pub fn ds_presentation(&self) -> String {
        let mut digest_input = Vec::new();
        self.signer.to_wire(&mut digest_input, None);
        digest_input.extend_from_slice(&dnskey_rdata(DNSKEY_FLAGS_KSK, &self.public));
        let digest = ring::digest::digest(&ring::digest::SHA256, &digest_input);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        format!("{} IN DS {} {} {} {}", self.signer, self.key_tag, ALG_ED25519, DIGEST_SHA256, hex)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key_pair.sign(data).as_ref().to_vec()
    }
}

fn dnskey_rdata(flags: u16, public: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(4 + public.len());
    d.extend_from_slice(&flags.to_be_bytes());
    d.push(3); // protocol
    d.push(ALG_ED25519);
    d.extend_from_slice(public);
    d
}

/// RFC 4034 Appendix B key tag for non-RSA/MD5 algorithms.
fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 { (b as u32) << 8 } else { b as u32 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// A zone with precomputed DNSSEC material.
pub struct SignedZone {
    pub origin: DnsName,
    rrsigs: HashMap<(DnsName, u16), Record>,
    /// Canonical-ordered NSEC chain: owner -> (NSEC record, its RRSIG).
    nsec: Vec<(DnsName, Record, Record)>,
    dnskey_rrset: Vec<Record>,
    dnskey_rrsig: Record,
}

impl SignedZone {
    pub fn dnskey_records(&self) -> (&[Record], &Record) {
        (&self.dnskey_rrset, &self.dnskey_rrsig)
    }

    /// RRSIG covering the (owner, type) rrset, if any.
    pub fn rrsig_for(&self, owner: &DnsName, rtype: u16) -> Option<&Record> {
        self.rrsigs.get(&(owner.clone(), rtype))
    }

    /// NSEC (and its RRSIG) proving `qname` does not exist: the record whose
    /// owner is the greatest name canonically <= qname (wraps to apex).
    pub fn covering_nsec(&self, qname: &DnsName) -> Option<(&Record, &Record)> {
        let target = canonical_key(qname);
        let mut best: Option<&(DnsName, Record, Record)> = None;
        for entry in &self.nsec {
            if canonical_key(&entry.0) <= target {
                best = Some(entry);
            } else {
                break;
            }
        }
        let entry = best.or_else(|| self.nsec.last())?;
        Some((&entry.1, &entry.2))
    }

    /// NSEC proving `owner` exists but lacks the queried type (NODATA).
    pub fn exact_nsec(&self, owner: &DnsName) -> Option<(&Record, &Record)> {
        self.nsec
            .iter()
            .find(|(name, _, _)| name == owner)
            .map(|(_, nsec, rrsig)| (nsec, rrsig))
    }

    /// Sign `zone` with `key`. Signatures are valid from `now - 3600` to
    /// `now + validity_secs`.
    pub fn sign(zone: &Zone, key: &DnssecKey, now: u64, validity_secs: u64) -> Self {
        let inception = now.saturating_sub(3600) as u32;
        let expiration = (now + validity_secs) as u32;
        let apex_ttl = zone.soa.ttl;

        let mut groups: HashMap<(DnsName, u16), Vec<Record>> = HashMap::new();
        for r in zone.all_records() {
            groups.entry((r.name.clone(), r.rtype())).or_default().push(r);
        }

        let mut rrsigs = HashMap::new();
        for ((owner, rtype), rrset) in &groups {
            rrsigs.insert(
                (owner.clone(), *rtype),
                sign_rrset(key, owner, *rtype, rrset, inception, expiration),
            );
        }

        let mut owners: Vec<DnsName> = groups.keys().map(|(n, _)| n.clone()).collect();
        owners.sort_by(|a, b| canonical_key(a).cmp(&canonical_key(b)));
        owners.dedup();

        let mut nsec = Vec::with_capacity(owners.len());
        for i in 0..owners.len() {
            let owner = &owners[i];
            let next = &owners[(i + 1) % owners.len()]; // wraps to apex
            let mut types: Vec<u16> =
                groups.keys().filter(|(n, _)| n == owner).map(|(_, t)| *t).collect();
            types.push(TYPE_RRSIG);
            types.push(TYPE_NSEC);
            if *owner == zone.origin {
                types.push(TYPE_DNSKEY);
            }
            types.sort_unstable();
            types.dedup();

            let nsec_rec = Record {
                name: owner.clone(),
                class: CLASS_IN,
                ttl: apex_ttl,
                rdata: RData::Unknown { rtype: TYPE_NSEC, data: nsec_rdata(next, &types) },
            };
            let rrsig = sign_rrset(
                key,
                owner,
                TYPE_NSEC,
                std::slice::from_ref(&nsec_rec),
                inception,
                expiration,
            );
            nsec.push((owner.clone(), nsec_rec, rrsig));
        }

        let dnskey_rrset = vec![key.dnskey_record(apex_ttl)];
        let dnskey_rrsig =
            sign_rrset(key, &zone.origin, TYPE_DNSKEY, &dnskey_rrset, inception, expiration);

        SignedZone { origin: zone.origin.clone(), rrsigs, nsec, dnskey_rrset, dnskey_rrsig }
    }
}

/// Build and sign the RRSIG covering one rrset.
fn sign_rrset(
    key: &DnssecKey,
    owner: &DnsName,
    rtype: u16,
    rrset: &[Record],
    inception: u32,
    expiration: u32,
) -> Record {
    let original_ttl = rrset[0].ttl;
    let labels = owner.label_count() as u8; // no wildcards signed yet

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&rtype.to_be_bytes());
    prefix.push(ALG_ED25519);
    prefix.push(labels);
    prefix.extend_from_slice(&original_ttl.to_be_bytes());
    prefix.extend_from_slice(&expiration.to_be_bytes());
    prefix.extend_from_slice(&inception.to_be_bytes());
    prefix.extend_from_slice(&key.key_tag.to_be_bytes());
    key.signer.to_wire(&mut prefix, None);

    // Canonical rrset: each RR in canonical form, sorted by rdata (RFC 4034
    // §6.3).
    let mut canon: Vec<Vec<u8>> = rrset
        .iter()
        .map(|r| {
            let mut b = Vec::new();
            r.encode_canonical(&mut b, original_ttl);
            b
        })
        .collect();
    canon.sort();

    let mut to_sign = prefix.clone();
    for rr in &canon {
        to_sign.extend_from_slice(rr);
    }
    let signature = key.sign(&to_sign);

    let mut rdata = prefix;
    rdata.extend_from_slice(&signature);
    Record {
        name: owner.clone(),
        class: CLASS_IN,
        ttl: original_ttl,
        rdata: RData::Unknown { rtype: TYPE_RRSIG, data: rdata },
    }
}

/// NSEC rdata: next owner name (uncompressed) + type bitmap (window 0 only;
/// every type we serve is < 256).
fn nsec_rdata(next: &DnsName, types: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    next.to_wire(&mut out, None);
    let max_type = types.iter().copied().max().unwrap_or(0);
    let mut bitmap = vec![0u8; (max_type as usize / 8) + 1];
    for &t in types {
        bitmap[t as usize / 8] |= 0x80 >> (t as usize % 8);
    }
    out.push(0); // window block 0
    out.push(bitmap.len() as u8);
    out.extend_from_slice(&bitmap);
    out
}

/// Canonical name ordering key (RFC 4034 §6.1): compare label sequences
/// right-to-left. Labels are already lowercased in `DnsName`.
fn canonical_key(name: &DnsName) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name.labels().to_vec();
    labels.reverse();
    labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_zone::parse_zone_file;
    use ring::signature;

    const ZONE: &str = "\
$ORIGIN example.dnssec.
$TTL 300
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@    IN NS  ns1
ns1  IN A   10.0.0.1
www  IN A   10.0.0.10
www  IN A   10.0.0.11
mail IN A   10.0.0.20
";

    fn signed() -> (SignedZone, DnssecKey) {
        let zone = parse_zone_file(ZONE).unwrap();
        let key = DnssecKey::from_seed(&[7u8; 32], zone.origin.clone()).unwrap();
        (SignedZone::sign(&zone, &key, 1_700_000_000, 1_209_600), key)
    }

    #[test]
    fn key_tag_stable_and_nonzero() {
        let s = DnsName::parse_str("x.").unwrap();
        let k1 = DnssecKey::from_seed(&[7u8; 32], s.clone()).unwrap();
        let k2 = DnssecKey::from_seed(&[7u8; 32], s).unwrap();
        assert_ne!(k1.key_tag(), 0);
        assert_eq!(k1.key_tag(), k2.key_tag());
    }

    #[test]
    fn rrsig_verifies_with_ring() {
        let (sz, key) = signed();
        let owner = DnsName::parse_str("www.example.dnssec").unwrap();
        let rrsig = sz.rrsig_for(&owner, dns_proto::message::TYPE_A).expect("A signed");
        let RData::Unknown { data, .. } = &rrsig.rdata else { panic!() };
        let (prefix, sig) = data.split_at(data.len() - 64); // Ed25519 sig = 64 bytes

        let zone = parse_zone_file(ZONE).unwrap();
        let rrset: Vec<Record> = zone
            .all_records()
            .into_iter()
            .filter(|r| r.name == owner && r.rtype() == 1)
            .collect();
        assert_eq!(rrset.len(), 2);
        let mut canon: Vec<Vec<u8>> = rrset
            .iter()
            .map(|r| {
                let mut b = Vec::new();
                r.encode_canonical(&mut b, 300);
                b
            })
            .collect();
        canon.sort();
        let mut to_verify = prefix.to_vec();
        for rr in &canon {
            to_verify.extend_from_slice(rr);
        }
        let pubkey = signature::UnparsedPublicKey::new(&signature::ED25519, &key.public);
        assert!(pubkey.verify(&to_verify, sig).is_ok(), "RRSIG must verify");
    }

    #[test]
    fn nsec_chain_ordered_and_covers_gaps() {
        let (sz, _) = signed();
        assert!(!sz.nsec.is_empty());
        for w in sz.nsec.windows(2) {
            assert!(canonical_key(&w[0].0) < canonical_key(&w[1].0));
        }
        let q = DnsName::parse_str("nope.example.dnssec").unwrap();
        assert!(sz.covering_nsec(&q).is_some());
    }

    #[test]
    fn ds_presentation_has_key_tag_and_alg() {
        let (_, key) = signed();
        let ds = key.ds_presentation();
        assert!(ds.contains(&format!("DS {}", key.key_tag())));
        assert!(ds.contains(" 15 2 "));
    }
}
