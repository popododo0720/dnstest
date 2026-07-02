//! DNSSEC signature validation (verifier side).
//!
//! Verifies RRSIGs against DNSKEYs and DS records against DNSKEYs, for the
//! algorithms in current use: RSA/SHA-256 (8), ECDSA P-256 (13), ECDSA P-384
//! (14), and Ed25519 (15). These are the primitives a validating resolver
//! composes into a chain of trust.

use dns_proto::message::Record;
use dns_proto::name::DnsName;
use ring::signature;

pub const ALG_RSASHA1: u8 = 5;
pub const ALG_RSASHA1_NSEC3: u8 = 7;
pub const ALG_RSASHA256: u8 = 8;
pub const ALG_RSASHA512: u8 = 10;
pub const ALG_ECDSAP256: u8 = 13;
pub const ALG_ECDSAP384: u8 = 14;
pub const ALG_ED25519: u8 = 15;

/// Parsed RRSIG rdata fields (RFC 4034 §3.1).
pub struct RrsigFields {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: DnsName,
    /// RRSIG rdata up to (not including) the signature — the digest prefix.
    pub prefix: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn parse_rrsig(rdata: &[u8]) -> Option<RrsigFields> {
    if rdata.len() < 18 {
        return None;
    }
    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
    let mut pos = 18;
    let signer = DnsName::from_wire(rdata, &mut pos).ok()?;
    let prefix = rdata[..pos].to_vec();
    let signature = rdata[pos..].to_vec();
    Some(RrsigFields {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
        prefix,
        signature,
    })
}

/// Parsed DNSKEY rdata (RFC 4034 §2.1).
pub struct DnskeyFields<'a> {
    pub flags: u16,
    pub algorithm: u8,
    pub public: &'a [u8],
}

pub fn parse_dnskey(rdata: &[u8]) -> Option<DnskeyFields<'_>> {
    if rdata.len() < 4 {
        return None;
    }
    Some(DnskeyFields {
        flags: u16::from_be_bytes([rdata[0], rdata[1]]),
        algorithm: rdata[3],
        public: &rdata[4..],
    })
}

/// RFC 4034 Appendix B key tag.
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in dnskey_rdata.iter().enumerate() {
        ac += if i & 1 == 0 { (b as u32) << 8 } else { b as u32 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// The bytes covered by an RRSIG: the RRSIG prefix followed by the RRset in
/// canonical form and order (RFC 4034 §6). Owner names use the wildcard form
/// when the RRSIG `labels` count is shorter than the owner (RFC 4035 §5.3.2).
fn signed_data(fields: &RrsigFields, rrset: &[Record]) -> Vec<u8> {
    let mut canon: Vec<Vec<u8>> = rrset
        .iter()
        .map(|r| {
            let owner = wildcard_owner(&r.name, fields.labels);
            let mut rec = r.clone();
            rec.name = owner;
            let mut b = Vec::new();
            rec.encode_canonical(&mut b, fields.original_ttl);
            b
        })
        .collect();
    canon.sort();

    let mut data = fields.prefix.clone();
    for rr in &canon {
        data.extend_from_slice(rr);
    }
    data
}

/// Collapse an owner to `*.<suffix>` when the RRSIG labels count indicates a
/// wildcard expansion; otherwise return it unchanged.
fn wildcard_owner(owner: &DnsName, rrsig_labels: u8) -> DnsName {
    let n = owner.label_count();
    if (rrsig_labels as usize) >= n {
        return owner.clone();
    }
    let skip = n - rrsig_labels as usize;
    owner.wildcard_at(skip).unwrap_or_else(|| owner.clone())
}

/// Verify an RRSIG over `rrset` using the DNSKEY rdata. Does not check timing
/// (the caller decides how strict to be about clock skew).
pub fn verify_rrsig(rrset: &[Record], rrsig_rdata: &[u8], dnskey_rdata: &[u8]) -> bool {
    let Some(fields) = parse_rrsig(rrsig_rdata) else { return false };
    let Some(key) = parse_dnskey(dnskey_rdata) else { return false };
    if fields.algorithm != key.algorithm {
        return false;
    }
    if fields.key_tag != key_tag(dnskey_rdata) {
        return false;
    }
    let data = signed_data(&fields, rrset);
    verify_signature(key.algorithm, key.public, &data, &fields.signature)
}

/// Raw signature check dispatched by DNSSEC algorithm number.
pub fn verify_signature(algorithm: u8, public: &[u8], data: &[u8], sig: &[u8]) -> bool {
    match algorithm {
        ALG_ED25519 => {
            signature::UnparsedPublicKey::new(&signature::ED25519, public)
                .verify(data, sig)
                .is_ok()
        }
        ALG_ECDSAP256 | ALG_ECDSAP384 => {
            // DNSKEY carries the bare point X||Y; ring wants 0x04||X||Y.
            let mut point = Vec::with_capacity(public.len() + 1);
            point.push(0x04);
            point.extend_from_slice(public);
            let alg = if algorithm == ALG_ECDSAP256 {
                &signature::ECDSA_P256_SHA256_FIXED
            } else {
                &signature::ECDSA_P384_SHA384_FIXED
            };
            signature::UnparsedPublicKey::new(alg, &point).verify(data, sig).is_ok()
        }
        // RSA (RFC 3110). Use the 1024-bit-tolerant legacy verifiers: several
        // TLD zones (notably .org) still sign delegations with 1024-bit ZSKs.
        ALG_RSASHA1 | ALG_RSASHA1_NSEC3 | ALG_RSASHA256 | ALG_RSASHA512 => {
            let Some((n, e)) = rsa_parts(public) else { return false };
            let params = match algorithm {
                ALG_RSASHA1 | ALG_RSASHA1_NSEC3 => {
                    &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                }
                ALG_RSASHA512 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                _ => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            };
            signature::RsaPublicKeyComponents { n, e }.verify(params, data, sig).is_ok()
        }
        _ => false, // unsupported algorithm: treat as bogus
    }
}

/// Split an RFC 3110 RSA public key (exponent length, exponent, modulus).
fn rsa_parts(public: &[u8]) -> Option<(&[u8], &[u8])> {
    if public.is_empty() {
        return None;
    }
    let (exp_len, off) = if public[0] == 0 {
        (u16::from_be_bytes([*public.get(1)?, *public.get(2)?]) as usize, 3)
    } else {
        (public[0] as usize, 1)
    };
    let e = public.get(off..off + exp_len)?;
    let n = public.get(off + exp_len..)?;
    Some((n, e))
}

/// Verify that a DS record matches a DNSKEY (RFC 4034 §5). Supports SHA-1 (1)
/// and SHA-256 (2) digests.
pub fn verify_ds(owner: &DnsName, dnskey_rdata: &[u8], ds_rdata: &[u8]) -> bool {
    if ds_rdata.len() < 4 {
        return false;
    }
    let ds_key_tag = u16::from_be_bytes([ds_rdata[0], ds_rdata[1]]);
    let ds_alg = ds_rdata[2];
    let digest_type = ds_rdata[3];
    let ds_digest = &ds_rdata[4..];

    let Some(key) = parse_dnskey(dnskey_rdata) else { return false };
    if ds_key_tag != key_tag(dnskey_rdata) || ds_alg != key.algorithm {
        return false;
    }
    let mut input = Vec::new();
    owner.to_wire(&mut input, None);
    input.extend_from_slice(dnskey_rdata);
    let digest = match digest_type {
        1 => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input),
        2 => ring::digest::digest(&ring::digest::SHA256, &input),
        _ => return false,
    };
    digest.as_ref() == ds_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ALG_ECDSAP256, ALG_ED25519, DnssecKey, SignedZone};
    use dns_proto::message::{RData, Record, TYPE_A};
    use dns_zone::parse_zone_file;

    const ZONE: &str = "\
$ORIGIN v.test.
$TTL 300
@    IN SOA ns h 1 2 3 4 300
@    IN NS ns
ns   IN A 10.0.0.1
www  IN A 10.0.0.10
www  IN A 10.0.0.11
";

    fn dnskey_rdata_of(sz: &SignedZone) -> Vec<u8> {
        let (rrset, _) = sz.dnskey_records();
        match &rrset[0].rdata {
            RData::Unknown { data, .. } => data.clone(),
            _ => panic!(),
        }
    }

    fn check_alg(alg: u8) {
        let zone = parse_zone_file(ZONE).unwrap();
        let (key, _) = DnssecKey::generate(zone.origin.clone(), alg, true).unwrap();
        let sz = SignedZone::sign(&zone, std::slice::from_ref(&key), 1_700_000_000, 1_209_600, None);
        let dnskey = dnskey_rdata_of(&sz);

        let www = DnsName::parse_str("www.v.test").unwrap();
        let rrset: Vec<Record> =
            zone.all_records().into_iter().filter(|r| r.name == www && r.rtype() == TYPE_A).collect();
        let rrsig = sz.rrsigs_for(&www, TYPE_A);
        let RData::Unknown { data: sig_rdata, .. } = &rrsig[0].rdata else { panic!() };

        assert!(verify_rrsig(&rrset, sig_rdata, &dnskey), "alg {alg} must verify");
        // Tamper the signature -> reject.
        let mut bad = sig_rdata.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(!verify_rrsig(&rrset, &bad, &dnskey), "alg {alg} tampered must fail");
    }

    #[test]
    fn verifies_ecdsa_and_ed25519() {
        check_alg(ALG_ECDSAP256);
        check_alg(ALG_ED25519);
    }

    #[test]
    fn verifies_rsa() {
        check_alg(crate::ALG_RSASHA256); // generates a 2048-bit RSA key, signs, verifies
    }

    #[test]
    fn ds_matches_generated_key() {
        let zone = parse_zone_file(ZONE).unwrap();
        let (key, _) = DnssecKey::generate(zone.origin.clone(), ALG_ED25519, true).unwrap();
        // Build the DS from the presentation and check it matches the DNSKEY.
        let sz = SignedZone::sign(&zone, std::slice::from_ref(&key), 1_700_000_000, 1_209_600, None);
        let dnskey = dnskey_rdata_of(&sz);
        // DS rdata: key_tag(2) alg(1) digest_type=2(1) sha256(dnskey).
        let mut input = Vec::new();
        zone.origin.to_wire(&mut input, None);
        input.extend_from_slice(&dnskey);
        let digest = ring::digest::digest(&ring::digest::SHA256, &input);
        let mut ds = Vec::new();
        ds.extend_from_slice(&key.key_tag().to_be_bytes());
        ds.push(ALG_ED25519);
        ds.push(2);
        ds.extend_from_slice(digest.as_ref());
        assert!(verify_ds(&zone.origin, &dnskey, &ds));
        // Wrong digest -> reject.
        let mut bad = ds.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert!(!verify_ds(&zone.origin, &dnskey, &bad));
    }
}
