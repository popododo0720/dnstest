//! NSEC3 hashed authenticated denial of existence (RFC 5155).
//!
//! Builds the hashed chain at signing time and answers the two proofs a
//! validator needs: a matching NSEC3 (name exists / NODATA) and a covering
//! NSEC3 (name falls in a gap). NXDOMAIN uses the closest-encloser proof:
//! match the closest encloser, cover the next-closer name, and cover the
//! wildcard at the closest encloser.

use dns_proto::message::{CLASS_IN, RData, Record, TYPE_NSEC3};
use dns_proto::name::DnsName;

pub const HASH_SHA1: u8 = 1;

/// NSEC3 parameters for a zone.
#[derive(Clone)]
pub struct Nsec3Params {
    pub iterations: u16,
    pub salt: Vec<u8>,
}

/// Iterated SHA-1 hash of a name (RFC 5155 §5). Input name is lowercased
/// canonical wire form.
pub fn hash_name(name: &DnsName, params: &Nsec3Params) -> Vec<u8> {
    let mut wire = Vec::new();
    name.to_wire(&mut wire, None);
    let mut digest = sha1(&[wire.as_slice(), params.salt.as_slice()].concat());
    for _ in 0..params.iterations {
        digest = sha1(&[digest.as_slice(), params.salt.as_slice()].concat());
    }
    digest
}

fn sha1(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref().to_vec()
}

/// RFC 4648 base32hex, lowercase, no padding — the NSEC3 owner label form.
pub fn base32hex(data: &[u8]) -> String {
    const A: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

/// NSEC3 rdata (RFC 5155 §3.2).
pub fn nsec3_rdata(
    params: &Nsec3Params,
    next_hash: &[u8],
    types: &[u16],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(HASH_SHA1);
    out.push(0); // flags (opt-out off)
    out.extend_from_slice(&params.iterations.to_be_bytes());
    out.push(params.salt.len() as u8);
    out.extend_from_slice(&params.salt);
    out.push(next_hash.len() as u8);
    out.extend_from_slice(next_hash);
    // Type bitmap (window 0 covers all types we serve).
    let max_type = types.iter().copied().max().unwrap_or(0);
    let mut bitmap = vec![0u8; (max_type as usize / 8) + 1];
    for &t in types {
        bitmap[t as usize / 8] |= 0x80 >> (t as usize % 8);
    }
    out.push(0);
    out.push(bitmap.len() as u8);
    out.extend_from_slice(&bitmap);
    out
}

/// NSEC3PARAM rdata for the apex.
pub fn nsec3param_rdata(params: &Nsec3Params) -> Vec<u8> {
    let mut out = vec![HASH_SHA1, 0];
    out.extend_from_slice(&params.iterations.to_be_bytes());
    out.push(params.salt.len() as u8);
    out.extend_from_slice(&params.salt);
    out
}

/// One entry of the hashed chain, before RRSIGs are attached.
pub struct Nsec3Node {
    pub hash: Vec<u8>,
    pub owner: DnsName,
    pub record: Record,
}

/// Build the sorted NSEC3 chain for the given owner names + their type maps.
/// `apex` is the zone origin; `ttl` the SOA-derived TTL.
pub fn build_chain(
    apex: &DnsName,
    owner_types: &[(DnsName, Vec<u16>)],
    params: &Nsec3Params,
    ttl: u32,
) -> Vec<Nsec3Node> {
    // Hash every owner, remember its type list.
    let mut hashed: Vec<(Vec<u8>, Vec<u16>)> = owner_types
        .iter()
        .map(|(name, types)| (hash_name(name, params), types.clone()))
        .collect();
    hashed.sort_by(|a, b| a.0.cmp(&b.0));
    hashed.dedup_by(|a, b| a.0 == b.0);

    let n = hashed.len();
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let (hash, types) = &hashed[i];
        let next = &hashed[(i + 1) % n].0; // wraps to the first hash
        let owner_label = base32hex(hash);
        let owner = DnsName::parse_str(&format!("{owner_label}.{apex}")).unwrap();
        let record = Record {
            name: owner.clone(),
            class: CLASS_IN,
            ttl,
            rdata: RData::Unknown { rtype: TYPE_NSEC3, data: nsec3_rdata(params, next, types) },
        };
        nodes.push(Nsec3Node { hash: hash.clone(), owner, record });
    }
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32hex_known_vectors() {
        // RFC 4648 base32hex test vectors.
        assert_eq!(base32hex(b"f"), "co");
        assert_eq!(base32hex(b"fo"), "cpng");
        assert_eq!(base32hex(b"foo"), "cpnmu");
    }

    #[test]
    fn hash_is_deterministic_and_iterates() {
        let name = DnsName::parse_str("www.example.").unwrap();
        let p0 = Nsec3Params { iterations: 0, salt: vec![0xAB, 0xCD] };
        let p1 = Nsec3Params { iterations: 5, salt: vec![0xAB, 0xCD] };
        assert_eq!(hash_name(&name, &p0), hash_name(&name, &p0));
        assert_ne!(hash_name(&name, &p0), hash_name(&name, &p1));
        assert_eq!(hash_name(&name, &p0).len(), 20); // SHA-1
    }
}
