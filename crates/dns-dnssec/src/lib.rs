//! DNSSEC online signing (RFC 4034/4035, 5702, 6605, 8080).
//!
//! Signing algorithms: ECDSA P-256/SHA-256 (13) and Ed25519 (15) — the two
//! algorithms RFC 8624 recommends for signing, both generatable by `ring`.
//! Multiple keys are supported for KSK/ZSK separation and pre-publish key
//! rollover: the DNSKEY RRset is signed by every SEP (KSK) key, zone data by
//! every non-SEP (ZSK) key, and a combined key signs both.
//!
//! DNSKEY/RRSIG/NSEC records are represented as [`RData::Unknown`] with
//! correctly-formed rdata; their embedded names must NOT be downcased (RFC
//! 6840 §5.1), which is exactly what verbatim rdata gives us.

pub mod nsec3;
pub mod validate;

use std::collections::HashMap;

use dns_proto::message::{
    CLASS_IN, RData, Record, TYPE_DNSKEY, TYPE_NSEC, TYPE_NSEC3, TYPE_NSEC3PARAM, TYPE_RRSIG,
};
use dns_proto::name::DnsName;
use nsec3::{Nsec3Params, hash_name};
use dns_zone::Zone;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};

pub const ALG_RSASHA256: u8 = 8;
pub const ALG_ECDSAP256: u8 = 13;
pub const ALG_ED25519: u8 = 15;

const FLAG_ZONE_KEY: u16 = 0x0100; // bit 7
const FLAG_SEP: u16 = 0x0001; // bit 15 (KSK)
const DIGEST_SHA256: u8 = 2;
const RSA_BITS: usize = 2048;

enum Material {
    Ed25519(Ed25519KeyPair),
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

/// A single DNSSEC key: algorithm, role (KSK/ZSK), and signing material.
pub struct DnssecKey {
    material: Material,
    algorithm: u8,
    /// DNSKEY flags: 257 = KSK/SEP, 256 = ZSK.
    flags: u16,
    public: Vec<u8>,
    signer: DnsName,
    key_tag: u16,
}

impl DnssecKey {
    /// Generate a key of `algorithm`; `ksk` sets the SEP flag. Returns the key
    /// and its persistable material (`alg:base64`).
    pub fn generate(signer: DnsName, algorithm: u8, ksk: bool) -> Result<(Self, String), String> {
        let rng = SystemRandom::new();
        let (material, secret, public) = match algorithm {
            ALG_ED25519 => {
                let seed = ring::rand::generate::<[u8; 32]>(&rng).map_err(|_| "rng")?.expose();
                let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| "ed25519")?;
                let public = kp.public_key().as_ref().to_vec();
                (Material::Ed25519(kp), seed.to_vec(), public)
            }
            ALG_ECDSAP256 => {
                let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).map_err(|_| "ecdsa gen")?;
                let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng)
                    .map_err(|_| "ecdsa load")?;
                // ring gives 0x04||X||Y; DNSKEY wants the bare X||Y.
                let public = kp.public_key().as_ref()[1..].to_vec();
                (Material::Ecdsa(kp), pkcs8.as_ref().to_vec(), public)
            }
            ALG_RSASHA256 => {
                // ring cannot generate RSA keys; use the `rsa` crate, then
                // load the PKCS#8 into ring for signing.
                use rsa::pkcs8::EncodePrivateKey;
                use rsa::traits::PublicKeyParts;
                let mut osrng = rand::rngs::OsRng;
                let priv_key = rsa::RsaPrivateKey::new(&mut osrng, RSA_BITS)
                    .map_err(|e| format!("rsa gen: {e}"))?;
                let pkcs8 = priv_key.to_pkcs8_der().map_err(|e| format!("rsa pkcs8: {e}"))?;
                let der = pkcs8.as_bytes().to_vec();
                let kp = RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("rsa load: {e}"))?;
                let public = rsa_dnskey_public(&priv_key.e().to_bytes_be(), &priv_key.n().to_bytes_be());
                (Material::Rsa(kp), der, public)
            }
            other => return Err(format!("unsupported signing algorithm {other}")),
        };
        let key = Self::finish(material, algorithm, ksk, signer, public);
        Ok((key, format!("{algorithm}:{}", b64(&secret))))
    }

    /// Load from the `alg:base64` material produced by [`generate`].
    pub fn from_material(signer: DnsName, encoded: &str, ksk: bool) -> Result<Self, String> {
        let (alg_str, b64s) = encoded.split_once(':').ok_or("expected alg:base64")?;
        let algorithm: u8 = alg_str.parse().map_err(|_| "bad algorithm number")?;
        let secret = unb64(b64s).ok_or("bad base64 material")?;
        let rng = SystemRandom::new();
        let (material, public) = match algorithm {
            ALG_ED25519 => {
                let seed: [u8; 32] =
                    secret.as_slice().try_into().map_err(|_| "seed must be 32 bytes")?;
                let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| "ed25519")?;
                let public = kp.public_key().as_ref().to_vec();
                (Material::Ed25519(kp), public)
            }
            ALG_ECDSAP256 => {
                let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
                let kp = EcdsaKeyPair::from_pkcs8(alg, &secret, &rng).map_err(|_| "ecdsa pkcs8")?;
                let public = kp.public_key().as_ref()[1..].to_vec();
                (Material::Ecdsa(kp), public)
            }
            ALG_RSASHA256 => {
                use rsa::pkcs8::DecodePrivateKey;
                use rsa::traits::PublicKeyParts;
                let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(&secret)
                    .map_err(|e| format!("rsa pkcs8: {e}"))?;
                let kp = RsaKeyPair::from_pkcs8(&secret).map_err(|e| format!("rsa load: {e}"))?;
                let public =
                    rsa_dnskey_public(&priv_key.e().to_bytes_be(), &priv_key.n().to_bytes_be());
                (Material::Rsa(kp), public)
            }
            other => return Err(format!("unsupported signing algorithm {other}")),
        };
        Ok(Self::finish(material, algorithm, ksk, signer, public))
    }

    fn finish(
        material: Material,
        algorithm: u8,
        ksk: bool,
        signer: DnsName,
        public: Vec<u8>,
    ) -> Self {
        let flags = FLAG_ZONE_KEY | if ksk { FLAG_SEP } else { 0 };
        let key_tag = key_tag(&dnskey_rdata(flags, algorithm, &public));
        DnssecKey { material, algorithm, flags, public, signer, key_tag }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn is_ksk(&self) -> bool {
        self.flags & FLAG_SEP != 0
    }

    fn dnskey_record(&self, ttl: u32) -> Record {
        Record {
            name: self.signer.clone(),
            class: CLASS_IN,
            ttl,
            rdata: RData::Unknown {
                rtype: TYPE_DNSKEY,
                data: dnskey_rdata(self.flags, self.algorithm, &self.public),
            },
        }
    }

    /// DS presentation (SHA-256) for uploading to the parent.
    pub fn ds_presentation(&self) -> String {
        let mut input = Vec::new();
        self.signer.to_wire(&mut input, None);
        input.extend_from_slice(&dnskey_rdata(self.flags, self.algorithm, &self.public));
        let digest = ring::digest::digest(&ring::digest::SHA256, &input);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        format!("{} IN DS {} {} {DIGEST_SHA256} {hex}", self.signer, self.key_tag, self.algorithm)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.material {
            Material::Ed25519(kp) => kp.sign(data).as_ref().to_vec(),
            Material::Ecdsa(kp) => {
                kp.sign(&rng, data).map(|s| s.as_ref().to_vec()).unwrap_or_default()
            }
            Material::Rsa(kp) => {
                let mut sig = vec![0u8; kp.public().modulus_len()];
                match kp.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, data, &mut sig) {
                    Ok(()) => sig,
                    Err(_) => Vec::new(),
                }
            }
        }
    }
}

/// RFC 3110 RSA public key in DNSKEY form: exponent length, exponent, modulus.
fn rsa_dnskey_public(exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if exp.len() <= 255 {
        out.push(exp.len() as u8);
    } else {
        out.push(0);
        out.extend_from_slice(&(exp.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(exp);
    out.extend_from_slice(modulus);
    out
}

fn dnskey_rdata(flags: u16, algorithm: u8, public: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(4 + public.len());
    d.extend_from_slice(&flags.to_be_bytes());
    d.push(3); // protocol
    d.push(algorithm);
    d.extend_from_slice(public);
    d
}

/// RFC 4034 Appendix B key tag (algorithms other than 1).
fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 { (b as u32) << 8 } else { b as u32 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// Authenticated-denial strategy for a signed zone.
enum Denial {
    /// NSEC chain: (owner, NSEC record, RRSIGs), canonically ordered.
    Nsec(Vec<(DnsName, Record, Vec<Record>)>),
    /// NSEC3 chain plus the set of existing owner names (for closest-encloser).
    Nsec3 {
        params: Nsec3Params,
        /// (hash, NSEC3 record, RRSIGs), ordered by hash.
        nodes: Vec<(Vec<u8>, Record, Vec<Record>)>,
        names: Vec<DnsName>,
    },
}

/// A zone with precomputed DNSSEC material. Multiple RRSIGs per rrset support
/// key rollover (each active ZSK contributes one signature).
pub struct SignedZone {
    pub origin: DnsName,
    rrsigs: HashMap<(DnsName, u16), Vec<Record>>,
    denial: Denial,
    dnskey_rrset: Vec<Record>,
    dnskey_rrsigs: Vec<Record>,
    /// NSEC3PARAM record (present only in NSEC3 mode).
    nsec3param: Option<Record>,
}

impl SignedZone {
    pub fn dnskey_records(&self) -> (&[Record], &[Record]) {
        (&self.dnskey_rrset, &self.dnskey_rrsigs)
    }

    pub fn rrsigs_for(&self, owner: &DnsName, rtype: u16) -> &[Record] {
        self.rrsigs.get(&(owner.clone(), rtype)).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn nsec3param(&self) -> Option<&Record> {
        self.nsec3param.as_ref()
    }

    /// Authority-section denial records (NSEC/NSEC3 + their RRSIGs) proving
    /// `qname` is absent. `nxdomain` distinguishes NXDOMAIN from NODATA.
    pub fn denial_records(&self, qname: &DnsName, nxdomain: bool) -> Vec<Record> {
        match &self.denial {
            Denial::Nsec(chain) => self.nsec_denial(chain, qname, nxdomain),
            Denial::Nsec3 { params, nodes, names } => {
                self.nsec3_denial(params, nodes, names, qname, nxdomain)
            }
        }
    }

    fn nsec_denial(
        &self,
        chain: &[(DnsName, Record, Vec<Record>)],
        qname: &DnsName,
        nxdomain: bool,
    ) -> Vec<Record> {
        let pick = |entry: &(DnsName, Record, Vec<Record>)| {
            let mut out = vec![entry.1.clone()];
            out.extend(entry.2.iter().cloned());
            out
        };
        if !nxdomain {
            // NODATA: the exact-match NSEC (or covering, as a fallback).
            if let Some(e) = chain.iter().find(|(n, _, _)| n == qname) {
                return pick(e);
            }
        }
        let target = canonical_key(qname);
        let mut best: Option<&(DnsName, Record, Vec<Record>)> = None;
        for entry in chain {
            if canonical_key(&entry.0) <= target {
                best = Some(entry);
            } else {
                break;
            }
        }
        best.or_else(|| chain.last()).map(pick).unwrap_or_default()
    }

    fn nsec3_denial(
        &self,
        params: &Nsec3Params,
        nodes: &[(Vec<u8>, Record, Vec<Record>)],
        names: &[DnsName],
        qname: &DnsName,
        nxdomain: bool,
    ) -> Vec<Record> {
        let emit = |node: &(Vec<u8>, Record, Vec<Record>), out: &mut Vec<Record>| {
            out.push(node.1.clone());
            out.extend(node.2.iter().cloned());
        };
        let matching = |h: &[u8]| nodes.iter().find(|(hash, _, _)| hash == h);
        let covering = |h: &[u8]| -> Option<&(Vec<u8>, Record, Vec<Record>)> {
            // The NSEC3 whose owner hash < h <= next hash (wrapping).
            for i in 0..nodes.len() {
                let cur = &nodes[i].0;
                let RData::Unknown { data, .. } = &nodes[i].1.rdata else { continue };
                let next = next_hash_of(data);
                let covers = if cur < &next {
                    cur.as_slice() < h && h <= next.as_slice()
                } else {
                    // Last node wraps: covers everything above cur or up to next.
                    h > cur.as_slice() || h <= next.as_slice()
                };
                if covers {
                    return Some(&nodes[i]);
                }
            }
            None
        };

        let mut out = Vec::new();
        if !nxdomain {
            // NODATA: NSEC3 matching the qname's hash.
            if let Some(node) = matching(&hash_name(qname, params)) {
                emit(node, &mut out);
            }
            return out;
        }

        // NXDOMAIN closest-encloser proof (RFC 5155 §7.2.1).
        let ce = closest_encloser(qname, names, &self.origin);
        let nc = next_closer(qname, &ce);
        // 1) NSEC3 matching the closest encloser.
        if let Some(node) = matching(&hash_name(&ce, params)) {
            emit(node, &mut out);
        }
        // 2) NSEC3 covering the next-closer name.
        if let Some(node) = covering(&hash_name(&nc, params)) {
            emit(node, &mut out);
        }
        // 3) NSEC3 covering the wildcard at the closest encloser.
        if let Some(wildcard) = prepend_star(&ce) {
            if let Some(node) = covering(&hash_name(&wildcard, params)) {
                emit(node, &mut out);
            }
        }
        // Deduplicate (the same NSEC3 can satisfy two roles).
        dedup_records(out)
    }

    /// Sign `zone` with `keys`, using NSEC3 when `nsec3` is set. DNSKEY is
    /// signed by SEP keys (or all when none is marked SEP); zone data by
    /// non-SEP keys (or all when none is).
    pub fn sign(
        zone: &Zone,
        keys: &[DnssecKey],
        now: u64,
        validity_secs: u64,
        nsec3: Option<Nsec3Params>,
    ) -> Self {
        let inception = now.saturating_sub(3600) as u32;
        let expiration = (now + validity_secs) as u32;
        let apex_ttl = zone.soa.ttl;

        let any_ksk = keys.iter().any(|k| k.is_ksk());
        let any_zsk = keys.iter().any(|k| !k.is_ksk());
        let ksks: Vec<&DnssecKey> = keys.iter().filter(|k| k.is_ksk() || !any_ksk).collect();
        let zsks: Vec<&DnssecKey> = keys.iter().filter(|k| !k.is_ksk() || !any_zsk).collect();

        let mut groups: HashMap<(DnsName, u16), Vec<Record>> = HashMap::new();
        for r in zone.all_records() {
            groups.entry((r.name.clone(), r.rtype())).or_default().push(r);
        }

        // NSEC3PARAM lives at the apex and must itself be covered by the
        // NSEC/NSEC3 type bitmap, so add it before computing bitmaps.
        let mut nsec3param = None;
        if let Some(params) = &nsec3 {
            let rec = Record {
                name: zone.origin.clone(),
                class: CLASS_IN,
                ttl: apex_ttl,
                rdata: RData::Unknown {
                    rtype: TYPE_NSEC3PARAM,
                    data: nsec3::nsec3param_rdata(params),
                },
            };
            groups.entry((zone.origin.clone(), TYPE_NSEC3PARAM)).or_default().push(rec.clone());
            nsec3param = Some(rec);
        }

        let mut rrsigs: HashMap<(DnsName, u16), Vec<Record>> = HashMap::new();
        for ((owner, rtype), rrset) in &groups {
            let sigs = zsks
                .iter()
                .map(|k| sign_rrset(k, owner, *rtype, rrset, inception, expiration))
                .collect();
            rrsigs.insert((owner.clone(), *rtype), sigs);
        }

        let mut owners: Vec<DnsName> = groups.keys().map(|(n, _)| n.clone()).collect();
        owners.sort_by(|a, b| canonical_key(a).cmp(&canonical_key(b)));
        owners.dedup();

        let types_at = |owner: &DnsName| -> Vec<u16> {
            let mut types: Vec<u16> =
                groups.keys().filter(|(n, _)| n == owner).map(|(_, t)| *t).collect();
            types.push(TYPE_RRSIG);
            if *owner == zone.origin {
                types.push(TYPE_DNSKEY);
            }
            types
        };

        let sign_denial = |owner: &DnsName, rtype: u16, rec: &Record| -> Vec<Record> {
            zsks.iter()
                .map(|k| sign_rrset(k, owner, rtype, std::slice::from_ref(rec), inception, expiration))
                .collect()
        };

        let denial = match &nsec3 {
            None => {
                let mut chain = Vec::with_capacity(owners.len());
                for i in 0..owners.len() {
                    let owner = &owners[i];
                    let next = &owners[(i + 1) % owners.len()];
                    let mut types = types_at(owner);
                    types.push(TYPE_NSEC);
                    types.sort_unstable();
                    types.dedup();
                    let rec = Record {
                        name: owner.clone(),
                        class: CLASS_IN,
                        ttl: apex_ttl,
                        rdata: RData::Unknown { rtype: TYPE_NSEC, data: nsec_rdata(next, &types) },
                    };
                    let sigs = sign_denial(owner, TYPE_NSEC, &rec);
                    chain.push((owner.clone(), rec, sigs));
                }
                Denial::Nsec(chain)
            }
            Some(params) => {
                let owner_types: Vec<(DnsName, Vec<u16>)> = owners
                    .iter()
                    .map(|o| {
                        let mut t = types_at(o);
                        t.sort_unstable();
                        t.dedup();
                        (o.clone(), t)
                    })
                    .collect();
                let chain = nsec3::build_chain(&zone.origin, &owner_types, params, apex_ttl);
                let nodes = chain
                    .into_iter()
                    .map(|node| {
                        let sigs = sign_denial(&node.owner, TYPE_NSEC3, &node.record);
                        (node.hash, node.record, sigs)
                    })
                    .collect();
                Denial::Nsec3 { params: params.clone(), nodes, names: owners.clone() }
            }
        };

        let dnskey_rrset: Vec<Record> = keys.iter().map(|k| k.dnskey_record(apex_ttl)).collect();
        let dnskey_rrsigs = ksks
            .iter()
            .map(|k| sign_rrset(k, &zone.origin, TYPE_DNSKEY, &dnskey_rrset, inception, expiration))
            .collect();

        SignedZone {
            origin: zone.origin.clone(),
            rrsigs,
            denial,
            dnskey_rrset,
            dnskey_rrsigs,
            nsec3param,
        }
    }
}

/// The next-hashed-owner field embedded in an NSEC3 rdata.
fn next_hash_of(nsec3_rdata: &[u8]) -> Vec<u8> {
    // hash_alg(1) flags(1) iter(2) salt_len(1) salt(salt_len) hash_len(1) hash
    let salt_len = nsec3_rdata[4] as usize;
    let hash_len_pos = 5 + salt_len;
    let hash_len = nsec3_rdata[hash_len_pos] as usize;
    nsec3_rdata[hash_len_pos + 1..hash_len_pos + 1 + hash_len].to_vec()
}

/// Longest ancestor of `qname` (down to the apex) that exists in `names`.
fn closest_encloser(qname: &DnsName, names: &[DnsName], apex: &DnsName) -> DnsName {
    let labels = qname.labels();
    let apex_len = apex.label_count();
    // Try progressively shorter suffixes of qname, longest first.
    for skip in 0..labels.len().saturating_sub(apex_len) {
        let cand = DnsName::from_labels(labels[skip..].to_vec()).ok();
        if let Some(cand) = cand {
            if names.contains(&cand) {
                return cand;
            }
        }
    }
    apex.clone()
}

/// The name one label longer than `ce` toward `qname` (RFC 5155 next closer).
fn next_closer(qname: &DnsName, ce: &DnsName) -> DnsName {
    let labels = qname.labels();
    let take = ce.label_count() + 1;
    if labels.len() <= take {
        return qname.clone();
    }
    let start = labels.len() - take;
    DnsName::from_labels(labels[start..].to_vec()).unwrap_or_else(|_| qname.clone())
}

fn prepend_star(name: &DnsName) -> Option<DnsName> {
    let mut labels = vec![b"*".to_vec()];
    labels.extend(name.labels().iter().cloned());
    DnsName::from_labels(labels).ok()
}

fn dedup_records(records: Vec<Record>) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for r in records {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

fn sign_rrset(
    key: &DnssecKey,
    owner: &DnsName,
    rtype: u16,
    rrset: &[Record],
    inception: u32,
    expiration: u32,
) -> Record {
    let original_ttl = rrset[0].ttl;
    let labels = owner.label_count() as u8;

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&rtype.to_be_bytes());
    prefix.push(key.algorithm);
    prefix.push(labels);
    prefix.extend_from_slice(&original_ttl.to_be_bytes());
    prefix.extend_from_slice(&expiration.to_be_bytes());
    prefix.extend_from_slice(&inception.to_be_bytes());
    prefix.extend_from_slice(&key.key_tag.to_be_bytes());
    key.signer.to_wire(&mut prefix, None);

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

fn nsec_rdata(next: &DnsName, types: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    next.to_wire(&mut out, None);
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

/// Canonical name ordering key (RFC 4034 §6.1).
fn canonical_key(name: &DnsName) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name.labels().to_vec();
    labels.reverse();
    labels
}

fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in cleaned.chunks(4) {
        let mut acc = 0u32;
        let mut bits = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)? as u32;
            bits += 6;
        }
        acc >>= bits % 8;
        bits -= bits % 8;
        for i in (0..bits).step_by(8).rev() {
            out.push((acc >> i) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_zone::parse_zone_file;

    const ZONE: &str = "\
$ORIGIN example.dnssec.
$TTL 300
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@    IN NS  ns1
ns1  IN A   10.0.0.1
www  IN A   10.0.0.10
www  IN A   10.0.0.11
";

    #[test]
    fn ecdsa_and_ed25519_keys_generate() {
        let s = DnsName::parse_str("x.").unwrap();
        for alg in [ALG_ECDSAP256, ALG_ED25519] {
            let (k, mat) = DnssecKey::generate(s.clone(), alg, true).unwrap();
            assert_ne!(k.key_tag(), 0);
            // Material round-trips to the same key tag.
            let k2 = DnssecKey::from_material(s.clone(), &mat, true).unwrap();
            assert_eq!(k.key_tag(), k2.key_tag());
        }
    }

    #[test]
    fn multi_key_rollover_signs_with_all_zsks() {
        let zone = parse_zone_file(ZONE).unwrap();
        // Two ZSKs (old+new) plus a KSK: rollover in progress.
        let (ksk, _) = DnssecKey::generate(zone.origin.clone(), ALG_ED25519, true).unwrap();
        let (zsk1, _) = DnssecKey::generate(zone.origin.clone(), ALG_ECDSAP256, false).unwrap();
        let (zsk2, _) = DnssecKey::generate(zone.origin.clone(), ALG_ED25519, false).unwrap();
        let keys = vec![ksk, zsk1, zsk2];
        let sz = SignedZone::sign(&zone, &keys, 1_700_000_000, 1_209_600, None);

        let www = DnsName::parse_str("www.example.dnssec").unwrap();
        // Each ZSK contributes one RRSIG over the A rrset.
        assert_eq!(sz.rrsigs_for(&www, dns_proto::message::TYPE_A).len(), 2);
        // DNSKEY signed by the single KSK.
        let (rrset, sigs) = sz.dnskey_records();
        assert_eq!(rrset.len(), 3, "all three keys published");
        assert_eq!(sigs.len(), 1, "DNSKEY signed by KSK only");
    }

    #[test]
    fn nsec3_denial_produces_closest_encloser_proof() {
        use dns_proto::message::{TYPE_NSEC3, TYPE_A};
        let zone = parse_zone_file(ZONE).unwrap();
        let (k, _) = DnssecKey::generate(zone.origin.clone(), ALG_ED25519, true).unwrap();
        let params = nsec3::Nsec3Params { iterations: 5, salt: vec![0xDE, 0xAD] };
        let sz = SignedZone::sign(&zone, &[k], 1_700_000_000, 1_209_600, Some(params));

        assert!(sz.nsec3param().is_some());
        // NXDOMAIN: closest-encloser proof = several NSEC3 + RRSIGs.
        let q = DnsName::parse_str("does.not.exist.example.dnssec").unwrap();
        let recs = sz.denial_records(&q, true);
        let n3 = recs.iter().filter(|r| r.rtype() == TYPE_NSEC3).count();
        assert!(n3 >= 2, "closest-encloser proof needs >=2 NSEC3, got {n3}");
        assert!(recs.iter().any(|r| r.rtype() == dns_proto::message::TYPE_RRSIG));

        // NODATA: matching NSEC3 for an existing name.
        let www = DnsName::parse_str("www.example.dnssec").unwrap();
        let nodata = sz.denial_records(&www, false);
        assert!(nodata.iter().any(|r| r.rtype() == TYPE_NSEC3));
        let _ = TYPE_A;
    }
}
