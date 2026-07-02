//! TSIG transaction signatures (RFC 8945).
//!
//! Supports the two HMAC-SHA2 algorithms that matter in practice,
//! `hmac-sha256` and `hmac-sha512`. A [`TsigKey`] carries the shared secret;
//! [`sign_request`]/[`sign_response`] attach a TSIG RR, and [`verify`] checks
//! an incoming one. Base64 secret handling lives here so callers stay simple.

use std::collections::HashMap;

use dns_proto::message::{
    Message, TSIG_BADKEY, TSIG_BADSIG, TSIG_BADTIME, Tsig,
};
use dns_proto::name::DnsName;
use ring::hmac;

const MAX_CLOCK_SKEW: u64 = 300; // seconds; also the default fudge

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    HmacSha256,
    HmacSha512,
}

impl Algorithm {
    fn wire_name(self) -> &'static str {
        match self {
            Algorithm::HmacSha256 => "hmac-sha256.",
            Algorithm::HmacSha512 => "hmac-sha512.",
        }
    }

    fn from_wire_name(name: &DnsName) -> Option<Self> {
        match name.to_string().to_ascii_lowercase().as_str() {
            "hmac-sha256." => Some(Algorithm::HmacSha256),
            "hmac-sha512." => Some(Algorithm::HmacSha512),
            _ => None,
        }
    }

    fn ring_algorithm(self) -> hmac::Algorithm {
        match self {
            Algorithm::HmacSha256 => hmac::HMAC_SHA256,
            Algorithm::HmacSha512 => hmac::HMAC_SHA512,
        }
    }
}

#[derive(Clone)]
pub struct TsigKey {
    pub name: DnsName,
    pub algorithm: Algorithm,
    secret: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TsigError {
    /// Unknown key name or algorithm (maps to RCODE NOTAUTH + BADKEY).
    BadKey,
    /// MAC mismatch (NOTAUTH + BADSIG).
    BadSig,
    /// Time outside the fudge window (NOTAUTH + BADTIME).
    BadTime,
    /// Message was not signed at all.
    Missing,
}

impl TsigError {
    /// TSIG error code for the error field of a reply's TSIG RR.
    pub fn tsig_code(&self) -> u16 {
        match self {
            TsigError::BadKey | TsigError::Missing => TSIG_BADKEY,
            TsigError::BadSig => TSIG_BADSIG,
            TsigError::BadTime => TSIG_BADTIME,
        }
    }
}

impl TsigKey {
    /// Build a key from a name, algorithm, and base64-encoded secret.
    pub fn new(name: &str, algorithm: Algorithm, secret_b64: &str) -> Result<Self, String> {
        let name = DnsName::parse_str(name).map_err(|e| format!("bad key name: {e}"))?;
        let secret = base64_decode(secret_b64).ok_or("secret is not valid base64")?;
        Ok(TsigKey { name, algorithm, secret })
    }

    fn hmac_key(&self) -> hmac::Key {
        hmac::Key::new(self.algorithm.ring_algorithm(), &self.secret)
    }
}

/// A set of keys indexed by name for server-side verification.
#[derive(Clone, Default)]
pub struct KeyRing {
    keys: HashMap<DnsName, TsigKey>,
}

impl KeyRing {
    pub fn insert(&mut self, key: TsigKey) {
        self.keys.insert(key.name.clone(), key);
    }

    pub fn get(&self, name: &DnsName) -> Option<&TsigKey> {
        self.keys.get(name)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The bytes HMACed for a TSIG: `prior_mac ++ message_bytes ++ variables`.
fn digest_input(message_bytes: &[u8], tsig: &Tsig, prior_mac: Option<&[u8]>) -> Vec<u8> {
    let mut data = Vec::with_capacity(message_bytes.len() + 64);
    if let Some(mac) = prior_mac {
        data.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        data.extend_from_slice(mac);
    }
    data.extend_from_slice(message_bytes);
    data.extend_from_slice(&tsig.variables());
    data
}

fn compute_mac(
    key: &TsigKey,
    message_bytes: &[u8],
    tsig: &Tsig,
    prior_mac: Option<&[u8]>,
) -> Vec<u8> {
    hmac::sign(&key.hmac_key(), &digest_input(message_bytes, tsig, prior_mac)).as_ref().to_vec()
}

fn make_tsig(key: &TsigKey, now: u64, original_id: u16, error: u16) -> Tsig {
    Tsig {
        key_name: key.name.clone(),
        algorithm: DnsName::parse_str(key.algorithm.wire_name()).unwrap(),
        time_signed: now,
        fudge: MAX_CLOCK_SKEW as u16,
        mac: Vec::new(),
        original_id,
        error,
        other: Vec::new(),
    }
}

/// Sign a request. Returns the wire bytes with a TSIG RR appended and the MAC
/// (needed later to verify the matching response).
pub fn sign_request(msg: &Message, key: &TsigKey, now: u64) -> (Vec<u8>, Vec<u8>) {
    let mut tsig = make_tsig(key, now, msg.id, 0);
    let body = msg.encode();
    tsig.mac = compute_mac(key, &body, &tsig, None);
    let mac = tsig.mac.clone();
    (msg.encode_with_tsig(&tsig), mac)
}

/// Sign a response, chaining the request's MAC into the digest (RFC 8945
/// §5.3.1).
pub fn sign_response(msg: &Message, key: &TsigKey, request_mac: &[u8], now: u64) -> Vec<u8> {
    let mut tsig = make_tsig(key, now, msg.id, 0);
    let body = msg.encode();
    tsig.mac = compute_mac(key, &body, &tsig, Some(request_mac));
    msg.encode_with_tsig(&tsig)
}

/// Produce an unsigned error reply carrying a TSIG RR with the given error
/// code (RFC 8945 §5.3.2: BADKEY/BADSIG replies still carry a TSIG).
pub fn sign_error(msg: &Message, key: &TsigKey, error: u16, now: u64) -> Vec<u8> {
    let tsig = make_tsig(key, now, msg.id, error);
    msg.encode_with_tsig(&tsig)
}

/// Verify the TSIG on a parsed message given the raw bytes it came from.
/// `prior_mac` is the request MAC when verifying a response.
pub fn verify(
    msg: &Message,
    raw: &[u8],
    keyring: &KeyRing,
    now: u64,
    prior_mac: Option<&[u8]>,
) -> Result<Vec<u8>, TsigError> {
    let (tsig, start) = match (&msg.tsig, msg.tsig_start) {
        (Some(t), Some(s)) => (t, s),
        _ => return Err(TsigError::Missing),
    };
    let key = keyring.get(&tsig.key_name).ok_or(TsigError::BadKey)?;
    if Algorithm::from_wire_name(&tsig.algorithm) != Some(key.algorithm) {
        return Err(TsigError::BadKey);
    }

    // The digested message is everything before the TSIG RR, with ARCOUNT
    // decremented to exclude it.
    let mut body = raw[..start].to_vec();
    let arcount = u16::from_be_bytes([body[10], body[11]]).wrapping_sub(1);
    body[10..12].copy_from_slice(&arcount.to_be_bytes());

    // ring's hmac::verify is constant-time and validates the tag length.
    let data = digest_input(&body, tsig, prior_mac);
    if hmac::verify(&key.hmac_key(), &data, &tsig.mac).is_err() {
        return Err(TsigError::BadSig);
    }
    if now.abs_diff(tsig.time_signed) > tsig.fudge as u64 {
        return Err(TsigError::BadTime);
    }
    Ok(tsig.mac.clone())
}

/// RFC 4648 base64 decode (standard alphabet, optional padding).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
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
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4);
    for chunk in cleaned.chunks(4) {
        let mut acc = 0u32;
        let mut bits = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)? as u32;
            bits += 6;
        }
        // Drop the leftover partial byte that padding would have represented.
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
    use dns_proto::message::{CLASS_IN, Flags, Question, TYPE_A};

    fn key() -> TsigKey {
        // 32 zero bytes, base64.
        TsigKey::new("test.key.", Algorithm::HmacSha256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap()
    }

    fn query() -> Message {
        let mut m = Message::new(0x4242, Flags { rd: true, ..Flags::default() });
        m.questions.push(Question {
            qname: DnsName::parse_str("example.com").unwrap(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });
        m
    }

    #[test]
    fn base64_roundtrips_known_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert!(base64_decode("****").is_none());
    }

    #[test]
    fn sign_then_verify_request() {
        let k = key();
        let mut ring = KeyRing::default();
        ring.insert(k.clone());

        let (wire, _mac) = sign_request(&query(), &k, 1_000_000);
        let parsed = Message::parse(&wire).unwrap();
        assert!(parsed.tsig.is_some());
        assert_eq!(verify(&parsed, &wire, &ring, 1_000_000, None).map(|_| ()), Ok(()));
    }

    #[test]
    fn tampered_message_fails() {
        let k = key();
        let mut ring = KeyRing::default();
        ring.insert(k.clone());
        let (mut wire, _) = sign_request(&query(), &k, 1_000_000);
        // Flip a bit in the question section.
        wire[13] ^= 0x01;
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(verify(&parsed, &wire, &ring, 1_000_000, None), Err(TsigError::BadSig));
    }

    #[test]
    fn clock_skew_rejected() {
        let k = key();
        let mut ring = KeyRing::default();
        ring.insert(k.clone());
        let (wire, _) = sign_request(&query(), &k, 1_000_000);
        let parsed = Message::parse(&wire).unwrap();
        // 10 minutes out: beyond the 300s fudge.
        assert_eq!(verify(&parsed, &wire, &ring, 1_000_600, None), Err(TsigError::BadTime));
    }

    #[test]
    fn unknown_key_rejected() {
        let (wire, _) = sign_request(&query(), &key(), 1_000_000);
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(
            verify(&parsed, &wire, &KeyRing::default(), 1_000_000, None),
            Err(TsigError::BadKey)
        );
    }

    #[test]
    fn request_response_mac_chain() {
        let k = key();
        let mut ring = KeyRing::default();
        ring.insert(k.clone());

        let (req_wire, req_mac) = sign_request(&query(), &k, 1_000_000);
        let req = Message::parse(&req_wire).unwrap();
        verify(&req, &req_wire, &ring, 1_000_000, None).unwrap();

        let resp = Message::response_to(&req);
        let resp_wire = sign_response(&resp, &k, &req_mac, 1_000_000);
        let resp_parsed = Message::parse(&resp_wire).unwrap();
        // Response verifies only when chained with the request MAC.
        assert!(verify(&resp_parsed, &resp_wire, &ring, 1_000_000, Some(&req_mac)).is_ok());
        assert_eq!(
            verify(&resp_parsed, &resp_wire, &ring, 1_000_000, None),
            Err(TsigError::BadSig)
        );
    }
}
