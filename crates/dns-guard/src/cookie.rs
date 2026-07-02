//! DNS Cookies (RFC 7873 / RFC 9018): a lightweight anti-spoofing and
//! anti-amplification transaction mechanism carried in an EDNS option.
//!
//! The client sends an 8-byte Client Cookie. The server returns that plus a
//! 16-byte Server Cookie computed as a keyed hash over the client cookie, the
//! client IP, a version, and a timestamp. A returning client echoes the whole
//! cookie; the server recomputes and compares, so an off-path spoofer (which
//! cannot see the server cookie) is detected.

use std::hash::Hasher;
use std::net::IpAddr;

use siphasher::sip::SipHasher24;

const VERSION: u8 = 1;
/// Server cookies older than this (seconds) are refreshed; older than 2x are
/// rejected (RFC 9018 §4.3 guidance).
const COOKIE_LIFETIME: u32 = 3600;

#[derive(Clone)]
pub struct CookieKey {
    k0: u64,
    k1: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CookieStatus {
    /// No COOKIE option present.
    Absent,
    /// Client cookie only (first contact): answer with a fresh server cookie.
    ClientOnly,
    /// A valid, current server cookie.
    Valid,
    /// A server cookie that verifies but is stale: answer with a fresh one.
    Stale,
    /// Malformed or forged cookie.
    Invalid,
}

impl CookieKey {
    /// Random per-process secret (server cookies do not need to persist across
    /// restarts; clients simply re-establish).
    pub fn random() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let bytes = ring::rand::generate::<[u8; 16]>(&rng)
            .map(|b| b.expose())
            .unwrap_or([0x5a; 16]);
        CookieKey {
            k0: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            k1: u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        }
    }

    fn hash(&self, client_cookie: &[u8], ip: IpAddr, timestamp: u32) -> u64 {
        let mut h = SipHasher24::new_with_keys(self.k0, self.k1);
        h.write(client_cookie);
        h.write_u8(VERSION);
        h.write_u32(timestamp);
        match ip {
            IpAddr::V4(a) => h.write(&a.octets()),
            IpAddr::V6(a) => h.write(&a.octets()),
        }
        h.finish()
    }

    /// Build the full 24-byte COOKIE option value (client cookie + server
    /// cookie) for a response.
    pub fn build(&self, client_cookie: &[u8; 8], ip: IpAddr, now: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(client_cookie);
        out.push(VERSION);
        out.extend_from_slice(&[0, 0, 0]); // reserved
        out.extend_from_slice(&now.to_be_bytes());
        out.extend_from_slice(&self.hash(client_cookie, ip, now).to_be_bytes());
        out
    }

    /// Classify the COOKIE option in a request.
    pub fn verify(&self, cookie: &[u8], ip: IpAddr, now: u32) -> CookieStatus {
        match cookie.len() {
            0 => CookieStatus::Absent,
            8 => CookieStatus::ClientOnly,
            // client(8) + server(16): version(1) reserved(3) ts(4) hash(8)
            24 => {
                let client = &cookie[0..8];
                if cookie[8] != VERSION {
                    return CookieStatus::Invalid;
                }
                let ts = u32::from_be_bytes(cookie[12..16].try_into().unwrap());
                let expected = self.hash(client, ip, ts).to_be_bytes();
                if cookie[16..24] != expected {
                    return CookieStatus::Invalid;
                }
                // Reject far-future or long-expired timestamps.
                let age = now.wrapping_sub(ts);
                if age > 2 * COOKIE_LIFETIME && ts <= now {
                    CookieStatus::Invalid
                } else if age > COOKIE_LIFETIME {
                    CookieStatus::Stale
                } else {
                    CookieStatus::Valid
                }
            }
            _ => CookieStatus::Invalid,
        }
    }

    /// The client cookie half (first 8 bytes) of a request option.
    pub fn client_cookie(cookie: &[u8]) -> Option<[u8; 8]> {
        cookie.get(0..8).map(|s| s.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn client_only_then_valid_roundtrip() {
        let key = CookieKey::random();
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let addr = ip("192.0.2.1");
        let now = 1_000_000;

        // First contact: client cookie only.
        assert_eq!(key.verify(&client, addr, now), CookieStatus::ClientOnly);

        // Server issues a full cookie; the client echoes it back → Valid.
        let full = key.build(&client, addr, now);
        assert_eq!(full.len(), 24);
        assert_eq!(key.verify(&full, addr, now), CookieStatus::Valid);
    }

    #[test]
    fn forged_or_wrong_ip_is_invalid() {
        let key = CookieKey::random();
        let client = [9u8; 8];
        let full = key.build(&client, ip("192.0.2.1"), 1_000_000);
        // Same cookie replayed from a different source address must fail.
        assert_eq!(key.verify(&full, ip("192.0.2.2"), 1_000_000), CookieStatus::Invalid);
        // Tampered hash.
        let mut bad = full.clone();
        bad[23] ^= 0xFF;
        assert_eq!(key.verify(&bad, ip("192.0.2.1"), 1_000_000), CookieStatus::Invalid);
    }

    #[test]
    fn stale_cookie_detected() {
        let key = CookieKey::random();
        let client = [7u8; 8];
        let addr = ip("192.0.2.9");
        let full = key.build(&client, addr, 1_000_000);
        // Well past the refresh window but still verifiable → Stale.
        assert_eq!(key.verify(&full, addr, 1_000_000 + COOKIE_LIFETIME + 5), CookieStatus::Stale);
    }

    #[test]
    fn bad_lengths_rejected() {
        let key = CookieKey::random();
        assert_eq!(key.verify(&[], ip("::1"), 0), CookieStatus::Absent);
        assert_eq!(key.verify(&[1, 2, 3], ip("::1"), 0), CookieStatus::Invalid);
        assert_eq!(key.verify(&[0u8; 40], ip("::1"), 0), CookieStatus::Invalid);
    }
}
