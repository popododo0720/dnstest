//! Access control (CIDR allowlists), per-client token-bucket rate limiting,
//! and DNS Cookies (anti-spoofing).

pub mod cookie;

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Instant;

/// A network in CIDR notation. A bare address is treated as a full-length
/// prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p.parse().map_err(|_| format!("bad prefix in '{s}'"))?;
                (a, Some(prefix))
            }
            None => (s, None),
        };
        let net: IpAddr = addr.parse().map_err(|_| format!("bad address in '{s}'"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(format!("prefix /{prefix} too long in '{s}'"));
        }
        Ok(Cidr { net, prefix })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p => u32::MAX << (32 - p as u32),
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p => u128::MAX << (128 - p as u32),
    }
}

/// Allowlist of client networks.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    nets: Vec<Cidr>,
}

impl Acl {
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let nets = entries.iter().map(|e| e.parse()).collect::<Result<_, _>>()?;
        Ok(Acl { nets })
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket rate limiter keyed by client address. `qps` tokens refill per
/// second up to `burst`. Over-limit queries should be *dropped* (not answered)
/// so the server cannot be used as a reflection amplifier.
pub struct RateLimiter {
    qps: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

/// Above this many tracked clients, stale buckets are purged opportunistically.
const CLEANUP_THRESHOLD: usize = 65_536;

impl RateLimiter {
    pub fn new(qps: u32, burst: u32) -> Self {
        RateLimiter {
            qps: qps as f64,
            burst: burst.max(qps) as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() > CLEANUP_THRESHOLD {
            buckets.retain(|_, b| now.duration_since(b.last).as_secs() < 60);
        }
        let bucket = buckets
            .entry(ip)
            .or_insert(Bucket { tokens: self.burst, last: now });
        let dt = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + dt * self.qps).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(ip("10.255.1.2")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("::1")));

        let host: Cidr = "192.168.0.5".parse().unwrap();
        assert!(host.contains(ip("192.168.0.5")));
        assert!(!host.contains(ip("192.168.0.6")));

        let any: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(any.contains(ip("8.8.8.8")));
    }

    #[test]
    fn cidr_v6() {
        let c: Cidr = "fd00::/8".parse().unwrap();
        assert!(c.contains(ip("fd12:3456::1")));
        assert!(!c.contains(ip("fe80::1")));
        assert!(!c.contains(ip("10.0.0.1")));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("banana/8".parse::<Cidr>().is_err());
        assert!("10.0.0.0/x".parse::<Cidr>().is_err());
    }

    #[test]
    fn acl_allowlist() {
        let acl = Acl::parse(&["127.0.0.0/8".into(), "::1/128".into()]).unwrap();
        assert!(acl.is_allowed(ip("127.0.0.1")));
        assert!(acl.is_allowed(ip("::1")));
        assert!(!acl.is_allowed(ip("8.8.8.8")));
        assert!(!Acl::default().is_allowed(ip("127.0.0.1")));
    }

    #[test]
    fn rate_limiter_burst_then_deny() {
        let rl = RateLimiter::new(1, 3);
        let client = ip("10.0.0.1");
        assert!(rl.allow(client));
        assert!(rl.allow(client));
        assert!(rl.allow(client));
        assert!(!rl.allow(client), "burst exhausted");
        // A different client has its own bucket.
        assert!(rl.allow(ip("10.0.0.2")));
    }
}
