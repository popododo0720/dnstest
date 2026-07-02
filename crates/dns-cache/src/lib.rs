//! TTL-aware response cache with negative caching (RFC 2308).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use dns_proto::message::{RCODE_NOERROR, RCODE_NXDOMAIN, RData, Record};
use dns_proto::name::DnsName;

const MAX_POSITIVE_TTL: u32 = 86_400;
const MAX_NEGATIVE_TTL: u32 = 3_600;
const DEFAULT_NEGATIVE_TTL: u32 = 60;
/// How long past expiry an entry may still be served stale (RFC 8767 §5).
const STALE_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// TTL stamped onto stale answers (RFC 8767 recommends <= 30s).
const STALE_TTL: u32 = 30;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub qname: DnsName,
    pub qtype: u16,
}

struct Entry {
    rcode: u8,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    /// DNSSEC-validated (AD bit) at insertion time.
    secure: bool,
    stored: Instant,
    expires: Instant,
}

/// A cache hit: response records plus their validated status.
pub struct Hit {
    pub rcode: u8,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub secure: bool,
}

pub struct Cache {
    inner: RwLock<HashMap<Key, Entry>>,
    max_entries: usize,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Cache { inner: RwLock::new(HashMap::new()), max_entries: max_entries.max(1) }
    }

    /// Cache hit with TTLs decremented by the time spent in the cache, and
    /// the DNSSEC-validated status preserved for the AD bit.
    pub fn get(&self, key: &Key) -> Option<Hit> {
        let now = Instant::now();
        {
            let map = self.inner.read().unwrap();
            match map.get(key) {
                None => return None,
                Some(e) if e.expires > now => {
                    let elapsed = now.duration_since(e.stored).as_secs() as u32;
                    let adjust = |r: &Record| {
                        let mut r = r.clone();
                        r.ttl = r.ttl.saturating_sub(elapsed).max(1);
                        r
                    };
                    return Some(Hit {
                        rcode: e.rcode,
                        answers: e.answers.iter().map(adjust).collect(),
                        authorities: e.authorities.iter().map(adjust).collect(),
                        secure: e.secure,
                    });
                }
                // Expired entries are kept for the serve-stale window and
                // only evicted once past it.
                Some(e) if now > e.expires + STALE_WINDOW => {}
                Some(_) => return None,
            }
        }
        self.inner.write().unwrap().remove(key);
        None
    }

    /// Serve-stale (RFC 8767): an expired entry within the stale window,
    /// answers re-labeled with a short TTL. Only for upstream outages.
    pub fn get_stale(&self, key: &Key) -> Option<Hit> {
        let now = Instant::now();
        let map = self.inner.read().unwrap();
        let e = map.get(key)?;
        if now <= e.expires || now > e.expires + STALE_WINDOW {
            return None;
        }
        let adjust = |r: &Record| {
            let mut r = r.clone();
            r.ttl = STALE_TTL;
            r
        };
        Some(Hit {
            rcode: e.rcode,
            answers: e.answers.iter().map(adjust).collect(),
            authorities: e.authorities.iter().map(adjust).collect(),
            secure: e.secure,
        })
    }

    /// Store a response. Only cacheable outcomes (NOERROR/NXDOMAIN) are kept;
    /// negative entries live for min(SOA minimum, SOA TTL) per RFC 2308.
    pub fn insert(
        &self,
        key: Key,
        rcode: u8,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        secure: bool,
    ) {
        if rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN {
            return;
        }
        let ttl = if answers.is_empty() {
            let soa_ttl = authorities.iter().find_map(|r| match &r.rdata {
                RData::Soa(soa) => Some(soa.minimum.min(r.ttl)),
                _ => None,
            });
            soa_ttl.unwrap_or(DEFAULT_NEGATIVE_TTL).min(MAX_NEGATIVE_TTL)
        } else {
            answers.iter().map(|r| r.ttl).min().unwrap_or(0).min(MAX_POSITIVE_TTL)
        };
        if ttl == 0 {
            return; // TTL 0 means "do not cache"
        }

        let now = Instant::now();
        let entry = Entry {
            rcode,
            answers,
            authorities,
            secure,
            stored: now,
            expires: now + Duration::from_secs(ttl as u64),
        };

        let mut map = self.inner.write().unwrap();
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            map.retain(|_, e| now <= e.expires + STALE_WINDOW);
            if map.len() >= self.max_entries {
                // Still full of live entries: shed an arbitrary ~10%. Simple
                // and O(n), but only runs when the cache is genuinely full.
                let victims: Vec<Key> =
                    map.keys().take(self.max_entries / 10 + 1).cloned().collect();
                for v in victims {
                    map.remove(&v);
                }
            }
        }
        map.insert(key, entry);
    }

    pub fn len(&self) -> usize {
        // Also exposed via the statistics API.
        self.inner.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_proto::message::{CLASS_IN, Soa};
    use std::net::Ipv4Addr;

    fn n(s: &str) -> DnsName {
        DnsName::parse_str(s).unwrap()
    }

    fn a_record(name: &str, ttl: u32) -> Record {
        Record {
            name: n(name),
            class: CLASS_IN,
            ttl,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }

    #[test]
    fn positive_roundtrip() {
        let cache = Cache::new(10);
        let key = Key { qname: n("www.example.com"), qtype: 1 };
        cache.insert(key.clone(), 0, vec![a_record("www.example.com", 300)], vec![], false);
        let hit = cache.get(&key).expect("hit");
        let (rcode, answers) = (hit.rcode, hit.answers);
        assert_eq!(rcode, 0);
        assert_eq!(answers.len(), 1);
        assert!(answers[0].ttl <= 300 && answers[0].ttl >= 299);
    }

    #[test]
    fn ttl_zero_and_servfail_not_cached() {
        let cache = Cache::new(10);
        let key = Key { qname: n("a.example"), qtype: 1 };
        cache.insert(key.clone(), 0, vec![a_record("a.example", 0)], vec![], false);
        assert!(cache.get(&key).is_none());
        cache.insert(key.clone(), 2, vec![a_record("a.example", 300)], vec![], false);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn negative_cached_from_soa() {
        let cache = Cache::new(10);
        let key = Key { qname: n("missing.example.com"), qtype: 1 };
        let soa = Record {
            name: n("example.com"),
            class: CLASS_IN,
            ttl: 3600,
            rdata: RData::Soa(Soa {
                mname: n("ns1.example.com"),
                rname: n("h.example.com"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 300,
            }),
        };
        cache.insert(key.clone(), 3, vec![], vec![soa], true);
        let hit = cache.get(&key).expect("negative hit");
        let (rcode, answers, authorities) = (hit.rcode, hit.answers, hit.authorities);
        assert_eq!(rcode, 3);
        assert!(answers.is_empty());
        assert_eq!(authorities.len(), 1);
    }

    #[test]
    fn eviction_keeps_bound() {
        let cache = Cache::new(5);
        for i in 0..50 {
            let key = Key { qname: n(&format!("h{i}.example.com")), qtype: 1 };
            cache.insert(key, 0, vec![a_record("x.example.com", 300)], vec![], false);
        }
        assert!(cache.len() <= 5);
    }
}
