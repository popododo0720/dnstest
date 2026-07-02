//! TTL-aware response cache with negative caching (RFC 2308).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use dns_proto::message::{RCODE_NOERROR, RCODE_NXDOMAIN, RData, Record};
use dns_proto::name::DnsName;

const MAX_POSITIVE_TTL: u32 = 86_400;
const MAX_NEGATIVE_TTL: u32 = 3_600;
const DEFAULT_NEGATIVE_TTL: u32 = 60;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub qname: DnsName,
    pub qtype: u16,
}

struct Entry {
    rcode: u8,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    stored: Instant,
    expires: Instant,
}

pub struct Cache {
    inner: RwLock<HashMap<Key, Entry>>,
    max_entries: usize,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Cache { inner: RwLock::new(HashMap::new()), max_entries: max_entries.max(1) }
    }

    /// Cache hit returns (rcode, answers, authorities) with TTLs decremented
    /// by the time spent in the cache.
    pub fn get(&self, key: &Key) -> Option<(u8, Vec<Record>, Vec<Record>)> {
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
                    return Some((
                        e.rcode,
                        e.answers.iter().map(adjust).collect(),
                        e.authorities.iter().map(adjust).collect(),
                    ));
                }
                Some(_) => {} // expired: fall through and remove
            }
        }
        self.inner.write().unwrap().remove(key);
        None
    }

    /// Store a response. Only cacheable outcomes (NOERROR/NXDOMAIN) are kept;
    /// negative entries live for min(SOA minimum, SOA TTL) per RFC 2308.
    pub fn insert(&self, key: Key, rcode: u8, answers: Vec<Record>, authorities: Vec<Record>) {
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
            stored: now,
            expires: now + Duration::from_secs(ttl as u64),
        };

        let mut map = self.inner.write().unwrap();
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            map.retain(|_, e| e.expires > now);
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
        cache.insert(key.clone(), 0, vec![a_record("www.example.com", 300)], vec![]);
        let (rcode, answers, _) = cache.get(&key).expect("hit");
        assert_eq!(rcode, 0);
        assert_eq!(answers.len(), 1);
        assert!(answers[0].ttl <= 300 && answers[0].ttl >= 299);
    }

    #[test]
    fn ttl_zero_and_servfail_not_cached() {
        let cache = Cache::new(10);
        let key = Key { qname: n("a.example"), qtype: 1 };
        cache.insert(key.clone(), 0, vec![a_record("a.example", 0)], vec![]);
        assert!(cache.get(&key).is_none());
        cache.insert(key.clone(), 2, vec![a_record("a.example", 300)], vec![]);
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
        cache.insert(key.clone(), 3, vec![], vec![soa]);
        let (rcode, answers, authorities) = cache.get(&key).expect("negative hit");
        assert_eq!(rcode, 3);
        assert!(answers.is_empty());
        assert_eq!(authorities.len(), 1);
    }

    #[test]
    fn eviction_keeps_bound() {
        let cache = Cache::new(5);
        for i in 0..50 {
            let key = Key { qname: n(&format!("h{i}.example.com")), qtype: 1 };
            cache.insert(key, 0, vec![a_record("x.example.com", 300)], vec![]);
        }
        assert!(cache.len() <= 5);
    }
}
