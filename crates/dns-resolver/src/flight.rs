//! Singleflight: concurrent identical lookups are merged so one upstream
//! query serves them all (cache-stampede protection).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dns_cache::Key;
use tokio::sync::watch;

type FlightMap = Arc<Mutex<HashMap<Key, watch::Receiver<bool>>>>;

#[derive(Default)]
pub struct Singleflight {
    inflight: FlightMap,
}

pub enum Role {
    /// This task performs the upstream query; dropping the guard (success or
    /// failure) releases the key and wakes all followers.
    Leader(FlightGuard),
    /// Another task is already querying: await the receiver, then re-check
    /// the cache.
    Follower(watch::Receiver<bool>),
}

impl Singleflight {
    pub fn begin(&self, key: &Key) -> Role {
        let mut map = self.inflight.lock().unwrap();
        if let Some(rx) = map.get(key) {
            return Role::Follower(rx.clone());
        }
        let (tx, rx) = watch::channel(false);
        map.insert(key.clone(), rx);
        Role::Leader(FlightGuard { key: key.clone(), map: self.inflight.clone(), tx: Some(tx) })
    }
}

pub struct FlightGuard {
    key: Key,
    map: FlightMap,
    tx: Option<watch::Sender<bool>>,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        // Remove BEFORE waking: a woken follower that still misses the cache
        // must be able to become the next leader.
        self.map.lock().unwrap().remove(&self.key);
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_proto::name::DnsName;

    fn key() -> Key {
        Key { qname: DnsName::parse_str("x.example").unwrap(), qtype: 1 }
    }

    #[test]
    fn leader_then_followers_then_release() {
        let sf = Singleflight::default();
        let Role::Leader(guard) = sf.begin(&key()) else {
            panic!("first begin must lead")
        };
        let Role::Follower(mut rx) = sf.begin(&key()) else {
            panic!("second begin must follow")
        };
        assert!(!*rx.borrow());
        drop(guard);
        // Guard drop marks completion and frees the key for a new leader.
        assert!(*rx.borrow_and_update() || rx.has_changed().is_err());
        assert!(matches!(sf.begin(&key()), Role::Leader(_)));
    }
}
