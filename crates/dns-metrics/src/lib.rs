//! Server statistics: lock-free counters exposed through the management API
//! (`GET /api/v1/statistics`), PowerDNS-style.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Latency bucket upper bounds, in microseconds.
const BUCKETS_US: [u64; 6] = [10, 100, 1_000, 10_000, 100_000, 1_000_000];

#[derive(Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS_US.len()],
    overflow: AtomicU64,
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn observe(&self, d: Duration) {
        let us = d.as_micros() as u64;
        match BUCKETS_US.iter().position(|&le| us <= le) {
            Some(i) => self.buckets[i].fetch_add(1, Relaxed),
            None => self.overflow.fetch_add(1, Relaxed),
        };
        self.sum_us.fetch_add(us, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }
}

pub struct Metrics {
    started: Instant,
    pub queries_udp: AtomicU64,
    pub queries_tcp: AtomicU64,
    /// Response counts indexed by rcode (0..15).
    rcodes: [AtomicU64; 16],
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub upstream_queries: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub upstream_failovers: AtomicU64,
    pub singleflight_merged: AtomicU64,
    pub rate_limited: AtomicU64,
    pub recursion_refused: AtomicU64,
    pub zone_reloads: AtomicU64,
    latency: Histogram,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            started: Instant::now(),
            queries_udp: AtomicU64::new(0),
            queries_tcp: AtomicU64::new(0),
            rcodes: Default::default(),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            upstream_failovers: AtomicU64::new(0),
            singleflight_merged: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            recursion_refused: AtomicU64::new(0),
            zone_reloads: AtomicU64::new(0),
            latency: Histogram::default(),
        }
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Relaxed);
    }

    pub fn observe_rcode(&self, rcode: u8) {
        self.rcodes[(rcode & 0xF) as usize].fetch_add(1, Relaxed);
    }

    pub fn observe_latency(&self, d: Duration) {
        self.latency.observe(d);
    }

    /// Flat name/value list for the statistics endpoint.
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = vec![
            ("uptime-seconds".into(), self.started.elapsed().as_secs()),
            ("queries-udp".into(), self.queries_udp.load(Relaxed)),
            ("queries-tcp".into(), self.queries_tcp.load(Relaxed)),
            ("cache-hits".into(), self.cache_hits.load(Relaxed)),
            ("cache-misses".into(), self.cache_misses.load(Relaxed)),
            ("upstream-queries".into(), self.upstream_queries.load(Relaxed)),
            ("upstream-failures".into(), self.upstream_failures.load(Relaxed)),
            ("upstream-failovers".into(), self.upstream_failovers.load(Relaxed)),
            ("singleflight-merged".into(), self.singleflight_merged.load(Relaxed)),
            ("rate-limited-drops".into(), self.rate_limited.load(Relaxed)),
            ("recursion-refused".into(), self.recursion_refused.load(Relaxed)),
            ("zone-reloads".into(), self.zone_reloads.load(Relaxed)),
        ];
        for (rc, c) in self.rcodes.iter().enumerate() {
            let v = c.load(Relaxed);
            if v > 0 {
                out.push((format!("responses-rcode-{rc}"), v));
            }
        }
        let count = self.latency.count.load(Relaxed);
        out.push(("latency-count".into(), count));
        out.push((
            "latency-avg-us".into(),
            if count == 0 { 0 } else { self.latency.sum_us.load(Relaxed) / count },
        ));
        for (i, le) in BUCKETS_US.iter().enumerate() {
            out.push((format!("latency-le-{le}us"), self.latency.buckets[i].load(Relaxed)));
        }
        out.push(("latency-overflow".into(), self.latency.overflow.load(Relaxed)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_counts() {
        let m = Metrics::new();
        Metrics::inc(&m.queries_udp);
        m.observe_rcode(3);
        m.observe_latency(Duration::from_micros(50));
        m.observe_latency(Duration::from_micros(50));

        let snap = m.snapshot();
        let get = |k: &str| snap.iter().find(|(n, _)| n == k).map(|(_, v)| *v);
        assert_eq!(get("queries-udp"), Some(1));
        assert_eq!(get("responses-rcode-3"), Some(1));
        assert_eq!(get("latency-count"), Some(2));
        assert_eq!(get("latency-avg-us"), Some(50));
        assert_eq!(get("latency-le-100us"), Some(2));
        assert_eq!(get("responses-rcode-0"), None, "zero counters omitted");
    }
}
