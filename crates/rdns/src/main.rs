//! rdns — a DNS server (authoritative + caching forwarder) with a
//! from-scratch RFC 1035 implementation and a PowerDNS-style management API.

mod api;
mod config;
mod server;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::collections::HashMap;

use clap::Parser;
use dns_guard::{Acl, RateLimiter};
use dns_metrics::Metrics;
use dns_proto::name::DnsName;
use dns_resolver::{Resolver, ResolverOptions, Rpz};
use dns_xfr::Secondary;
use dns_zone::Zone;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rdns", version, about)]
struct Args {
    /// TOML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override the configured listen address
    #[arg(short, long)]
    listen: Option<std::net::SocketAddr>,

    /// Additional zone file(s)
    #[arg(short, long)]
    zone: Vec<PathBuf>,

    /// Disable forwarding regardless of configuration
    #[arg(long)]
    no_forward: bool,
}

fn load_zones(explicit: &[PathBuf], zone_dir: Option<&Path>) -> Result<Vec<Zone>, String> {
    let mut paths: Vec<PathBuf> = explicit.to_vec();
    if let Some(dir) = zone_dir {
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "zone") {
                paths.push(path);
            }
        }
    }
    let mut zones: Vec<Zone> = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let zone =
            dns_zone::parse_zone_file(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if zones.iter().any(|z| z.origin == zone.origin) {
            return Err(format!("{}: duplicate zone {}", path.display(), zone.origin));
        }
        info!("loaded zone {} ({} records) from {}", zone.origin, zone.record_count, path.display());
        zones.push(zone);
    }
    Ok(zones)
}

fn load_rpz(cfg: &config::Config) -> Result<Rpz, String> {
    let Some(path) = &cfg.rpz.file else {
        return Ok(Rpz::default());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rpz = Rpz::parse(&text)?;
    info!("loaded {} rpz rule(s) from {}", rpz.len(), path.display());
    Ok(rpz)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_keyring(cfg: &config::Config) -> Result<dns_tsig::KeyRing, String> {
    let mut ring = dns_tsig::KeyRing::default();
    for k in &cfg.tsig_keys {
        let algo = match k.algorithm.to_ascii_lowercase().as_str() {
            "hmac-sha256" => dns_tsig::Algorithm::HmacSha256,
            "hmac-sha512" => dns_tsig::Algorithm::HmacSha512,
            other => return Err(format!("unknown tsig algorithm '{other}'")),
        };
        ring.insert(dns_tsig::TsigKey::new(&k.name, algo, &k.secret)?);
        info!("loaded tsig key {}", k.name);
    }
    Ok(ring)
}

/// Load the Ed25519 signing seed, generating and persisting one if absent.
fn load_dnssec_key(cfg: &config::Config) -> Result<Option<(dns_dnssec::DnssecKey, Vec<DnsName>)>, String> {
    if cfg.dnssec.zones.is_empty() {
        return Ok(None);
    }
    let origins: Vec<DnsName> = cfg
        .dnssec
        .zones
        .iter()
        .map(|z| DnsName::parse_str(z).map_err(|e| format!("dnssec zone '{z}': {e}")))
        .collect::<Result<_, _>>()?;
    // The signer name is only used inside RRSIG/DS; any signed origin works as
    // the key owner. Use the first configured zone.
    let signer = origins[0].clone();

    let seed = match &cfg.dnssec.key_file {
        Some(path) if path.exists() => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            decode_seed(text.trim()).ok_or_else(|| format!("{}: bad base64 seed", path.display()))?
        }
        maybe_path => {
            let (key, seed) = dns_dnssec::DnssecKey::generate(signer.clone())?;
            if let Some(path) = maybe_path {
                std::fs::write(path, base64_encode(&seed))
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                info!("generated new DNSSEC key at {}", path.display());
            }
            let key_tag = key.key_tag();
            info!("DNSSEC key tag {key_tag}; DS to publish at parent:\n{}", key.ds_presentation());
            return Ok(Some((key, origins)));
        }
    };
    let mut seed_arr = [0u8; 32];
    if seed.len() != 32 {
        return Err("dnssec seed must be 32 bytes".into());
    }
    seed_arr.copy_from_slice(&seed);
    let key = dns_dnssec::DnssecKey::from_seed(&seed_arr, signer)?;
    info!("DNSSEC key tag {}; DS to publish at parent:\n{}", key.key_tag(), key.ds_presentation());
    Ok(Some((key, origins)))
}

fn base64_encode(data: &[u8]) -> String {
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

fn decode_seed(s: &str) -> Option<Vec<u8>> {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rdns=info")),
        )
        .init();

    let args = Args::parse();
    let mut cfg = config::load(args.config.as_deref())?;
    if let Some(listen) = args.listen {
        cfg.listen = listen;
    }
    cfg.zones.extend(args.zone.clone());
    if args.no_forward {
        cfg.recursion.enabled = false;
    }

    let metrics = Arc::new(Metrics::new());
    let zones = load_zones(&cfg.zones, cfg.zone_dir.as_deref())?;
    let upstreams = if cfg.recursion.enabled { cfg.recursion.upstreams.clone() } else { vec![] };
    let acl = Acl::parse(&cfg.recursion.allow)?;
    let transfer_acl = Acl::parse(&cfg.transfer.allow)?;
    let limiter = (cfg.rate_limit.qps > 0)
        .then(|| RateLimiter::new(cfg.rate_limit.qps, cfg.rate_limit.burst));

    let mut forwards = Vec::new();
    for f in &cfg.forwards {
        let zone = DnsName::parse_str(&f.zone).map_err(|e| format!("forward zone: {e}"))?;
        info!("forward zone {zone} -> {:?}", f.upstreams);
        forwards.push((zone, f.upstreams.clone()));
    }
    let rpz = load_rpz(&cfg)?;
    let keyring = build_keyring(&cfg)?;
    let journal = Arc::new(dns_xfr::Journal::default());

    let resolver = Arc::new(Resolver::new(
        ResolverOptions {
            zones,
            upstreams: upstreams.clone(),
            forwards,
            cache_size: cfg.cache.max_entries,
            rpz,
            signed: Default::default(),
        },
        metrics.clone(),
    ));

    // DNSSEC: load/generate the signing key and sign the configured zones.
    let dnssec = load_dnssec_key(&cfg)?.map(|(k, o)| (Arc::new(k), o));
    let validity = cfg.dnssec.validity_days * 86_400;
    if let Some((key, origins)) = &dnssec {
        resolver.resign(key, origins, unix_now(), validity);
        info!("signed {} zone(s) with DNSSEC", origins.len());
    }

    // Secondary zones: one refresh task per zone, kickable via NOTIFY.
    let mut secondaries: HashMap<DnsName, Arc<Secondary>> = HashMap::new();
    for sc in &cfg.secondaries {
        let origin = DnsName::parse_str(&sc.zone).map_err(|e| format!("secondary zone: {e}"))?;
        let tsig_key = sc
            .tsig_key
            .as_ref()
            .map(|name| {
                cfg.tsig_keys
                    .iter()
                    .find(|k| k.name == *name)
                    .ok_or_else(|| format!("secondary {origin}: unknown tsig key '{name}'"))
                    .and_then(|k| {
                        let algo = match k.algorithm.to_ascii_lowercase().as_str() {
                            "hmac-sha512" => dns_tsig::Algorithm::HmacSha512,
                            _ => dns_tsig::Algorithm::HmacSha256,
                        };
                        dns_tsig::TsigKey::new(&k.name, algo, &k.secret)
                    })
            })
            .transpose()?;
        let sec = Arc::new(Secondary {
            origin: origin.clone(),
            primaries: sc.primaries.clone(),
            tsig_key,
            kick: tokio::sync::Notify::new(),
        });
        info!("secondary zone {origin} from {:?}", sc.primaries);
        secondaries.insert(origin, sec.clone());
        tokio::spawn(dns_xfr::run_secondary(sec, resolver.clone(), metrics.clone()));
    }

    let require_tsig = cfg
        .transfer
        .require_tsig
        .as_ref()
        .map(|n| DnsName::parse_str(n).map_err(|e| format!("transfer.require_tsig: {e}")))
        .transpose()?;

    let ctx = Arc::new(server::ServerCtx {
        resolver: resolver.clone(),
        metrics: metrics.clone(),
        acl,
        limiter,
        query_log: cfg.query_log,
        transfer_acl,
        secondaries,
        journal: journal.clone(),
        tsig_keys: keyring,
        require_tsig,
    });

    let workers = if cfg.workers == 0 {
        std::thread::available_parallelism().map(usize::from).unwrap_or(4)
    } else {
        cfg.workers
    };
    for sock in server::reuseport_udp_sockets(cfg.listen, workers)? {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = server::run_udp_worker(sock, ctx).await {
                error!("udp worker died: {e}");
            }
        });
    }
    let tcp = TcpListener::bind(cfg.listen).await?;
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = server::run_tcp(tcp, ctx).await {
                error!("tcp listener died: {e}");
            }
        });
    }

    // DNS-over-TLS and DNS-over-HTTPS.
    if let Some(tls_cfg) = &cfg.tls {
        if tls_cfg.dot_listen.is_some() || tls_cfg.doh_listen.is_some() {
            let acceptor = dns_tls::acceptor(
                tls_cfg.cert.as_deref(),
                tls_cfg.key.as_deref(),
                &tls_cfg.self_signed_names,
            )?;
            if let Some(addr) = tls_cfg.dot_listen {
                let listener = TcpListener::bind(addr).await?;
                let (acc, ctx) = (acceptor.clone(), ctx.clone());
                tokio::spawn(async move {
                    if let Err(e) = server::run_dot(listener, acc, ctx).await {
                        error!("dot listener died: {e}");
                    }
                });
                info!("DNS-over-TLS on {addr}");
            }
            if let Some(addr) = tls_cfg.doh_listen {
                let listener = TcpListener::bind(addr).await?;
                let (acc, ctx) = (acceptor.clone(), ctx.clone());
                tokio::spawn(async move {
                    if let Err(e) = server::run_doh(listener, acc, ctx).await {
                        error!("doh listener died: {e}");
                    }
                });
                info!("DNS-over-HTTPS on https://{addr}/dns-query");
            }
        }
    }

    if let Some(api_cfg) = &cfg.api {
        let listener = TcpListener::bind(api_cfg.listen).await?;
        let api_ctx = Arc::new(api::ApiCtx {
            resolver: resolver.clone(),
            metrics: metrics.clone(),
            key: api_cfg.key.clone(),
            zone_dir: cfg.zone_dir.clone(),
            notify_targets: cfg.transfer.notify.clone(),
            journal: journal.clone(),
            dnssec: dnssec.as_ref().map(|(k, o)| (k.clone(), o.clone(), validity)),
            write_lock: tokio::sync::Mutex::new(()),
        });
        tokio::spawn(async move {
            if let Err(e) = api::run(listener, api_ctx).await {
                error!("api listener died: {e}");
            }
        });
        info!("management api on http://{}", api_cfg.listen);
    }

    info!(
        "listening on {} (udp x{workers} + tcp), recursion: {}",
        cfg.listen,
        if upstreams.is_empty() {
            "disabled".to_string()
        } else {
            format!("{upstreams:?} for {:?}", cfg.recursion.allow)
        }
    );

    // SIGHUP reloads zones from disk; SIGTERM / ctrl-c shut down.
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = hup.recv() => {
                match load_zones(&cfg.zones, cfg.zone_dir.as_deref()) {
                    Ok(zones) => {
                        resolver.set_zones(zones);
                        Metrics::inc(&metrics.zone_reloads);
                        info!("zones reloaded");
                    }
                    Err(e) => warn!("zone reload failed, keeping current zones: {e}"),
                }
                match load_rpz(&cfg) {
                    Ok(rpz) => resolver.set_rpz(rpz),
                    Err(e) => warn!("rpz reload failed, keeping current rules: {e}"),
                }
                if let Some((key, origins)) = &dnssec {
                    resolver.resign(key, origins, unix_now(), validity);
                    info!("re-signed {} DNSSEC zone(s)", origins.len());
                }
            }
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutting down");
    Ok(())
}
