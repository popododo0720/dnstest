//! rdns — a DNS server (authoritative + caching forwarder) with a
//! from-scratch RFC 1035 implementation and a management API.

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

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
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

/// Load (or generate) the DNSSEC signing keys. The key file holds one
/// `alg:base64` line per key; a bare KSK is generated and persisted when the
/// file is absent. Lines may be prefixed `ksk ` or `zsk ` to set the role.
fn load_dnssec_keys(
    cfg: &config::Config,
) -> Result<Option<(Vec<dns_dnssec::DnssecKey>, Vec<DnsName>)>, String> {
    if cfg.dnssec.zones.is_empty() {
        return Ok(None);
    }
    let origins: Vec<DnsName> = cfg
        .dnssec
        .zones
        .iter()
        .map(|z| DnsName::parse_str(z).map_err(|e| format!("dnssec zone '{z}': {e}")))
        .collect::<Result<_, _>>()?;
    let signer = origins[0].clone();
    let alg = match cfg.dnssec.algorithm.to_ascii_lowercase().as_str() {
        "ed25519" => dns_dnssec::ALG_ED25519,
        "ecdsap256" | "ecdsa" => dns_dnssec::ALG_ECDSAP256,
        "rsasha256" | "rsa" => dns_dnssec::ALG_RSASHA256,
        other => return Err(format!("unknown dnssec algorithm '{other}'")),
    };

    let mut keys = Vec::new();
    match &cfg.dnssec.key_file {
        Some(path) if path.exists() => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let (ksk, material) = match line.split_once(' ') {
                    Some(("ksk", m)) => (true, m.trim()),
                    Some(("zsk", m)) => (false, m.trim()),
                    _ => (true, line), // bare line = combined KSK
                };
                keys.push(dns_dnssec::DnssecKey::from_material(signer.clone(), material, ksk)?);
            }
        }
        maybe_path => {
            let (key, material) = dns_dnssec::DnssecKey::generate(signer.clone(), alg, true)?;
            if let Some(path) = maybe_path {
                std::fs::write(path, format!("ksk {material}\n"))
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                info!("generated new DNSSEC key at {}", path.display());
            }
            keys.push(key);
        }
    }
    for k in &keys {
        info!(
            "DNSSEC {} key tag {}; DS to publish at parent:\n{}",
            if k.is_ksk() { "KSK" } else { "ZSK" },
            k.key_tag(),
            k.ds_presentation()
        );
    }
    Ok(Some((keys, origins)))
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
    let recursive = cfg.recursion.enabled
        && cfg.recursion.mode.eq_ignore_ascii_case("recursive");
    let upstreams = if cfg.recursion.enabled && !recursive {
        cfg.recursion.upstreams.clone()
    } else {
        vec![]
    };
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
    let journal = Arc::new(match &cfg.journal_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| format!("journal_dir: {e}"))?;
            info!("persistent IXFR journal in {}", dir.display());
            dns_xfr::Journal::with_dir(dir.clone())
        }
        None => dns_xfr::Journal::default(),
    });

    let resolver = Arc::new(Resolver::new(
        ResolverOptions {
            zones,
            upstreams: upstreams.clone(),
            forwards,
            cache_size: cfg.cache.max_entries,
            rpz,
            signed: Default::default(),
            validate: cfg.recursion.validate,
            recursive,
        },
        metrics.clone(),
    ));

    // DNSSEC: load/generate the signing key and sign the configured zones.
    let dnssec = load_dnssec_keys(&cfg)?.map(|(k, o)| (Arc::new(k), o));
    let validity = cfg.dnssec.validity_days * 86_400;
    let nsec3 = if cfg.dnssec.nsec3 {
        let salt = decode_hex(&cfg.dnssec.nsec3_salt)
            .ok_or_else(|| "dnssec.nsec3_salt must be hex".to_string())?;
        Some(dns_dnssec::nsec3::Nsec3Params { iterations: cfg.dnssec.nsec3_iterations, salt })
    } else {
        None
    };
    if let Some((keys, origins)) = &dnssec {
        resolver.resign(keys, origins, unix_now(), validity, nsec3.clone());
        info!(
            "signed {} zone(s) with {} DNSSEC key(s) ({})",
            origins.len(),
            keys.len(),
            if nsec3.is_some() { "NSEC3" } else { "NSEC" }
        );

        // Automatic re-signing before signatures expire: refresh at a third of
        // the validity window (RFC 6781 §4.1.1.1 refresh interval), so RRSIGs
        // are always renewed well ahead of expiry with no operator action.
        let interval = (validity / 3).max(3600);
        let (keys, origins, nsec3c) = (keys.clone(), origins.clone(), nsec3.clone());
        let (resolver_c, metrics_c) = (resolver.clone(), metrics.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                resolver_c.resign(&keys, &origins, unix_now(), validity, nsec3c.clone());
                dns_metrics::Metrics::inc(&metrics_c.zone_reloads);
                info!("DNSSEC: refreshed signatures for {} zone(s)", origins.len());
            }
        });
        info!("DNSSEC: auto re-sign every {}h", interval / 3600);
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

    // RFC 2136 dynamic updates: enabled when an allow-list is configured.
    let updates = if cfg.update.allow.is_empty() {
        None
    } else {
        let require_update_tsig = cfg
            .update
            .require_tsig
            .as_ref()
            .map(|n| DnsName::parse_str(n).map_err(|e| format!("update.require_tsig: {e}")))
            .transpose()?;
        info!("dynamic updates (RFC 2136) enabled for {:?}", cfg.update.allow);
        Some(server::UpdateCtx {
            acl: Acl::parse(&cfg.update.allow)?,
            require_tsig: require_update_tsig,
            zone_dir: cfg.zone_dir.clone(),
            notify_targets: cfg.transfer.notify.clone(),
            dnssec: dnssec.as_ref().map(|(k, o)| (k.clone(), o.clone(), validity, nsec3.clone())),
        })
    };

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
        updates,
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

    // DNS-over-TLS and DNS-over-HTTPS. DoT and DoH need different ALPN, so
    // each gets its own acceptor from the same certificate.
    if let Some(tls_cfg) = &cfg.tls {
        let cert = tls_cfg.cert.as_deref();
        let key = tls_cfg.key.as_deref();
        let names = &tls_cfg.self_signed_names;
        if let Some(addr) = tls_cfg.dot_listen {
            // DoT does not require ALPN.
            let acc = dns_tls::acceptor(cert, key, names, &[])?;
            let listener = TcpListener::bind(addr).await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = server::run_dot(listener, acc, ctx).await {
                    error!("dot listener died: {e}");
                }
            });
            info!("DNS-over-TLS on {addr}");
        }
        if let Some(addr) = tls_cfg.doh_listen {
            // Advertise HTTP/2 (preferred) and HTTP/1.1.
            let acc = dns_tls::acceptor(cert, key, names, &[b"h2", b"http/1.1"])?;
            let listener = TcpListener::bind(addr).await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = server::run_doh(listener, acc, ctx).await {
                    error!("doh listener died: {e}");
                }
            });
            info!("DNS-over-HTTPS (h2 + http/1.1) on https://{addr}/dns-query");
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
            dnssec: dnssec.as_ref().map(|(k, o)| (k.clone(), o.clone(), validity, nsec3.clone())),
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
                if let Some((keys, origins)) = &dnssec {
                    resolver.resign(keys, origins, unix_now(), validity, nsec3.clone());
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
