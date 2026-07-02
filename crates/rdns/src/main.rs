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

    let resolver = Arc::new(Resolver::new(
        ResolverOptions {
            zones,
            upstreams: upstreams.clone(),
            forwards,
            cache_size: cfg.cache.max_entries,
            rpz,
        },
        metrics.clone(),
    ));

    // Secondary zones: one refresh task per zone, kickable via NOTIFY.
    let mut secondaries: HashMap<DnsName, Arc<Secondary>> = HashMap::new();
    for sc in &cfg.secondaries {
        let origin = DnsName::parse_str(&sc.zone).map_err(|e| format!("secondary zone: {e}"))?;
        let sec = Arc::new(Secondary {
            origin: origin.clone(),
            primaries: sc.primaries.clone(),
            kick: tokio::sync::Notify::new(),
        });
        info!("secondary zone {origin} from {:?}", sc.primaries);
        secondaries.insert(origin, sec.clone());
        tokio::spawn(dns_xfr::run_secondary(sec, resolver.clone(), metrics.clone()));
    }

    let ctx = Arc::new(server::ServerCtx {
        resolver: resolver.clone(),
        metrics: metrics.clone(),
        acl,
        limiter,
        query_log: cfg.query_log,
        transfer_acl,
        secondaries,
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

    if let Some(api_cfg) = &cfg.api {
        let listener = TcpListener::bind(api_cfg.listen).await?;
        let api_ctx = Arc::new(api::ApiCtx {
            resolver: resolver.clone(),
            metrics: metrics.clone(),
            key: api_cfg.key.clone(),
            zone_dir: cfg.zone_dir.clone(),
            notify_targets: cfg.transfer.notify.clone(),
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
            }
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutting down");
    Ok(())
}
