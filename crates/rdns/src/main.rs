//! rdns — a DNS server (authoritative + caching forwarder) with a
//! from-scratch RFC 1035 implementation and a PowerDNS-style management API.

mod api;
mod config;
mod server;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use dns_guard::{Acl, RateLimiter};
use dns_metrics::Metrics;
use dns_resolver::Resolver;
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
    let limiter = (cfg.rate_limit.qps > 0)
        .then(|| RateLimiter::new(cfg.rate_limit.qps, cfg.rate_limit.burst));

    let resolver = Arc::new(Resolver::new(
        zones,
        upstreams.clone(),
        cfg.cache.max_entries,
        metrics.clone(),
    ));
    let ctx = Arc::new(server::ServerCtx {
        resolver: resolver.clone(),
        metrics: metrics.clone(),
        acl,
        limiter,
        query_log: cfg.query_log,
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
            }
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    info!("shutting down");
    Ok(())
}
