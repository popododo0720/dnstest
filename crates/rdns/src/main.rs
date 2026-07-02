//! rdns — a DNS server (authoritative + caching forwarder) with a
//! from-scratch RFC 1035 wire-format implementation.

mod server;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;
use tracing_subscriber::EnvFilter;

use dns_resolver::Resolver;

#[derive(Parser, Debug)]
#[command(name = "rdns", version, about)]
struct Args {
    /// Address to listen on (both UDP and TCP)
    #[arg(short, long, default_value = "127.0.0.1:5300")]
    listen: SocketAddr,

    /// Upstream resolver for non-authoritative queries
    #[arg(short, long, default_value = "1.1.1.1:53")]
    upstream: SocketAddr,

    /// Authoritative-only mode: refuse anything outside the loaded zones
    #[arg(long)]
    no_forward: bool,

    /// Zone file(s) to serve authoritatively (repeatable)
    #[arg(short, long)]
    zone: Vec<PathBuf>,

    /// Maximum number of cached responses
    #[arg(long, default_value_t = 10_000)]
    cache_size: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rdns=info")),
        )
        .init();

    let args = Args::parse();

    let mut zones = Vec::new();
    for path in &args.zone {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let zone = dns_zone::parse_zone_file(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        info!(
            "loaded zone {} ({} records) from {}",
            zone.origin,
            zone.record_count,
            path.display()
        );
        zones.push(zone);
    }

    let upstream = (!args.no_forward).then_some(args.upstream);
    let resolver = Arc::new(Resolver::new(zones, upstream, args.cache_size));

    let udp = UdpSocket::bind(args.listen).await?;
    let tcp = TcpListener::bind(args.listen).await?;
    match upstream {
        Some(up) => info!("listening on {} (udp+tcp), forwarding to {up}", args.listen),
        None => info!("listening on {} (udp+tcp), authoritative only", args.listen),
    }

    tokio::select! {
        r = server::run_udp(udp, resolver.clone()) => r?,
        r = server::run_tcp(tcp, resolver) => r?,
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    Ok(())
}
