//! PowerDNS-style management REST API.
//!
//! ```text
//! GET    /api/v1/zones             list zones
//! POST   /api/v1/zones             create a zone (rrsets must include SOA)
//! GET    /api/v1/zones/{name}      zone detail with rrsets
//! PATCH  /api/v1/zones/{name}      rrset changes (changetype REPLACE|DELETE)
//! DELETE /api/v1/zones/{name}      remove a zone
//! GET    /api/v1/statistics        server counters
//! ```
//!
//! Every request must carry the configured key in `X-API-Key`. Changes are
//! applied atomically to the live zone set and persisted to `zone_dir` (when
//! configured) so they survive restarts and SIGHUP reloads.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dns_metrics::Metrics;
use dns_proto::message::{RData, type_name};
use dns_proto::name::DnsName;
use dns_resolver::Resolver;
use dns_zone::Zone;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

const MAX_BODY: usize = 1 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ApiCtx {
    pub resolver: Arc<Resolver>,
    pub metrics: Arc<Metrics>,
    pub key: String,
    pub zone_dir: Option<PathBuf>,
    /// Secondaries to NOTIFY after a change.
    pub notify_targets: Vec<std::net::SocketAddr>,
    /// Change journal, for IXFR after API edits.
    pub journal: Arc<dns_xfr::Journal>,
    /// DNSSEC signer + origins + validity; re-signs edited zones.
    pub dnssec: Option<(Arc<dns_dnssec::DnssecKey>, Vec<DnsName>, u64)>,
    /// Serializes writers; readers work on lock-free snapshots.
    pub write_lock: tokio::sync::Mutex<()>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// After a zone edit: record the change in the journal (for IXFR) and re-sign
/// if the zone is DNSSEC-signed.
fn after_change(ctx: &ApiCtx, old: Option<&Zone>, new: &Zone) {
    if let Some(old) = old {
        ctx.journal.record(old, new);
    }
    if let Some((key, origins, validity)) = &ctx.dnssec {
        if origins.contains(&new.origin) {
            ctx.resolver.resign(key, origins, unix_now(), *validity);
        }
    }
}

/// Tell configured secondaries the zone changed (fire-and-forget).
fn notify_secondaries(ctx: &ApiCtx, origin: &DnsName) {
    for &target in &ctx.notify_targets {
        let origin = origin.clone();
        let metrics = ctx.metrics.clone();
        tokio::spawn(async move {
            match dns_xfr::send_notify(target, &origin).await {
                Ok(()) => Metrics::inc(&metrics.notify_sent),
                Err(e) => warn!("notify {target} about {origin} failed: {e}"),
            }
        });
    }
}

#[derive(Serialize)]
struct ZoneSummary {
    name: String,
    serial: u32,
    records: usize,
}

#[derive(Serialize)]
struct RrsetOut {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    ttl: u32,
    records: Vec<String>,
}

#[derive(Serialize)]
struct ZoneDetail {
    name: String,
    serial: u32,
    rrsets: Vec<RrsetOut>,
}

#[derive(Deserialize)]
struct RrsetIn {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    changetype: Option<String>,
    #[serde(default)]
    records: Vec<String>,
}

#[derive(Deserialize)]
struct ZoneCreate {
    name: String,
    rrsets: Vec<RrsetIn>,
}

#[derive(Deserialize)]
struct ZonePatch {
    rrsets: Vec<RrsetIn>,
}

struct Reply {
    status: &'static str,
    body: String,
}

impl Reply {
    fn json(status: &'static str, body: String) -> Self {
        Reply { status, body }
    }

    fn ok(value: impl Serialize) -> Self {
        Self::json("200 OK", serde_json::to_string_pretty(&value).unwrap_or_default())
    }

    fn error(status: &'static str, msg: impl Into<String>) -> Self {
        Self::json(status, format!("{{\"error\":{}}}", serde_json::Value::from(msg.into())))
    }
}

pub async fn run(listener: TcpListener, ctx: Arc<ApiCtx>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = timeout(REQUEST_TIMEOUT, serve_conn(stream, ctx)).await {
                let _ = e;
                warn!("api connection from {peer} timed out");
            }
        });
    }
}

async fn serve_conn(mut stream: TcpStream, ctx: Arc<ApiCtx>) {
    let Some((method, path, headers, body)) = read_request(&mut stream).await else {
        return;
    };
    let authorized = header_value(&headers, "x-api-key").is_some_and(|k| k == ctx.key);
    let reply = if !authorized {
        Reply::error("401 Unauthorized", "missing or wrong X-API-Key")
    } else {
        route(&ctx, &method, &path, &body).await
    };
    let out = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply.status,
        reply.body.len(),
        reply.body
    );
    let _ = stream.write_all(out.as_bytes()).await;
}

/// Minimal HTTP/1.1 request reader: request line, headers, Content-Length body.
async fn read_request(stream: &mut TcpStream) -> Option<(String, String, String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: String = lines.collect::<Vec<_>>().join("\n");

    let content_length: usize = header_value(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return None;
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Some((method, path, headers, body))
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

async fn route(ctx: &ApiCtx, method: &str, path: &str, body: &[u8]) -> Reply {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, segments.as_slice()) {
        ("GET", ["api", "v1", "statistics"]) => statistics(ctx),
        ("GET", ["api", "v1", "zones"]) => list_zones(ctx),
        ("POST", ["api", "v1", "zones"]) => create_zone(ctx, body).await,
        ("GET", ["api", "v1", "zones", name]) => get_zone(ctx, name),
        ("PATCH", ["api", "v1", "zones", name]) => patch_zone(ctx, name, body).await,
        ("DELETE", ["api", "v1", "zones", name]) => delete_zone(ctx, name).await,
        ("GET" | "POST" | "PATCH" | "DELETE" | "PUT", _) => {
            Reply::error("404 Not Found", "no such endpoint")
        }
        _ => Reply::error("405 Method Not Allowed", "unsupported method"),
    }
}

fn statistics(ctx: &ApiCtx) -> Reply {
    let mut snap = ctx.metrics.snapshot();
    snap.push(("cache-entries".into(), ctx.resolver.cache_len() as u64));
    snap.push(("zones".into(), ctx.resolver.zones().len() as u64));
    let items: Vec<serde_json::Value> = snap
        .into_iter()
        .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
        .collect();
    Reply::ok(items)
}

fn zone_serial(zone: &Zone) -> u32 {
    match &zone.soa.rdata {
        RData::Soa(soa) => soa.serial,
        _ => 0,
    }
}

fn list_zones(ctx: &ApiCtx) -> Reply {
    let zones = ctx.resolver.zones();
    let out: Vec<ZoneSummary> = zones
        .iter()
        .map(|z| ZoneSummary {
            name: z.origin.to_string(),
            serial: zone_serial(z),
            records: z.record_count,
        })
        .collect();
    Reply::ok(out)
}

fn get_zone(ctx: &ApiCtx, name: &str) -> Reply {
    let Ok(origin) = DnsName::parse_str(name) else {
        return Reply::error("400 Bad Request", "invalid zone name");
    };
    let zones = ctx.resolver.zones();
    let Some(zone) = zones.iter().find(|z| z.origin == origin) else {
        return Reply::error("404 Not Found", "no such zone");
    };
    let rrsets = zone
        .rrsets()
        .into_iter()
        .map(|r| RrsetOut {
            name: r.name.to_string(),
            rtype: type_name(r.rtype),
            ttl: r.ttl,
            records: r.contents,
        })
        .collect();
    Reply::ok(ZoneDetail { name: zone.origin.to_string(), serial: zone_serial(zone), rrsets })
}

async fn create_zone(ctx: &ApiCtx, body: &[u8]) -> Reply {
    let req: ZoneCreate = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Reply::error("400 Bad Request", format!("bad json: {e}")),
    };
    let Ok(origin) = DnsName::parse_str(&req.name) else {
        return Reply::error("400 Bad Request", "invalid zone name");
    };

    let _guard = ctx.write_lock.lock().await;
    let current = ctx.resolver.zones();
    if current.iter().any(|z| z.origin == origin) {
        return Reply::error("409 Conflict", "zone already exists");
    }

    // Start from an empty shell, then apply the rrsets through the same
    // validated path PATCH uses. The SOA must come first so the shell can be
    // built around it.
    let Some(soa_in) = req.rrsets.iter().find(|r| r.rtype.eq_ignore_ascii_case("SOA")) else {
        return Reply::error("400 Bad Request", "zone must include an SOA rrset");
    };
    let soa_content = match soa_in.records.as_slice() {
        [one] => one,
        _ => return Reply::error("400 Bad Request", "SOA rrset must have exactly one record"),
    };
    let soa_rdata = match dns_zone::rdata_from_text("SOA", soa_content, &origin) {
        Ok(r) => r,
        Err(e) => return Reply::error("400 Bad Request", format!("bad SOA: {e}")),
    };
    let soa_record = dns_proto::message::Record {
        name: origin.clone(),
        class: dns_proto::message::CLASS_IN,
        ttl: soa_in.ttl.unwrap_or(3600),
        rdata: soa_rdata,
    };
    let mut zone = match Zone::from_records(origin.clone(), vec![soa_record]) {
        Ok(z) => z,
        Err(e) => return Reply::error("400 Bad Request", e),
    };
    for rrset in req.rrsets.iter().filter(|r| !r.rtype.eq_ignore_ascii_case("SOA")) {
        if let Err(e) = apply_rrset(&mut zone, rrset) {
            return Reply::error("400 Bad Request", e);
        }
    }

    let mut zones = current.as_ref().clone();
    zones.push(zone.clone());
    ctx.resolver.set_zones(zones);
    after_change(ctx, None, &zone);
    persist(ctx, &zone);
    notify_secondaries(ctx, &origin);
    info!("api: created zone {origin}");
    Reply::json("201 Created", serde_json::json!({"name": origin.to_string()}).to_string())
}

async fn patch_zone(ctx: &ApiCtx, name: &str, body: &[u8]) -> Reply {
    let req: ZonePatch = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Reply::error("400 Bad Request", format!("bad json: {e}")),
    };
    let Ok(origin) = DnsName::parse_str(name) else {
        return Reply::error("400 Bad Request", "invalid zone name");
    };

    let _guard = ctx.write_lock.lock().await;
    let current = ctx.resolver.zones();
    let Some(idx) = current.iter().position(|z| z.origin == origin) else {
        return Reply::error("404 Not Found", "no such zone");
    };

    let old = current[idx].clone();
    let mut zone = old.clone();
    for rrset in &req.rrsets {
        if let Err(e) = apply_rrset(&mut zone, rrset) {
            return Reply::error("400 Bad Request", e);
        }
    }
    zone.bump_serial();

    let mut zones = current.as_ref().clone();
    zones[idx] = zone.clone();
    ctx.resolver.set_zones(zones);
    after_change(ctx, Some(&old), &zone);
    persist(ctx, &zone);
    notify_secondaries(ctx, &origin);
    info!("api: patched zone {origin} ({} rrsets)", req.rrsets.len());
    Reply::ok(serde_json::json!({"name": origin.to_string(), "serial": zone_serial(&zone)}))
}

async fn delete_zone(ctx: &ApiCtx, name: &str) -> Reply {
    let Ok(origin) = DnsName::parse_str(name) else {
        return Reply::error("400 Bad Request", "invalid zone name");
    };
    let _guard = ctx.write_lock.lock().await;
    let current = ctx.resolver.zones();
    let Some(idx) = current.iter().position(|z| z.origin == origin) else {
        return Reply::error("404 Not Found", "no such zone");
    };
    let mut zones = current.as_ref().clone();
    zones.remove(idx);
    ctx.resolver.set_zones(zones);
    if let Some(path) = zone_path(ctx, &origin) {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!("api: cannot remove {}: {e}", path.display());
        }
    }
    info!("api: deleted zone {origin}");
    Reply::ok(serde_json::json!({"deleted": origin.to_string()}))
}

fn apply_rrset(zone: &mut Zone, rrset: &RrsetIn) -> Result<(), String> {
    let owner = DnsName::parse_str(&rrset.name).map_err(|e| format!("bad name: {e}"))?;
    let changetype = rrset.changetype.as_deref().unwrap_or("REPLACE");
    match changetype.to_ascii_uppercase().as_str() {
        "REPLACE" => {
            zone.replace_rrset(&owner, &rrset.rtype, rrset.ttl.unwrap_or(3600), &rrset.records)
        }
        "DELETE" => zone.delete_rrset(&owner, &rrset.rtype),
        other => Err(format!("unsupported changetype '{other}'")),
    }
}

fn zone_path(ctx: &ApiCtx, origin: &DnsName) -> Option<PathBuf> {
    let dir = ctx.zone_dir.as_ref()?;
    let stem = origin.to_string().trim_end_matches('.').to_string();
    Some(dir.join(format!("{stem}.zone")))
}

fn persist(ctx: &ApiCtx, zone: &Zone) {
    let Some(path) = zone_path(ctx, &zone.origin) else {
        warn!("api: no zone_dir configured, change to {} is in-memory only", zone.origin);
        return;
    };
    if let Err(e) = std::fs::write(&path, zone.to_zonefile()) {
        warn!("api: cannot persist {}: {e}", path.display());
    }
}
