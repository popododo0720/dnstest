//! TOML configuration with CLI overrides.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// DNS listen address (UDP and TCP).
    pub listen: SocketAddr,
    /// UDP worker count; 0 means one per CPU core.
    pub workers: usize,
    /// Explicit zone files.
    pub zones: Vec<PathBuf>,
    /// Directory of `*.zone` files; also where API changes are persisted.
    pub zone_dir: Option<PathBuf>,
    /// Log every query at info level.
    pub query_log: bool,
    pub recursion: Recursion,
    pub cache: CacheCfg,
    pub rate_limit: RateLimitCfg,
    /// Management REST API; absent = disabled.
    pub api: Option<ApiCfg>,
    pub transfer: TransferCfg,
    /// Zones mirrored from primaries via AXFR.
    #[serde(rename = "secondary")]
    pub secondaries: Vec<SecondaryCfg>,
    /// Conditional forwarding: send matching queries to dedicated upstreams.
    #[serde(rename = "forward")]
    pub forwards: Vec<ForwardCfg>,
    pub rpz: RpzCfg,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:5300".parse().unwrap(),
            workers: 0,
            zones: Vec::new(),
            zone_dir: None,
            query_log: true,
            recursion: Recursion::default(),
            cache: CacheCfg::default(),
            rate_limit: RateLimitCfg::default(),
            api: None,
            transfer: TransferCfg::default(),
            secondaries: Vec::new(),
            forwards: Vec::new(),
            rpz: RpzCfg::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferCfg {
    /// Networks allowed to AXFR our zones; empty = transfers denied.
    pub allow: Vec<String>,
    /// Secondaries to NOTIFY when a zone changes.
    pub notify: Vec<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryCfg {
    pub zone: String,
    pub primaries: Vec<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardCfg {
    pub zone: String,
    pub upstreams: Vec<SocketAddr>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RpzCfg {
    /// Blocklist file: `domain` (NXDOMAIN) or `domain address` (sinkhole).
    pub file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Recursion {
    pub enabled: bool,
    /// Tried in order; the first healthy upstream becomes preferred.
    pub upstreams: Vec<SocketAddr>,
    /// Client networks allowed to use recursion (open-resolver protection).
    pub allow: Vec<String>,
}

impl Default for Recursion {
    fn default() -> Self {
        Recursion {
            enabled: true,
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            allow: vec!["127.0.0.0/8".into(), "::1/128".into()],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheCfg {
    pub max_entries: usize,
}

impl Default for CacheCfg {
    fn default() -> Self {
        CacheCfg { max_entries: 100_000 }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitCfg {
    /// Per-client queries per second; 0 disables rate limiting.
    pub qps: u32,
    /// Bucket size; defaults to `qps` when smaller.
    pub burst: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCfg {
    pub listen: SocketAddr,
    /// Required in the X-API-Key header on every /api request.
    pub key: String,
}

pub fn load(path: Option<&Path>) -> Result<Config, String> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
