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
    /// Directory for persistent IXFR journals (survives restart).
    pub journal_dir: Option<PathBuf>,
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
    /// TSIG keys usable for transfers, indexed by name.
    #[serde(rename = "tsig_key")]
    pub tsig_keys: Vec<TsigKeyCfg>,
    pub dnssec: DnssecCfg,
    /// DNS-over-TLS / DNS-over-HTTPS; absent = disabled.
    pub tls: Option<TlsCfg>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:5300".parse().unwrap(),
            workers: 0,
            zones: Vec::new(),
            zone_dir: None,
            journal_dir: None,
            query_log: true,
            recursion: Recursion::default(),
            cache: CacheCfg::default(),
            rate_limit: RateLimitCfg::default(),
            api: None,
            transfer: TransferCfg::default(),
            secondaries: Vec::new(),
            forwards: Vec::new(),
            rpz: RpzCfg::default(),
            tsig_keys: Vec::new(),
            dnssec: DnssecCfg::default(),
            tls: None,
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
    /// Require this TSIG key name on AXFR/IXFR requests (empty = IP ACL only).
    pub require_tsig: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryCfg {
    pub zone: String,
    pub primaries: Vec<SocketAddr>,
    /// TSIG key name to sign transfer requests with.
    #[serde(default)]
    pub tsig_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyCfg {
    pub name: String,
    /// "hmac-sha256" (default) or "hmac-sha512".
    #[serde(default = "default_tsig_alg")]
    pub algorithm: String,
    /// Base64-encoded shared secret.
    pub secret: String,
}

fn default_tsig_alg() -> String {
    "hmac-sha256".into()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnssecCfg {
    /// File holding the signing key material (`alg:base64`). Auto-generated if
    /// missing. Multiple lines = multiple keys (KSK/ZSK, rollover).
    pub key_file: Option<PathBuf>,
    /// Zone origins to sign online.
    pub zones: Vec<String>,
    /// Signature validity window in days.
    #[serde(default = "default_validity_days")]
    pub validity_days: u64,
    /// Signing algorithm for auto-generated keys: "ecdsap256" or "ed25519".
    #[serde(default = "default_dnssec_alg")]
    pub algorithm: String,
    /// Use NSEC3 hashed denial instead of NSEC.
    #[serde(default)]
    pub nsec3: bool,
    /// NSEC3 hash iterations.
    #[serde(default)]
    pub nsec3_iterations: u16,
    /// NSEC3 salt as hex (empty = no salt).
    #[serde(default)]
    pub nsec3_salt: String,
}

fn default_dnssec_alg() -> String {
    "ecdsap256".into()
}

fn default_validity_days() -> u64 {
    14
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsCfg {
    /// PEM certificate chain; self-signed if omitted (dev only).
    pub cert: Option<PathBuf>,
    /// PEM private key.
    pub key: Option<PathBuf>,
    /// Names for the self-signed certificate.
    pub self_signed_names: Vec<String>,
    /// DNS-over-TLS listen address (RFC 7858, usually :853).
    pub dot_listen: Option<SocketAddr>,
    /// DNS-over-HTTPS listen address (RFC 8484).
    pub doh_listen: Option<SocketAddr>,
}

impl Default for TlsCfg {
    fn default() -> Self {
        TlsCfg {
            cert: None,
            key: None,
            self_signed_names: vec!["localhost".into()],
            dot_listen: None,
            doh_listen: None,
        }
    }
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
    /// Validate forwarded answers against the DNSSEC root trust anchor.
    #[serde(default)]
    pub validate: bool,
}

impl Default for Recursion {
    fn default() -> Self {
        Recursion {
            enabled: true,
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            allow: vec!["127.0.0.0/8".into(), "::1/128".into()],
            validate: false,
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
