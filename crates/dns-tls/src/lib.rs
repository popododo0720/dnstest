//! TLS setup for DNS-over-TLS (RFC 7858) and helpers for DNS-over-HTTPS
//! (RFC 8484). The actual DNS serve loops live in the server binary; this
//! crate owns certificate handling and the DoH HTTP codec so those concerns
//! stay out of the transport code.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Build a TLS acceptor from PEM cert+key files, or generate a self-signed
/// certificate for the given DNS names when no files are provided (dev/lab).
pub fn acceptor(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    self_signed_names: &[String],
) -> Result<TlsAcceptor, String> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_pem(c, k)?,
        _ => generate_self_signed(self_signed_names)?,
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("cannot read {}: {e}", cert_path.display()))?;
    let key_pem =
        std::fs::read(key_path).map_err(|e| format!("cannot read {}: {e}", key_path.display()))?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("bad certificate pem: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates in cert file".into());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| format!("bad key pem: {e}"))?
        .ok_or("no private key in key file")?;
    Ok((certs, key))
}

fn generate_self_signed(
    names: &[String],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let names = if names.is_empty() { vec!["localhost".to_string()] } else { names.to_vec() };
    let cert = rcgen::generate_simple_self_signed(names).map_err(|e| format!("rcgen: {e}"))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| format!("key der: {e}"))?;
    Ok((vec![cert_der], key_der))
}

/// A parsed DoH request: the DNS query wire bytes from either a
/// `GET ?dns=<base64url>` or a `POST` with `application/dns-message`.
pub struct DohRequest {
    pub dns: Vec<u8>,
}

/// Parse the HTTP request head + body for a DoH query (RFC 8484 §4.1).
/// Returns None for anything that is not a well-formed /dns-query request.
pub fn parse_doh(head: &str, body: &[u8]) -> Option<DohRequest> {
    let mut req_line = head.lines().next()?.split_whitespace();
    let method = req_line.next()?;
    let target = req_line.next()?;
    let path = target.split('?').next().unwrap_or(target);
    if !path.ends_with("/dns-query") {
        return None;
    }
    match method {
        "POST" => Some(DohRequest { dns: body.to_vec() }),
        "GET" => {
            let query = target.split_once('?')?.1;
            let dns_param = query.split('&').find_map(|kv| kv.strip_prefix("dns="))?;
            Some(DohRequest { dns: base64url_decode(dns_param)? })
        }
        _ => None,
    }
}

/// Format a DoH HTTP/1.1 response carrying a DNS message.
pub fn doh_response(dns: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\n\r\n",
        dns.len()
    )
    .into_bytes();
    out.extend_from_slice(dns);
    out
}

pub fn http_error(status: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

/// RFC 4648 §5 base64url decode, no padding.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_acceptor_builds() {
        assert!(acceptor(None, None, &["dns.example".into()]).is_ok());
    }

    #[test]
    fn doh_get_extracts_dns() {
        // base64url of bytes [0xAB, 0xCD] is "q80"
        let head = "GET /dns-query?dns=q80 HTTP/1.1\r\nHost: x\r\n\r\n";
        let req = parse_doh(head, b"").expect("valid GET");
        assert_eq!(req.dns, vec![0xAB, 0xCD]);
    }

    #[test]
    fn doh_post_uses_body() {
        let head = "POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\n\r\n";
        let req = parse_doh(head, &[1, 2, 3]).expect("valid POST");
        assert_eq!(req.dns, vec![1, 2, 3]);
    }

    #[test]
    fn doh_rejects_other_paths() {
        assert!(parse_doh("GET /favicon.ico HTTP/1.1\r\n\r\n", b"").is_none());
        assert!(parse_doh("PUT /dns-query HTTP/1.1\r\n\r\n", b"").is_none());
    }

    #[test]
    fn response_has_dns_content_type() {
        let r = doh_response(&[9, 9]);
        let s = String::from_utf8_lossy(&r);
        assert!(s.contains("application/dns-message"));
        assert!(s.contains("Content-Length: 2"));
        assert!(r.ends_with(&[9, 9]));
    }
}
