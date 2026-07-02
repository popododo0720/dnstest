//! Zone transfers (RFC 5936 AXFR, RFC 1996 NOTIFY) and the secondary-zone
//! refresh loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dns_metrics::Metrics;
use dns_proto::message::{
    CLASS_IN, Flags, Message, OPCODE_NOTIFY, Question, RData, TYPE_AXFR, TYPE_SOA,
};
use dns_proto::name::DnsName;
use dns_resolver::Resolver;
use dns_zone::Zone;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{info, warn};

const XFR_TIMEOUT: Duration = Duration::from_secs(15);
const SOA_TIMEOUT: Duration = Duration::from_secs(3);
/// Records per AXFR response message (interop-friendly chunking).
const AXFR_CHUNK: usize = 100;
/// Bounds for the SOA-driven refresh interval.
const REFRESH_MIN: u64 = 15;
const REFRESH_MAX: u64 = 86_400;
/// Retry interval while a secondary has no data or its primaries are down.
const RETRY: u64 = 60;

/// Build the framed (2-byte length prefixed) TCP messages answering an AXFR:
/// SOA, all other records, closing SOA.
pub fn axfr_messages(zone: &Zone, query: &Message) -> Vec<Vec<u8>> {
    let mut records = zone.all_records();
    records.push(zone.soa.clone());

    records
        .chunks(AXFR_CHUNK)
        .map(|chunk| {
            let mut m = Message::response_to(query);
            m.flags.aa = true;
            m.answers = chunk.to_vec();
            let wire = m.encode();
            let mut framed = Vec::with_capacity(wire.len() + 2);
            framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            framed.extend_from_slice(&wire);
            framed
        })
        .collect()
}

/// Pull a zone from a primary over TCP.
pub async fn axfr_pull(primary: SocketAddr, origin: &DnsName) -> Result<Zone, String> {
    timeout(XFR_TIMEOUT, async {
        let mut query = Message::new(xfr_id(), Flags::default());
        query.questions.push(Question {
            qname: origin.clone(),
            qtype: TYPE_AXFR,
            qclass: CLASS_IN,
        });
        let wire = query.encode();

        let mut stream = TcpStream::connect(primary).await.map_err(|e| e.to_string())?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(&wire);
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;

        let mut records = Vec::new();
        let mut soa_seen = 0u32;
        // Stream messages until the closing SOA.
        while soa_seen < 2 {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await.map_err(|e| e.to_string())?;
            let m = Message::parse(&data).map_err(|e| format!("bad axfr message: {e}"))?;
            if m.id != query.id || !m.flags.qr {
                return Err("axfr reply does not match query".into());
            }
            if m.flags.rcode != 0 {
                return Err(format!("axfr refused (rcode {})", m.flags.rcode));
            }
            if m.answers.is_empty() && records.is_empty() && soa_seen == 0 {
                return Err("axfr stream carried no records".into());
            }
            for r in m.answers {
                if r.rtype() == TYPE_SOA {
                    soa_seen += 1;
                    if soa_seen == 2 {
                        break; // closing SOA is not part of the zone data
                    }
                }
                records.push(r);
            }
        }
        Zone::from_records(origin.clone(), records)
    })
    .await
    .map_err(|_| "axfr timed out".to_string())?
}

/// Ask a primary for the zone's current serial (UDP SOA query).
pub async fn query_soa_serial(primary: SocketAddr, origin: &DnsName) -> Result<u32, String> {
    timeout(SOA_TIMEOUT, async {
        let mut query = Message::new(xfr_id(), Flags::default());
        query.questions.push(Question {
            qname: origin.clone(),
            qtype: TYPE_SOA,
            qclass: CLASS_IN,
        });
        let bind: SocketAddr =
            if primary.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        sock.connect(primary).await.map_err(|e| e.to_string())?;
        sock.send(&query.encode()).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 2048];
        let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
        let m = Message::parse(&buf[..n]).map_err(|e| e.to_string())?;
        if m.id != query.id || !m.flags.qr {
            return Err("soa reply does not match query".into());
        }
        m.answers
            .iter()
            .find_map(|r| match &r.rdata {
                RData::Soa(soa) if r.name == *origin => Some(soa.serial),
                _ => None,
            })
            .ok_or_else(|| "no SOA in reply".into())
    })
    .await
    .map_err(|_| "soa query timed out".to_string())?
}

/// Fire-and-forget NOTIFY (RFC 1996) telling a secondary the zone changed.
pub async fn send_notify(target: SocketAddr, origin: &DnsName) -> Result<(), String> {
    let mut msg = Message::new(
        xfr_id(),
        Flags { opcode: OPCODE_NOTIFY, aa: true, ..Flags::default() },
    );
    msg.questions.push(Question { qname: origin.clone(), qtype: TYPE_SOA, qclass: CLASS_IN });
    let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.send_to(&msg.encode(), target).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// A zone this server mirrors from primaries.
pub struct Secondary {
    pub origin: DnsName,
    pub primaries: Vec<SocketAddr>,
    /// Poked by incoming NOTIFYs to refresh immediately.
    pub kick: tokio::sync::Notify,
}

/// RFC 1982 serial arithmetic: is `a` newer than `b`?
fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

/// Refresh loop for one secondary zone: poll the primaries' SOA serial (or
/// wake on NOTIFY) and AXFR when the zone is missing or outdated.
pub async fn run_secondary(sec: Arc<Secondary>, resolver: Arc<Resolver>, metrics: Arc<Metrics>) {
    loop {
        let current = resolver
            .zones()
            .iter()
            .find(|z| z.origin == sec.origin)
            .map(|z| match &z.soa.rdata {
                RData::Soa(soa) => soa.serial,
                _ => 0,
            });

        let mut refresh = RETRY;
        for &primary in &sec.primaries {
            match query_soa_serial(primary, &sec.origin).await {
                Ok(serial) if current.is_none_or(|cur| serial_gt(serial, cur)) => {
                    match axfr_pull(primary, &sec.origin).await {
                        Ok(zone) => {
                            info!(
                                "secondary {}: transferred serial {serial} from {primary} ({} records)",
                                sec.origin, zone.record_count
                            );
                            refresh = zone_refresh(&zone);
                            resolver.upsert_zone(zone);
                            Metrics::inc(&metrics.axfr_in);
                        }
                        Err(e) => {
                            warn!("secondary {}: axfr from {primary} failed: {e}", sec.origin);
                            continue;
                        }
                    }
                    break;
                }
                Ok(_) => {
                    // Up to date; poll again after the zone's refresh interval.
                    if let Some(zone) =
                        resolver.zones().iter().find(|z| z.origin == sec.origin)
                    {
                        refresh = zone_refresh(zone);
                    }
                    break;
                }
                Err(e) => {
                    warn!("secondary {}: soa check at {primary} failed: {e}", sec.origin);
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(refresh)) => {}
            _ = sec.kick.notified() => {
                info!("secondary {}: refresh kicked by NOTIFY", sec.origin);
            }
        }
    }
}

fn zone_refresh(zone: &Zone) -> u64 {
    match &zone.soa.rdata {
        RData::Soa(soa) => (soa.refresh as u64).clamp(REFRESH_MIN, REFRESH_MAX),
        _ => RETRY,
    }
}

fn xfr_id() -> u16 {
    // Ids here protect against cross-talk, not off-path attackers (transfers
    // are TCP or ACLed); a time-derived id is sufficient.
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_zone::parse_zone_file;

    #[test]
    fn serial_arithmetic() {
        assert!(serial_gt(2, 1));
        assert!(!serial_gt(1, 2));
        assert!(!serial_gt(5, 5));
        // Wraparound: 1 is newer than 0xFFFF_FFFF.
        assert!(serial_gt(1, u32::MAX));
        assert!(!serial_gt(u32::MAX, 1));
    }

    #[test]
    fn axfr_messages_bracket_with_soa() {
        let zone = parse_zone_file(
            "$ORIGIN t.\n@ IN SOA ns h 7 2 3 4 5\n@ IN NS ns\nns IN A 1.2.3.4\n",
        )
        .unwrap();
        let mut query = Message::new(9, Flags::default());
        query.questions.push(Question {
            qname: zone.origin.clone(),
            qtype: TYPE_AXFR,
            qclass: CLASS_IN,
        });
        let frames = axfr_messages(&zone, &query);
        assert_eq!(frames.len(), 1);
        let m = Message::parse(&frames[0][2..]).unwrap();
        assert_eq!(m.answers.len(), 4); // SOA, NS, A, closing SOA
        assert_eq!(m.answers.first().unwrap().rtype(), TYPE_SOA);
        assert_eq!(m.answers.last().unwrap().rtype(), TYPE_SOA);
    }
}
