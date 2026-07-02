//! Zone transfers (RFC 5936 AXFR, RFC 1996 NOTIFY) and the secondary-zone
//! refresh loop.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_metrics::Metrics;
use dns_proto::message::{
    CLASS_IN, Flags, Message, OPCODE_NOTIFY, Question, RData, Record, TYPE_AXFR, TYPE_SOA,
};
use dns_proto::name::DnsName;
use dns_resolver::Resolver;
use dns_tsig::TsigKey;
use dns_zone::Zone;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{info, warn};

/// Deltas kept per zone for incremental transfers.
const JOURNAL_DEPTH: usize = 64;

const XFR_TIMEOUT: Duration = Duration::from_secs(15);
const SOA_TIMEOUT: Duration = Duration::from_secs(3);
/// Records per AXFR response message (interop-friendly chunking).
const AXFR_CHUNK: usize = 100;
/// Bounds for the SOA-driven refresh interval.
const REFRESH_MIN: u64 = 15;
const REFRESH_MAX: u64 = 86_400;
/// Retry interval while a secondary has no data or its primaries are down.
const RETRY: u64 = 60;

/// Frame a record stream into length-prefixed TCP transfer messages.
fn frame_transfer(records: Vec<Record>, query: &Message) -> Vec<Vec<u8>> {
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

/// Build the messages answering an AXFR: SOA, all other records, closing SOA.
pub fn axfr_messages(zone: &Zone, query: &Message) -> Vec<Vec<u8>> {
    let mut records = zone.all_records();
    records.push(zone.soa.clone());
    frame_transfer(records, query)
}

fn zone_serial(zone: &Zone) -> u32 {
    match &zone.soa.rdata {
        RData::Soa(soa) => soa.serial,
        _ => 0,
    }
}

/// A single serial-to-serial change set.
#[derive(Clone)]
struct Diff {
    from: u32,
    to: u32,
    deleted: Vec<Record>,
    added: Vec<Record>,
}

/// Per-zone change history enabling incremental transfers (RFC 1995).
///
/// When a directory is configured the log is also appended to
/// `<origin>journal` on disk so IXFR survives restarts. The on-disk format is
/// a line-oriented text journal (one delta per `DELTA…END` block), which
/// round-trips through the same record text encoding zone files use.
#[derive(Default)]
pub struct Journal {
    zones: Mutex<HashMap<DnsName, VecDeque<Diff>>>,
    dir: Option<std::path::PathBuf>,
}

impl Journal {
    /// A journal that persists to `dir`, loading any existing history.
    pub fn with_dir(dir: std::path::PathBuf) -> Self {
        let mut zones: HashMap<DnsName, VecDeque<Diff>> = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "journal") {
                    if let Some((origin, diffs)) = load_journal_file(&path) {
                        zones.insert(origin, diffs);
                    }
                }
            }
        }
        Journal { zones: Mutex::new(zones), dir: Some(dir) }
    }

    fn journal_path(&self, origin: &DnsName) -> Option<std::path::PathBuf> {
        let stem = origin.to_string();
        let stem = stem.trim_end_matches('.');
        self.dir.as_ref().map(|d| d.join(format!("{stem}.journal")))
    }

    /// Record the change from `old` to `new` (called after every edit).
    pub fn record(&self, old: &Zone, new: &Zone) {
        let (from, to) = (zone_serial(old), zone_serial(new));
        if from == to {
            return;
        }
        let old_recs = old.all_records();
        let new_recs = new.all_records();
        let deleted: Vec<Record> =
            old_recs.iter().filter(|r| !new_recs.contains(r)).cloned().collect();
        let added: Vec<Record> =
            new_recs.iter().filter(|r| !old_recs.contains(r)).cloned().collect();
        let diff = Diff { from, to, deleted, added };

        if let Some(path) = self.journal_path(&new.origin) {
            if let Err(e) = append_diff(&path, &diff) {
                warn!("journal append for {} failed: {e}", new.origin);
            }
        }

        let mut map = self.zones.lock().unwrap();
        let log = map.entry(new.origin.clone()).or_default();
        log.push_back(diff);
        while log.len() > JOURNAL_DEPTH {
            log.pop_front();
        }
    }

    /// Chain of deltas taking `from_serial` up to the current serial, or None
    /// if the history does not reach back that far.
    fn chain(&self, origin: &DnsName, from_serial: u32, current: u32) -> Option<Vec<Diff>> {
        if from_serial == current {
            return Some(Vec::new());
        }
        let map = self.zones.lock().unwrap();
        let log = map.get(origin)?;
        let mut out = Vec::new();
        let mut serial = from_serial;
        while serial != current {
            let diff = log.iter().find(|d| d.from == serial)?.clone();
            serial = diff.to;
            out.push(diff);
            if out.len() > JOURNAL_DEPTH {
                return None; // loop guard
            }
        }
        Some(out)
    }
}

/// Answer an IXFR (RFC 1995). Falls back to a full AXFR-style transfer when
/// the requested serial is not in the journal.
pub fn ixfr_messages(
    zone: &Zone,
    query: &Message,
    client_serial: u32,
    journal: &Journal,
) -> Vec<Vec<u8>> {
    let current = zone_serial(zone);
    let Some(chain) = journal.chain(&zone.origin, client_serial, current) else {
        return axfr_messages(zone, query);
    };
    if chain.is_empty() {
        // Client already current: reply with just the SOA (RFC 1995 §2).
        return frame_transfer(vec![zone.soa.clone()], query);
    }

    // newSOA, [oldSOA, deletions, newerSOA, additions]..., newSOA
    let mut records = vec![zone.soa.clone()];
    for diff in chain {
        records.push(soa_with_serial(zone, diff.from));
        records.extend(diff.deleted);
        records.push(soa_with_serial(zone, diff.to));
        records.extend(diff.added);
    }
    records.push(zone.soa.clone());
    frame_transfer(records, query)
}

fn record_line(tag: &str, r: &Record) -> String {
    format!("{tag} {} {} {} {}\n", r.name, r.ttl, dns_proto::message::type_name(r.rtype()), r.rdata.text())
}

/// Parse a `DEL`/`ADD` journal line back into a Record (origin gives relative
/// name context, though journal names are always absolute).
fn parse_record_line(rest: &str, origin: &DnsName) -> Option<Record> {
    let mut it = rest.splitn(4, ' ');
    let name = DnsName::parse_str(it.next()?).ok()?;
    let ttl: u32 = it.next()?.parse().ok()?;
    let rtype = it.next()?;
    let content = it.next()?;
    let rdata = dns_zone::rdata_from_text(rtype, content, origin).ok()?;
    Some(Record { name, class: CLASS_IN, ttl, rdata })
}

/// Append one delta to the on-disk journal (create/append, line-buffered).
fn append_diff(path: &std::path::Path, diff: &Diff) -> std::io::Result<()> {
    use std::io::Write;
    let mut buf = String::new();
    buf.push_str(&format!("DELTA {} {}\n", diff.from, diff.to));
    for r in &diff.deleted {
        buf.push_str(&record_line("DEL", r));
    }
    for r in &diff.added {
        buf.push_str(&record_line("ADD", r));
    }
    buf.push_str("END\n");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(buf.as_bytes())
}

/// Load a persisted journal file back into deltas, capped at JOURNAL_DEPTH.
fn load_journal_file(path: &std::path::Path) -> Option<(DnsName, VecDeque<Diff>)> {
    let stem = path.file_stem()?.to_str()?;
    let origin = DnsName::parse_str(stem).ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    let mut diffs = VecDeque::new();
    let mut cur: Option<Diff> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("DELTA ") {
            let mut it = rest.split_whitespace();
            let from = it.next()?.parse().ok()?;
            let to = it.next()?.parse().ok()?;
            cur = Some(Diff { from, to, deleted: Vec::new(), added: Vec::new() });
        } else if let Some(rest) = line.strip_prefix("DEL ") {
            if let (Some(d), Some(r)) = (cur.as_mut(), parse_record_line(rest, &origin)) {
                d.deleted.push(r);
            }
        } else if let Some(rest) = line.strip_prefix("ADD ") {
            if let (Some(d), Some(r)) = (cur.as_mut(), parse_record_line(rest, &origin)) {
                d.added.push(r);
            }
        } else if line == "END" {
            if let Some(d) = cur.take() {
                diffs.push_back(d);
            }
        }
    }
    while diffs.len() > JOURNAL_DEPTH {
        diffs.pop_front();
    }
    Some((origin, diffs))
}

/// The zone's SOA record rewritten with a specific serial (for IXFR framing).
fn soa_with_serial(zone: &Zone, serial: u32) -> Record {
    let mut rec = zone.soa.clone();
    if let RData::Soa(soa) = &mut rec.rdata {
        soa.serial = serial;
    }
    rec
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode a request, TSIG-signing it when a key is present. Returns the wire
/// bytes and the request MAC (empty when unsigned).
fn encode_signed(query: &Message, key: Option<&TsigKey>) -> (Vec<u8>, Vec<u8>) {
    match key {
        Some(k) => dns_tsig::sign_request(query, k, now_secs()),
        None => (query.encode(), Vec::new()),
    }
}

/// Pull a zone from a primary over TCP, optionally TSIG-signed.
pub async fn axfr_pull(
    primary: SocketAddr,
    origin: &DnsName,
    key: Option<&TsigKey>,
) -> Result<Zone, String> {
    timeout(XFR_TIMEOUT, async {
        let mut query = Message::new(xfr_id(), Flags::default());
        query.questions.push(Question {
            qname: origin.clone(),
            qtype: TYPE_AXFR,
            qclass: CLASS_IN,
        });
        let (wire, request_mac) = encode_signed(&query, key);

        let mut stream = TcpStream::connect(primary).await.map_err(|e| e.to_string())?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(&wire);
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;

        let mut keyring = dns_tsig::KeyRing::default();
        if let Some(k) = key {
            keyring.insert(k.clone());
        }
        let mut prior_mac = request_mac;

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
            // Verify TSIG on any signed message, chaining on the prior MAC.
            if key.is_some() && m.tsig.is_some() {
                match dns_tsig::verify(&m, &data, &keyring, now_secs(), Some(&prior_mac)) {
                    Ok(mac) => prior_mac = mac,
                    Err(e) => return Err(format!("axfr tsig verify failed: {e:?}")),
                }
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

/// Ask a primary for the zone's current serial (UDP SOA query, optional TSIG).
pub async fn query_soa_serial(
    primary: SocketAddr,
    origin: &DnsName,
    key: Option<&TsigKey>,
) -> Result<u32, String> {
    timeout(SOA_TIMEOUT, async {
        let mut query = Message::new(xfr_id(), Flags::default());
        query.questions.push(Question {
            qname: origin.clone(),
            qtype: TYPE_SOA,
            qclass: CLASS_IN,
        });
        let (wire, _mac) = encode_signed(&query, key);
        let bind: SocketAddr =
            if primary.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        sock.connect(primary).await.map_err(|e| e.to_string())?;
        sock.send(&wire).await.map_err(|e| e.to_string())?;
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
    /// TSIG key to sign transfer requests with (must match the primary's).
    pub tsig_key: Option<TsigKey>,
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
            match query_soa_serial(primary, &sec.origin, sec.tsig_key.as_ref()).await {
                Ok(serial) if current.is_none_or(|cur| serial_gt(serial, cur)) => {
                    match axfr_pull(primary, &sec.origin, sec.tsig_key.as_ref()).await {
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

    fn ixfr_query(origin: &DnsName, client_serial: u32) -> Message {
        use dns_proto::message::TYPE_IXFR;
        let mut q = Message::new(3, Flags::default());
        q.questions.push(Question { qname: origin.clone(), qtype: TYPE_IXFR, qclass: CLASS_IN });
        // The client's current SOA goes in the authority section.
        let mut soa = parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 1 2 3 4 5\n").unwrap().soa;
        if let RData::Soa(s) = &mut soa.rdata {
            s.serial = client_serial;
        }
        q.authorities.push(soa);
        q
    }

    #[test]
    fn ixfr_incremental_then_fallback() {
        let v1 =
            parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 1.2.3.4\na IN A 10.0.0.1\n")
                .unwrap();
        let v2 =
            parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 2 2 3 4 5\n@ IN NS ns\nns IN A 1.2.3.4\nb IN A 10.0.0.2\n")
                .unwrap();
        let journal = Journal::default();
        journal.record(&v1, &v2);

        // Client at serial 1 gets an incremental reply framed as
        // newSOA, oldSOA, deletions, newSOA, additions, newSOA.
        let q = ixfr_query(&v2.origin, 1);
        let frames = ixfr_messages(&v2, &q, 1, &journal);
        let m = Message::parse(&frames[0][2..]).unwrap();
        let types: Vec<u16> = m.answers.iter().map(|r| r.rtype()).collect();
        assert_eq!(m.answers.first().unwrap().rtype(), TYPE_SOA);
        assert_eq!(m.answers.last().unwrap().rtype(), TYPE_SOA);
        // The deleted A (a) and added A (b) both appear.
        assert!(m.answers.iter().any(|r| r.rdata.text() == "10.0.0.1"));
        assert!(m.answers.iter().any(|r| r.rdata.text() == "10.0.0.2"));
        assert!(types.iter().filter(|&&t| t == TYPE_SOA).count() >= 4);

        // Unknown starting serial falls back to a full AXFR-style transfer.
        let q0 = ixfr_query(&v2.origin, 999);
        let frames = ixfr_messages(&v2, &q0, 999, &journal);
        let m = Message::parse(&frames[0][2..]).unwrap();
        // AXFR-style: opens and closes with SOA, includes all current records.
        assert_eq!(m.answers.first().unwrap().rtype(), TYPE_SOA);
        assert!(m.answers.iter().any(|r| r.rdata.text() == "10.0.0.2"));
        assert!(!m.answers.iter().any(|r| r.rdata.text() == "10.0.0.1"));
    }

    #[test]
    fn journal_persists_across_reload() {
        let dir = std::env::temp_dir().join(format!("rdns-jtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let v1 = parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\na IN A 10.0.0.1\n").unwrap();
        let v2 = parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 2 2 3 4 5\n@ IN NS ns\nb IN A 10.0.0.2\n").unwrap();
        {
            let j = Journal::with_dir(dir.clone());
            j.record(&v1, &v2);
        }
        // A fresh Journal reloads the delta from disk and can still serve IXFR.
        let j2 = Journal::with_dir(dir.clone());
        let q = ixfr_query(&v2.origin, 1);
        let frames = ixfr_messages(&v2, &q, 1, &j2);
        let m = Message::parse(&frames[0][2..]).unwrap();
        assert!(m.answers.iter().any(|r| r.rdata.text() == "10.0.0.1"), "reloaded deletion");
        assert!(m.answers.iter().any(|r| r.rdata.text() == "10.0.0.2"), "reloaded addition");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ixfr_up_to_date_returns_single_soa() {
        let z = parse_zone_file("$ORIGIN t.\n@ IN SOA ns h 5 2 3 4 5\n@ IN NS ns\n").unwrap();
        let q = ixfr_query(&z.origin, 5);
        let frames = ixfr_messages(&z, &q, 5, &Journal::default());
        let m = Message::parse(&frames[0][2..]).unwrap();
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].rtype(), TYPE_SOA);
    }
}
