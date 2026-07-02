//! DNS message wire format: RFC 1035 plus EDNS0 (RFC 6891).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::name::{Compressor, DnsName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadLabel,
    NameTooLong,
    CompressionLoop,
    BadRdata,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "message truncated"),
            WireError::BadLabel => write!(f, "unsupported label type"),
            WireError::NameTooLong => write!(f, "name too long"),
            WireError::CompressionLoop => write!(f, "compression pointer loop"),
            WireError::BadRdata => write!(f, "malformed rdata"),
        }
    }
}

impl std::error::Error for WireError {}

pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const CLASS_ANY: u16 = 255;

pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_NOTIFY: u8 = 4;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_DS: u16 = 43;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_IXFR: u16 = 251;
pub const TYPE_AXFR: u16 = 252;
pub const TYPE_TSIG: u16 = 250;
pub const TYPE_ANY: u16 = 255;

pub const RCODE_NOTAUTH: u8 = 9;
/// TSIG extended rcodes (carried in the TSIG error field, RFC 8945 §4.3).
pub const TSIG_BADSIG: u16 = 16;
pub const TSIG_BADKEY: u16 = 17;
pub const TSIG_BADTIME: u16 = 18;

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_NS => "NS".into(),
        TYPE_CNAME => "CNAME".into(),
        TYPE_SOA => "SOA".into(),
        TYPE_PTR => "PTR".into(),
        TYPE_MX => "MX".into(),
        TYPE_TXT => "TXT".into(),
        TYPE_AAAA => "AAAA".into(),
        TYPE_SRV => "SRV".into(),
        TYPE_OPT => "OPT".into(),
        TYPE_DS => "DS".into(),
        TYPE_RRSIG => "RRSIG".into(),
        TYPE_NSEC => "NSEC".into(),
        TYPE_DNSKEY => "DNSKEY".into(),
        TYPE_IXFR => "IXFR".into(),
        TYPE_AXFR => "AXFR".into(),
        TYPE_TSIG => "TSIG".into(),
        TYPE_ANY => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Inverse of [`type_name`] for the types this server understands.
pub fn type_code(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "NS" => Some(TYPE_NS),
        "CNAME" => Some(TYPE_CNAME),
        "SOA" => Some(TYPE_SOA),
        "PTR" => Some(TYPE_PTR),
        "MX" => Some(TYPE_MX),
        "TXT" => Some(TYPE_TXT),
        "AAAA" => Some(TYPE_AAAA),
        "SRV" => Some(TYPE_SRV),
        _ => None,
    }
}

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

pub fn rcode_name(rc: u8) -> String {
    match rc {
        RCODE_NOERROR => "NOERROR".into(),
        RCODE_FORMERR => "FORMERR".into(),
        RCODE_SERVFAIL => "SERVFAIL".into(),
        RCODE_NXDOMAIN => "NXDOMAIN".into(),
        RCODE_NOTIMP => "NOTIMP".into(),
        RCODE_REFUSED => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

/// Header flag word, unpacked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: u8,
}

impl Flags {
    pub fn from_u16(v: u16) -> Self {
        Flags {
            qr: v & 0x8000 != 0,
            opcode: ((v >> 11) & 0xF) as u8,
            aa: v & 0x0400 != 0,
            tc: v & 0x0200 != 0,
            rd: v & 0x0100 != 0,
            ra: v & 0x0080 != 0,
            ad: v & 0x0020 != 0,
            cd: v & 0x0010 != 0,
            rcode: (v & 0xF) as u8,
        }
    }

    pub fn to_u16(self) -> u16 {
        (self.qr as u16) << 15
            | ((self.opcode & 0xF) as u16) << 11
            | (self.aa as u16) << 10
            | (self.tc as u16) << 9
            | (self.rd as u16) << 8
            | (self.ra as u16) << 7
            | (self.ad as u16) << 5
            | (self.cd as u16) << 4
            | (self.rcode & 0xF) as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub mname: DnsName,
    pub rname: DnsName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(DnsName),
    Cname(DnsName),
    Ptr(DnsName),
    Soa(Soa),
    Mx { preference: u16, exchange: DnsName },
    Txt(Vec<Vec<u8>>),
    Srv { priority: u16, weight: u16, port: u16, target: DnsName },
    Unknown { rtype: u16, data: Vec<u8> },
}

impl RData {
    pub fn rtype(&self) -> u16 {
        match self {
            RData::A(_) => TYPE_A,
            RData::Aaaa(_) => TYPE_AAAA,
            RData::Ns(_) => TYPE_NS,
            RData::Cname(_) => TYPE_CNAME,
            RData::Ptr(_) => TYPE_PTR,
            RData::Soa(_) => TYPE_SOA,
            RData::Mx { .. } => TYPE_MX,
            RData::Txt(_) => TYPE_TXT,
            RData::Srv { .. } => TYPE_SRV,
            RData::Unknown { rtype, .. } => *rtype,
        }
    }

    /// Master-file / API content representation ("10 mail.example.com.",
    /// "\"txt string\"", ...). Inverse of zone-file rdata parsing.
    pub fn text(&self) -> String {
        match self {
            RData::A(ip) => ip.to_string(),
            RData::Aaaa(ip) => ip.to_string(),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.to_string(),
            RData::Soa(s) => format!(
                "{} {} {} {} {} {} {}",
                s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum
            ),
            RData::Mx { preference, exchange } => format!("{preference} {exchange}"),
            RData::Txt(strings) => strings
                .iter()
                .map(|s| format!("\"{}\"", String::from_utf8_lossy(s).replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(" "),
            RData::Srv { priority, weight, port, target } => {
                format!("{priority} {weight} {port} {target}")
            }
            // RFC 3597 generic encoding.
            RData::Unknown { data, .. } => {
                let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
                format!("\\# {} {hex}", data.len())
            }
        }
    }

    fn parse(rtype: u16, buf: &[u8], pos: &mut usize, rdlen: usize) -> Result<Self, WireError> {
        let end = pos.checked_add(rdlen).ok_or(WireError::Truncated)?;
        if end > buf.len() {
            return Err(WireError::Truncated);
        }
        let rdata = match rtype {
            TYPE_A => {
                let b: [u8; 4] = read_bytes(buf, pos, 4)?.try_into().unwrap();
                RData::A(Ipv4Addr::from(b))
            }
            TYPE_AAAA => {
                let b: [u8; 16] = read_bytes(buf, pos, 16)?.try_into().unwrap();
                RData::Aaaa(Ipv6Addr::from(b))
            }
            TYPE_NS => RData::Ns(DnsName::from_wire(buf, pos)?),
            TYPE_CNAME => RData::Cname(DnsName::from_wire(buf, pos)?),
            TYPE_PTR => RData::Ptr(DnsName::from_wire(buf, pos)?),
            TYPE_SOA => RData::Soa(Soa {
                mname: DnsName::from_wire(buf, pos)?,
                rname: DnsName::from_wire(buf, pos)?,
                serial: read_u32(buf, pos)?,
                refresh: read_u32(buf, pos)?,
                retry: read_u32(buf, pos)?,
                expire: read_u32(buf, pos)?,
                minimum: read_u32(buf, pos)?,
            }),
            TYPE_MX => RData::Mx {
                preference: read_u16(buf, pos)?,
                exchange: DnsName::from_wire(buf, pos)?,
            },
            TYPE_TXT => {
                let mut strings = Vec::new();
                while *pos < end {
                    let len = read_u8(buf, pos)? as usize;
                    if *pos + len > end {
                        return Err(WireError::BadRdata);
                    }
                    strings.push(read_bytes(buf, pos, len)?.to_vec());
                }
                RData::Txt(strings)
            }
            TYPE_SRV => RData::Srv {
                priority: read_u16(buf, pos)?,
                weight: read_u16(buf, pos)?,
                port: read_u16(buf, pos)?,
                target: DnsName::from_wire(buf, pos)?,
            },
            _ => RData::Unknown {
                rtype,
                data: read_bytes(buf, pos, rdlen)?.to_vec(),
            },
        };
        if *pos != end {
            return Err(WireError::BadRdata);
        }
        Ok(rdata)
    }

    fn encode(&self, out: &mut Vec<u8>, comp: &mut Compressor) {
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            RData::Ns(n) => n.to_wire(out, Some(comp)),
            RData::Cname(n) => n.to_wire(out, Some(comp)),
            RData::Ptr(n) => n.to_wire(out, Some(comp)),
            RData::Soa(soa) => {
                soa.mname.to_wire(out, Some(comp));
                soa.rname.to_wire(out, Some(comp));
                out.extend_from_slice(&soa.serial.to_be_bytes());
                out.extend_from_slice(&soa.refresh.to_be_bytes());
                out.extend_from_slice(&soa.retry.to_be_bytes());
                out.extend_from_slice(&soa.expire.to_be_bytes());
                out.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            RData::Mx { preference, exchange } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.to_wire(out, Some(comp));
            }
            RData::Txt(strings) => {
                for s in strings {
                    out.push(s.len() as u8);
                    out.extend_from_slice(s);
                }
            }
            RData::Srv { priority, weight, port, target } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                // RFC 2782: the SRV target must not be compressed.
                target.to_wire(out, None);
            }
            RData::Unknown { data, .. } => out.extend_from_slice(data),
        }
    }

    /// Canonical rdata (RFC 4034 §6.2): names uncompressed. Our names are
    /// stored lowercased, so `to_wire(None)` already yields canonical output.
    pub fn encode_canonical(&self, out: &mut Vec<u8>) {
        match self {
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.to_wire(out, None),
            RData::Soa(soa) => {
                soa.mname.to_wire(out, None);
                soa.rname.to_wire(out, None);
                out.extend_from_slice(&soa.serial.to_be_bytes());
                out.extend_from_slice(&soa.refresh.to_be_bytes());
                out.extend_from_slice(&soa.retry.to_be_bytes());
                out.extend_from_slice(&soa.expire.to_be_bytes());
                out.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            RData::Mx { preference, exchange } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.to_wire(out, None);
            }
            RData::Srv { priority, weight, port, target } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                target.to_wire(out, None);
            }
            // Types with no embedded names encode identically either way.
            _ => {
                let mut comp = Compressor::default();
                self.encode(out, &mut comp);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: DnsName,
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
    pub fn rtype(&self) -> u16 {
        self.rdata.rtype()
    }

    fn encode(&self, out: &mut Vec<u8>, comp: &mut Compressor) {
        self.name.to_wire(out, Some(comp));
        out.extend_from_slice(&self.rtype().to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        self.rdata.encode(out, comp);
        let rdlen = (out.len() - len_at - 2) as u16;
        out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }

    /// Canonical RR wire form for DNSSEC (RFC 4034 §6.2): owner and rdata
    /// names uncompressed and lowercased, with `original_ttl` in place of the
    /// live TTL. DnsName already stores labels lowercased, so no case fixups
    /// are needed here.
    pub fn encode_canonical(&self, out: &mut Vec<u8>, original_ttl: u32) {
        self.name.to_wire(out, None);
        out.extend_from_slice(&self.rtype().to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&original_ttl.to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        self.rdata.encode_canonical(out);
        let rdlen = (out.len() - len_at - 2) as u16;
        out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

/// EDNS0 pseudo-record (the OPT RR abuses the name/class/ttl fields, so it is
/// modeled separately rather than as a `Record`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    pub udp_payload: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub do_bit: bool,
    pub options: Vec<u8>,
}

impl Edns {
    /// The OPT record this server attaches to its own messages. 1232 bytes is
    /// the DNS-flag-day-2020 recommendation (fits any sane MTU unfragmented).
    pub fn ours() -> Self {
        Edns { udp_payload: 1232, ext_rcode: 0, version: 0, do_bit: false, options: Vec::new() }
    }
}

/// TSIG record (RFC 8945). Modeled separately from `Record` like OPT because
/// it hijacks the owner/class/ttl fields and must be the final RR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tsig {
    /// Owner name of the TSIG RR == the shared key's name.
    pub key_name: DnsName,
    pub algorithm: DnsName,
    /// Seconds since the Unix epoch (48-bit on the wire).
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: u16,
    pub other: Vec<u8>,
}

impl Tsig {
    /// The RR-specific "TSIG variables" digested into the MAC (RFC 8945
    /// §4.3.3): owner name, class ANY, TTL 0, then algorithm/time/fudge/
    /// error/other but NOT the MAC itself.
    pub fn variables(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.key_name.to_wire(&mut v, None);
        v.extend_from_slice(&CLASS_ANY.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // TTL
        self.algorithm.to_wire(&mut v, None);
        v.extend_from_slice(&self.time_signed.to_be_bytes()[2..]); // 48-bit
        v.extend_from_slice(&self.fudge.to_be_bytes());
        v.extend_from_slice(&self.error.to_be_bytes());
        v.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.other);
        v
    }

    fn encode_rr(&self, out: &mut Vec<u8>) {
        self.key_name.to_wire(out, None);
        out.extend_from_slice(&TYPE_TSIG.to_be_bytes());
        out.extend_from_slice(&CLASS_ANY.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        self.algorithm.to_wire(out, None);
        out.extend_from_slice(&self.time_signed.to_be_bytes()[2..]);
        out.extend_from_slice(&self.fudge.to_be_bytes());
        out.extend_from_slice(&(self.mac.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.original_id.to_be_bytes());
        out.extend_from_slice(&self.error.to_be_bytes());
        out.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.other);
        let rdlen = (out.len() - len_at - 2) as u16;
        out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }

    fn parse_rdata(key_name: DnsName, buf: &[u8], pos: &mut usize) -> Result<Self, WireError> {
        let algorithm = DnsName::from_wire(buf, pos)?;
        let hi = read_u16(buf, pos)? as u64;
        let lo = read_u32(buf, pos)? as u64;
        let time_signed = (hi << 32) | lo;
        let fudge = read_u16(buf, pos)?;
        let mac_size = read_u16(buf, pos)? as usize;
        let mac = read_bytes(buf, pos, mac_size)?.to_vec();
        let original_id = read_u16(buf, pos)?;
        let error = read_u16(buf, pos)?;
        let other_len = read_u16(buf, pos)? as usize;
        let other = read_bytes(buf, pos, other_len)?.to_vec();
        Ok(Tsig { key_name, algorithm, time_signed, fudge, mac, original_id, error, other })
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub edns: Option<Edns>,
    /// Present when a TSIG RR terminated the message (RFC 8945).
    pub tsig: Option<Tsig>,
    /// Byte offset where the TSIG RR's owner name began, for MAC recompute.
    /// Transient: set by [`Message::parse`], never encoded.
    pub tsig_start: Option<usize>,
}

impl Message {
    pub fn new(id: u16, flags: Flags) -> Self {
        Message {
            id,
            flags,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
            tsig: None,
            tsig_start: None,
        }
    }

    /// Empty response skeleton: id/opcode/RD echoed, QR set, question copied,
    /// and an OPT record included iff the query had one.
    pub fn response_to(query: &Message) -> Self {
        let mut resp = Message::new(
            query.id,
            Flags { qr: true, opcode: query.flags.opcode, rd: query.flags.rd, ..Flags::default() },
        );
        resp.questions = query.questions.clone();
        resp.edns = query.edns.as_ref().map(|_| Edns::ours());
        resp
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        let mut pos = 0;
        let id = read_u16(buf, &mut pos)?;
        let flags = Flags::from_u16(read_u16(buf, &mut pos)?);
        let qd = read_u16(buf, &mut pos)? as usize;
        let an = read_u16(buf, &mut pos)? as usize;
        let ns = read_u16(buf, &mut pos)? as usize;
        let ar = read_u16(buf, &mut pos)? as usize;

        let mut msg = Message::new(id, flags);
        for _ in 0..qd {
            msg.questions.push(Question {
                qname: DnsName::from_wire(buf, &mut pos)?,
                qtype: read_u16(buf, &mut pos)?,
                qclass: read_u16(buf, &mut pos)?,
            });
        }
        for _ in 0..an {
            if let Entry::Rr(r) = parse_entry(buf, &mut pos)? {
                msg.answers.push(r);
            }
        }
        for _ in 0..ns {
            if let Entry::Rr(r) = parse_entry(buf, &mut pos)? {
                msg.authorities.push(r);
            }
        }
        for _ in 0..ar {
            let start = pos;
            match parse_entry(buf, &mut pos)? {
                Entry::Rr(r) => msg.additionals.push(r),
                // RFC 6891: at most one OPT; keep the first, ignore extras.
                Entry::Opt(e) => {
                    if msg.edns.is_none() {
                        msg.edns = Some(e);
                    }
                }
                // RFC 8945: TSIG must be the last RR; remember where it began
                // so the MAC can be recomputed over the preceding bytes.
                Entry::Tsig(t) => {
                    msg.tsig = Some(t);
                    msg.tsig_start = Some(start);
                }
            }
        }
        Ok(msg)
    }

    /// Append a fully-formed TSIG RR and bump ARCOUNT. Used after the MAC has
    /// been computed over `encode()` output.
    pub fn encode_with_tsig(&self, tsig: &Tsig) -> Vec<u8> {
        let mut out = self.encode();
        tsig.encode_rr(&mut out);
        let arcount = u16::from_be_bytes([out[10], out[11]]).wrapping_add(1);
        out[10..12].copy_from_slice(&arcount.to_be_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut comp = Compressor::default();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        let ar = self.additionals.len() + self.edns.is_some() as usize;
        out.extend_from_slice(&(ar as u16).to_be_bytes());

        for q in &self.questions {
            q.qname.to_wire(&mut out, Some(&mut comp));
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for r in self.answers.iter().chain(&self.authorities).chain(&self.additionals) {
            r.encode(&mut out, &mut comp);
        }
        if let Some(e) = &self.edns {
            out.push(0); // root owner name
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&e.udp_payload.to_be_bytes());
            let ttl: u32 = (e.ext_rcode as u32) << 24
                | (e.version as u32) << 16
                | if e.do_bit { 0x8000 } else { 0 };
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(e.options.len() as u16).to_be_bytes());
            out.extend_from_slice(&e.options);
        }
        out
    }

    /// Encode within `limit` bytes; if the full message does not fit, emit a
    /// truncated (TC=1) header-plus-question so the client retries over TCP.
    pub fn encode_limited(&self, limit: usize) -> Vec<u8> {
        let full = self.encode();
        if full.len() <= limit {
            return full;
        }
        let mut t = self.clone();
        t.flags.tc = true;
        t.answers.clear();
        t.authorities.clear();
        t.additionals.clear();
        t.encode()
    }
}

enum Entry {
    Rr(Record),
    Opt(Edns),
    Tsig(Tsig),
}

fn parse_entry(buf: &[u8], pos: &mut usize) -> Result<Entry, WireError> {
    let name = DnsName::from_wire(buf, pos)?;
    let rtype = read_u16(buf, pos)?;
    let class = read_u16(buf, pos)?;
    let ttl = read_u32(buf, pos)?;
    let rdlen = read_u16(buf, pos)? as usize;
    if rtype == TYPE_TSIG {
        let end = pos.checked_add(rdlen).ok_or(WireError::Truncated)?;
        let t = Tsig::parse_rdata(name, buf, pos)?;
        if *pos != end {
            return Err(WireError::BadRdata);
        }
        return Ok(Entry::Tsig(t));
    }
    if rtype == TYPE_OPT {
        let data = read_bytes(buf, pos, rdlen)?.to_vec();
        return Ok(Entry::Opt(Edns {
            udp_payload: class,
            ext_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            do_bit: ttl & 0x8000 != 0,
            options: data,
        }));
    }
    let rdata = RData::parse(rtype, buf, pos, rdlen)?;
    Ok(Entry::Rr(Record { name, class, ttl, rdata }))
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, WireError> {
    let b = *buf.get(*pos).ok_or(WireError::Truncated)?;
    *pos += 1;
    Ok(b)
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, WireError> {
    let s = read_bytes(buf, pos, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, WireError> {
    let s = read_bytes(buf, pos, 4)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], WireError> {
    let end = pos.checked_add(n).ok_or(WireError::Truncated)?;
    let s = buf.get(*pos..end).ok_or(WireError::Truncated)?;
    *pos = end;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> DnsName {
        DnsName::parse_str(s).unwrap()
    }

    fn sample_response() -> Message {
        let mut m = Message::new(
            0x1234,
            Flags { qr: true, aa: true, rd: true, ra: true, ..Flags::default() },
        );
        m.questions.push(Question { qname: name("www.example.com"), qtype: TYPE_A, qclass: CLASS_IN });
        m.answers.push(Record {
            name: name("www.example.com"),
            class: CLASS_IN,
            ttl: 300,
            rdata: RData::Cname(name("web.example.com")),
        });
        m.answers.push(Record {
            name: name("web.example.com"),
            class: CLASS_IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
        });
        m.authorities.push(Record {
            name: name("example.com"),
            class: CLASS_IN,
            ttl: 3600,
            rdata: RData::Soa(Soa {
                mname: name("ns1.example.com"),
                rname: name("hostmaster.example.com"),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 300,
            }),
        });
        m.additionals.push(Record {
            name: name("example.com"),
            class: CLASS_IN,
            ttl: 60,
            rdata: RData::Mx { preference: 10, exchange: name("mail.example.com") },
        });
        m.edns = Some(Edns::ours());
        m
    }

    #[test]
    fn full_roundtrip_with_compression() {
        let m = sample_response();
        let wire = m.encode();
        let back = Message::parse(&wire).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.flags, m.flags);
        assert_eq!(back.questions, m.questions);
        assert_eq!(back.answers, m.answers);
        assert_eq!(back.authorities, m.authorities);
        assert_eq!(back.additionals, m.additionals);
        assert_eq!(back.edns, m.edns);

        // Compression must actually shrink the message: every repeated
        // "example.com" suffix after the first costs 2 bytes, not 13.
        let uncompressed_estimate: usize = 12
            + m.questions.iter().map(|q| q.qname.wire_len() + 4).sum::<usize>();
        assert!(wire.len() > uncompressed_estimate); // sanity
        let occurrences = wire.windows(7).filter(|w| w == b"example").count();
        assert_eq!(occurrences, 1, "suffix should be encoded once and pointed to");
    }

    #[test]
    fn truncation_sets_tc_and_fits() {
        let m = sample_response();
        let full = m.encode();
        let limited = m.encode_limited(full.len() - 1);
        assert!(limited.len() <= full.len() - 1);
        let back = Message::parse(&limited).unwrap();
        assert!(back.flags.tc);
        assert!(back.answers.is_empty());
        assert_eq!(back.questions, m.questions);
    }

    #[test]
    fn txt_and_srv_roundtrip() {
        let mut m = Message::new(1, Flags::default());
        m.answers.push(Record {
            name: name("example.com"),
            class: CLASS_IN,
            ttl: 60,
            rdata: RData::Txt(vec![b"hello world".to_vec(), b"second".to_vec()]),
        });
        m.answers.push(Record {
            name: name("_http._tcp.example.com"),
            class: CLASS_IN,
            ttl: 60,
            rdata: RData::Srv { priority: 0, weight: 5, port: 8080, target: name("www.example.com") },
        });
        let back = Message::parse(&m.encode()).unwrap();
        assert_eq!(back.answers, m.answers);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::parse(&[0, 1, 2]).is_err());
        // Header claiming one question but no question bytes.
        let hdr = [0u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(Message::parse(&hdr).is_err());
    }
}
