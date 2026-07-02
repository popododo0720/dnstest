//! Authoritative zones: RFC 1035 master-file parsing and lookups.
//!
//! Supported master-file subset: `$ORIGIN` / `$TTL` directives, comments,
//! multi-line records via parentheses, quoted strings, `@`, relative names,
//! owner-name inheritance from the previous record, and wildcards.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use dns_proto::message::{
    CLASS_IN, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, RData, Record, Soa, TYPE_ANY,
    TYPE_CNAME, TYPE_SOA, type_code, type_name,
};
use dns_proto::name::DnsName;

#[derive(Debug)]
pub struct ZoneError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for ZoneError {}

fn err(line: usize, msg: impl Into<String>) -> ZoneError {
    ZoneError { line, msg: msg.into() }
}

#[derive(Clone)]
pub struct Zone {
    pub origin: DnsName,
    pub soa: Record,
    pub record_count: usize,
    records: HashMap<DnsName, Vec<Record>>,
}

/// Outcome of an authoritative lookup.
pub struct LookupResult {
    pub rcode: u8,
    pub answers: Vec<Record>,
    /// True when the final step was NXDOMAIN or NODATA — the responder should
    /// attach the zone SOA to the authority section (negative caching hint).
    pub negative: bool,
    /// A CNAME chain left the zone at this target; the resolver may continue
    /// upstream if recursion was requested.
    pub offsite: Option<DnsName>,
}

impl Zone {
    pub fn lookup(&self, qname: &DnsName, qtype: u16) -> LookupResult {
        let mut answers: Vec<Record> = Vec::new();
        let mut name = qname.clone();
        // Bounded CNAME chase within the zone.
        for _ in 0..8 {
            let Some(node) = self.find_node(&name) else {
                // RFC 4592-ish nuance: a name with descendants but no records
                // of its own (empty non-terminal) is NODATA, not NXDOMAIN.
                let rcode = if self.has_names_below(&name) || !answers.is_empty() {
                    RCODE_NOERROR
                } else {
                    RCODE_NXDOMAIN
                };
                return LookupResult { rcode, answers, negative: true, offsite: None };
            };

            let matched: Vec<Record> = node
                .iter()
                .filter(|r| qtype == TYPE_ANY || r.rtype() == qtype)
                .cloned()
                .collect();
            if !matched.is_empty() {
                answers.extend(matched);
                return LookupResult { rcode: RCODE_NOERROR, answers, negative: false, offsite: None };
            }

            if let Some(cname) = node.iter().find(|r| r.rtype() == TYPE_CNAME) {
                let RData::Cname(target) = &cname.rdata else { unreachable!() };
                let target = target.clone();
                answers.push(cname.clone());
                if target.ends_with(&self.origin) {
                    name = target;
                    continue;
                }
                return LookupResult {
                    rcode: RCODE_NOERROR,
                    answers,
                    negative: false,
                    offsite: Some(target),
                };
            }

            // Name exists, no records of the requested type: NODATA.
            return LookupResult { rcode: RCODE_NOERROR, answers, negative: true, offsite: None };
        }
        // CNAME loop inside the zone data.
        LookupResult { rcode: RCODE_SERVFAIL, answers, negative: false, offsite: None }
    }

    /// Exact node, or a wildcard match synthesized with the query name as owner.
    fn find_node(&self, name: &DnsName) -> Option<Vec<Record>> {
        if let Some(rrs) = self.records.get(name) {
            return Some(rrs.clone());
        }
        let max_skip = name.label_count().checked_sub(self.origin.label_count())?;
        for skip in 1..=max_skip {
            let Some(wildcard) = name.wildcard_at(skip) else { break };
            if let Some(rrs) = self.records.get(&wildcard) {
                return Some(
                    rrs.iter()
                        .map(|r| {
                            let mut r = r.clone();
                            r.name = name.clone();
                            r
                        })
                        .collect(),
                );
            }
        }
        None
    }

    fn has_names_below(&self, name: &DnsName) -> bool {
        self.records.keys().any(|k| k != name && k.ends_with(name))
    }
}

/// An owner/type group of records, the unit of the management API.
pub struct Rrset {
    pub name: DnsName,
    pub rtype: u16,
    pub ttl: u32,
    pub contents: Vec<String>,
}

impl Zone {
    /// Assemble and validate a zone from loose records: every owner must be
    /// at/under the origin and exactly one SOA must be owned by the origin.
    pub fn from_records(origin: DnsName, all: Vec<Record>) -> Result<Zone, String> {
        let mut soa: Option<Record> = None;
        let mut records: HashMap<DnsName, Vec<Record>> = HashMap::new();
        let mut count = 0;
        for r in all {
            if !r.name.ends_with(&origin) {
                return Err(format!("{} is outside zone {}", r.name, origin));
            }
            if r.rtype() == TYPE_SOA {
                if r.name != origin {
                    return Err("SOA owner must be the zone origin".into());
                }
                if soa.is_some() {
                    return Err("duplicate SOA record".into());
                }
                soa = Some(r.clone());
            }
            records.entry(r.name.clone()).or_default().push(r);
            count += 1;
        }
        let soa = soa.ok_or("zone has no SOA record")?;
        Ok(Zone { origin, soa, record_count: count, records })
    }

    /// All rrsets, SOA first, then sorted by owner and type.
    pub fn rrsets(&self) -> Vec<Rrset> {
        let mut out = Vec::new();
        for (name, rrs) in &self.records {
            let mut types: Vec<u16> = rrs.iter().map(Record::rtype).collect();
            types.sort_unstable();
            types.dedup();
            for rtype in types {
                let members: Vec<&Record> = rrs.iter().filter(|r| r.rtype() == rtype).collect();
                out.push(Rrset {
                    name: name.clone(),
                    rtype,
                    ttl: members[0].ttl,
                    contents: members.iter().map(|r| r.rdata.text()).collect(),
                });
            }
        }
        out.sort_by(|a, b| {
            let a_key = (a.rtype != TYPE_SOA, a.name.to_string(), a.rtype);
            let b_key = (b.rtype != TYPE_SOA, b.name.to_string(), b.rtype);
            a_key.cmp(&b_key)
        });
        out
    }

    /// Replace (or create) the rrset for (name, rtype) with the given
    /// contents, PowerDNS `changetype: REPLACE` semantics.
    pub fn replace_rrset(
        &mut self,
        name: &DnsName,
        rtype: &str,
        ttl: u32,
        contents: &[String],
    ) -> Result<(), String> {
        let code = type_code(rtype).ok_or_else(|| format!("unsupported type '{rtype}'"))?;
        if !name.ends_with(&self.origin) {
            return Err(format!("{name} is outside zone {}", self.origin));
        }
        if contents.is_empty() {
            return Err("empty contents; use changetype DELETE to remove an rrset".into());
        }
        let mut new_records = Vec::with_capacity(contents.len());
        for content in contents {
            let rdata = rdata_from_text(rtype, content, &self.origin)?;
            new_records.push(Record { name: name.clone(), class: CLASS_IN, ttl, rdata });
        }

        if code == TYPE_SOA {
            if *name != self.origin {
                return Err("SOA owner must be the zone origin".into());
            }
            if new_records.len() != 1 {
                return Err("SOA rrset must contain exactly one record".into());
            }
            self.soa = new_records[0].clone();
        }
        // RFC 1034 §3.6.2: CNAME cannot coexist with other data.
        let node = self.records.entry(name.clone()).or_default();
        let node_has_other = node.iter().any(|r| r.rtype() != code);
        if code == TYPE_CNAME && node_has_other {
            return Err(format!("{name} already has non-CNAME records"));
        }
        if code != TYPE_CNAME && node.iter().any(|r| r.rtype() == TYPE_CNAME) {
            return Err(format!("{name} is a CNAME; delete it first"));
        }
        if new_records.len() > 1 && code == TYPE_CNAME {
            return Err("CNAME rrset must contain exactly one record".into());
        }

        node.retain(|r| r.rtype() != code);
        node.extend(new_records);
        self.recount();
        Ok(())
    }

    /// Remove the rrset for (name, rtype), PowerDNS `changetype: DELETE`.
    pub fn delete_rrset(&mut self, name: &DnsName, rtype: &str) -> Result<(), String> {
        let code = type_code(rtype).ok_or_else(|| format!("unsupported type '{rtype}'"))?;
        if code == TYPE_SOA {
            return Err("cannot delete the SOA; delete the zone instead".into());
        }
        if let Some(node) = self.records.get_mut(name) {
            node.retain(|r| r.rtype() != code);
            if node.is_empty() {
                self.records.remove(name);
            }
        }
        self.recount();
        Ok(())
    }

    /// Bump the SOA serial so secondaries and caches see the change.
    pub fn bump_serial(&mut self) {
        let RData::Soa(soa) = &mut self.soa.rdata else { return };
        soa.serial = soa.serial.wrapping_add(1);
        let origin = self.origin.clone();
        let fresh = self.soa.clone();
        if let Some(node) = self.records.get_mut(&origin) {
            for r in node.iter_mut().filter(|r| r.rtype() == TYPE_SOA) {
                *r = fresh.clone();
            }
        }
    }

    /// Every record with the SOA first — the AXFR payload order.
    pub fn all_records(&self) -> Vec<Record> {
        let mut out = Vec::with_capacity(self.record_count);
        out.push(self.soa.clone());
        for rrs in self.records.values() {
            out.extend(rrs.iter().filter(|r| r.rtype() != TYPE_SOA).cloned());
        }
        out
    }

    fn recount(&mut self) {
        self.record_count = self.records.values().map(Vec::len).sum();
    }

    /// Serialize back to master-file format (round-trips through
    /// [`parse_zone_file`]).
    pub fn to_zonefile(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(1024);
        let _ = writeln!(out, "; generated by rdns");
        let _ = writeln!(out, "$ORIGIN {}", self.origin);
        for rrset in self.rrsets() {
            for content in &rrset.contents {
                let _ = writeln!(
                    out,
                    "{} {} IN {} {}",
                    rrset.name,
                    rrset.ttl,
                    type_name(rrset.rtype),
                    content
                );
            }
        }
        out
    }
}

/// Parse rdata from its textual content, e.g. `("MX", "10 mail.example.com.")`.
pub fn rdata_from_text(rtype: &str, text: &str, origin: &DnsName) -> Result<RData, String> {
    let mut depth = 0;
    let toks = tokenize_line(text, &mut depth, 0).map_err(|e| e.msg)?;
    if depth != 0 {
        return Err("unbalanced parentheses".into());
    }
    parse_rdata(&rtype.to_ascii_uppercase(), &toks, origin, 0).map_err(|e| e.msg)
}

/// Parse a zone file. The file must contain a `$ORIGIN` directive and exactly
/// one SOA record owned by the origin.
pub fn parse_zone_file(text: &str) -> Result<Zone, ZoneError> {
    let mut origin: Option<DnsName> = None;
    let mut default_ttl: u32 = 3600;
    let mut last_name: Option<DnsName> = None;
    let mut all: Vec<(usize, Record)> = Vec::new();

    for (line_no, starts_ws, toks) in logical_lines(text)? {
        let first = toks[0].text();
        if first.eq_ignore_ascii_case("$ORIGIN") {
            let arg = toks.get(1).ok_or_else(|| err(line_no, "$ORIGIN needs a name"))?;
            origin = Some(
                DnsName::parse_str(arg.text()).map_err(|e| err(line_no, format!("bad origin: {e}")))?,
            );
            continue;
        }
        if first.eq_ignore_ascii_case("$TTL") {
            let arg = toks.get(1).ok_or_else(|| err(line_no, "$TTL needs a value"))?;
            default_ttl = parse_num(arg.text(), line_no, "$TTL")?;
            continue;
        }

        let origin = origin
            .as_ref()
            .ok_or_else(|| err(line_no, "record before $ORIGIN directive"))?;
        let mut i = 0;
        let name = if starts_ws {
            last_name
                .clone()
                .ok_or_else(|| err(line_no, "record starts with whitespace but no previous owner"))?
        } else {
            i = 1;
            resolve_name(toks[0].text(), origin, line_no)?
        };

        // Optional TTL and class, in either order.
        let mut ttl = default_ttl;
        while let Some(tok) = toks.get(i) {
            let t = tok.text();
            if t.bytes().all(|b| b.is_ascii_digit()) && !t.is_empty() {
                ttl = parse_num(t, line_no, "TTL")?;
                i += 1;
            } else if t.eq_ignore_ascii_case("IN") {
                i += 1;
            } else {
                break;
            }
        }

        let rtype = toks
            .get(i)
            .ok_or_else(|| err(line_no, "missing record type"))?
            .text()
            .to_ascii_uppercase();
        let rdata_toks = &toks[i + 1..];
        let rdata = parse_rdata(&rtype, rdata_toks, origin, line_no)?;

        all.push((line_no, Record { name: name.clone(), class: CLASS_IN, ttl, rdata }));
        last_name = Some(name);
    }

    let origin = origin.ok_or_else(|| err(0, "zone file has no $ORIGIN directive"))?;
    Zone::from_records(origin, all.into_iter().map(|(_, r)| r).collect())
        .map_err(|msg| err(0, msg))
}

fn resolve_name(token: &str, origin: &DnsName, line_no: usize) -> Result<DnsName, ZoneError> {
    if token == "@" {
        return Ok(origin.clone());
    }
    let name =
        DnsName::parse_str(token).map_err(|e| err(line_no, format!("bad name '{token}': {e}")))?;
    if token.ends_with('.') {
        Ok(name)
    } else {
        name.concat(origin).map_err(|e| err(line_no, format!("bad name '{token}': {e}")))
    }
}

fn parse_num<T: std::str::FromStr>(s: &str, line_no: usize, what: &str) -> Result<T, ZoneError> {
    s.parse().map_err(|_| err(line_no, format!("bad {what} value '{s}'")))
}

fn parse_rdata(
    rtype: &str,
    toks: &[Tok],
    origin: &DnsName,
    line_no: usize,
) -> Result<RData, ZoneError> {
    let want = |n: usize| -> Result<(), ZoneError> {
        if toks.len() == n {
            Ok(())
        } else {
            Err(err(line_no, format!("{rtype} expects {n} field(s), got {}", toks.len())))
        }
    };
    match rtype {
        "A" => {
            want(1)?;
            let ip: Ipv4Addr = parse_num(toks[0].text(), line_no, "IPv4 address")?;
            Ok(RData::A(ip))
        }
        "AAAA" => {
            want(1)?;
            let ip: Ipv6Addr = parse_num(toks[0].text(), line_no, "IPv6 address")?;
            Ok(RData::Aaaa(ip))
        }
        "NS" => {
            want(1)?;
            Ok(RData::Ns(resolve_name(toks[0].text(), origin, line_no)?))
        }
        "CNAME" => {
            want(1)?;
            Ok(RData::Cname(resolve_name(toks[0].text(), origin, line_no)?))
        }
        "PTR" => {
            want(1)?;
            Ok(RData::Ptr(resolve_name(toks[0].text(), origin, line_no)?))
        }
        "MX" => {
            want(2)?;
            Ok(RData::Mx {
                preference: parse_num(toks[0].text(), line_no, "MX preference")?,
                exchange: resolve_name(toks[1].text(), origin, line_no)?,
            })
        }
        "TXT" => {
            if toks.is_empty() {
                return Err(err(line_no, "TXT needs at least one string"));
            }
            let mut strings = Vec::new();
            for t in toks {
                let bytes = t.text().as_bytes();
                if bytes.len() > 255 {
                    return Err(err(line_no, "TXT string exceeds 255 bytes"));
                }
                strings.push(bytes.to_vec());
            }
            Ok(RData::Txt(strings))
        }
        "SOA" => {
            want(7)?;
            Ok(RData::Soa(Soa {
                mname: resolve_name(toks[0].text(), origin, line_no)?,
                rname: resolve_name(toks[1].text(), origin, line_no)?,
                serial: parse_num(toks[2].text(), line_no, "SOA serial")?,
                refresh: parse_num(toks[3].text(), line_no, "SOA refresh")?,
                retry: parse_num(toks[4].text(), line_no, "SOA retry")?,
                expire: parse_num(toks[5].text(), line_no, "SOA expire")?,
                minimum: parse_num(toks[6].text(), line_no, "SOA minimum")?,
            }))
        }
        "SRV" => {
            want(4)?;
            Ok(RData::Srv {
                priority: parse_num(toks[0].text(), line_no, "SRV priority")?,
                weight: parse_num(toks[1].text(), line_no, "SRV weight")?,
                port: parse_num(toks[2].text(), line_no, "SRV port")?,
                target: resolve_name(toks[3].text(), origin, line_no)?,
            })
        }
        other => Err(err(line_no, format!("unsupported record type '{other}'"))),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
}

impl Tok {
    fn text(&self) -> &str {
        match self {
            Tok::Word(s) | Tok::Quoted(s) => s,
        }
    }
}

/// Group physical lines into logical records, honoring `(`...`)` continuations,
/// `;` comments, and quoted strings. Yields (first line number, whether the
/// record started with whitespace, tokens).
fn logical_lines(text: &str) -> Result<Vec<(usize, bool, Vec<Tok>)>, ZoneError> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut current: Vec<Tok> = Vec::new();
    let mut current_line = 0usize;
    let mut current_ws = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let toks = tokenize_line(raw, &mut depth, line_no)?;
        if current.is_empty() && !toks.is_empty() {
            current_line = line_no;
            current_ws = raw.starts_with([' ', '\t']);
        }
        current.extend(toks);
        if depth == 0 && !current.is_empty() {
            out.push((current_line, current_ws, std::mem::take(&mut current)));
        }
    }
    if depth != 0 {
        return Err(err(current_line, "unclosed '(' at end of file"));
    }
    Ok(out)
}

fn tokenize_line(line: &str, depth: &mut u32, line_no: usize) -> Result<Vec<Tok>, ZoneError> {
    let chars: Vec<char> = line.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == ';' {
            break;
        } else if c == '(' {
            *depth += 1;
            i += 1;
        } else if c == ')' {
            if *depth == 0 {
                return Err(err(line_no, "unbalanced ')'"));
            }
            *depth -= 1;
            i += 1;
        } else if c == '"' {
            i += 1;
            let start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err(err(line_no, "unterminated quoted string"));
            }
            toks.push(Tok::Quoted(chars[start..i].iter().collect()));
            i += 1;
        } else {
            let start = i;
            while i < chars.len()
                && !chars[i].is_whitespace()
                && !matches!(chars[i], '(' | ')' | ';' | '"')
            {
                i += 1;
            }
            toks.push(Tok::Word(chars[start..i].iter().collect()));
        }
    }
    Ok(toks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_proto::message::{TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_TXT};

    const ZONE: &str = r#"
$ORIGIN example.lab.
$TTL 3600

@       IN SOA ns1 hostmaster (
            2026070201 ; serial
            7200       ; refresh
            3600       ; retry
            1209600    ; expire
            300 )      ; negative-cache TTL

@       IN NS   ns1
ns1     IN A    10.0.0.1
www     600 IN A 10.0.0.10
        IN A    10.0.0.11
www     IN AAAA fd00::10
api     IN CNAME www
ext     IN CNAME example.com.
@       IN MX   10 mail
mail    IN A    10.0.0.20
@       IN TXT  "hello from rdns" "v=spf1 -all"
_http._tcp IN SRV 0 5 8080 www
*.dev   IN A    10.0.0.99
"#;

    fn zone() -> Zone {
        parse_zone_file(ZONE).expect("zone parses")
    }

    fn n(s: &str) -> DnsName {
        DnsName::parse_str(s).unwrap()
    }

    #[test]
    fn parses_soa_with_parens_and_comments() {
        let z = zone();
        assert_eq!(z.origin, n("example.lab"));
        let RData::Soa(soa) = &z.soa.rdata else { panic!() };
        assert_eq!(soa.serial, 2026070201);
        assert_eq!(soa.minimum, 300);
        assert_eq!(soa.mname, n("ns1.example.lab"));
    }

    #[test]
    fn owner_inheritance_and_ttl() {
        let z = zone();
        let r = z.lookup(&n("www.example.lab"), TYPE_A);
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert_eq!(r.answers.len(), 2, "two A records, one via inherited owner");
        assert_eq!(r.answers[0].ttl, 600);
    }

    #[test]
    fn cname_chase_in_zone() {
        let z = zone();
        let r = z.lookup(&n("api.example.lab"), TYPE_AAAA);
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert_eq!(r.answers.len(), 2); // CNAME + AAAA of target
        assert_eq!(r.answers[0].rtype(), TYPE_CNAME);
        assert_eq!(r.answers[1].rtype(), TYPE_AAAA);
        assert!(r.offsite.is_none());
    }

    #[test]
    fn cname_offsite_target() {
        let z = zone();
        let r = z.lookup(&n("ext.example.lab"), TYPE_A);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.offsite, Some(n("example.com")));
    }

    #[test]
    fn negative_answers() {
        let z = zone();
        let nx = z.lookup(&n("nope.example.lab"), TYPE_A);
        assert_eq!(nx.rcode, RCODE_NXDOMAIN);
        assert!(nx.negative);

        // Name exists but not that type: NODATA.
        let nodata = z.lookup(&n("mail.example.lab"), TYPE_MX);
        assert_eq!(nodata.rcode, RCODE_NOERROR);
        assert!(nodata.negative);
        assert!(nodata.answers.is_empty());

        // Empty non-terminal (_tcp has children, no records): NODATA not NXDOMAIN.
        let ent = z.lookup(&n("_tcp.example.lab"), TYPE_A);
        assert_eq!(ent.rcode, RCODE_NOERROR);
        assert!(ent.negative);
    }

    #[test]
    fn wildcard_synthesis() {
        let z = zone();
        let r = z.lookup(&n("anything.dev.example.lab"), TYPE_A);
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert_eq!(r.answers.len(), 1);
        // Owner must be the query name, not the wildcard.
        assert_eq!(r.answers[0].name, n("anything.dev.example.lab"));
    }

    #[test]
    fn txt_strings() {
        let z = zone();
        let r = z.lookup(&n("example.lab"), TYPE_TXT);
        let RData::Txt(strings) = &r.answers[0].rdata else { panic!() };
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], b"hello from rdns");
    }

    #[test]
    fn rejects_broken_zones() {
        assert!(parse_zone_file("www IN A 1.2.3.4").is_err()); // no $ORIGIN
        assert!(parse_zone_file("$ORIGIN a.\nwww IN A 1.2.3.4").is_err()); // no SOA
        assert!(
            parse_zone_file("$ORIGIN a.\n@ IN SOA ns1 h 1 2 3 4 5\nwww IN A 999.2.3.4").is_err()
        );
    }
}
