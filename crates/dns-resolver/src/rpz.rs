//! Response Policy Zone (lite): block or sinkhole domains during recursive
//! resolution. A rule covers the name and everything below it.
//!
//! File format, one rule per line:
//! ```text
//! # comment
//! phishing.example            ; NXDOMAIN
//! malware.test  10.0.0.99     ; sinkhole: answer with this address
//! ```

use std::collections::HashMap;
use std::net::IpAddr;

use dns_proto::name::DnsName;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpzAction {
    /// Answer NXDOMAIN.
    Block,
    /// Answer A/AAAA queries with this sinkhole address.
    Redirect(IpAddr),
}

#[derive(Default)]
pub struct Rpz {
    rules: HashMap<DnsName, RpzAction>,
}

impl Rpz {
    pub fn parse(text: &str) -> Result<Rpz, String> {
        let mut rules = HashMap::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let name_str = fields.next().unwrap();
            let name = DnsName::parse_str(name_str)
                .map_err(|e| format!("rpz line {}: bad name '{name_str}': {e}", i + 1))?;
            let action = match fields.next() {
                None => RpzAction::Block,
                Some(ip) => RpzAction::Redirect(
                    ip.parse().map_err(|_| format!("rpz line {}: bad address '{ip}'", i + 1))?,
                ),
            };
            if fields.next().is_some() {
                return Err(format!("rpz line {}: trailing fields", i + 1));
            }
            rules.insert(name, action);
        }
        Ok(Rpz { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Most-specific rule covering `qname` (the name itself or an ancestor).
    pub fn lookup(&self, qname: &DnsName) -> Option<RpzAction> {
        if self.rules.is_empty() {
            return None;
        }
        let labels = qname.labels();
        for skip in 0..labels.len() {
            let candidate = DnsName::from_labels(labels[skip..].to_vec()).ok()?;
            if let Some(action) = self.rules.get(&candidate) {
                return Some(*action);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> DnsName {
        DnsName::parse_str(s).unwrap()
    }

    #[test]
    fn parse_and_match() {
        let rpz = Rpz::parse(
            "# blocklist\nphishing.example\nmalware.test 10.0.0.99 ; sinkhole\n\n",
        )
        .unwrap();
        assert_eq!(rpz.len(), 2);
        assert_eq!(rpz.lookup(&n("phishing.example")), Some(RpzAction::Block));
        // Subdomains are covered.
        assert_eq!(rpz.lookup(&n("login.phishing.example")), Some(RpzAction::Block));
        assert_eq!(
            rpz.lookup(&n("malware.test")),
            Some(RpzAction::Redirect("10.0.0.99".parse().unwrap()))
        );
        // Suffix-of-a-label is NOT a match.
        assert_eq!(rpz.lookup(&n("notphishing.example")), None);
        assert_eq!(rpz.lookup(&n("example")), None);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Rpz::parse("bad.name 999.9.9.9").is_err());
        assert!(Rpz::parse("a.b 1.2.3.4 extra").is_err());
    }
}
