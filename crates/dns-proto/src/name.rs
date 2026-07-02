//! Domain names: RFC 1035 wire format, including compression pointers.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use crate::message::WireError;

pub const MAX_NAME_WIRE_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;
/// Belt-and-suspenders bound on pointer chases; combined with the "pointers
/// must go backwards" rule this makes malicious compression loops impossible.
const MAX_POINTER_JUMPS: usize = 64;

/// A fully-qualified domain name stored as lowercase labels (DNS names are
/// compared case-insensitively, RFC 4343). The root name has zero labels.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    EmptyLabel,
    LabelTooLong,
    NameTooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::EmptyLabel => write!(f, "empty label"),
            NameError::LabelTooLong => write!(f, "label exceeds {MAX_LABEL_LEN} octets"),
            NameError::NameTooLong => write!(f, "name exceeds {MAX_NAME_WIRE_LEN} octets"),
        }
    }
}

impl std::error::Error for NameError {}

impl DnsName {
    pub fn root() -> Self {
        DnsName { labels: Vec::new() }
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Length in uncompressed wire form (length octets + labels + root octet).
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, NameError> {
        let name = DnsName { labels };
        name.validate()?;
        Ok(name)
    }

    fn validate(&self) -> Result<(), NameError> {
        for l in &self.labels {
            if l.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if l.len() > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong);
            }
        }
        if self.wire_len() > MAX_NAME_WIRE_LEN {
            return Err(NameError::NameTooLong);
        }
        Ok(())
    }

    /// Parse a dotted name such as `www.example.com.`. A trailing dot is
    /// accepted but not required; relative resolution against an origin is the
    /// caller's job (see [`DnsName::concat`]).
    pub fn parse_str(s: &str) -> Result<Self, NameError> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() {
            return Ok(Self::root());
        }
        let labels = s
            .split('.')
            .map(|l| l.as_bytes().to_ascii_lowercase())
            .collect();
        Self::from_labels(labels)
    }

    /// `self` + `suffix`, e.g. `www` + `example.com.` = `www.example.com.`
    pub fn concat(&self, suffix: &DnsName) -> Result<Self, NameError> {
        let mut labels = self.labels.clone();
        labels.extend(suffix.labels.iter().cloned());
        Self::from_labels(labels)
    }

    /// True if `self` equals `suffix` or is a subdomain of it.
    pub fn ends_with(&self, suffix: &DnsName) -> bool {
        let n = suffix.labels.len();
        self.labels.len() >= n && self.labels[self.labels.len() - n..] == suffix.labels[..]
    }

    /// Wildcard candidate `*.<self minus the first `skip` labels>`.
    pub fn wildcard_at(&self, skip: usize) -> Option<Self> {
        if skip == 0 || skip > self.labels.len() {
            return None;
        }
        let mut labels = vec![b"*".to_vec()];
        labels.extend(self.labels[skip..].iter().cloned());
        Some(DnsName { labels })
    }

    /// Decode a (possibly compressed) name. `pos` is advanced past the name in
    /// the *current* location — i.e. past the first compression pointer if one
    /// was followed.
    pub fn from_wire(buf: &[u8], pos: &mut usize) -> Result<Self, WireError> {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut cur = *pos;
        let mut end_of_name: Option<usize> = None;
        let mut jumps = 0usize;
        let mut wire_len = 1usize; // terminating root octet

        loop {
            let len = *buf.get(cur).ok_or(WireError::Truncated)? as usize;
            if len == 0 {
                cur += 1;
                break;
            } else if len & 0xC0 == 0xC0 {
                let b2 = *buf.get(cur + 1).ok_or(WireError::Truncated)? as usize;
                let target = ((len & 0x3F) << 8) | b2;
                if end_of_name.is_none() {
                    end_of_name = Some(cur + 2);
                }
                // RFC 1035: a pointer refers to a *prior* occurrence.
                if target >= cur {
                    return Err(WireError::CompressionLoop);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(WireError::CompressionLoop);
                }
                cur = target;
            } else if len <= MAX_LABEL_LEN {
                let start = cur + 1;
                let end = start + len;
                let label = buf.get(start..end).ok_or(WireError::Truncated)?;
                wire_len += len + 1;
                if wire_len > MAX_NAME_WIRE_LEN {
                    return Err(WireError::NameTooLong);
                }
                labels.push(label.to_ascii_lowercase());
                cur = end;
            } else {
                // 0x40/0x80 prefixes: obsolete extended label types.
                return Err(WireError::BadLabel);
            }
        }

        *pos = end_of_name.unwrap_or(cur);
        Ok(DnsName { labels })
    }

    /// Encode the name, emitting a compression pointer for the longest suffix
    /// already present in `compressor` and registering new suffixes.
    pub fn to_wire(&self, out: &mut Vec<u8>, mut compressor: Option<&mut Compressor>) {
        for i in 0..self.labels.len() {
            if let Some(c) = compressor.as_deref_mut() {
                if let Some(&off) = c.offsets.get(&self.labels[i..]) {
                    out.extend_from_slice(&(0xC000u16 | off).to_be_bytes());
                    return;
                }
                // Pointers only address the first 16 KiB - 2 bits of a message.
                if out.len() <= 0x3FFF {
                    c.offsets.insert(self.labels[i..].to_vec(), out.len() as u16);
                }
            }
            let label = &self.labels[i];
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for l in &self.labels {
            for &b in l {
                match b {
                    b'.' => f.write_str("\\.")?,
                    0x21..=0x7E => f.write_char(b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_char('.')?;
        }
        Ok(())
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Suffix → offset map shared across one encoded message.
#[derive(Default)]
pub struct Compressor {
    offsets: HashMap<Vec<Vec<u8>>, u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> DnsName {
        DnsName::parse_str(s).unwrap()
    }

    #[test]
    fn parse_and_display() {
        assert_eq!(n("WWW.Example.COM.").to_string(), "www.example.com.");
        assert_eq!(DnsName::root().to_string(), ".");
        assert_eq!(n("a.b").label_count(), 2);
        assert!(DnsName::parse_str("a..b").is_err());
        assert!(DnsName::parse_str(&"x".repeat(64)).is_err());
    }

    #[test]
    fn suffix_relations() {
        assert!(n("www.example.com").ends_with(&n("example.com")));
        assert!(n("example.com").ends_with(&n("example.com")));
        assert!(!n("example.com").ends_with(&n("www.example.com")));
        assert!(n("anything").ends_with(&DnsName::root()));
        assert_eq!(n("a.b.c").wildcard_at(1).unwrap(), n("*.b.c"));
    }

    #[test]
    fn wire_roundtrip_plain() {
        let name = n("mail.example.com");
        let mut buf = Vec::new();
        name.to_wire(&mut buf, None);
        assert_eq!(buf.len(), name.wire_len());
        let mut pos = 0;
        let back = DnsName::from_wire(&buf, &mut pos).unwrap();
        assert_eq!(back, name);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn wire_roundtrip_compressed() {
        let a = n("www.example.com");
        let b = n("mail.example.com");
        let mut buf = Vec::new();
        let mut comp = Compressor::default();
        a.to_wire(&mut buf, Some(&mut comp));
        let start_b = buf.len();
        b.to_wire(&mut buf, Some(&mut comp));
        // "example.com" suffix of b must have been emitted as a 2-byte pointer.
        assert_eq!(buf.len() - start_b, 1 + 4 + 2);

        let mut pos = 0;
        assert_eq!(DnsName::from_wire(&buf, &mut pos).unwrap(), a);
        assert_eq!(DnsName::from_wire(&buf, &mut pos).unwrap(), b);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn rejects_pointer_loops() {
        // Pointer at offset 0 pointing to itself.
        let buf = [0xC0, 0x00];
        let mut pos = 0;
        assert_eq!(
            DnsName::from_wire(&buf, &mut pos),
            Err(WireError::CompressionLoop)
        );
        // Forward pointer is equally invalid.
        let buf = [0xC0, 0x02, 3, b'f', b'o', b'o', 0];
        let mut pos = 0;
        assert_eq!(
            DnsName::from_wire(&buf, &mut pos),
            Err(WireError::CompressionLoop)
        );
    }
}
