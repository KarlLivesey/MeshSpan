// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use thiserror::Error;

const HEADER_BYTES: usize = 12;
const MAXIMUM_MESSAGE_BYTES: usize = 65_535;
const MAXIMUM_POINTERS: usize = 32;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;

/// Canonical absolute DNS name with validated wire-length bounds.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsName(String);

impl DnsName {
    /// Validates and canonicalises an ASCII DNS name.
    ///
    /// # Errors
    ///
    /// Rejects empty, non-ASCII, oversized, malformed or root names.
    pub fn new(value: &str) -> Result<Self, DnsWireError> {
        let value = value
            .strip_suffix('.')
            .unwrap_or(value)
            .to_ascii_lowercase();
        if value.is_empty() || value.len() > 253 || !value.is_ascii() {
            return Err(DnsWireError::InvalidName);
        }
        for label in value.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(DnsWireError::InvalidName);
            }
        }
        Ok(Self(value))
    }

    /// Returns the canonical lower-case name without a trailing dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), DnsWireError> {
        for label in self.0.split('.') {
            output.push(u8::try_from(label.len()).map_err(|_| DnsWireError::InvalidName)?);
            output.extend_from_slice(label.as_bytes());
        }
        output.push(0);
        Ok(())
    }
}

/// One exact DNS TXT character-string value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxtValue(Vec<u8>);

impl TxtValue {
    /// Copies one non-empty TXT value fitting one RFC 1035 character-string.
    ///
    /// # Errors
    ///
    /// Rejects empty values and values longer than 255 bytes.
    pub fn new(value: &[u8]) -> Result<Self, DnsWireError> {
        if value.is_empty() || value.len() > usize::from(u8::MAX) {
            return Err(DnsWireError::InvalidTxt);
        }
        Ok(Self(value.to_vec()))
    }

    /// Returns the exact TXT bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Exact non-recursive authoritative TXT query and response expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    id: u16,
    name: DnsName,
}

impl DnsQuery {
    /// Creates one query with a caller-generated non-zero correlation identity.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, which are reserved to catch missing entropy.
    pub fn txt(id: u16, name: DnsName) -> Result<Self, DnsWireError> {
        if id == 0 {
            return Err(DnsWireError::InvalidId);
        }
        Ok(Self { id, name })
    }

    /// Encodes the complete bounded DNS request.
    ///
    /// # Errors
    ///
    /// Fails if the already validated name cannot be represented canonically.
    pub fn encode(&self) -> Result<Vec<u8>, DnsWireError> {
        let mut output = Vec::with_capacity(HEADER_BYTES + self.name.0.len() + 6);
        output.extend_from_slice(&self.id.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&[0; 6]);
        self.name.encode(&mut output)?;
        output.extend_from_slice(&TYPE_TXT.to_be_bytes());
        output.extend_from_slice(&CLASS_IN.to_be_bytes());
        Ok(output)
    }

    /// Proves that a complete authoritative response contains the exact expected TXT value.
    ///
    /// # Errors
    ///
    /// Rejects correlation mismatch, truncation, recursion, non-success status, malformed names,
    /// compression cycles, count/length overflow, question substitution and trailing bytes.
    pub fn response_contains(
        &self,
        response: &[u8],
        expected: &TxtValue,
    ) -> Result<bool, DnsWireError> {
        if response.len() < HEADER_BYTES || response.len() > MAXIMUM_MESSAGE_BYTES {
            return Err(DnsWireError::InvalidMessage);
        }
        let header = Header::decode(response)?;
        if header.id != self.id || !header.response || !header.authoritative || header.opcode != 0 {
            return Err(DnsWireError::InvalidMessage);
        }
        if header.truncated {
            return Err(DnsWireError::Truncated);
        }
        if header.rcode != 0 {
            return Err(DnsWireError::Rejected);
        }
        if header.questions != 1 {
            return Err(DnsWireError::InvalidMessage);
        }
        let mut cursor = HEADER_BYTES;
        let question = decode_name(response, &mut cursor)?;
        if question != self.name
            || read_u16(response, &mut cursor)? != TYPE_TXT
            || read_u16(response, &mut cursor)? != CLASS_IN
        {
            return Err(DnsWireError::InvalidMessage);
        }
        let mut found = false;
        for index in 0..header.total_records()? {
            let owner = decode_name(response, &mut cursor)?;
            let record_type = read_u16(response, &mut cursor)?;
            let class = read_u16(response, &mut cursor)?;
            let _ttl = read_u32(response, &mut cursor)?;
            let length = usize::from(read_u16(response, &mut cursor)?);
            let rdata = take(response, &mut cursor, length)?;
            if index < usize::from(header.answers)
                && owner == self.name
                && record_type == TYPE_TXT
                && class == CLASS_IN
                && exact_txt(rdata, expected.as_bytes())
            {
                found = true;
            }
        }
        if cursor != response.len() {
            return Err(DnsWireError::InvalidMessage);
        }
        Ok(found)
    }
}

struct Header {
    id: u16,
    response: bool,
    authoritative: bool,
    opcode: u8,
    truncated: bool,
    rcode: u8,
    questions: u16,
    answers: u16,
    authorities: u16,
    additional: u16,
}

impl Header {
    fn decode(bytes: &[u8]) -> Result<Self, DnsWireError> {
        let mut cursor = 0;
        let id = read_u16(bytes, &mut cursor)?;
        let flags = read_u16(bytes, &mut cursor)?;
        Ok(Self {
            id,
            response: flags & 0x8000 != 0,
            authoritative: flags & 0x0400 != 0,
            opcode: ((flags >> 11) & 0x0f) as u8,
            truncated: flags & 0x0200 != 0,
            rcode: (flags & 0x000f) as u8,
            questions: read_u16(bytes, &mut cursor)?,
            answers: read_u16(bytes, &mut cursor)?,
            authorities: read_u16(bytes, &mut cursor)?,
            additional: read_u16(bytes, &mut cursor)?,
        })
    }

    fn total_records(&self) -> Result<usize, DnsWireError> {
        usize::from(self.answers)
            .checked_add(usize::from(self.authorities))
            .and_then(|value| value.checked_add(usize::from(self.additional)))
            .ok_or(DnsWireError::InvalidMessage)
    }
}

fn decode_name(bytes: &[u8], cursor: &mut usize) -> Result<DnsName, DnsWireError> {
    let mut labels = Vec::new();
    let mut scan = *cursor;
    let mut consumed = None;
    let mut pointers = BTreeSet::new();
    for _ in 0..=MAXIMUM_POINTERS {
        let length = *bytes.get(scan).ok_or(DnsWireError::InvalidMessage)?;
        if length == 0 {
            *cursor = consumed.unwrap_or(scan + 1);
            return DnsName::new(&labels.join("."));
        }
        if length & 0xc0 == 0xc0 {
            let second = *bytes.get(scan + 1).ok_or(DnsWireError::InvalidMessage)?;
            let pointer = usize::from(u16::from(length & 0x3f) << 8 | u16::from(second));
            if pointer >= bytes.len() || !pointers.insert(pointer) {
                return Err(DnsWireError::InvalidMessage);
            }
            consumed.get_or_insert(scan + 2);
            scan = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsWireError::InvalidMessage);
        }
        let start = scan + 1;
        let label = take_at(bytes, start, usize::from(length))?;
        labels.push(std::str::from_utf8(label).map_err(|_| DnsWireError::InvalidMessage)?);
        scan = start + usize::from(length);
    }
    Err(DnsWireError::InvalidMessage)
}

fn exact_txt(rdata: &[u8], expected: &[u8]) -> bool {
    rdata
        .first()
        .is_some_and(|length| usize::from(*length) + 1 == rdata.len())
        && rdata.get(1..) == Some(expected)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, DnsWireError> {
    let value: [u8; 2] = take(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| DnsWireError::InvalidMessage)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, DnsWireError> {
    let value: [u8; 4] = take(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| DnsWireError::InvalidMessage)?;
    Ok(u32::from_be_bytes(value))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], DnsWireError> {
    let value = take_at(bytes, *cursor, length)?;
    *cursor = cursor
        .checked_add(length)
        .ok_or(DnsWireError::InvalidMessage)?;
    Ok(value)
}

fn take_at(bytes: &[u8], start: usize, length: usize) -> Result<&[u8], DnsWireError> {
    let end = start
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(DnsWireError::InvalidMessage)?;
    Ok(&bytes[start..end])
}

/// Closed DNS wire failure without returning hostile bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DnsWireError {
    /// Query correlation identity is missing.
    #[error("DNS message identity is invalid")]
    InvalidId,
    /// DNS name is not canonical or representable.
    #[error("DNS name is invalid")]
    InvalidName,
    /// TXT value cannot fit one character-string.
    #[error("DNS TXT value is invalid")]
    InvalidTxt,
    /// Message framing, counts, names or expected question are invalid.
    #[error("DNS message is invalid")]
    InvalidMessage,
    /// UDP response requires an exact TCP retry.
    #[error("DNS response is truncated")]
    Truncated,
    /// Authoritative server returned a non-success response code.
    #[error("DNS server rejected the request")]
    Rejected,
}
