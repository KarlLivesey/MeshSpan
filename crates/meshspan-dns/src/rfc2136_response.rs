// SPDX-License-Identifier: GPL-2.0-only

use thiserror::Error;

use crate::{
    DnsName, DnsWireError, Rfc2136RequestError, Rfc2136TsigKey, SignedRfc2136Request,
    wire::{decode_name, read_u16, read_u32, take},
};

const CLASS_ANY: u16 = 255;
const HEADER_BYTES: usize = 12;
const MAXIMUM_DNS_MESSAGE_BYTES: usize = 65_535;
const MAXIMUM_FUDGE_SECONDS: u16 = 3_600;
const TYPE_TSIG: u16 = 250;
const UPDATE_OPCODE: u16 = 5;

struct TsigFields<'a> {
    owner: DnsName,
    algorithm: DnsName,
    time_signed: u64,
    fudge: u16,
    mac: &'a [u8],
    original_id: u16,
    error: u16,
    other: &'a [u8],
    record_start: usize,
}

struct Response<'a> {
    rcode: u8,
    additional_count: u16,
    tsig: TsigFields<'a>,
}

impl SignedRfc2136Request {
    /// Authenticates and validates the complete response to this exact update request.
    ///
    /// Authentication, identity and time checks occur before a DNS or TSIG rejection is exposed.
    ///
    /// # Errors
    ///
    /// Rejects missing, malformed, stale, incorrectly keyed, truncated or tampered responses and
    /// reports authenticated non-success DNS results without returning hostile response bytes.
    pub fn verify_response(
        &self,
        response: &[u8],
        key: &Rfc2136TsigKey,
        now_seconds: u64,
    ) -> Result<(), Rfc2136ResponseError> {
        let parsed = parse_response(response)?;
        validate_tsig_identity(&parsed.tsig, self, key)?;
        let authenticated = response_mac_input(response, &parsed, self)?;
        key.algorithm()
            .verify(key.secret(), &authenticated, parsed.tsig.mac)
            .map_err(|_| Rfc2136ResponseError::Authentication)?;
        validate_tsig_time(&parsed.tsig, now_seconds)?;
        if parsed.rcode != 0 || parsed.tsig.error != 0 {
            return Err(Rfc2136ResponseError::Rejected {
                rcode: parsed.rcode,
                tsig_error: parsed.tsig.error,
            });
        }
        Ok(())
    }
}

fn parse_response(bytes: &[u8]) -> Result<Response<'_>, Rfc2136ResponseError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAXIMUM_DNS_MESSAGE_BYTES {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    let mut cursor = 0;
    let _response_id = read_u16(bytes, &mut cursor)?;
    let flags = read_u16(bytes, &mut cursor)?;
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0x000f) as u8;
    if !response || opcode != UPDATE_OPCODE || truncated {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    let zone_count = read_u16(bytes, &mut cursor)?;
    let prerequisite_count = read_u16(bytes, &mut cursor)?;
    let update_count = read_u16(bytes, &mut cursor)?;
    let additional_count = read_u16(bytes, &mut cursor)?;
    if additional_count == 0 {
        return Err(Rfc2136ResponseError::Authentication);
    }
    for _ in 0..zone_count {
        skip_question(bytes, &mut cursor)?;
    }
    for _ in 0..prerequisite_count {
        skip_non_tsig_record(bytes, &mut cursor)?;
    }
    for _ in 0..update_count {
        skip_non_tsig_record(bytes, &mut cursor)?;
    }
    for _ in 1..additional_count {
        skip_non_tsig_record(bytes, &mut cursor)?;
    }
    let tsig = parse_tsig(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    Ok(Response {
        rcode,
        additional_count,
        tsig,
    })
}

fn skip_question(bytes: &[u8], cursor: &mut usize) -> Result<(), Rfc2136ResponseError> {
    decode_name(bytes, cursor)?;
    read_u16(bytes, cursor)?;
    read_u16(bytes, cursor)?;
    Ok(())
}

fn skip_non_tsig_record(bytes: &[u8], cursor: &mut usize) -> Result<(), Rfc2136ResponseError> {
    decode_name(bytes, cursor)?;
    let record_type = read_u16(bytes, cursor)?;
    read_u16(bytes, cursor)?;
    read_u32(bytes, cursor)?;
    let length = usize::from(read_u16(bytes, cursor)?);
    take(bytes, cursor, length)?;
    if record_type == TYPE_TSIG {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    Ok(())
}

fn parse_tsig<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<TsigFields<'a>, Rfc2136ResponseError> {
    let record_start = *cursor;
    let owner = decode_uncompressed_name(bytes, cursor, bytes.len())?;
    if read_u16(bytes, cursor)? != TYPE_TSIG
        || read_u16(bytes, cursor)? != CLASS_ANY
        || read_u32(bytes, cursor)? != 0
    {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    let rdata_length = usize::from(read_u16(bytes, cursor)?);
    let rdata_end = cursor
        .checked_add(rdata_length)
        .filter(|end| *end <= bytes.len())
        .ok_or(Rfc2136ResponseError::InvalidMessage)?;
    let algorithm = decode_uncompressed_name(bytes, cursor, rdata_end)?;
    let time_signed = read_u48(bytes, cursor)?;
    let fudge = read_u16(bytes, cursor)?;
    let mac_length = usize::from(read_u16(bytes, cursor)?);
    let mac = take(bytes, cursor, mac_length)?;
    let original_id = read_u16(bytes, cursor)?;
    let error = read_u16(bytes, cursor)?;
    let other_length = usize::from(read_u16(bytes, cursor)?);
    let other = take(bytes, cursor, other_length)?;
    if *cursor != rdata_end {
        return Err(Rfc2136ResponseError::InvalidMessage);
    }
    Ok(TsigFields {
        owner,
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
        record_start,
    })
}

fn validate_tsig_identity(
    tsig: &TsigFields<'_>,
    request: &SignedRfc2136Request,
    key: &Rfc2136TsigKey,
) -> Result<(), Rfc2136ResponseError> {
    if tsig.owner != *key.name()
        || tsig.algorithm != key.algorithm().name()?
        || tsig.original_id != request.id()
        || tsig.fudge == 0
        || tsig.fudge > MAXIMUM_FUDGE_SECONDS
    {
        return Err(Rfc2136ResponseError::Authentication);
    }
    Ok(())
}

fn validate_tsig_time(tsig: &TsigFields<'_>, now_seconds: u64) -> Result<(), Rfc2136ResponseError> {
    if now_seconds.abs_diff(tsig.time_signed) > u64::from(tsig.fudge) {
        return Err(Rfc2136ResponseError::Authentication);
    }
    Ok(())
}

fn response_mac_input(
    bytes: &[u8],
    response: &Response<'_>,
    request: &SignedRfc2136Request,
) -> Result<Vec<u8>, Rfc2136ResponseError> {
    let mut authenticated = Vec::with_capacity(bytes.len() + request.request_mac().len() + 128);
    authenticated.extend_from_slice(
        &u16::try_from(request.request_mac().len())
            .map_err(|_| Rfc2136ResponseError::InvalidMessage)?
            .to_be_bytes(),
    );
    authenticated.extend_from_slice(request.request_mac());
    let message_start = authenticated.len();
    authenticated.extend_from_slice(&bytes[..response.tsig.record_start]);
    authenticated[message_start..message_start + 2].copy_from_slice(&request.id().to_be_bytes());
    authenticated[message_start + 10..message_start + 12]
        .copy_from_slice(&(response.additional_count - 1).to_be_bytes());
    response.tsig.owner.encode(&mut authenticated)?;
    authenticated.extend_from_slice(&CLASS_ANY.to_be_bytes());
    authenticated.extend_from_slice(&0_u32.to_be_bytes());
    response.tsig.algorithm.encode(&mut authenticated)?;
    append_time(&mut authenticated, response.tsig.time_signed);
    authenticated.extend_from_slice(&response.tsig.fudge.to_be_bytes());
    authenticated.extend_from_slice(&response.tsig.error.to_be_bytes());
    authenticated.extend_from_slice(
        &u16::try_from(response.tsig.other.len())
            .map_err(|_| Rfc2136ResponseError::InvalidMessage)?
            .to_be_bytes(),
    );
    authenticated.extend_from_slice(response.tsig.other);
    Ok(authenticated)
}

fn decode_uncompressed_name(
    bytes: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<DnsName, Rfc2136ResponseError> {
    let mut labels = Vec::new();
    loop {
        let length = usize::from(
            *bytes
                .get(*cursor)
                .filter(|_| *cursor < limit)
                .ok_or(Rfc2136ResponseError::InvalidMessage)?,
        );
        *cursor = cursor
            .checked_add(1)
            .ok_or(Rfc2136ResponseError::InvalidMessage)?;
        if length == 0 {
            return DnsName::new(&labels.join(".")).map_err(Into::into);
        }
        if length > 63 || cursor.checked_add(length).is_none_or(|end| end > limit) {
            return Err(Rfc2136ResponseError::InvalidMessage);
        }
        let label = take(bytes, cursor, length)?;
        labels.push(std::str::from_utf8(label).map_err(|_| Rfc2136ResponseError::InvalidMessage)?);
    }
}

fn read_u48(bytes: &[u8], cursor: &mut usize) -> Result<u64, Rfc2136ResponseError> {
    let value = take(bytes, cursor, 6)?;
    Ok(value
        .iter()
        .fold(0_u64, |total, byte| (total << 8) | u64::from(*byte)))
}

fn append_time(output: &mut Vec<u8>, seconds: u64) {
    output.extend_from_slice(&seconds.to_be_bytes()[2..]);
}

/// Closed authenticated-update response failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Rfc2136ResponseError {
    /// DNS message structure, bounds or update response flags are invalid.
    #[error("RFC 2136 response is invalid")]
    InvalidMessage,
    /// Response is absent, unsigned, stale, incorrectly keyed or fails its TSIG MAC.
    #[error("RFC 2136 response authentication failed")]
    Authentication,
    /// The authenticated DNS server rejected the update.
    #[error("RFC 2136 update was rejected with DNS code {rcode} and TSIG code {tsig_error}")]
    Rejected {
        /// Four-bit DNS response code.
        rcode: u8,
        /// Extended TSIG response code.
        tsig_error: u16,
    },
    /// Shared DNS parsing failed.
    #[error("RFC 2136 response DNS value is invalid")]
    Wire(#[from] DnsWireError),
    /// Internal request authentication state was invalid.
    #[error("RFC 2136 request authentication state is invalid")]
    Request(#[from] Rfc2136RequestError),
}
