// SPDX-License-Identifier: GPL-2.0-only

//! Strict upload query, cursor and raw-range header decoding.

use axum::http::{HeaderMap, HeaderName};
use meshspan_api_contract::{
    ListUploadRangesQuery, OperationId, UploadRangeCursor as ApiUploadRangeCursor,
    validate_list_upload_ranges_query,
};

use super::{NativeUploadError, UploadRangeCursor, UploadRangePageRequest};
use crate::native_query::has_valid_percent_encoding;

const DEFAULT_RANGE_PAGE_LIMIT: u16 = 100;
pub(super) const OPERATION_ID_HEADER: HeaderName = HeaderName::from_static("meshspan-operation-id");
pub(super) const STAGE_FENCE_HEADER: HeaderName = HeaderName::from_static("meshspan-stage-fence");
pub(super) const CONTENT_BLAKE3_HEADER: HeaderName =
    HeaderName::from_static("meshspan-content-blake3");

pub(super) struct UploadRangeHeaders {
    pub(super) operation_id: OperationId,
    pub(super) stage_fence: u64,
    pub(super) content_blake3: [u8; 32],
}

pub(super) fn parse_range_page_query(
    raw_query: Option<&str>,
) -> Result<UploadRangePageRequest, NativeUploadError> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(UploadRangePageRequest {
            cursor: None,
            limit: DEFAULT_RANGE_PAGE_LIMIT,
        });
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(NativeUploadError::InvalidInput);
    }
    let mut query = ListUploadRangesQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor = Some(
                    ApiUploadRangeCursor::from_encoded(value.into_owned())
                        .ok_or(NativeUploadError::InvalidInput)?,
                );
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(parse_decimal(&value)?);
            }
            _ => return Err(NativeUploadError::InvalidInput),
        }
    }
    validate_list_upload_ranges_query(&query).map_err(|_| NativeUploadError::InvalidInput)?;
    Ok(UploadRangePageRequest {
        cursor: query.cursor.as_ref().map(decode_cursor).transpose()?,
        limit: query.limit.unwrap_or(DEFAULT_RANGE_PAGE_LIMIT),
    })
}

pub(super) fn parse_range_headers(
    headers: &HeaderMap,
) -> Result<UploadRangeHeaders, NativeUploadError> {
    let operation_id = one_header(headers, &OPERATION_ID_HEADER)?
        .to_str()
        .ok()
        .and_then(OperationId::parse)
        .ok_or(NativeUploadError::InvalidInput)?;
    let stage_fence = parse_decimal(
        one_header(headers, &STAGE_FENCE_HEADER)?
            .to_str()
            .map_err(|_| NativeUploadError::InvalidInput)?,
    )?;
    if stage_fence == 0 {
        return Err(NativeUploadError::InvalidInput);
    }
    let content_blake3 = decode_digest(
        one_header(headers, &CONTENT_BLAKE3_HEADER)?
            .to_str()
            .map_err(|_| NativeUploadError::InvalidInput)?,
    )?;
    Ok(UploadRangeHeaders {
        operation_id,
        stage_fence,
        content_blake3,
    })
}

pub(super) fn parse_range_offset(value: &str) -> Result<u64, NativeUploadError> {
    let offset = parse_decimal(value)?;
    (offset <= 9_007_199_254_740_991)
        .then_some(offset)
        .ok_or(NativeUploadError::InvalidInput)
}

fn decode_cursor(value: &ApiUploadRangeCursor) -> Result<UploadRangeCursor, NativeUploadError> {
    let mut fields = value.as_str().split('.');
    if fields.next() != Some("v1") {
        return Err(NativeUploadError::InvalidInput);
    }
    let checkpoint_sequence = fields
        .next()
        .ok_or(NativeUploadError::InvalidInput)
        .and_then(parse_decimal)?;
    let after_start = fields
        .next()
        .ok_or(NativeUploadError::InvalidInput)
        .and_then(parse_decimal)?;
    if fields.next().is_some() {
        return Err(NativeUploadError::InvalidInput);
    }
    Ok(UploadRangeCursor {
        checkpoint_sequence,
        after_start,
    })
}

fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<&'a axum::http::HeaderValue, NativeUploadError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(NativeUploadError::InvalidInput)?;
    if values.next().is_some() {
        Err(NativeUploadError::InvalidInput)
    } else {
        Ok(value)
    }
}

fn parse_decimal<T>(value: &str) -> Result<T, NativeUploadError>
where
    T: std::str::FromStr,
{
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(NativeUploadError::InvalidInput);
    }
    value.parse().map_err(|_| NativeUploadError::InvalidInput)
}

fn decode_digest(value: &str) -> Result<[u8; 32], NativeUploadError> {
    if value.len() != 64 {
        return Err(NativeUploadError::InvalidInput);
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(NativeUploadError::InvalidInput);
    }
    for (destination, pair) in digest.iter_mut().zip(pairs) {
        let high = decode_nibble(pair[0]).ok_or(NativeUploadError::InvalidInput)?;
        let low = decode_nibble(pair[1]).ok_or(NativeUploadError::InvalidInput)?;
        *destination = (high << 4) | low;
    }
    Ok(digest)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
