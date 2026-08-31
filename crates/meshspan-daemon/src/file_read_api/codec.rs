// SPDX-License-Identifier: GPL-2.0-only

//! Strict query parsing for native bounded file reads.

use meshspan_api_contract::{
    MAX_FILE_READ_BYTES, MAX_SAFE_FILE_OFFSET, NamespacePath as ApiNamespacePath, ReadFileQuery,
    validate_read_file_query,
};

use super::service::FileReadError;
use crate::native_query::has_valid_percent_encoding;

pub(super) fn parse_file_read_query(
    raw_query: Option<&str>,
) -> Result<ReadFileQuery, FileReadError> {
    let raw_query = raw_query.ok_or(FileReadError::InvalidInput)?;
    if raw_query.is_empty()
        || raw_query.len() > 16_384
        || !has_valid_percent_encoding(raw_query.as_bytes())
    {
        return Err(FileReadError::InvalidInput);
    }
    let mut path = None;
    let mut offset = None;
    let mut length = None;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "path" if path.is_none() => {
                path = Some(
                    ApiNamespacePath::from_decoded(value.into_owned())
                        .ok_or(FileReadError::InvalidInput)?,
                );
            }
            "offset" if offset.is_none() => {
                offset = Some(parse_decimal::<u64>(&value)?);
            }
            "length" if length.is_none() => {
                length = Some(parse_decimal::<u32>(&value)?);
            }
            _ => return Err(FileReadError::InvalidInput),
        }
    }
    let query = ReadFileQuery {
        path: path.ok_or(FileReadError::InvalidInput)?,
        offset,
        length,
    };
    validate_read_file_query(&query).map_err(|_| FileReadError::InvalidInput)?;
    if query
        .offset
        .is_some_and(|value| value > MAX_SAFE_FILE_OFFSET)
        || query
            .length
            .is_some_and(|value| value == 0 || value > MAX_FILE_READ_BYTES)
    {
        return Err(FileReadError::InvalidInput);
    }
    Ok(query)
}

fn parse_decimal<T>(value: &str) -> Result<T, FileReadError>
where
    T: std::str::FromStr,
{
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(FileReadError::InvalidInput);
    }
    value.parse().map_err(|_| FileReadError::InvalidInput)
}
