// SPDX-License-Identifier: GPL-2.0-only

//! Cursor and strict public projection for authentication-method inventory.

use meshspan_api_contract::{
    ApiKeyId as ApiApiKeyId, ApiKeyScope, AuthenticationMethodCursor as ApiCursor,
    AuthenticationMethodDetails as ApiDetails, AuthenticationMethodId as ApiMethodId,
    AuthenticationMethodState as ApiState, AuthenticationMethodSummary as ApiSummary,
    ListAuthenticationMethodsResponse,
};
use meshspan_domain::{AuthenticationMethodId, AuthenticationMethodKind, PrincipalId};
use meshspan_metadata::{
    AuthenticationMethodCursor, AuthenticationMethodRecord, AuthenticationMethodRecordDetails, Page,
};

use super::AuthenticationMethodListingError;

pub(super) fn decode_cursor(
    cursor: &ApiCursor,
    principal_id: PrincipalId,
) -> Result<AuthenticationMethodCursor, AuthenticationMethodListingError> {
    let fields = cursor.as_str().split('.').collect::<Vec<_>>();
    if fields.len() != 6 || fields[0] != "v1" || fields[1] != "am" {
        return Err(AuthenticationMethodListingError::InvalidRequest);
    }
    let encoded_principal = PrincipalId::from_bytes(decode_array(fields[2])?)
        .map_err(|_| AuthenticationMethodListingError::InvalidRequest)?;
    let state = fields[3]
        .parse::<u8>()
        .ok()
        .filter(|value| (1..=3).contains(value))
        .ok_or(AuthenticationMethodListingError::InvalidRequest)?;
    let kind = parse_kind(fields[4])?;
    let method_id = AuthenticationMethodId::from_bytes(decode_array(fields[5])?)
        .map_err(|_| AuthenticationMethodListingError::InvalidRequest)?;
    if encoded_principal != principal_id {
        return Err(AuthenticationMethodListingError::InvalidRequest);
    }
    Ok(AuthenticationMethodCursor::new(
        principal_id,
        state,
        kind,
        method_id,
    ))
}

pub(super) fn list_response(
    limit: u16,
    page: Page<AuthenticationMethodRecord, AuthenticationMethodCursor>,
) -> Result<ListAuthenticationMethodsResponse, AuthenticationMethodListingError> {
    let methods = page
        .items
        .into_iter()
        .map(public_method)
        .collect::<Result<Vec<_>, _>>()?;
    let next_page_url = page
        .next
        .map(|cursor| next_page_url(limit, cursor))
        .transpose()?;
    Ok(ListAuthenticationMethodsResponse {
        methods,
        next_page_url,
    })
}

fn public_method(
    record: AuthenticationMethodRecord,
) -> Result<ApiSummary, AuthenticationMethodListingError> {
    if record.label.is_empty()
        || record.label.chars().count() > 80
        || record.label.chars().any(char::is_control)
        || !(0..=9_007_199_254_740_991).contains(&record.created_at.get())
        || record
            .last_used_at
            .is_some_and(|value| !(0..=9_007_199_254_740_991).contains(&value.get()))
        || record
            .expires_at
            .is_some_and(|value| !(0..=9_007_199_254_740_991).contains(&value.get()))
        || record.revision.get() == 0
        || record.revision.get() > 9_007_199_254_740_991
    {
        return Err(AuthenticationMethodListingError::Failed);
    }
    Ok(ApiSummary {
        method_id: ApiMethodId::from_uuid_bytes(record.method_id.as_bytes())
            .ok_or(AuthenticationMethodListingError::Failed)?,
        label: record.label,
        state: public_state(record.state)?,
        details: public_details(&record.details)?,
        created_at_epoch_micros: record.created_at.get(),
        last_used_at_epoch_micros: record.last_used_at.map(meshspan_domain::UnixMicros::get),
        expires_at_epoch_micros: record.expires_at.map(meshspan_domain::UnixMicros::get),
        revision: record.revision.get(),
    })
}

fn public_details(
    details: &AuthenticationMethodRecordDetails,
) -> Result<ApiDetails, AuthenticationMethodListingError> {
    match details {
        AuthenticationMethodRecordDetails::Passkey {
            backup_eligible,
            backup_state,
        } => Ok(ApiDetails::Passkey {
            backup_eligible: *backup_eligible,
            backup_state: *backup_state,
        }),
        AuthenticationMethodRecordDetails::Totp => Ok(ApiDetails::Totp),
        AuthenticationMethodRecordDetails::RecoveryCodes { remaining_codes } => {
            Ok(ApiDetails::RecoveryCodes {
                remaining_codes: *remaining_codes,
            })
        }
        AuthenticationMethodRecordDetails::ApiKey {
            key_id,
            scopes,
            valid_from,
        } => Ok(ApiDetails::ApiKey {
            key_id: ApiApiKeyId::from_uuid_bytes(key_id.as_bytes())
                .ok_or(AuthenticationMethodListingError::Failed)?,
            scopes: public_scopes(*scopes)?,
            valid_from_epoch_micros: valid_from.get(),
        }),
    }
}

fn public_scopes(bits: u64) -> Result<Vec<ApiKeyScope>, AuthenticationMethodListingError> {
    if bits == 0 || bits & !0b111 != 0 {
        return Err(AuthenticationMethodListingError::Failed);
    }
    let mut scopes = Vec::with_capacity(3);
    if bits & 1 != 0 {
        scopes.push(ApiKeyScope::HttpsSession);
    }
    if bits & 2 != 0 {
        scopes.push(ApiKeyScope::HeadlessApi);
    }
    if bits & 4 != 0 {
        scopes.push(ApiKeyScope::SmbSession);
    }
    Ok(scopes)
}

const fn public_state(state: u8) -> Result<ApiState, AuthenticationMethodListingError> {
    match state {
        1 => Ok(ApiState::Active),
        2 => Ok(ApiState::Suspended),
        3 => Ok(ApiState::Revoked),
        _ => Err(AuthenticationMethodListingError::Failed),
    }
}

fn next_page_url(
    limit: u16,
    cursor: AuthenticationMethodCursor,
) -> Result<String, AuthenticationMethodListingError> {
    let encoded = encode_cursor(cursor);
    let url =
        format!("/api/latest/users/current/authentication-methods?limit={limit}&cursor={encoded}");
    (url.len() <= 16_384)
        .then_some(url)
        .ok_or(AuthenticationMethodListingError::Failed)
}

fn encode_cursor(cursor: AuthenticationMethodCursor) -> String {
    format!(
        "v1.am.{}.{}.{}.{}",
        encode_hex(&cursor.principal_id().as_bytes()),
        cursor.state(),
        kind_code(cursor.kind()),
        encode_hex(&cursor.method_id().as_bytes())
    )
}

const fn kind_code(kind: AuthenticationMethodKind) -> &'static str {
    match kind {
        AuthenticationMethodKind::Passkey => "1",
        AuthenticationMethodKind::Totp => "2",
        AuthenticationMethodKind::RecoveryCode => "3",
        AuthenticationMethodKind::ApiKey => "4",
    }
}

fn parse_kind(value: &str) -> Result<AuthenticationMethodKind, AuthenticationMethodListingError> {
    match value {
        "1" => Ok(AuthenticationMethodKind::Passkey),
        "2" => Ok(AuthenticationMethodKind::Totp),
        "3" => Ok(AuthenticationMethodKind::RecoveryCode),
        "4" => Ok(AuthenticationMethodKind::ApiKey),
        _ => Err(AuthenticationMethodListingError::InvalidRequest),
    }
}

fn encode_hex<const N: usize>(value: &[u8; N]) -> String {
    let mut output = String::with_capacity(N * 2);
    for byte in value {
        use std::fmt::Write;
        let _ignored = write!(output, "{byte:02x}");
    }
    output
}

fn decode_array(value: &str) -> Result<[u8; 16], AuthenticationMethodListingError> {
    if value.len() != 32 {
        return Err(AuthenticationMethodListingError::InvalidRequest);
    }
    let mut output = [0; 16];
    for (index, destination) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *destination = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AuthenticationMethodListingError::InvalidRequest)?;
    }
    Ok(output)
}
