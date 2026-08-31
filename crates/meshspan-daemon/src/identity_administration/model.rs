// SPDX-License-Identifier: GPL-2.0-only

//! Strict public/domain identity conversion, deterministic identities and cursor codec.

use meshspan_api_contract::{
    CreatePrincipalResponse, ListPrincipalsQuery, ListPrincipalsResponse,
    OperationId as ApiOperationId, PrincipalCursor as ApiPrincipalCursor,
    PrincipalId as ApiPrincipalId, PrincipalKind as ApiPrincipalKind,
    PrincipalState as ApiPrincipalState, PrincipalSummary,
};
use meshspan_domain::{AuditEventId, GroupId, OperationId, PrincipalId, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateGroup, CreateUser, Page, PrincipalCursor,
    PrincipalKind, PrincipalRecord, RecordName,
};
use sha2::{Digest, Sha256};

use super::{IdentityAdministrationCommit, IdentityAdministrationError, IdentityAdministrator};
use crate::create_mesh_setup::parse_uuid;

const USER_ID_DOMAIN: &[u8] = b"meshspan.identity.user-id.v1\0";
const GROUP_ID_DOMAIN: &[u8] = b"meshspan.identity.group-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.identity.audit-id.v1\0";

pub(super) fn domain_operation(
    value: &ApiOperationId,
) -> Result<OperationId, IdentityAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| IdentityAdministrationError::InvalidInput)?,
    )
    .map_err(|_| IdentityAdministrationError::InvalidInput)
}

pub(super) fn user_command(
    request: &meshspan_api_contract::CreateUserRequest,
) -> Result<(OperationId, PrincipalId, AuthoritativeCommand), IdentityAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let principal_id = derived_principal(USER_ID_DOMAIN, operation_id)?;
    let name = RecordName::new(request.display_name.as_str())
        .map_err(|_| IdentityAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        principal_id,
        AuthoritativeCommand::CreateUser(CreateUser { principal_id, name }),
    ))
}

pub(super) fn group_command(
    request: &meshspan_api_contract::CreateGroupRequest,
) -> Result<(OperationId, PrincipalId, AuthoritativeCommand), IdentityAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let principal_id = derived_principal(GROUP_ID_DOMAIN, operation_id)?;
    let group_id = GroupId::from_bytes(principal_id.as_bytes())
        .map_err(|_| IdentityAdministrationError::Failed)?;
    let name = RecordName::new(request.display_name.as_str())
        .map_err(|_| IdentityAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        principal_id,
        AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id,
            name,
            activation_policy_id: None,
        }),
    ))
}

pub(super) fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
    occurred_at: meshspan_domain::UnixMicros,
) -> Result<CommandContext, IdentityAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| IdentityAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| IdentityAdministrationError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(super) fn creation_response(
    request_operation: &ApiOperationId,
    commit: IdentityAdministrationCommit,
    record: PrincipalRecord,
) -> Result<CreatePrincipalResponse, IdentityAdministrationError> {
    if commit.result_digest == [0; 32]
        || record.principal_id != commit.principal_id
        || record.revision.get() != commit.committed_revision
        || record.created_at != commit.occurred_at
    {
        return Err(IdentityAdministrationError::Failed);
    }
    Ok(CreatePrincipalResponse {
        operation_id: request_operation.clone(),
        principal: public_principal(record)?,
    })
}

pub(super) fn list_response(
    api_kind: ApiPrincipalKind,
    query: &ListPrincipalsQuery,
    limit: u16,
    page: Page<PrincipalRecord, PrincipalCursor>,
) -> Result<ListPrincipalsResponse, IdentityAdministrationError> {
    let principals = page
        .items
        .into_iter()
        .map(public_principal)
        .collect::<Result<Vec<_>, _>>()?;
    let next_page_url = page
        .next
        .as_ref()
        .map(|cursor| next_page_url(api_kind, query, limit, cursor))
        .transpose()?;
    Ok(ListPrincipalsResponse {
        kind: api_kind,
        principals,
        next_page_url,
    })
}

pub(super) fn decode_cursor(
    cursor: &ApiPrincipalCursor,
    expected_kind: PrincipalKind,
) -> Result<PrincipalCursor, IdentityAdministrationError> {
    let fields = cursor.as_str().split('.').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "v1" || fields[1] != kind_code(expected_kind) {
        return Err(IdentityAdministrationError::InvalidInput);
    }
    let principal_id = PrincipalId::from_bytes(decode_array(fields[2])?)
        .map_err(|_| IdentityAdministrationError::InvalidInput)?;
    let name_bytes = decode_hex(fields[3])?;
    let canonical_name =
        String::from_utf8(name_bytes).map_err(|_| IdentityAdministrationError::InvalidInput)?;
    let validated =
        RecordName::new(&canonical_name).map_err(|_| IdentityAdministrationError::InvalidInput)?;
    if validated.display() != canonical_name || validated.canonical() != canonical_name {
        return Err(IdentityAdministrationError::InvalidInput);
    }
    Ok(PrincipalCursor::new(
        expected_kind,
        canonical_name,
        principal_id,
    ))
}

pub(super) const fn domain_kind(kind: ApiPrincipalKind) -> PrincipalKind {
    match kind {
        ApiPrincipalKind::User => PrincipalKind::User,
        ApiPrincipalKind::Group => PrincipalKind::Group,
    }
}

fn public_principal(
    record: PrincipalRecord,
) -> Result<PrincipalSummary, IdentityAdministrationError> {
    let kind = match record.kind {
        PrincipalKind::User => ApiPrincipalKind::User,
        PrincipalKind::Group => ApiPrincipalKind::Group,
        PrincipalKind::Service => return Err(IdentityAdministrationError::Failed),
    };
    let state = match record.state {
        1 => ApiPrincipalState::Active,
        2 => ApiPrincipalState::Suspended,
        3 => ApiPrincipalState::Retired,
        _ => return Err(IdentityAdministrationError::Failed),
    };
    let revision = record.revision.get();
    if revision == 0
        || revision > 9_007_199_254_740_991
        || !(0..=9_007_199_254_740_991).contains(&record.created_at.get())
    {
        return Err(IdentityAdministrationError::Failed);
    }
    Ok(PrincipalSummary {
        principal_id: ApiPrincipalId::from_uuid_bytes(record.principal_id.as_bytes())
            .ok_or(IdentityAdministrationError::Failed)?,
        kind,
        display_name: record.display_name,
        state,
        created_at_epoch_micros: record.created_at.get(),
        revision,
    })
}

fn next_page_url(
    kind: ApiPrincipalKind,
    query: &ListPrincipalsQuery,
    limit: u16,
    cursor: &PrincipalCursor,
) -> Result<String, IdentityAdministrationError> {
    let cursor = encode_cursor(cursor)?;
    let endpoint = match kind {
        ApiPrincipalKind::User => "users",
        ApiPrincipalKind::Group => "groups",
    };
    let url = format!(
        "/api/latest/admin/{endpoint}?limit={limit}&cursor={}",
        cursor.as_str()
    );
    let _ = query;
    (url.len() <= 16_384)
        .then_some(url)
        .ok_or(IdentityAdministrationError::Failed)
}

fn encode_cursor(
    cursor: &PrincipalCursor,
) -> Result<ApiPrincipalCursor, IdentityAdministrationError> {
    let mut encoded = format!("v1.{}.", kind_code(cursor.kind()));
    append_hex(&mut encoded, &cursor.principal_id().as_bytes());
    encoded.push('.');
    append_hex(&mut encoded, cursor.canonical_name().as_bytes());
    ApiPrincipalCursor::from_encoded(encoded).ok_or(IdentityAdministrationError::Failed)
}

const fn kind_code(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "u",
        PrincipalKind::Group => "g",
        PrincipalKind::Service => "s",
    }
}

fn derived_principal(
    domain: &[u8],
    operation_id: OperationId,
) -> Result<PrincipalId, IdentityAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| IdentityAdministrationError::Failed)?;
    PrincipalId::from_bytes(bytes).map_err(|_| IdentityAdministrationError::Failed)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], IdentityAdministrationError> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| IdentityAdministrationError::InvalidInput)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, IdentityAdministrationError> {
    if !value.len().is_multiple_of(2) {
        return Err(IdentityAdministrationError::InvalidInput);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(IdentityAdministrationError::InvalidInput)?;
            let low = hex_nibble(pair[1]).ok_or(IdentityAdministrationError::InvalidInput)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
