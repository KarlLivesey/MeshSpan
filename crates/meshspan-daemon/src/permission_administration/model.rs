// SPDX-License-Identifier: GPL-2.0-only

//! Strict permission boundary conversion, deterministic identities and cursor codec.

use meshspan_api_contract::{
    AssuranceLevel as ApiAssuranceLevel, CreateVolumePermissionGrantRequest,
    CreateVolumePermissionGrantResponse, ListVolumePermissionGrantsQuery,
    ListVolumePermissionGrantsResponse, NamespaceRight, NullableField,
    PermissionActivationPolicyId as ApiPolicyId, PermissionGrantCursor as ApiCursor,
    PermissionGrantId as ApiGrantId, PermissionGrantInheritance as ApiInheritance,
    RevokePermissionGrantResponse, VolumeId as ApiVolumeId, VolumePermissionGrantSummary,
};
use meshspan_domain::{
    ActivationPolicyId, AssuranceLevel, AuditEventId, DurationMicros, GrantId, OperationId,
    PrincipalId, Rights, UnixMicros, VolumeId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, CreateActivationPolicy, GrantInheritance,
    GrantPermission, GrantPermissionWithActivation, Page, PermissionGrantRecord,
    PermissionGrantRevocationRecord, PermissionScope, RevokePermissionGrant, ScopedGrantCursor,
};
use sha2::{Digest, Sha256};

use super::PermissionAdministrationError;
use crate::IdentityAdministrator;
use crate::create_mesh_setup::parse_uuid;

const GRANT_ID_DOMAIN: &[u8] = b"meshspan.permission-administration.grant-id.v1\0";
const POLICY_ID_DOMAIN: &[u8] = b"meshspan.permission-administration.policy-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.permission-administration.audit-id.v1\0";

pub(super) fn domain_volume(
    value: &ApiVolumeId,
) -> Result<VolumeId, PermissionAdministrationError> {
    VolumeId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| PermissionAdministrationError::InvalidInput)?,
    )
    .map_err(|_| PermissionAdministrationError::InvalidInput)
}

pub(super) fn domain_grant(value: &ApiGrantId) -> Result<GrantId, PermissionAdministrationError> {
    GrantId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| PermissionAdministrationError::InvalidInput)?,
    )
    .map_err(|_| PermissionAdministrationError::InvalidInput)
}

pub(super) fn domain_operation(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, PermissionAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| PermissionAdministrationError::InvalidInput)?,
    )
    .map_err(|_| PermissionAdministrationError::InvalidInput)
}

pub(super) fn domain_principal(
    value: &meshspan_api_contract::PrincipalId,
) -> Result<PrincipalId, PermissionAdministrationError> {
    PrincipalId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| PermissionAdministrationError::InvalidInput)?,
    )
    .map_err(|_| PermissionAdministrationError::InvalidInput)
}

pub(super) fn grant_command(
    volume_id: VolumeId,
    request: &CreateVolumePermissionGrantRequest,
) -> Result<(OperationId, GrantId, AuthoritativeCommand), PermissionAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let grant_id = derived_id::<GrantId>(GRANT_ID_DOMAIN, operation_id)?;
    let activation_policy_id = match &request.activation {
        NullableField::Value(_) => Some(derived_id::<ActivationPolicyId>(
            POLICY_ID_DOMAIN,
            operation_id,
        )?),
        NullableField::Missing | NullableField::Null => None,
    };
    let grant = GrantPermission {
        grant_id,
        subject_principal_id: domain_principal(&request.subject_principal_id)?,
        scope: PermissionScope::Volume(volume_id),
        rights: domain_rights(&request.rights)?,
        inheritance: domain_inheritance(request.inheritance),
        valid_from: public_instant(&request.valid_from_epoch_micros),
        valid_until: public_instant(&request.valid_until_epoch_micros),
        activation_policy_id,
    };
    let command = match (&request.activation, activation_policy_id) {
        (NullableField::Value(requirement), Some(policy_id)) => {
            AuthoritativeCommand::GrantPermissionWithActivation(GrantPermissionWithActivation {
                policy: CreateActivationPolicy {
                    policy_id,
                    maximum_duration: DurationMicros::new(requirement.maximum_duration_micros),
                    reason_required: requirement.reason_required,
                    minimum_assurance: domain_assurance(requirement.minimum_assurance),
                    valid_from: grant.valid_from,
                    valid_until: grant.valid_until,
                },
                grant,
            })
        }
        (NullableField::Missing | NullableField::Null, None) => {
            AuthoritativeCommand::GrantPermission(grant)
        }
        _ => return Err(PermissionAdministrationError::Failed),
    };
    Ok((operation_id, grant_id, command))
}

pub(super) fn revoke_command(
    grant_id: GrantId,
    request: &meshspan_api_contract::RevokePermissionGrantRequest,
) -> Result<(OperationId, AuthoritativeCommand), PermissionAdministrationError> {
    Ok((
        domain_operation(&request.operation_id)?,
        AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
            grant_id,
            reason: request.reason.as_str().to_owned(),
        }),
    ))
}

pub(super) fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
    occurred_at: UnixMicros,
) -> Result<CommandContext, PermissionAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| PermissionAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| PermissionAdministrationError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(super) fn validate_receipt(
    receipt: CommandReceipt,
    grant_id: GrantId,
    expected_digest: [u8; 32],
) -> Result<(), PermissionAdministrationError> {
    if receipt.entity.kind != meshspan_metadata::EntityKind::PermissionGrant
        || receipt.entity.id != grant_id.as_bytes()
        || receipt.request_digest != expected_digest
        || receipt.result_digest == [0; 32]
    {
        return Err(PermissionAdministrationError::Conflict);
    }
    Ok(())
}

pub(super) fn validate_grant(
    record: PermissionGrantRecord,
    command: &AuthoritativeCommand,
) -> Result<(), PermissionAdministrationError> {
    let expected = match command {
        AuthoritativeCommand::GrantPermission(grant) => grant,
        AuthoritativeCommand::GrantPermissionWithActivation(value) => &value.grant,
        _ => return Err(PermissionAdministrationError::Failed),
    };
    if record.grant_id != expected.grant_id
        || record.subject_principal_id != expected.subject_principal_id
        || record.scope != expected.scope
        || record.rights != expected.rights
        || record.inheritance != expected.inheritance
        || record.valid_from != expected.valid_from
        || record.valid_until != expected.valid_until
        || record.activation_policy_id != expected.activation_policy_id
    {
        return Err(PermissionAdministrationError::Conflict);
    }
    Ok(())
}

pub(super) fn list_response(
    api_volume_id: ApiVolumeId,
    query: &ListVolumePermissionGrantsQuery,
    limit: u16,
    page: Page<PermissionGrantRecord, ScopedGrantCursor>,
) -> Result<ListVolumePermissionGrantsResponse, PermissionAdministrationError> {
    let grants = page
        .items
        .into_iter()
        .map(public_grant)
        .collect::<Result<Vec<_>, _>>()?;
    let next_page_url = page
        .next
        .map(|cursor| next_page_url(&api_volume_id, query, limit, cursor))
        .transpose()?;
    Ok(ListVolumePermissionGrantsResponse {
        volume_id: api_volume_id,
        grants,
        next_page_url,
    })
}

pub(super) fn create_response(
    operation_id: meshspan_api_contract::OperationId,
    record: PermissionGrantRecord,
) -> Result<CreateVolumePermissionGrantResponse, PermissionAdministrationError> {
    Ok(CreateVolumePermissionGrantResponse {
        operation_id,
        grant: public_grant(record)?,
    })
}

pub(super) fn revoke_response(
    operation_id: meshspan_api_contract::OperationId,
    record: PermissionGrantRevocationRecord,
) -> Result<RevokePermissionGrantResponse, PermissionAdministrationError> {
    let revision = record.revision.get();
    if revision == 0
        || revision > 9_007_199_254_740_991
        || !(0..=9_007_199_254_740_991).contains(&record.revoked_at.get())
    {
        return Err(PermissionAdministrationError::Failed);
    }
    Ok(RevokePermissionGrantResponse {
        operation_id,
        grant_id: ApiGrantId::from_uuid_bytes(record.grant_id.as_bytes())
            .ok_or(PermissionAdministrationError::Failed)?,
        revoked_at_epoch_micros: record.revoked_at.get(),
        revision,
    })
}

pub(super) fn decode_cursor(
    cursor: &ApiCursor,
    expected_volume: VolumeId,
) -> Result<ScopedGrantCursor, PermissionAdministrationError> {
    let fields = cursor.as_str().split('.').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "v1" || fields[1] != "vg" {
        return Err(PermissionAdministrationError::InvalidInput);
    }
    let volume_id = VolumeId::from_bytes(decode_array(fields[2])?)
        .map_err(|_| PermissionAdministrationError::InvalidInput)?;
    let grant_id = GrantId::from_bytes(decode_array(fields[3])?)
        .map_err(|_| PermissionAdministrationError::InvalidInput)?;
    if volume_id != expected_volume {
        return Err(PermissionAdministrationError::InvalidInput);
    }
    Ok(ScopedGrantCursor::new(
        PermissionScope::Volume(volume_id),
        grant_id,
    ))
}

fn public_grant(
    record: PermissionGrantRecord,
) -> Result<VolumePermissionGrantSummary, PermissionAdministrationError> {
    let PermissionScope::Volume(volume_id) = record.scope else {
        return Err(PermissionAdministrationError::Failed);
    };
    let revision = record.revision.get();
    if revision == 0
        || revision > 9_007_199_254_740_991
        || !(0..=9_007_199_254_740_991).contains(&record.created_at.get())
    {
        return Err(PermissionAdministrationError::Failed);
    }
    Ok(VolumePermissionGrantSummary {
        grant_id: ApiGrantId::from_uuid_bytes(record.grant_id.as_bytes())
            .ok_or(PermissionAdministrationError::Failed)?,
        subject_principal_id: meshspan_api_contract::PrincipalId::from_uuid_bytes(
            record.subject_principal_id.as_bytes(),
        )
        .ok_or(PermissionAdministrationError::Failed)?,
        volume_id: ApiVolumeId::from_uuid_bytes(volume_id.as_bytes())
            .ok_or(PermissionAdministrationError::Failed)?,
        rights: public_rights(record.rights),
        inheritance: public_inheritance(record.inheritance),
        valid_from_epoch_micros: record.valid_from.map(UnixMicros::get),
        valid_until_epoch_micros: record.valid_until.map(UnixMicros::get),
        activation_policy_id: record
            .activation_policy_id
            .map(|policy_id| {
                ApiPolicyId::from_uuid_bytes(policy_id.as_bytes())
                    .ok_or(PermissionAdministrationError::Failed)
            })
            .transpose()?,
        created_by: meshspan_api_contract::PrincipalId::from_uuid_bytes(
            record.created_by.as_bytes(),
        )
        .ok_or(PermissionAdministrationError::Failed)?,
        created_at_epoch_micros: record.created_at.get(),
        revision,
    })
}

fn next_page_url(
    volume_id: &ApiVolumeId,
    query: &ListVolumePermissionGrantsQuery,
    limit: u16,
    cursor: ScopedGrantCursor,
) -> Result<String, PermissionAdministrationError> {
    let PermissionScope::Volume(cursor_volume) = cursor.scope() else {
        return Err(PermissionAdministrationError::Failed);
    };
    let mut encoded = "v1.vg.".to_owned();
    append_hex(&mut encoded, &cursor_volume.as_bytes());
    encoded.push('.');
    append_hex(&mut encoded, &cursor.grant_id().as_bytes());
    let cursor = ApiCursor::from_encoded(encoded).ok_or(PermissionAdministrationError::Failed)?;
    let url = format!(
        "/api/latest/admin/volumes/{}/permission-grants?limit={limit}&cursor={}",
        volume_id.as_str(),
        cursor.as_str()
    );
    let _ = query;
    (url.len() <= 16_384)
        .then_some(url)
        .ok_or(PermissionAdministrationError::Failed)
}

fn domain_rights(rights: &[NamespaceRight]) -> Result<Rights, PermissionAdministrationError> {
    let mut result = Rights::default();
    for right in rights {
        result = result.union(domain_right(*right));
    }
    (!result.is_empty())
        .then_some(result)
        .ok_or(PermissionAdministrationError::InvalidInput)
}

const fn domain_right(right: NamespaceRight) -> Rights {
    match right {
        NamespaceRight::Traverse => Rights::TRAVERSE,
        NamespaceRight::List => Rights::LIST,
        NamespaceRight::ReadData => Rights::READ_DATA,
        NamespaceRight::CreateChild => Rights::CREATE_CHILD,
        NamespaceRight::WriteData => Rights::WRITE_DATA,
        NamespaceRight::AppendData => Rights::APPEND_DATA,
        NamespaceRight::Rename => Rights::RENAME,
        NamespaceRight::Delete => Rights::DELETE,
        NamespaceRight::ReadAttributes => Rights::READ_ATTRIBUTES,
        NamespaceRight::WriteAttributes => Rights::WRITE_ATTRIBUTES,
        NamespaceRight::ReadPermissions => Rights::READ_PERMISSIONS,
        NamespaceRight::ChangePermissions => Rights::CHANGE_PERMISSIONS,
        NamespaceRight::ChangeOwner => Rights::CHANGE_OWNER,
    }
}

fn public_rights(rights: Rights) -> Vec<NamespaceRight> {
    const DEFINITIONS: [(Rights, NamespaceRight); 13] = [
        (Rights::TRAVERSE, NamespaceRight::Traverse),
        (Rights::LIST, NamespaceRight::List),
        (Rights::READ_DATA, NamespaceRight::ReadData),
        (Rights::CREATE_CHILD, NamespaceRight::CreateChild),
        (Rights::WRITE_DATA, NamespaceRight::WriteData),
        (Rights::APPEND_DATA, NamespaceRight::AppendData),
        (Rights::RENAME, NamespaceRight::Rename),
        (Rights::DELETE, NamespaceRight::Delete),
        (Rights::READ_ATTRIBUTES, NamespaceRight::ReadAttributes),
        (Rights::WRITE_ATTRIBUTES, NamespaceRight::WriteAttributes),
        (Rights::READ_PERMISSIONS, NamespaceRight::ReadPermissions),
        (
            Rights::CHANGE_PERMISSIONS,
            NamespaceRight::ChangePermissions,
        ),
        (Rights::CHANGE_OWNER, NamespaceRight::ChangeOwner),
    ];
    DEFINITIONS
        .into_iter()
        .filter_map(|(required, public)| rights.contains(required).then_some(public))
        .collect()
}

const fn domain_inheritance(value: ApiInheritance) -> GrantInheritance {
    match value {
        ApiInheritance::Object => GrantInheritance::Object,
        ApiInheritance::Descendants => GrantInheritance::Descendants,
        ApiInheritance::ObjectAndDescendants => GrantInheritance::ObjectAndDescendants,
    }
}

const fn public_inheritance(value: GrantInheritance) -> ApiInheritance {
    match value {
        GrantInheritance::Object => ApiInheritance::Object,
        GrantInheritance::Descendants => ApiInheritance::Descendants,
        GrantInheritance::ObjectAndDescendants => ApiInheritance::ObjectAndDescendants,
    }
}

const fn domain_assurance(value: ApiAssuranceLevel) -> AssuranceLevel {
    match value {
        ApiAssuranceLevel::SingleFactor => AssuranceLevel::SingleFactor,
        ApiAssuranceLevel::MultiFactor => AssuranceLevel::MultiFactor,
        ApiAssuranceLevel::RecentStepUp => AssuranceLevel::RecentStepUp,
    }
}

const fn public_instant(
    value: &NullableField<meshspan_api_contract::PermissionGrantInstant>,
) -> Option<UnixMicros> {
    match value {
        NullableField::Value(value) => Some(UnixMicros::new(value.epoch_micros())),
        NullableField::Missing | NullableField::Null => None,
    }
}

trait DerivedIdentifier: Sized {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError>;
}

impl DerivedIdentifier for GrantId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl DerivedIdentifier for ActivationPolicyId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

fn derived_id<T: DerivedIdentifier>(
    domain: &[u8],
    operation_id: OperationId,
) -> Result<T, PermissionAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| PermissionAdministrationError::Failed)?;
    T::from_derived_bytes(bytes).map_err(|_| PermissionAdministrationError::Failed)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], PermissionAdministrationError> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| PermissionAdministrationError::InvalidInput)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, PermissionAdministrationError> {
    if !value.len().is_multiple_of(2) {
        return Err(PermissionAdministrationError::InvalidInput);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(PermissionAdministrationError::InvalidInput)?;
            let low = hex_nibble(pair[1]).ok_or(PermissionAdministrationError::InvalidInput)?;
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
