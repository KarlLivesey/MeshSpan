// SPDX-License-Identifier: GPL-2.0-only

//! Bounded canonical bytes for authoritative commands carried by consensus.

mod acknowledgement_policy;
mod acme;
mod authentication;
mod availability_cell;
mod backup;
mod bootstrap;
mod certificate_name;
mod decoder;
mod encoder;
mod enrolment;
mod external_certificate;
mod fault_group;
mod identity;
mod locality_policy;
mod maintenance_work;
mod mesh_local_certificate;
mod namespace;
mod node_wrapping_key;
mod protection_policy;
mod recovery;
mod secret_generation;
mod session;
mod smb_export;
mod storage_target;
mod volume_head;

use meshspan_domain::{AuditEventId, OperationId, PrincipalId, Revision, UnixMicros};
use thiserror::Error;

use self::decoder::Decoder;
use self::encoder::Encoder;
use crate::{AuthoritativeCommand, CommandContext};

/// Current closed metadata-command wire format.
pub const METADATA_COMMAND_VERSION: u16 = 4;

const MAGIC: [u8; 4] = *b"MSC\x04";
const MAXIMUM_COMMAND_BYTES: usize = 1024 * 1024;

/// One completely decoded replicated state-machine input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAuthoritativeCommand {
    /// Context committed with the command rather than reconstructed at apply time.
    pub context: CommandContext,
    /// Validated typed command.
    pub command: AuthoritativeCommand,
}

/// Encodes one supported command into deterministic, bounded bytes.
///
/// # Errors
///
/// Rejects unsupported command families and values exceeding the closed format's bounds.
pub fn encode_authoritative_command(
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let mut encoder = Encoder::new(MAXIMUM_COMMAND_BYTES);
    encoder.fixed(&MAGIC)?;
    encoder.identifier(context.operation_id.as_bytes())?;
    encoder.identifier(context.actor_principal_id.as_bytes())?;
    encoder.identifier(context.audit_event_id.as_bytes())?;
    encoder.i64(context.occurred_at.get())?;
    encoder.optional_u64(context.expected_revision.map(Revision::get))?;
    encode_command(&mut encoder, command)?;
    Ok(encoder.finish())
}

/// Decodes one exact closed-format command and rejects trailing or non-canonical input.
///
/// # Errors
///
/// Rejects malformed, oversized, unsupported or semantically invalid input.
pub fn decode_authoritative_command(
    bytes: &[u8],
) -> Result<DecodedAuthoritativeCommand, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_COMMAND_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<4>()? != MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let actor_principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let audit_event_id = AuditEventId::from_bytes(decoder.identifier()?)?;
    let occurred_at = UnixMicros::new(decoder.i64()?);
    let expected_revision = decoder.optional_u64()?.map(Revision::new);
    let command = decode_command(&mut decoder)?;
    decoder.finish()?;
    Ok(DecodedAuthoritativeCommand {
        context: CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id,
            occurred_at,
            expected_revision,
        },
        command,
    })
}

fn encode_command(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<(), MetadataCommandCodecError> {
    if encode_extension_command(encoder, command)? {
        return Ok(());
    }
    match command {
        AuthoritativeCommand::BootstrapAppliance(value) => {
            encoder.u16(1)?;
            bootstrap::encode(encoder, value)
        }
        AuthoritativeCommand::ConfirmRecoveryBundleSaved(value) => {
            recovery::encode(encoder, *value)
        }
        AuthoritativeCommand::CreateUser(value) => identity::encode_user(encoder, value),
        AuthoritativeCommand::CreateGroup(value) => identity::encode_group(encoder, value),
        AuthoritativeCommand::AddGroupMember(value) => identity::encode_add_member(encoder, value),
        AuthoritativeCommand::RemoveGroupMember(value) => {
            identity::encode_remove_member(encoder, value)
        }
        AuthoritativeCommand::GrantPermission(value) => {
            identity::encode_grant_permission(encoder, value)
        }
        AuthoritativeCommand::GrantPermissionWithActivation(value) => {
            identity::encode_grant_permission_with_activation(encoder, value)
        }
        AuthoritativeCommand::RevokePermissionGrant(value) => {
            identity::encode_revoke_permission(encoder, value)
        }
        AuthoritativeCommand::CreateAuthenticationMethod(value) => {
            authentication::encode_create(encoder, value)
        }
        AuthoritativeCommand::IssueAuthenticationSession(value) => {
            session::encode_issue(encoder, value)
        }
        AuthoritativeCommand::StepUpAuthenticationSession(value) => {
            session::encode_step_up(encoder, value)
        }
        AuthoritativeCommand::RevokeAuthenticationSession(value) => {
            session::encode_revoke_session(encoder, value)
        }
        AuthoritativeCommand::RevokeAuthenticationMethod(value) => {
            session::encode_revoke_method(encoder, value)
        }
        AuthoritativeCommand::CreateVolume(value) => namespace::encode_volume(encoder, value),
        AuthoritativeCommand::RegisterStorageTarget(value) => {
            storage_target::encode(encoder, value)
        }
        AuthoritativeCommand::CreateFaultGroup(value) => fault_group::encode_create(encoder, value),
        AuthoritativeCommand::SetHostFaultGroupMembership(value) => {
            fault_group::encode_membership(encoder, *value)
        }
        AuthoritativeCommand::CreateProtectionPolicy(value) => {
            protection_policy::encode_create(encoder, value)
        }
        AuthoritativeCommand::AssignVolumeProtectionPolicy(value) => {
            protection_policy::encode_assignment(encoder, *value)
        }
        AuthoritativeCommand::CreateAvailabilityCell(value) => {
            availability_cell::encode_create(encoder, value)
        }
        AuthoritativeCommand::SetHostAvailabilityCellMembership(value) => {
            availability_cell::encode_host_membership(encoder, *value)
        }
        AuthoritativeCommand::SetTargetAvailabilityCellMembership(value) => {
            availability_cell::encode_target_membership(encoder, *value)
        }
        AuthoritativeCommand::CreateLocalityPolicy(value) => {
            locality_policy::encode_create(encoder, value)
        }
        AuthoritativeCommand::AssignVolumeLocalityPolicy(value) => {
            locality_policy::encode_assignment(encoder, *value)
        }
        AuthoritativeCommand::CreateAcknowledgementPolicy(value) => {
            acknowledgement_policy::encode_create(encoder, value)
        }
        AuthoritativeCommand::AssignVolumeAcknowledgementPolicy(value) => {
            acknowledgement_policy::encode_assignment(encoder, *value)
        }
        AuthoritativeCommand::PublishSmbExport(value) => smb_export::encode_publish(encoder, value),
        AuthoritativeCommand::WithdrawSmbExport(value) => {
            smb_export::encode_withdraw(encoder, value)
        }
        AuthoritativeCommand::RegisterNodeWrappingKey(value) => {
            node_wrapping_key::encode(encoder, value)
        }
        AuthoritativeCommand::CommitSecretGeneration(value) => {
            secret_generation::encode(encoder, value)
        }
        AuthoritativeCommand::IssueJoinGrant(value) => enrolment::encode_issue(encoder, value),
        AuthoritativeCommand::ConsumeJoinGrant(value) => enrolment::encode_consume(encoder, value),
        AuthoritativeCommand::ActivateNode(value) => enrolment::encode_activate(encoder, value),
        AuthoritativeCommand::CommitConvergedVolumeHead(value) => {
            volume_head::encode(encoder, *value)
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

/// Dispatches command families which own their complete tag space and payload encoding.
fn encode_extension_command(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    if acme::encode_command(encoder, command)? {
        return Ok(true);
    }
    if external_certificate::encode_command(encoder, command)? {
        return Ok(true);
    }
    if mesh_local_certificate::encode_command(encoder, command)? {
        return Ok(true);
    }
    if backup::encode_command(encoder, command)? {
        return Ok(true);
    }
    if maintenance_work::encode_command(encoder, command)? {
        return Ok(true);
    }
    Ok(false)
}

fn decode_command(
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let kind = decoder.u16()?;
    if acme::is_command_kind(kind) {
        return acme::decode_command(kind, decoder);
    }
    if external_certificate::is_command_kind(kind) {
        return external_certificate::decode_command(kind, decoder);
    }
    if mesh_local_certificate::is_command_kind(kind) {
        return mesh_local_certificate::decode_command(kind, decoder);
    }
    if backup::is_command_kind(kind) {
        return backup::decode_command(kind, decoder);
    }
    if maintenance_work::is_command_kind(kind) {
        return maintenance_work::decode_command(kind, decoder);
    }
    if let Some(command) = decode_storage_policy_command(kind, decoder)? {
        return Ok(command);
    }
    match kind {
        1 => bootstrap::decode(decoder)
            .map(Box::new)
            .map(AuthoritativeCommand::BootstrapAppliance),
        recovery::CONFIRM_RECOVERY_BUNDLE_SAVED => {
            recovery::decode(decoder).map(AuthoritativeCommand::ConfirmRecoveryBundleSaved)
        }
        2 => identity::decode_user(decoder).map(AuthoritativeCommand::CreateUser),
        3 => identity::decode_group(decoder).map(AuthoritativeCommand::CreateGroup),
        4 => identity::decode_add_member(decoder).map(AuthoritativeCommand::AddGroupMember),
        5 => identity::decode_remove_member(decoder).map(AuthoritativeCommand::RemoveGroupMember),
        identity::GRANT_PERMISSION => {
            identity::decode_grant_permission(decoder).map(AuthoritativeCommand::GrantPermission)
        }
        identity::GRANT_PERMISSION_WITH_ACTIVATION => {
            identity::decode_grant_permission_with_activation(decoder)
                .map(AuthoritativeCommand::GrantPermissionWithActivation)
        }
        identity::REVOKE_PERMISSION => identity::decode_revoke_permission(decoder)
            .map(AuthoritativeCommand::RevokePermissionGrant),
        6 => authentication::decode_create(decoder)
            .map(AuthoritativeCommand::CreateAuthenticationMethod),
        7 => session::decode_issue(decoder).map(AuthoritativeCommand::IssueAuthenticationSession),
        8 => {
            session::decode_step_up(decoder).map(AuthoritativeCommand::StepUpAuthenticationSession)
        }
        9 => session::decode_revoke_session(decoder)
            .map(AuthoritativeCommand::RevokeAuthenticationSession),
        10 => session::decode_revoke_method(decoder)
            .map(AuthoritativeCommand::RevokeAuthenticationMethod),
        namespace::CREATE_VOLUME => {
            namespace::decode_volume(decoder).map(AuthoritativeCommand::CreateVolume)
        }
        storage_target::REGISTER_STORAGE_TARGET => {
            storage_target::decode(decoder).map(AuthoritativeCommand::RegisterStorageTarget)
        }
        smb_export::PUBLISH_SMB_EXPORT => {
            smb_export::decode_publish(decoder).map(AuthoritativeCommand::PublishSmbExport)
        }
        smb_export::WITHDRAW_SMB_EXPORT => {
            smb_export::decode_withdraw(decoder).map(AuthoritativeCommand::WithdrawSmbExport)
        }
        node_wrapping_key::REGISTER_NODE_WRAPPING_KEY => {
            node_wrapping_key::decode(decoder).map(AuthoritativeCommand::RegisterNodeWrappingKey)
        }
        secret_generation::COMMIT_SECRET_GENERATION => {
            secret_generation::decode(decoder).map(AuthoritativeCommand::CommitSecretGeneration)
        }
        enrolment::ISSUE_JOIN_GRANT => {
            enrolment::decode_issue(decoder).map(AuthoritativeCommand::IssueJoinGrant)
        }
        enrolment::CONSUME_JOIN_GRANT => {
            enrolment::decode_consume(decoder).map(AuthoritativeCommand::ConsumeJoinGrant)
        }
        enrolment::ACTIVATE_NODE => {
            enrolment::decode_activate(decoder).map(AuthoritativeCommand::ActivateNode)
        }
        volume_head::COMMIT_CONVERGED_VOLUME_HEAD => {
            volume_head::decode(decoder).map(AuthoritativeCommand::CommitConvergedVolumeHead)
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn decode_storage_policy_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<Option<AuthoritativeCommand>, MetadataCommandCodecError> {
    let command = match kind {
        fault_group::CREATE_FAULT_GROUP => {
            fault_group::decode_create(decoder).map(AuthoritativeCommand::CreateFaultGroup)
        }
        fault_group::SET_HOST_FAULT_GROUP_MEMBERSHIP => fault_group::decode_membership(decoder)
            .map(AuthoritativeCommand::SetHostFaultGroupMembership),
        protection_policy::CREATE_PROTECTION_POLICY => protection_policy::decode_create(decoder)
            .map(AuthoritativeCommand::CreateProtectionPolicy),
        protection_policy::ASSIGN_VOLUME_PROTECTION_POLICY => {
            protection_policy::decode_assignment(decoder)
                .map(AuthoritativeCommand::AssignVolumeProtectionPolicy)
        }
        availability_cell::CREATE_AVAILABILITY_CELL => availability_cell::decode_create(decoder)
            .map(AuthoritativeCommand::CreateAvailabilityCell),
        availability_cell::SET_HOST_AVAILABILITY_CELL_MEMBERSHIP => {
            availability_cell::decode_host_membership(decoder)
                .map(AuthoritativeCommand::SetHostAvailabilityCellMembership)
        }
        availability_cell::SET_TARGET_AVAILABILITY_CELL_MEMBERSHIP => {
            availability_cell::decode_target_membership(decoder)
                .map(AuthoritativeCommand::SetTargetAvailabilityCellMembership)
        }
        locality_policy::CREATE_LOCALITY_POLICY => {
            locality_policy::decode_create(decoder).map(AuthoritativeCommand::CreateLocalityPolicy)
        }
        locality_policy::ASSIGN_VOLUME_LOCALITY_POLICY => {
            locality_policy::decode_assignment(decoder)
                .map(AuthoritativeCommand::AssignVolumeLocalityPolicy)
        }
        acknowledgement_policy::CREATE_ACKNOWLEDGEMENT_POLICY => {
            acknowledgement_policy::decode_create(decoder)
                .map(AuthoritativeCommand::CreateAcknowledgementPolicy)
        }
        acknowledgement_policy::ASSIGN_VOLUME_ACKNOWLEDGEMENT_POLICY => {
            acknowledgement_policy::decode_assignment(decoder)
                .map(AuthoritativeCommand::AssignVolumeAcknowledgementPolicy)
        }
        _ => return Ok(None),
    }?;
    Ok(Some(command))
}

/// Closed failures for hostile replicated command bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataCommandCodecError {
    /// Bytes are truncated, non-canonical or semantically invalid.
    #[error("metadata command bytes are invalid")]
    Invalid,
    /// The typed command family has no representation in this codec version.
    #[error("metadata command is not supported by this codec version")]
    Unsupported,
    /// A bounded field or the complete command exceeds its maximum.
    #[error("metadata command exceeds a format bound")]
    CapacityExceeded,
}

impl From<meshspan_domain::IdentifierError> for MetadataCommandCodecError {
    fn from(_: meshspan_domain::IdentifierError) -> Self {
        Self::Invalid
    }
}

impl From<crate::RecordNameError> for MetadataCommandCodecError {
    fn from(_: crate::RecordNameError) -> Self {
        Self::Invalid
    }
}

impl From<crate::RepositoryCommandError> for MetadataCommandCodecError {
    fn from(_: crate::RepositoryCommandError) -> Self {
        Self::Invalid
    }
}

impl From<meshspan_contracts::BoundedItemsError> for MetadataCommandCodecError {
    fn from(_: meshspan_contracts::BoundedItemsError) -> Self {
        Self::CapacityExceeded
    }
}

#[cfg(test)]
mod tests;
