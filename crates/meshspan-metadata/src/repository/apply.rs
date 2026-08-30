// SPDX-License-Identifier: GPL-2.0-only

//! Transaction orchestration for deterministic committed command application.

use meshspan_domain::{OperationId, PrincipalId, Revision};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::receipt::{decode_receipt, encode_result, result_digest, validate_position};
use super::{
    ApplyDisposition, CommandReceipt, EntityReference, LogPosition, RepositoryError,
    authentication_method, bootstrap, cleanup_attestation, cleanup_completion, cleanup_inventory,
    cleanup_permit, cleanup_reclamation, cluster, component, federation_grant,
    federation_mutation_admission, federation_principal, federation_quarantine,
    federation_relationship, federation_storage_allocation, federation_succession, identity,
    namespace, retention, root_delegation, routing, session, snapshot_schedule, tags,
    user_snapshot, version_cleanup, volume_head,
};
use crate::{AuthoritativeCommand, CommandContext, PartitionDatabase};

const POLICY_COMMITTED_OUTCOME: u8 = 3;
const RESULT_KIND_ENTITY_REFERENCE: u8 = 1;
const RECORD_VERSION: u8 = 1;
const SYSTEM_MANAGE_RIGHT: i64 = 1;

#[derive(Clone, Copy)]
struct AppliedState {
    position: LogPosition,
    revision: Revision,
}

struct StoredOperation {
    request_digest: Vec<u8>,
    result_payload: Vec<u8>,
    result_digest: Vec<u8>,
    revision: i64,
    committed_index: i64,
}

pub(super) fn read_current_revision(
    database: &PartitionDatabase,
) -> Result<Revision, RepositoryError> {
    let stored = database.connection().query_row(
        "SELECT state_revision FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(Revision::new(
        u64::try_from(stored).map_err(|_| RepositoryError::CorruptState)?,
    ))
}

pub(super) fn apply_committed(
    database: &mut PartitionDatabase,
    position: LogPosition,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, RepositoryError> {
    apply_committed_inner(database, position, context, command, None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApplyFaultPoint {
    AfterCommand,
    AfterOperation,
    AfterAudit,
    BeforeCommit,
}

#[cfg(test)]
pub(super) fn apply_committed_with_fault(
    database: &mut PartitionDatabase,
    position: LogPosition,
    context: CommandContext,
    command: &AuthoritativeCommand,
    fault: ApplyFaultPoint,
) -> Result<CommandReceipt, RepositoryError> {
    apply_committed_inner(database, position, context, command, Some(fault))
}

fn apply_committed_inner(
    database: &mut PartitionDatabase,
    position: LogPosition,
    context: CommandContext,
    command: &AuthoritativeCommand,
    fault: Option<ApplyFaultPoint>,
) -> Result<CommandReceipt, RepositoryError> {
    validate_position(position)?;
    let partition_id = database.partition_id();
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = read_applied_state(&transaction)?;
    validate_transition(state, position)?;
    let request_digest = command.request_digest(context);
    if let Some(stored) = load_operation(&transaction, context.operation_id)? {
        if stored.request_digest.as_slice() != request_digest {
            return Err(RepositoryError::OperationConflict);
        }
        advance_applied_position(&transaction, state.revision, position)?;
        let mut receipt = decode_receipt(
            context.operation_id,
            &stored.request_digest,
            &stored.result_payload,
            &stored.result_digest,
            stored.revision,
            stored.committed_index,
            position,
        )?;
        receipt.disposition = ApplyDisposition::Replayed;
        transaction.commit()?;
        return Ok(receipt);
    }
    if cleanup_inventory::is_reserved_operation(&transaction, context.operation_id)? {
        return Err(RepositoryError::OperationConflict);
    }

    if context
        .expected_revision
        .is_some_and(|expected| expected != state.revision)
    {
        return Err(RepositoryError::StaleRevision);
    }

    let revision = state
        .revision
        .next()
        .map_err(|_| RepositoryError::CapacityExceeded)?;
    authorise(&transaction, context, command)?;
    let entity = execute(
        &transaction,
        partition_id.as_bytes(),
        context,
        command,
        revision,
    )?;
    inject_fault(fault, ApplyFaultPoint::AfterCommand)?;
    let payload = encode_result(entity, revision, position)?;
    let stored_result_digest = result_digest(&payload);
    insert_operation(
        &transaction,
        partition_id.as_bytes(),
        position,
        context,
        command_kind(command),
        request_digest,
        &payload,
        stored_result_digest,
        revision,
    )?;
    inject_fault(fault, ApplyFaultPoint::AfterOperation)?;
    insert_audit_event(
        &transaction,
        context,
        command_kind(command),
        entity,
        request_digest,
        stored_result_digest,
    )?;
    inject_fault(fault, ApplyFaultPoint::AfterAudit)?;
    advance_applied_position(&transaction, revision, position)?;
    inject_fault(fault, ApplyFaultPoint::BeforeCommit)?;
    transaction.commit()?;
    Ok(CommandReceipt {
        disposition: ApplyDisposition::Applied,
        operation_id: context.operation_id,
        request_digest,
        result_digest: stored_result_digest,
        committed_revision: revision,
        committed_position: position,
        applied_position: position,
        entity,
    })
}

fn inject_fault(
    selected: Option<ApplyFaultPoint>,
    current: ApplyFaultPoint,
) -> Result<(), RepositoryError> {
    if selected == Some(current) {
        Err(RepositoryError::InjectedFault)
    } else {
        Ok(())
    }
}

fn read_applied_state(transaction: &Transaction<'_>) -> Result<AppliedState, RepositoryError> {
    let (index, term, revision) = transaction.query_row(
        "SELECT last_log_index, last_log_term, state_revision
         FROM applied_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    Ok(AppliedState {
        position: LogPosition {
            index: parse_u64(index)?,
            term: parse_u64(term)?,
        },
        revision: Revision::new(parse_u64(revision)?),
    })
}

fn validate_transition(state: AppliedState, next: LogPosition) -> Result<(), RepositoryError> {
    let expected_index = state
        .position
        .index
        .checked_add(1)
        .ok_or(RepositoryError::InvalidLogPosition)?;
    if next.index != expected_index || next.term < state.position.term {
        return Err(RepositoryError::InvalidLogPosition);
    }
    Ok(())
}

pub(super) fn operation_exists(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<bool, RepositoryError> {
    Ok(load_operation(transaction, operation_id)?.is_some())
}

fn load_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<Option<StoredOperation>, RepositoryError> {
    let operation = operation_id.as_bytes();
    transaction
        .query_row(
            "SELECT request_digest, result_payload, result_digest, revision,
                    committed_log_index
             FROM operations WHERE operation_id = ?1",
            [operation.as_slice()],
            |row| {
                Ok(StoredOperation {
                    request_digest: row.get(0)?,
                    result_payload: row.get(1)?,
                    result_digest: row.get(2)?,
                    revision: row.get(3)?,
                    committed_index: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn authorise(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), RepositoryError> {
    if let AuthoritativeCommand::BootstrapMesh(value) = command {
        let existing: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM principals LIMIT 1)",
            [],
            |row| row.get(0),
        )?;
        return if existing == 0 && context.actor_principal_id == value.administrator_id {
            Ok(())
        } else {
            Err(RepositoryError::InvalidCommand)
        };
    }
    let self_activation_principal = match command {
        AuthoritativeCommand::ActivateGrant(value) => Some(value.principal_id),
        AuthoritativeCommand::ActivateGroup(value) => Some(value.principal_id),
        AuthoritativeCommand::CreateApiKeyAuthenticationMethod(value) => Some(value.principal_id),
        AuthoritativeCommand::IssueAuthenticationSession(value) => Some(value.principal_id),
        _ => None,
    };
    if matches!(command, AuthoritativeCommand::ConsumeJoinGrant(_)) {
        return Ok(());
    }
    if let Some(principal_id) = self_activation_principal {
        return if context.actor_principal_id == principal_id {
            Ok(())
        } else {
            Err(RepositoryError::InvalidCommand)
        };
    }
    match command {
        AuthoritativeCommand::RevokeAuthenticationSession(value)
            if context.actor_principal_id == value.principal_id =>
        {
            return Ok(());
        }
        AuthoritativeCommand::RevokeAuthenticationMethod(value)
            if context.actor_principal_id == value.principal_id =>
        {
            return Ok(());
        }
        AuthoritativeCommand::RevokeAccessActivation(value)
            if context.actor_principal_id == value.principal_id =>
        {
            return Ok(());
        }
        _ => {}
    }
    require_system_administrator(
        transaction,
        context.actor_principal_id,
        context.occurred_at.get(),
    )
}

fn require_system_administrator(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
    now: i64,
) -> Result<(), RepositoryError> {
    let principal = principal_id.as_bytes();
    let authorised: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM role_grants rg
            JOIN roles r ON r.role_id = rg.role_id
            JOIN principals p ON p.principal_id = rg.principal_id
            WHERE rg.principal_id = ?1 AND p.state = 1
              AND (r.system_rights & ?2) = ?2
              AND (rg.valid_from IS NULL OR rg.valid_from <= ?3)
              AND (rg.valid_until IS NULL OR rg.valid_until > ?3)
              AND rg.activation_policy_id IS NULL
         )",
        params![principal.as_slice(), SYSTEM_MANAGE_RIGHT, now],
        |row| row.get(0),
    )?;
    if authorised == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn execute(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if is_cleanup_command(command) {
        return execute_cleanup_command(transaction, context, command, revision);
    }
    if is_identity_command(command) {
        return execute_identity_command(transaction, context, command, revision);
    }
    if federation_relationship::is_command(command) {
        return federation_relationship::execute(transaction, context, command, revision);
    }
    if federation_grant::is_command(command) {
        return federation_grant::execute(transaction, context, command, revision);
    }
    if federation_storage_allocation::is_command(command) {
        return federation_storage_allocation::execute(transaction, context, command, revision);
    }
    if federation_principal::is_command(command) {
        return federation_principal::execute(transaction, context, command, revision);
    }
    if federation_succession::is_command(command) {
        return federation_succession::execute(transaction, context, command, revision);
    }
    if let AuthoritativeCommand::AdmitFederatedMutation(value) = command {
        return federation_mutation_admission::admit(transaction, context, value, revision);
    }
    if federation_quarantine::is_command(command) {
        return federation_quarantine::execute(transaction, context, command, revision);
    }
    if is_routing_command(command) {
        return execute_routing_command(transaction, partition_id, context, command, revision);
    }
    match command {
        AuthoritativeCommand::BootstrapMesh(value) => {
            bootstrap::bootstrap(transaction, partition_id, context, value, revision)
        }
        AuthoritativeCommand::CreateVolume(value) => {
            namespace::create_volume(transaction, context, value, revision)
        }
        AuthoritativeCommand::CommitConvergedVolumeHead(value) => {
            volume_head::commit(transaction, context, value, revision)
        }
        AuthoritativeCommand::CreateVolumeSnapshot(_)
        | AuthoritativeCommand::RestoreVolumeSnapshot(_)
        | AuthoritativeCommand::RequestVolumeSnapshotExpiry(_)
        | AuthoritativeCommand::RemoveVolumeSnapshotRoot(_)
        | AuthoritativeCommand::ConfigureSnapshotSchedule(_)
        | AuthoritativeCommand::RunSnapshotSchedule(_) => {
            execute_snapshot_command(transaction, context, command, revision)
        }
        AuthoritativeCommand::ConfigureVersionRetention(value) => {
            retention::configure(transaction, context, *value, revision)
        }
        AuthoritativeCommand::CreateObject(value) => {
            namespace::create_object(transaction, context, value, revision)
        }
        AuthoritativeCommand::ReplaceObjectOwners(value) => {
            namespace::replace_object_owners(transaction, context, value, revision)
        }
        AuthoritativeCommand::SetObjectGrantInheritance(value) => {
            namespace::set_grant_inheritance(transaction, *value, revision)
        }
        AuthoritativeCommand::CreateTag(value) => {
            tags::create(transaction, context, value, revision)
        }
        AuthoritativeCommand::AttachTag(value) => {
            tags::attach(transaction, context, value.tag_id, value.target)
        }
        AuthoritativeCommand::DetachTag(value) => {
            tags::detach(transaction, value.tag_id, value.target)
        }
        AuthoritativeCommand::CreateComponent(value) => {
            component::create(transaction, context, value, revision)
        }
        AuthoritativeCommand::ConfigureComponent(value) => {
            component::configure(transaction, context, value, revision)
        }
        AuthoritativeCommand::AssignComponent(value) => {
            component::assign(transaction, value, revision)
        }
        AuthoritativeCommand::IssueJoinGrant(value) => {
            cluster::issue_join_grant(transaction, context, *value, revision)
        }
        AuthoritativeCommand::ConsumeJoinGrant(value) => {
            cluster::consume_join_grant(transaction, partition_id, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn is_routing_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::RegisterRoutingSigner(_)
            | AuthoritativeCommand::CreateMetadataPartition(_)
            | AuthoritativeCommand::CreateScopeRoute(_)
            | AuthoritativeCommand::InstallScopeRouteProjection(_)
            | AuthoritativeCommand::BeginScopeHandoff(_)
            | AuthoritativeCommand::FreezeScopeHandoff(_)
            | AuthoritativeCommand::ActivateScopeHandoff(_)
            | AuthoritativeCommand::AbortScopeHandoff(_)
    )
}

fn execute_routing_command(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let repository_partition_id = meshspan_domain::PartitionId::from_bytes(partition_id)
        .map_err(|_| RepositoryError::CorruptState)?;
    match command {
        AuthoritativeCommand::RegisterRoutingSigner(value) => {
            routing::register_signer(transaction, context, *value, revision)
        }
        AuthoritativeCommand::CreateMetadataPartition(value) => {
            routing::create_partition(transaction, context, value, revision)
        }
        AuthoritativeCommand::CreateScopeRoute(value) => root_delegation::create_scope(
            transaction,
            repository_partition_id,
            context,
            *value,
            revision,
        ),
        AuthoritativeCommand::InstallScopeRouteProjection(value) => {
            root_delegation::install_projection(
                transaction,
                repository_partition_id,
                context,
                value,
                revision,
            )
        }
        AuthoritativeCommand::BeginScopeHandoff(value) => root_delegation::begin_handoff(
            transaction,
            repository_partition_id,
            context,
            *value,
            revision,
        ),
        AuthoritativeCommand::FreezeScopeHandoff(value) => root_delegation::freeze_handoff(
            transaction,
            repository_partition_id,
            context,
            *value,
            revision,
        ),
        AuthoritativeCommand::ActivateScopeHandoff(value) => root_delegation::activate_handoff(
            transaction,
            repository_partition_id,
            context,
            *value,
            revision,
        ),
        AuthoritativeCommand::AbortScopeHandoff(value) => root_delegation::abort_handoff(
            transaction,
            repository_partition_id,
            context,
            *value,
            revision,
        ),
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn is_identity_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::CreateUser(_)
            | AuthoritativeCommand::CreateGroup(_)
            | AuthoritativeCommand::ChangePrincipalState(_)
            | AuthoritativeCommand::AddGroupMember(_)
            | AuthoritativeCommand::RemoveGroupMember(_)
            | AuthoritativeCommand::CreateActivationPolicy(_)
            | AuthoritativeCommand::GrantPermission(_)
            | AuthoritativeCommand::RevokePermissionGrant(_)
            | AuthoritativeCommand::ActivateGrant(_)
            | AuthoritativeCommand::ActivateGroup(_)
            | AuthoritativeCommand::RevokeAccessActivation(_)
            | AuthoritativeCommand::CreateApiKeyAuthenticationMethod(_)
            | AuthoritativeCommand::RevokeAuthenticationMethod(_)
            | AuthoritativeCommand::IssueAuthenticationSession(_)
            | AuthoritativeCommand::RevokeAuthenticationSession(_)
    )
}

fn execute_identity_command(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::CreateUser(value) => {
            identity::create_user(transaction, context, value, revision)
        }
        AuthoritativeCommand::CreateGroup(value) => {
            identity::create_group(transaction, context, value, revision)
        }
        AuthoritativeCommand::ChangePrincipalState(value) => {
            identity::change_principal_state(transaction, context, value, revision)
        }
        AuthoritativeCommand::AddGroupMember(value) => {
            identity::add_group_member(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RemoveGroupMember(value) => {
            identity::remove_group_member(transaction, context, value, revision)
        }
        AuthoritativeCommand::CreateActivationPolicy(value) => {
            identity::create_activation_policy(transaction, value, revision)
        }
        AuthoritativeCommand::GrantPermission(value) => {
            identity::grant_permission(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RevokePermissionGrant(value) => {
            identity::revoke_permission_grant(transaction, context, value, revision)
        }
        AuthoritativeCommand::ActivateGrant(value) => {
            identity::activate_grant(transaction, context, value, revision)
        }
        AuthoritativeCommand::ActivateGroup(value) => {
            identity::activate_group(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeAccessActivation(value) => {
            identity::revoke_access_activation(transaction, context, value, revision)
        }
        AuthoritativeCommand::CreateApiKeyAuthenticationMethod(value) => {
            authentication_method::create_api_key(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeAuthenticationMethod(value) => {
            authentication_method::revoke(transaction, context, value, revision)
        }
        AuthoritativeCommand::IssueAuthenticationSession(value) => {
            session::issue(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RevokeAuthenticationSession(value) => {
            session::revoke(transaction, context, *value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn is_cleanup_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::ProposeVersionCleanup(_)
            | AuthoritativeCommand::RegisterCleanupAttestationKey(_)
            | AuthoritativeCommand::AttestVersionCleanup(_)
            | AuthoritativeCommand::AuthoriseVersionCleanup(_)
            | AuthoritativeCommand::CancelVersionCleanup(_)
            | AuthoritativeCommand::AppendVersionCleanupItems(_)
            | AuthoritativeCommand::SealVersionCleanupInventory(_)
            | AuthoritativeCommand::IssueVersionCleanupPermit(_)
            | AuthoritativeCommand::CompleteVersionCleanupItem(_)
            | AuthoritativeCommand::ConfirmVersionCleanupReclamation(_)
    )
}

fn execute_cleanup_command(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::ProposeVersionCleanup(value) => {
            version_cleanup::propose(transaction, context, value, revision)
        }
        AuthoritativeCommand::RegisterCleanupAttestationKey(value) => {
            cleanup_attestation::register_key(transaction, context, *value, revision)
        }
        AuthoritativeCommand::AttestVersionCleanup(value) => {
            cleanup_attestation::attest(transaction, context, value, revision)
        }
        AuthoritativeCommand::AuthoriseVersionCleanup(value) => {
            version_cleanup::authorise(transaction, context, *value, revision)
        }
        AuthoritativeCommand::CancelVersionCleanup(value) => {
            version_cleanup::cancel(transaction, context, *value, revision)
        }
        AuthoritativeCommand::AppendVersionCleanupItems(value) => {
            cleanup_inventory::append(transaction, context, value, revision)
        }
        AuthoritativeCommand::SealVersionCleanupInventory(value) => {
            cleanup_inventory::seal(transaction, context, *value, revision)
        }
        AuthoritativeCommand::IssueVersionCleanupPermit(value) => {
            cleanup_permit::issue(transaction, context, *value, revision)
        }
        AuthoritativeCommand::CompleteVersionCleanupItem(value) => {
            cleanup_completion::complete(transaction, context, *value, revision)
        }
        AuthoritativeCommand::ConfirmVersionCleanupReclamation(value) => {
            cleanup_reclamation::confirm(transaction, context, *value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn execute_snapshot_command(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::CreateVolumeSnapshot(value) => {
            user_snapshot::create(transaction, context, value, revision)
        }
        AuthoritativeCommand::RestoreVolumeSnapshot(value) => {
            user_snapshot::restore(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RequestVolumeSnapshotExpiry(value) => {
            user_snapshot::request_expiry(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RemoveVolumeSnapshotRoot(value) => {
            user_snapshot::remove_root(transaction, context, *value, revision)
        }
        AuthoritativeCommand::ConfigureSnapshotSchedule(value) => {
            snapshot_schedule::configure(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RunSnapshotSchedule(value) => {
            snapshot_schedule::run(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the stored operation row is one atomic record"
)]
fn insert_operation(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    position: LogPosition,
    context: CommandContext,
    operation_kind: u8,
    request_digest: [u8; 32],
    result_payload: &[u8],
    stored_result_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let operation = context.operation_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO operations(
            operation_id, partition_id, actor_principal_id, actor_node_id,
            operation_kind, request_version, request_digest, outcome, durability_scope,
            started_at, completed_at, committed_log_index, result_kind, result_version,
            result_payload, result_digest, error_kind, revision
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, NULL, ?8, ?8, ?9, ?10, ?5,
                   ?11, ?12, NULL, ?13)",
        params![
            operation.as_slice(),
            partition_id.as_slice(),
            actor.as_slice(),
            operation_kind,
            RECORD_VERSION,
            request_digest.as_slice(),
            POLICY_COMMITTED_OUTCOME,
            context.occurred_at.get(),
            to_i64(position.index)?,
            RESULT_KIND_ENTITY_REFERENCE,
            result_payload,
            stored_result_digest.as_slice(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(())
}

fn insert_audit_event(
    transaction: &Transaction<'_>,
    context: CommandContext,
    event_kind: u8,
    entity: EntityReference,
    request_digest: [u8; 32],
    stored_result_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let previous: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT event_digest FROM audit_events ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if previous.as_ref().is_some_and(|value| value.len() != 32) {
        return Err(RepositoryError::CorruptState);
    }
    let event_digest = audit_digest(
        context,
        event_kind,
        entity,
        request_digest,
        stored_result_digest,
        previous.as_deref(),
    );
    let event = context.audit_event_id.as_bytes();
    let operation = context.operation_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO audit_events(
            event_id, operation_id, sequence, actor_principal_id, actor_node_id,
            event_kind, subject_kind, subject_id, occurred_at, redacted_payload,
            previous_event_digest, event_digest
         ) VALUES (?1, ?2, 0, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            event.as_slice(),
            operation.as_slice(),
            actor.as_slice(),
            event_kind,
            entity.kind as u8,
            entity.id.as_slice(),
            context.occurred_at.get(),
            [RECORD_VERSION, event_kind].as_slice(),
            previous,
            event_digest.as_slice()
        ],
    )?;
    Ok(())
}

fn audit_digest(
    context: CommandContext,
    event_kind: u8,
    entity: EntityReference,
    request_digest: [u8; 32],
    stored_result_digest: [u8; 32],
    previous: Option<&[u8]>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metadata.audit.v1");
    digest.update(context.audit_event_id.as_bytes());
    digest.update(context.operation_id.as_bytes());
    digest.update(context.actor_principal_id.as_bytes());
    digest.update(context.occurred_at.get().to_be_bytes());
    digest.update([event_kind, entity.kind as u8]);
    digest.update(entity.id);
    digest.update(request_digest);
    digest.update(stored_result_digest);
    match previous {
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

fn advance_applied_position(
    transaction: &Transaction<'_>,
    revision: Revision,
    position: LogPosition,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE applied_state
         SET last_log_index = ?1, last_log_term = ?2, state_revision = ?3
         WHERE singleton = 1",
        params![
            to_i64(position.index)?,
            to_i64(position.term)?,
            to_i64(revision.get())?
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn command_kind(command: &AuthoritativeCommand) -> u8 {
    match command {
        AuthoritativeCommand::BootstrapMesh(_) => 1,
        AuthoritativeCommand::CreateUser(_) => 2,
        AuthoritativeCommand::CreateGroup(_) => 3,
        AuthoritativeCommand::AddGroupMember(_) => 4,
        AuthoritativeCommand::CreateActivationPolicy(_) => 5,
        AuthoritativeCommand::CreateVolume(_) => 6,
        AuthoritativeCommand::CreateObject(_) => 7,
        AuthoritativeCommand::GrantPermission(_) => 8,
        AuthoritativeCommand::ActivateGrant(_) => 9,
        AuthoritativeCommand::ActivateGroup(_) => 10,
        AuthoritativeCommand::CreateComponent(_) => 11,
        AuthoritativeCommand::ConfigureComponent(_) => 12,
        AuthoritativeCommand::AssignComponent(_) => 13,
        AuthoritativeCommand::IssueJoinGrant(_) => 14,
        AuthoritativeCommand::ConsumeJoinGrant(_) => 15,
        AuthoritativeCommand::RegisterRoutingSigner(_) => 16,
        AuthoritativeCommand::CreateMetadataPartition(_) => 17,
        AuthoritativeCommand::CreateScopeRoute(_) => 18,
        AuthoritativeCommand::InstallScopeRouteProjection(_) => 70,
        AuthoritativeCommand::BeginScopeHandoff(_) => 19,
        AuthoritativeCommand::FreezeScopeHandoff(_) => 20,
        AuthoritativeCommand::ActivateScopeHandoff(_) => 21,
        AuthoritativeCommand::AbortScopeHandoff(_) => 22,
        AuthoritativeCommand::CreateTag(_) => 23,
        AuthoritativeCommand::AttachTag(_) => 24,
        AuthoritativeCommand::DetachTag(_) => 25,
        AuthoritativeCommand::ReplaceObjectOwners(_) => 26,
        AuthoritativeCommand::CommitConvergedVolumeHead(_) => 27,
        AuthoritativeCommand::CreateVolumeSnapshot(_) => 28,
        AuthoritativeCommand::ConfigureVersionRetention(_) => 29,
        AuthoritativeCommand::RequestVolumeSnapshotExpiry(_) => 30,
        AuthoritativeCommand::ConfigureSnapshotSchedule(_) => 31,
        AuthoritativeCommand::RunSnapshotSchedule(_) => 32,
        AuthoritativeCommand::RestoreVolumeSnapshot(_) => 33,
        AuthoritativeCommand::RemoveVolumeSnapshotRoot(_) => 34,
        AuthoritativeCommand::ProposeVersionCleanup(_) => 35,
        AuthoritativeCommand::RegisterCleanupAttestationKey(_) => 36,
        AuthoritativeCommand::AttestVersionCleanup(_) => 37,
        AuthoritativeCommand::AuthoriseVersionCleanup(_) => 38,
        AuthoritativeCommand::CancelVersionCleanup(_) => 39,
        AuthoritativeCommand::AppendVersionCleanupItems(_) => 40,
        AuthoritativeCommand::SealVersionCleanupInventory(_) => 41,
        AuthoritativeCommand::IssueVersionCleanupPermit(_) => 42,
        AuthoritativeCommand::CompleteVersionCleanupItem(_) => 43,
        AuthoritativeCommand::ConfirmVersionCleanupReclamation(_) => 44,
        AuthoritativeCommand::IssueAuthenticationSession(_) => 45,
        AuthoritativeCommand::RevokeAuthenticationSession(_) => 46,
        AuthoritativeCommand::CreateApiKeyAuthenticationMethod(_) => 74,
        AuthoritativeCommand::RevokeAuthenticationMethod(_) => 75,
        AuthoritativeCommand::SetObjectGrantInheritance(_) => 47,
        AuthoritativeCommand::RemoveGroupMember(_) => 48,
        AuthoritativeCommand::RevokePermissionGrant(_) => 49,
        AuthoritativeCommand::RevokeAccessActivation(_) => 50,
        AuthoritativeCommand::ChangePrincipalState(_) => 51,
        AuthoritativeCommand::ProposeFederationRelationship(_) => 52,
        AuthoritativeCommand::ApproveFederationRelationship(_) => 53,
        AuthoritativeCommand::RotateFederationTrustIdentity(_) => 54,
        AuthoritativeCommand::RestrictFederationRelationship(_) => 55,
        AuthoritativeCommand::RecoverFederationRelationship(_) => 56,
        AuthoritativeCommand::RevokeFederationRelationship(_) => 57,
        AuthoritativeCommand::RetireFederationRelationship(_) => 58,
        AuthoritativeCommand::IssueFederationGrant(_) => 59,
        AuthoritativeCommand::ReplaceFederationGrant(_) => 60,
        AuthoritativeCommand::RevokeFederationGrant(_) => 61,
        AuthoritativeCommand::UpsertFederatedPrincipalProjection(_) => 62,
        AuthoritativeCommand::DesignateFederationSuccessor(_) => 63,
        AuthoritativeCommand::AcceptFederationSuccessor(_) => 64,
        AuthoritativeCommand::ActivateFederationSuccessor(_) => 65,
        AuthoritativeCommand::RevokeFederationSuccessorDesignation(_) => 66,
        AuthoritativeCommand::RetainFederatedMutationQuarantine(_) => 67,
        AuthoritativeCommand::SurfaceFederatedMutationQuarantine(_) => 68,
        AuthoritativeCommand::ResolveFederatedMutationQuarantine(_) => 69,
        AuthoritativeCommand::AdmitFederatedMutation(_) => 73,
        AuthoritativeCommand::IssueFederationStorageAllocation(_) => 71,
        AuthoritativeCommand::RevokeFederationStorageAllocation(_) => 72,
    }
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
