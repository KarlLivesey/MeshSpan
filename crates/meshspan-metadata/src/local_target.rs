// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe node-local journal for storage-folder registration.

use meshspan_domain::{
    AuditEventId, ComponentInstanceId, HostId, MeshId, NodeId, OperationId, PrincipalId, TargetId,
    UnixMicros,
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{
    AuthoritativeCommand, CommandContext, CreateComponent, LocalDatabase, RecordName,
    RegisterStorageTarget, StorageUsageLimit,
};

const PREPARED: i64 = 1;
const MARKER_WRITTEN: i64 = 2;
const AUTHORITY_COMMITTED: i64 = 3;
const ACTIVE: i64 = 4;
const MAXIMUM_CANONICAL_PATH_BYTES: usize = 16_384;
const MAXIMUM_PROVIDER_CONFIGURATION_BYTES: usize = 512 * 1_024;
const TARGET_COLUMNS: &str = "target_id, registration_operation_id, mesh_id, node_id, host_id,
    actor_principal_id, audit_event_id, provider_instance_id, target_display_name,
    provider_display_name, canonical_path, generation, usage_limit_kind, usage_limit_value,
    provider_implementation_id, provider_contract_major, provider_contract_minor,
    provider_schema_version, provider_configuration, provider_configuration_digest,
    marker_fingerprint, authority_result_digest, state, prepared_at, marker_written_at,
    authority_committed_at, activated_at, revision";

/// Complete immutable intent persisted before a provider marker is created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewLocalTarget {
    /// Stable target identity.
    pub target_id: TargetId,
    /// Idempotency identity of the authoritative registration.
    pub registration_operation_id: OperationId,
    /// Mesh which will own the target bytes.
    pub mesh_id: MeshId,
    /// Local node that owns the initial target generation.
    pub node_id: NodeId,
    /// Expected host of the local node.
    pub host_id: HostId,
    /// Administrator authorising the local configuration.
    pub actor_principal_id: PrincipalId,
    /// Stable audit identity for the authoritative command.
    pub audit_event_id: AuditEventId,
    /// Provider component created atomically with the target.
    pub provider: CreateComponent,
    /// Human-readable target name.
    pub target_name: RecordName,
    /// Exact canonical local path bytes; never replicated.
    pub canonical_path: Vec<u8>,
    /// Initial authority-fenced generation.
    pub generation: u64,
    /// Target capacity ceiling.
    pub usage_limit: StorageUsageLimit,
    /// Local authoritative preparation instant used by the command.
    pub prepared_at: UnixMicros,
}

/// Durable progress through one cross-database target registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalTargetState {
    /// Intent is durable; no marker is known to have completed.
    Prepared,
    /// Exact target marker is durable and can be reopened.
    MarkerWritten,
    /// Root metadata authority committed the exact target command.
    AuthorityCommitted,
    /// Local provider activation completed.
    Active,
}

/// Complete non-secret evidence needed to resume target registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTargetRecord {
    /// Immutable preparation input.
    pub intent: NewLocalTarget,
    /// Exact durable marker fingerprint once written.
    pub marker_fingerprint: Option<[u8; 32]>,
    /// Exact authoritative result digest once committed.
    pub authority_result_digest: Option<[u8; 32]>,
    /// Current durable local transition.
    pub state: LocalTargetState,
    /// Local observation time of marker completion.
    pub marker_written_at: Option<UnixMicros>,
    /// Local observation time of authoritative completion.
    pub authority_committed_at: Option<UnixMicros>,
    /// Local provider activation time.
    pub activated_at: Option<UnixMicros>,
    /// Monotonic local journal revision.
    pub revision: u64,
}

impl LocalTargetRecord {
    /// Reconstructs the exact authoritative input after marker completion.
    ///
    /// # Errors
    ///
    /// Fails closed before a non-zero durable marker fingerprint exists.
    pub fn authority_input(
        &self,
    ) -> Result<(CommandContext, AuthoritativeCommand), LocalTargetError> {
        let marker_fingerprint = self.marker_fingerprint.ok_or(LocalTargetError::Invalid)?;
        let context = CommandContext {
            operation_id: self.intent.registration_operation_id,
            actor_principal_id: self.intent.actor_principal_id,
            audit_event_id: self.intent.audit_event_id,
            occurred_at: self.intent.prepared_at,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
            target_id: self.intent.target_id,
            node_id: self.intent.node_id,
            host_id: self.intent.host_id,
            provider: self.intent.provider.clone(),
            name: self.intent.target_name.clone(),
            generation: self.intent.generation,
            marker_fingerprint,
            backing_device_fingerprint: None,
            filesystem_fingerprint: None,
            usage_limit: self.intent.usage_limit,
        });
        Ok((context, command))
    }
}

/// Whether a requested local transition changed durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalTargetDisposition {
    /// This call made the transition durable.
    Applied,
    /// The exact transition was already durable.
    Replayed,
}

impl LocalDatabase {
    /// Journals one exact target intent before writing anything beneath the provider folder.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity/configuration, a changed retry, conflicting local ownership or
    /// storage failure.
    pub fn prepare_local_target(
        &mut self,
        target: &NewLocalTarget,
    ) -> Result<LocalTargetDisposition, LocalTargetError> {
        let node_id = self.node_id();
        validate_new(node_id, target)?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_conflicting(&transaction, target)? {
            ensure_node(&existing, node_id)?;
            return if existing.intent == *target {
                Ok(LocalTargetDisposition::Replayed)
            } else {
                Err(LocalTargetError::Conflict)
            };
        }
        insert_target(&transaction, target)?;
        transaction.commit()?;
        Ok(LocalTargetDisposition::Applied)
    }

    /// Records the exact self-validating marker installed beneath the folder.
    ///
    /// # Errors
    ///
    /// Rejects missing, substituted, out-of-order or non-monotonic evidence and storage failure.
    pub fn record_local_target_marker(
        &mut self,
        target_id: TargetId,
        marker_fingerprint: [u8; 32],
        written_at: UnixMicros,
    ) -> Result<LocalTargetDisposition, LocalTargetError> {
        if marker_fingerprint == [0; 32] {
            return Err(LocalTargetError::Invalid);
        }
        let node_id = self.node_id();
        transition(
            self.connection_mut(),
            node_id,
            target_id,
            MARKER_WRITTEN,
            marker_fingerprint,
            written_at,
        )
    }

    /// Records the exact root-authority result after commit or replay resolution.
    ///
    /// # Errors
    ///
    /// Rejects missing, substituted, out-of-order or non-monotonic evidence and storage failure.
    pub fn record_local_target_authority_commit(
        &mut self,
        target_id: TargetId,
        result_digest: [u8; 32],
        committed_at: UnixMicros,
    ) -> Result<LocalTargetDisposition, LocalTargetError> {
        if result_digest == [0; 32] {
            return Err(LocalTargetError::Invalid);
        }
        let node_id = self.node_id();
        transition(
            self.connection_mut(),
            node_id,
            target_id,
            AUTHORITY_COMMITTED,
            result_digest,
            committed_at,
        )
    }

    /// Marks an authority-committed target locally active after reopening succeeds.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, out-of-order, corrupt or non-monotonic transition and storage failure.
    pub fn activate_local_target(
        &mut self,
        target_id: TargetId,
        activated_at: UnixMicros,
    ) -> Result<LocalTargetDisposition, LocalTargetError> {
        let node_id = self.node_id();
        transition(
            self.connection_mut(),
            node_id,
            target_id,
            ACTIVE,
            [0; 32],
            activated_at,
        )
    }

    /// Loads one exact target registration journal.
    ///
    /// # Errors
    ///
    /// Fails closed for unreadable, malformed or differently node-bound evidence.
    pub fn local_target(
        &self,
        target_id: TargetId,
    ) -> Result<Option<LocalTargetRecord>, LocalTargetError> {
        let record = load_target(self.connection(), target_id)?;
        if let Some(record) = &record {
            ensure_node(record, self.node_id())?;
        }
        Ok(record)
    }

    /// Loads the target registration journal bound to one exact canonical local path.
    ///
    /// Paths are opaque operating-system bytes and remain node-local. This lookup allows a
    /// repeated `--storage-path` to resume its original identities rather than inventing another
    /// target after restart.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized path and fails closed for unreadable, malformed or
    /// differently node-bound evidence.
    pub fn local_target_by_path(
        &self,
        canonical_path: &[u8],
    ) -> Result<Option<LocalTargetRecord>, LocalTargetError> {
        if canonical_path.is_empty() || canonical_path.len() > MAXIMUM_CANONICAL_PATH_BYTES {
            return Err(LocalTargetError::Invalid);
        }
        let statement =
            format!("SELECT {TARGET_COLUMNS} FROM local_targets WHERE canonical_path = ?1 LIMIT 2");
        let record = self
            .connection()
            .query_row(&statement, [canonical_path], raw_target)
            .optional()?
            .map(|raw| decode_target(&raw))
            .transpose()?;
        if let Some(record) = &record {
            ensure_node(record, self.node_id())?;
        }
        Ok(record)
    }
}

fn validate_new(node_id: NodeId, target: &NewLocalTarget) -> Result<(), LocalTargetError> {
    target
        .usage_limit
        .validate()
        .map_err(|_| LocalTargetError::Invalid)?;
    target
        .provider
        .validate_shape(MAXIMUM_PROVIDER_CONFIGURATION_BYTES)
        .map_err(|_| LocalTargetError::Invalid)?;
    if target.node_id != node_id
        || target.provider.component_kind != 1
        || target.canonical_path.is_empty()
        || target.canonical_path.len() > MAXIMUM_CANONICAL_PATH_BYTES
        || target.generation == 0
    {
        Err(LocalTargetError::Invalid)
    } else {
        Ok(())
    }
}

fn load_conflicting(
    transaction: &Transaction<'_>,
    target: &NewLocalTarget,
) -> Result<Option<LocalTargetRecord>, LocalTargetError> {
    let target_id = target.target_id.as_bytes();
    let operation_id = target.registration_operation_id.as_bytes();
    let statement = format!(
        "SELECT {TARGET_COLUMNS} FROM local_targets
         WHERE target_id = ?1 OR registration_operation_id = ?2 OR canonical_path = ?3
            OR provider_instance_id = ?4
         LIMIT 1"
    );
    transaction
        .query_row(
            &statement,
            params![
                target_id.as_slice(),
                operation_id.as_slice(),
                target.canonical_path,
                target.provider.instance_id.as_bytes().as_slice(),
            ],
            raw_target,
        )
        .optional()?
        .map(|raw| decode_target(&raw))
        .transpose()
}

fn insert_target(
    transaction: &Transaction<'_>,
    target: &NewLocalTarget,
) -> Result<(), LocalTargetError> {
    let (usage_kind, usage_value) = encode_usage_limit(target.usage_limit)?;
    transaction.execute(
        "INSERT INTO local_targets(
            target_id, registration_operation_id, mesh_id, node_id, host_id,
            actor_principal_id, audit_event_id, provider_instance_id,
            target_display_name, provider_display_name, canonical_path, generation,
            usage_limit_kind, usage_limit_value, provider_implementation_id,
            provider_contract_major, provider_contract_minor, provider_schema_version,
            provider_configuration, provider_configuration_digest, marker_fingerprint,
            authority_result_digest, state, prepared_at, marker_written_at,
            authority_committed_at, activated_at, revision
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, NULL, NULL, ?21, ?22, NULL, NULL, NULL, 1
         )",
        params![
            target.target_id.as_bytes().as_slice(),
            target.registration_operation_id.as_bytes().as_slice(),
            target.mesh_id.as_bytes().as_slice(),
            target.node_id.as_bytes().as_slice(),
            target.host_id.as_bytes().as_slice(),
            target.actor_principal_id.as_bytes().as_slice(),
            target.audit_event_id.as_bytes().as_slice(),
            target.provider.instance_id.as_bytes().as_slice(),
            target.target_name.display(),
            target.provider.name.display(),
            target.canonical_path,
            to_i64(target.generation)?,
            usage_kind,
            usage_value,
            target.provider.implementation_id,
            target.provider.contract_major,
            target.provider.contract_minor,
            target.provider.schema_version,
            target.provider.canonical_configuration,
            target.provider.configuration_digest.as_slice(),
            PREPARED,
            target.prepared_at.get(),
        ],
    )?;
    Ok(())
}

fn transition(
    connection: &mut rusqlite::Connection,
    node_id: NodeId,
    target_id: TargetId,
    requested_state: i64,
    evidence: [u8; 32],
    occurred_at: UnixMicros,
) -> Result<LocalTargetDisposition, LocalTargetError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing =
        load_target_transaction(&transaction, target_id)?.ok_or(LocalTargetError::Conflict)?;
    ensure_node(&existing, node_id)?;
    if state_code(existing.state) >= requested_state {
        validate_replay(&existing, requested_state, evidence)?;
        return Ok(LocalTargetDisposition::Replayed);
    }
    if state_code(existing.state) + 1 != requested_state || occurred_at < previous_time(&existing) {
        return Err(LocalTargetError::Conflict);
    }
    apply_transition(
        &transaction,
        target_id,
        requested_state,
        evidence,
        occurred_at,
    )?;
    transaction.commit()?;
    Ok(LocalTargetDisposition::Applied)
}

fn apply_transition(
    transaction: &Transaction<'_>,
    target_id: TargetId,
    requested_state: i64,
    evidence: [u8; 32],
    occurred_at: UnixMicros,
) -> Result<(), LocalTargetError> {
    let target = target_id.as_bytes();
    let changed = match requested_state {
        MARKER_WRITTEN => transaction.execute(
            "UPDATE local_targets SET state = ?1, marker_fingerprint = ?2,
                    marker_written_at = ?3, revision = revision + 1
             WHERE target_id = ?4 AND state = ?5",
            params![
                requested_state,
                evidence.as_slice(),
                occurred_at.get(),
                target.as_slice(),
                PREPARED
            ],
        )?,
        AUTHORITY_COMMITTED => transaction.execute(
            "UPDATE local_targets SET state = ?1, authority_result_digest = ?2,
                    authority_committed_at = ?3, revision = revision + 1
             WHERE target_id = ?4 AND state = ?5",
            params![
                requested_state,
                evidence.as_slice(),
                occurred_at.get(),
                target.as_slice(),
                MARKER_WRITTEN
            ],
        )?,
        ACTIVE => transaction.execute(
            "UPDATE local_targets SET state = ?1, activated_at = ?2, revision = revision + 1
             WHERE target_id = ?3 AND state = ?4",
            params![
                requested_state,
                occurred_at.get(),
                target.as_slice(),
                AUTHORITY_COMMITTED
            ],
        )?,
        _ => return Err(LocalTargetError::Invalid),
    };
    if changed == 1 {
        Ok(())
    } else {
        Err(LocalTargetError::Conflict)
    }
}

fn validate_replay(
    existing: &LocalTargetRecord,
    requested_state: i64,
    evidence: [u8; 32],
) -> Result<(), LocalTargetError> {
    let matches = match requested_state {
        MARKER_WRITTEN => existing.marker_fingerprint == Some(evidence),
        AUTHORITY_COMMITTED => existing.authority_result_digest == Some(evidence),
        ACTIVE => true,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(LocalTargetError::Conflict)
    }
}

fn previous_time(target: &LocalTargetRecord) -> UnixMicros {
    target
        .authority_committed_at
        .or(target.marker_written_at)
        .unwrap_or(target.intent.prepared_at)
}

fn load_target(
    connection: &rusqlite::Connection,
    target_id: TargetId,
) -> Result<Option<LocalTargetRecord>, LocalTargetError> {
    let target = target_id.as_bytes();
    let statement = format!("SELECT {TARGET_COLUMNS} FROM local_targets WHERE target_id = ?1");
    connection
        .query_row(&statement, [target.as_slice()], raw_target)
        .optional()?
        .map(|raw| decode_target(&raw))
        .transpose()
}

fn load_target_transaction(
    transaction: &Transaction<'_>,
    target_id: TargetId,
) -> Result<Option<LocalTargetRecord>, LocalTargetError> {
    let target = target_id.as_bytes();
    let statement = format!("SELECT {TARGET_COLUMNS} FROM local_targets WHERE target_id = ?1");
    transaction
        .query_row(&statement, [target.as_slice()], raw_target)
        .optional()?
        .map(|raw| decode_target(&raw))
        .transpose()
}

struct RawTarget {
    values: Vec<rusqlite::types::Value>,
}

fn raw_target(row: &Row<'_>) -> rusqlite::Result<RawTarget> {
    let mut values = Vec::with_capacity(28);
    for index in 0..28 {
        values.push(row.get(index)?);
    }
    Ok(RawTarget { values })
}

fn decode_target(raw: &RawTarget) -> Result<LocalTargetRecord, LocalTargetError> {
    let value = |index: usize| raw.values.get(index).ok_or(LocalTargetError::Invalid);
    let bytes = |index: usize| match value(index)? {
        rusqlite::types::Value::Blob(bytes) => Ok(bytes.clone()),
        _ => Err(LocalTargetError::Invalid),
    };
    let optional_bytes = |index: usize| match value(index)? {
        rusqlite::types::Value::Null => Ok(None),
        rusqlite::types::Value::Blob(bytes) => Ok(Some(bytes.clone())),
        _ => Err(LocalTargetError::Invalid),
    };
    let integer = |index: usize| match value(index)? {
        rusqlite::types::Value::Integer(value) => Ok(*value),
        _ => Err(LocalTargetError::Invalid),
    };
    let text = |index: usize| match value(index)? {
        rusqlite::types::Value::Text(value) => Ok(value.clone()),
        _ => Err(LocalTargetError::Invalid),
    };
    let provider = CreateComponent {
        instance_id: ComponentInstanceId::from_bytes(array(bytes(7)?)?)?,
        component_kind: 1,
        name: RecordName::new(&text(9)?)?,
        implementation_id: text(14)?,
        contract_major: u16_value(integer(15)?)?,
        contract_minor: u16_value(integer(16)?)?,
        schema_version: u32_value(integer(17)?)?,
        canonical_configuration: bytes(18)?,
        configuration_digest: array(bytes(19)?)?,
    };
    let record = LocalTargetRecord {
        intent: NewLocalTarget {
            target_id: TargetId::from_bytes(array(bytes(0)?)?)?,
            registration_operation_id: OperationId::from_bytes(array(bytes(1)?)?)?,
            mesh_id: MeshId::from_bytes(array(bytes(2)?)?)?,
            node_id: NodeId::from_bytes(array(bytes(3)?)?)?,
            host_id: HostId::from_bytes(array(bytes(4)?)?)?,
            actor_principal_id: PrincipalId::from_bytes(array(bytes(5)?)?)?,
            audit_event_id: AuditEventId::from_bytes(array(bytes(6)?)?)?,
            provider,
            target_name: RecordName::new(&text(8)?)?,
            canonical_path: bytes(10)?,
            generation: u64_value(integer(11)?)?,
            usage_limit: decode_usage_limit(integer(12)?, integer(13)?)?,
            prepared_at: UnixMicros::new(integer(23)?),
        },
        marker_fingerprint: optional_bytes(20)?.map(array).transpose()?,
        authority_result_digest: optional_bytes(21)?.map(array).transpose()?,
        state: decode_state(integer(22)?)?,
        marker_written_at: optional_instant(value(24)?)?,
        authority_committed_at: optional_instant(value(25)?)?,
        activated_at: optional_instant(value(26)?)?,
        revision: u64_value(integer(27)?)?,
    };
    validate_new(record.intent.node_id, &record.intent)?;
    validate_record(&record)?;
    Ok(record)
}

fn validate_record(record: &LocalTargetRecord) -> Result<(), LocalTargetError> {
    if record.marker_fingerprint == Some([0; 32]) || record.authority_result_digest == Some([0; 32])
    {
        return Err(LocalTargetError::Invalid);
    }
    let valid = match record.state {
        LocalTargetState::Prepared => {
            record.marker_fingerprint.is_none()
                && record.authority_result_digest.is_none()
                && record.marker_written_at.is_none()
                && record.authority_committed_at.is_none()
                && record.activated_at.is_none()
        }
        LocalTargetState::MarkerWritten => {
            record.marker_fingerprint.is_some()
                && record.authority_result_digest.is_none()
                && record.marker_written_at.is_some()
                && record.authority_committed_at.is_none()
                && record.activated_at.is_none()
        }
        LocalTargetState::AuthorityCommitted => {
            record.marker_fingerprint.is_some()
                && record.authority_result_digest.is_some()
                && record.marker_written_at.is_some()
                && record.authority_committed_at.is_some()
                && record.activated_at.is_none()
        }
        LocalTargetState::Active => {
            record.marker_fingerprint.is_some()
                && record.authority_result_digest.is_some()
                && record.marker_written_at.is_some()
                && record.authority_committed_at.is_some()
                && record.activated_at.is_some()
        }
    };
    let times_ordered = record
        .marker_written_at
        .is_none_or(|instant| instant >= record.intent.prepared_at)
        && record.authority_committed_at.is_none_or(|instant| {
            record
                .marker_written_at
                .is_some_and(|marker| instant >= marker)
        })
        && record.activated_at.is_none_or(|instant| {
            record
                .authority_committed_at
                .is_some_and(|committed| instant >= committed)
        });
    let expected_revision = u64_value(state_code(record.state))?;
    if valid && times_ordered && record.revision == expected_revision {
        Ok(())
    } else {
        Err(LocalTargetError::Invalid)
    }
}

fn ensure_node(record: &LocalTargetRecord, node_id: NodeId) -> Result<(), LocalTargetError> {
    if record.intent.node_id == node_id {
        Ok(())
    } else {
        Err(LocalTargetError::Invalid)
    }
}

fn encode_usage_limit(limit: StorageUsageLimit) -> Result<(i64, i64), LocalTargetError> {
    limit.validate().map_err(|_| LocalTargetError::Invalid)?;
    match limit {
        StorageUsageLimit::Percent(value) => Ok((1, i64::from(value))),
        StorageUsageLimit::Bytes(value) => Ok((2, to_i64(value)?)),
    }
}

fn decode_usage_limit(kind: i64, value: i64) -> Result<StorageUsageLimit, LocalTargetError> {
    let limit = match kind {
        1 => {
            StorageUsageLimit::Percent(u8::try_from(value).map_err(|_| LocalTargetError::Invalid)?)
        }
        2 => StorageUsageLimit::Bytes(u64_value(value)?),
        _ => return Err(LocalTargetError::Invalid),
    };
    limit.validate().map_err(|_| LocalTargetError::Invalid)
}

const fn decode_state(value: i64) -> Result<LocalTargetState, LocalTargetError> {
    match value {
        PREPARED => Ok(LocalTargetState::Prepared),
        MARKER_WRITTEN => Ok(LocalTargetState::MarkerWritten),
        AUTHORITY_COMMITTED => Ok(LocalTargetState::AuthorityCommitted),
        ACTIVE => Ok(LocalTargetState::Active),
        _ => Err(LocalTargetError::Invalid),
    }
}

const fn state_code(state: LocalTargetState) -> i64 {
    match state {
        LocalTargetState::Prepared => PREPARED,
        LocalTargetState::MarkerWritten => MARKER_WRITTEN,
        LocalTargetState::AuthorityCommitted => AUTHORITY_COMMITTED,
        LocalTargetState::Active => ACTIVE,
    }
}

fn optional_instant(
    value: &rusqlite::types::Value,
) -> Result<Option<UnixMicros>, LocalTargetError> {
    match value {
        rusqlite::types::Value::Null => Ok(None),
        rusqlite::types::Value::Integer(value) => Ok(Some(UnixMicros::new(*value))),
        _ => Err(LocalTargetError::Invalid),
    }
}

fn array<const LENGTH: usize>(bytes: Vec<u8>) -> Result<[u8; LENGTH], LocalTargetError> {
    bytes.try_into().map_err(|_| LocalTargetError::Invalid)
}

fn to_i64(value: u64) -> Result<i64, LocalTargetError> {
    i64::try_from(value).map_err(|_| LocalTargetError::Invalid)
}

fn u64_value(value: i64) -> Result<u64, LocalTargetError> {
    u64::try_from(value).map_err(|_| LocalTargetError::Invalid)
}

fn u32_value(value: i64) -> Result<u32, LocalTargetError> {
    u32::try_from(value).map_err(|_| LocalTargetError::Invalid)
}

fn u16_value(value: i64) -> Result<u16, LocalTargetError> {
    u16::try_from(value).map_err(|_| LocalTargetError::Invalid)
}

/// Closed target-journal failures which never expose local paths or command bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalTargetError {
    /// SQLite rejected or could not durably commit the transition.
    #[error("local storage target persistence failed")]
    Store,
    /// Supplied or persisted evidence violates the closed registration contract.
    #[error("local storage target evidence is invalid")]
    Invalid,
    /// Another target or changed retry conflicts with the requested transition.
    #[error("local storage target state conflicts with the requested transition")]
    Conflict,
}

impl From<rusqlite::Error> for LocalTargetError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Store
    }
}

impl From<crate::RecordNameError> for LocalTargetError {
    fn from(_: crate::RecordNameError) -> Self {
        Self::Invalid
    }
}

impl From<meshspan_domain::IdentifierError> for LocalTargetError {
    fn from(_: meshspan_domain::IdentifierError) -> Self {
        Self::Invalid
    }
}
