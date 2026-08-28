// SPDX-License-Identifier: GPL-2.0-only

//! Identity-bound target journal and atomic capacity reservations.

use std::path::{Path, PathBuf};
use std::time::Duration;

use meshspan_contracts::{ContractVersion, RequestContext, ReservationClass, StorageReservation};
use meshspan_domain::{OperationId, RandomSource, Revision, TargetId, UnixMicros};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

use crate::{TargetMarker, UsageLimit};

const SCHEMA_VERSION: u32 = 1;
const SCHEMA: &str = include_str!("../schema/001_initial.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_SUBDIRECTORY: &str = "storage-targets";

/// Measured physical target capacity supplied at one admission instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityObservation {
    /// Total bytes reported by the backing filesystem.
    pub total_bytes: u64,
    /// Bytes currently available to this daemon identity.
    pub available_bytes: u64,
}

impl CapacityObservation {
    fn validate(self) -> Result<Self, TargetJournalError> {
        if self.total_bytes == 0 || self.available_bytes > self.total_bytes {
            Err(TargetJournalError::InvalidInput)
        } else {
            Ok(self)
        }
    }
}

/// Target-local capacity policy kept separate from physical observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityPolicy {
    /// Provider-owned usage ceiling.
    pub usage_limit: UsageLimit,
    /// Headroom unavailable to ordinary foreground writes.
    pub repair_reserve_bytes: u64,
    /// Authoritative desired-configuration revision for safe policy replacement.
    pub revision: Revision,
}

/// Exact persisted capacity accounting for one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalCapacity {
    /// Bytes belonging to committed inventory.
    pub committed_bytes: u64,
    /// Bytes held by active reservations.
    pub reserved_bytes: u64,
    /// Configured repair headroom.
    pub repair_reserve_bytes: u64,
}

/// Complete bounded input for one target-local capacity decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveCapacityRequest {
    /// Version, operation, deadline and optional authority revision.
    pub context: RequestContext,
    /// Exact target identity repeated across the trust boundary.
    pub target_id: TargetId,
    /// Exact target generation repeated across the trust boundary.
    pub target_generation: u64,
    /// Independent capacity budget being requested.
    pub class: ReservationClass,
    /// Maximum bytes that may become durable.
    pub bytes: u64,
    /// Current physical capacity observation.
    pub observation: CapacityObservation,
    /// Current authoritative time used for expiry admission.
    pub now: UnixMicros,
}

/// One WAL/FULL-sync journal bound to an exact target marker generation.
pub struct TargetJournal {
    connection: Connection,
    marker: TargetMarker,
    policy: CapacityPolicy,
}

impl TargetJournal {
    /// Opens, migrates, hardens and identity-binds one target journal.
    ///
    /// # Errors
    ///
    /// Rejects IO/SQLite failure, migration drift, invalid policy, entropy failure and any
    /// mismatch between the existing journal and the target's exact marker generation.
    pub fn open(
        daemon_state_dir: &Path,
        marker: TargetMarker,
        policy: CapacityPolicy,
        opened_at: UnixMicros,
        random: &mut impl RandomSource,
    ) -> Result<Self, TargetJournalError> {
        validate_policy(policy)?;
        let file_path = journal_path(daemon_state_dir, marker.target_id())?;
        let mut connection = open_connection(&file_path)?;
        migrate(&mut connection, opened_at)?;
        bind_identity(&mut connection, marker, policy, opened_at, random)?;
        check_integrity(&connection)?;
        Ok(Self {
            connection,
            marker,
            policy,
        })
    }

    /// Returns the exact target marker to which this journal is bound.
    #[must_use]
    pub const fn marker(&self) -> TargetMarker {
        self.marker
    }

    /// Returns durable committed, reserved and repair-headroom counters.
    ///
    /// # Errors
    ///
    /// Fails closed when counters are absent, negative or exceed supported integer bounds.
    pub fn capacity(&self) -> Result<JournalCapacity, TargetJournalError> {
        self.connection
            .query_row(
                "SELECT committed_bytes, reserved_bytes, repair_reserve_bytes
                 FROM target_state WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(Into::into)
            .and_then(|row| {
                Ok(JournalCapacity {
                    committed_bytes: to_u64(row.0)?,
                    reserved_bytes: to_u64(row.1)?,
                    repair_reserve_bytes: to_u64(row.2)?,
                })
            })
    }

    /// Reserves capacity idempotently for one exact target generation and budget class.
    ///
    /// # Errors
    ///
    /// Rejects stale identity/deadline/version, zero/excessive capacity, arithmetic overflow and
    /// conflicting operation reuse without changing durable accounting.
    pub fn reserve(
        &mut self,
        request: ReserveCapacityRequest,
    ) -> Result<StorageReservation, TargetJournalError> {
        let ReserveCapacityRequest {
            context,
            target_id,
            target_generation,
            class,
            bytes,
            observation,
            now,
        } = request;
        validate_reservation_identity(context, self.marker, target_id, target_generation, bytes)?;
        let request_digest =
            reservation_request_digest(context, target_id, target_generation, class, bytes);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_reservation(&transaction, context.operation_id)? {
            return resolve_existing(existing, request_digest, self.marker, context.operation_id);
        }
        validate_new_reservation(context, observation, now)?;
        expire_active_reservations(&transaction, now)?;
        admit_capacity(&transaction, self.policy, class, bytes, observation)?;
        let capability_key = load_capability_key(&transaction)?;
        let reservation_digest = reservation_authority_digest(&capability_key, request_digest);
        insert_reservation(
            &transaction,
            context,
            class,
            bytes,
            request_digest,
            reservation_digest,
            now,
        )?;
        transaction.commit()?;
        Ok(StorageReservation {
            operation_id: context.operation_id,
            target_id,
            target_generation,
            class,
            maximum_bytes: bytes,
            expires_at: context.deadline,
            reservation_digest,
        })
    }

    /// Expires all due active reservations and releases their capacity exactly once.
    ///
    /// # Errors
    ///
    /// Fails atomically for corrupt accounting or SQLite failure.
    pub fn expire_reservations(&mut self, now: UnixMicros) -> Result<u64, TargetJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expired = expire_active_reservations(&transaction, now)?;
        transaction.commit()?;
        Ok(expired)
    }

    /// Runs bounded SQLite structural and foreign-key verification.
    ///
    /// # Errors
    ///
    /// Rejects every result other than exact structural `ok` and no foreign-key rows.
    pub fn check_integrity(&self) -> Result<(), TargetJournalError> {
        check_integrity(&self.connection)
    }
}

#[derive(Clone, Copy)]
struct StoredReservation {
    request_digest: [u8; 32],
    reservation_digest: [u8; 32],
    class: ReservationClass,
    maximum_bytes: u64,
    expires_at: UnixMicros,
}

struct StoredTargetState {
    mesh_id: Vec<u8>,
    target_id: Vec<u8>,
    generation: i64,
    marker_fingerprint: Vec<u8>,
    usage_kind: i64,
    usage_value: i64,
    repair_reserve: i64,
    policy_revision: i64,
}

fn journal_path(state_dir: &Path, target_id: TargetId) -> Result<PathBuf, TargetJournalError> {
    std::fs::create_dir_all(state_dir)?;
    let state_dir = std::fs::canonicalize(state_dir)?;
    let target_dir = state_dir.join(STATE_SUBDIRECTORY);
    std::fs::create_dir_all(&target_dir)?;
    Ok(target_dir.join(format!("{target_id}.sqlite3")))
}

fn open_connection(file_path: &Path) -> Result<Connection, TargetJournalError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(file_path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(connection)
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), TargetJournalError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(TargetJournalError::UnsupportedSchema);
    }
    let expected: [u8; 32] = blake3::hash(SCHEMA.as_bytes()).into();
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![SCHEMA_VERSION, expected.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    let stored: Vec<u8> = connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
        [SCHEMA_VERSION],
        |row| row.get(0),
    )?;
    let count: i64 = connection.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
        row.get(0)
    })?;
    if count != 1 || stored.as_slice() != expected {
        return Err(TargetJournalError::MigrationMismatch);
    }
    Ok(())
}

fn bind_identity(
    connection: &mut Connection,
    marker: TargetMarker,
    policy: CapacityPolicy,
    opened_at: UnixMicros,
    random: &mut impl RandomSource,
) -> Result<(), TargetJournalError> {
    let (usage_kind, usage_value) = encode_usage_limit(policy.usage_limit)?;
    let mesh = marker.mesh_id().as_bytes();
    let target = marker.target_id().as_bytes();
    let fingerprint = marker.fingerprint().as_bytes();
    let generation = to_i64(marker.generation())?;
    let repair_reserve = to_i64(policy.repair_reserve_bytes)?;
    let policy_revision = to_i64(policy.revision.get())?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM target_state WHERE singleton = 1)",
        [],
        |row| row.get(0),
    )?;
    if exists == 0 {
        let mut capability_key = [0; 32];
        random.fill_bytes(&mut capability_key)?;
        transaction.execute(
            "INSERT INTO target_state(
            singleton, mesh_id, target_id, target_generation, marker_fingerprint,
            usage_limit_kind, usage_limit_value, repair_reserve_bytes, policy_revision,
            capability_key, created_at, last_opened_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                mesh.as_slice(),
                target.as_slice(),
                generation,
                fingerprint.as_slice(),
                usage_kind,
                usage_value,
                repair_reserve,
                policy_revision,
                capability_key.as_slice(),
                opened_at.get(),
            ],
        )?;
    }
    let stored = transaction.query_row(
        "SELECT mesh_id, target_id, target_generation, marker_fingerprint,
                usage_limit_kind, usage_limit_value, repair_reserve_bytes, policy_revision
         FROM target_state WHERE singleton = 1",
        [],
        |row| {
            Ok(StoredTargetState {
                mesh_id: row.get(0)?,
                target_id: row.get(1)?,
                generation: row.get(2)?,
                marker_fingerprint: row.get(3)?,
                usage_kind: row.get(4)?,
                usage_value: row.get(5)?,
                repair_reserve: row.get(6)?,
                policy_revision: row.get(7)?,
            })
        },
    )?;
    if stored.mesh_id != mesh
        || stored.target_id != target
        || stored.generation != generation
        || stored.marker_fingerprint != fingerprint
    {
        return Err(TargetJournalError::IdentityMismatch);
    }
    let stored_revision = to_u64(stored.policy_revision)?;
    if stored_revision > policy.revision.get() {
        return Err(TargetJournalError::StalePolicy);
    }
    if stored_revision == policy.revision.get()
        && (stored.usage_kind != usage_kind
            || stored.usage_value != usage_value
            || stored.repair_reserve != repair_reserve)
    {
        return Err(TargetJournalError::PolicyConflict);
    }
    if stored_revision < policy.revision.get() {
        transaction.execute(
            "UPDATE target_state SET usage_limit_kind = ?1, usage_limit_value = ?2,
                    repair_reserve_bytes = ?3, policy_revision = ?4
             WHERE singleton = 1",
            params![usage_kind, usage_value, repair_reserve, policy_revision],
        )?;
    }
    transaction.execute(
        "UPDATE target_state SET last_opened_at = ?1 WHERE singleton = 1",
        [opened_at.get()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_policy(policy: CapacityPolicy) -> Result<(), TargetJournalError> {
    if policy.revision == Revision::ZERO {
        Err(TargetJournalError::InvalidInput)
    } else {
        encode_usage_limit(policy.usage_limit).map(|_| ())
    }
}

fn encode_usage_limit(limit: UsageLimit) -> Result<(i64, i64), TargetJournalError> {
    match limit {
        UsageLimit::Percent(value) if (1..=100).contains(&value) => Ok((1, i64::from(value))),
        UsageLimit::Bytes(value) if value > 0 => Ok((2, to_i64(value)?)),
        UsageLimit::Percent(_) | UsageLimit::Bytes(_) => Err(TargetJournalError::InvalidInput),
    }
}

fn validate_reservation_identity(
    context: RequestContext,
    marker: TargetMarker,
    target_id: TargetId,
    target_generation: u64,
    bytes: u64,
) -> Result<(), TargetJournalError> {
    if context.contract_version != ContractVersion::V1_0
        || target_id != marker.target_id()
        || target_generation != marker.generation()
        || bytes == 0
        || i64::try_from(bytes).is_err()
    {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_new_reservation(
    context: RequestContext,
    observation: CapacityObservation,
    now: UnixMicros,
) -> Result<(), TargetJournalError> {
    observation.validate()?;
    if context.deadline <= now {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}

fn reservation_request_digest(
    context: RequestContext,
    target_id: TargetId,
    target_generation: u64,
    class: ReservationClass,
    bytes: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.reservation-request.v1");
    digest.update(&context.operation_id.as_bytes());
    digest.update(&target_id.as_bytes());
    digest.update(&target_generation.to_be_bytes());
    digest.update(&[reservation_class_code(class)]);
    digest.update(&bytes.to_be_bytes());
    digest.update(&context.deadline.get().to_be_bytes());
    match context.expected_revision {
        Some(revision) => {
            digest.update(&[1]);
            digest.update(&revision.get().to_be_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
    digest.finalize().into()
}

fn reservation_authority_digest(key: &[u8; 32], request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(key);
    digest.update(b"meshspan.storage.reservation-authority.v1");
    digest.update(&request_digest);
    digest.finalize().into()
}

fn load_reservation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<Option<StoredReservation>, TargetJournalError> {
    let operation = operation_id.as_bytes();
    transaction
        .query_row(
            "SELECT request_digest, reservation_digest, reservation_class,
                    maximum_bytes, expires_at
             FROM reservations WHERE operation_id = ?1",
            [operation.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(StoredReservation {
                request_digest: copy_digest(&row.0)?,
                reservation_digest: copy_digest(&row.1)?,
                class: decode_reservation_class(row.2)?,
                maximum_bytes: to_u64(row.3)?,
                expires_at: UnixMicros::new(row.4),
            })
        })
        .transpose()
}

fn resolve_existing(
    existing: StoredReservation,
    request_digest: [u8; 32],
    marker: TargetMarker,
    operation_id: OperationId,
) -> Result<StorageReservation, TargetJournalError> {
    if existing.request_digest != request_digest {
        return Err(TargetJournalError::OperationConflict);
    }
    Ok(StorageReservation {
        operation_id,
        target_id: marker.target_id(),
        target_generation: marker.generation(),
        class: existing.class,
        maximum_bytes: existing.maximum_bytes,
        expires_at: existing.expires_at,
        reservation_digest: existing.reservation_digest,
    })
}

fn expire_active_reservations(
    transaction: &Transaction<'_>,
    now: UnixMicros,
) -> Result<u64, TargetJournalError> {
    let released: i64 = transaction.query_row(
        "SELECT COALESCE(sum(maximum_bytes), 0) FROM reservations
         WHERE state = 1 AND expires_at <= ?1",
        [now.get()],
        |row| row.get(0),
    )?;
    let changed = transaction.execute(
        "UPDATE reservations SET state = 3, terminal_at = ?1
         WHERE state = 1 AND expires_at <= ?1",
        [now.get()],
    )?;
    if released > 0 {
        let updated = transaction.execute(
            "UPDATE target_state SET reserved_bytes = reserved_bytes - ?1
             WHERE singleton = 1 AND reserved_bytes >= ?1",
            [released],
        )?;
        if updated != 1 {
            return Err(TargetJournalError::CorruptState);
        }
    }
    u64::try_from(changed).map_err(|_| TargetJournalError::CorruptState)
}

fn admit_capacity(
    transaction: &Transaction<'_>,
    policy: CapacityPolicy,
    class: ReservationClass,
    bytes: u64,
    observation: CapacityObservation,
) -> Result<(), TargetJournalError> {
    let (committed, reserved): (i64, i64) = transaction.query_row(
        "SELECT committed_bytes, reserved_bytes FROM target_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let committed = to_u64(committed)?;
    let reserved = to_u64(reserved)?;
    let used = committed
        .checked_add(reserved)
        .ok_or(TargetJournalError::CorruptState)?;
    let ceiling = usage_ceiling(policy.usage_limit, observation.total_bytes)?;
    let logical_available = ceiling.saturating_sub(used);
    let repair_headroom = match class {
        ReservationClass::ForegroundWrite => policy.repair_reserve_bytes,
        ReservationClass::Repair | ReservationClass::Relocation => 0,
    };
    let physical_available = observation
        .available_bytes
        .saturating_sub(reserved)
        .saturating_sub(repair_headroom);
    if bytes > logical_available || bytes > physical_available {
        return Err(TargetJournalError::CapacityExhausted);
    }
    let stored_bytes = to_i64(bytes)?;
    let updated = transaction.execute(
        "UPDATE target_state SET reserved_bytes = reserved_bytes + ?1
         WHERE singleton = 1 AND reserved_bytes <= ?2",
        params![stored_bytes, i64::MAX - stored_bytes],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn usage_ceiling(limit: UsageLimit, total_bytes: u64) -> Result<u64, TargetJournalError> {
    match limit {
        UsageLimit::Percent(percent) if (1..=100).contains(&percent) => Ok(total_bytes / 100
            * u64::from(percent)
            + (total_bytes % 100) * u64::from(percent) / 100),
        UsageLimit::Bytes(bytes) if bytes > 0 => Ok(bytes.min(total_bytes)),
        UsageLimit::Percent(_) | UsageLimit::Bytes(_) => Err(TargetJournalError::InvalidInput),
    }
}

fn load_capability_key(transaction: &Transaction<'_>) -> Result<[u8; 32], TargetJournalError> {
    let key: Vec<u8> = transaction.query_row(
        "SELECT capability_key FROM target_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    copy_digest(&key)
}

fn insert_reservation(
    transaction: &Transaction<'_>,
    context: RequestContext,
    class: ReservationClass,
    bytes: u64,
    request_digest: [u8; 32],
    reservation_digest: [u8; 32],
    now: UnixMicros,
) -> Result<(), TargetJournalError> {
    let operation = context.operation_id.as_bytes();
    transaction.execute(
        "INSERT INTO reservations(
            operation_id, request_digest, reservation_digest, reservation_class,
            maximum_bytes, expires_at, state, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        params![
            operation.as_slice(),
            request_digest.as_slice(),
            reservation_digest.as_slice(),
            i64::from(reservation_class_code(class)),
            to_i64(bytes)?,
            context.deadline.get(),
            now.get(),
        ],
    )?;
    Ok(())
}

const fn reservation_class_code(class: ReservationClass) -> u8 {
    match class {
        ReservationClass::ForegroundWrite => 1,
        ReservationClass::Repair => 2,
        ReservationClass::Relocation => 3,
    }
}

fn decode_reservation_class(value: i64) -> Result<ReservationClass, TargetJournalError> {
    match value {
        1 => Ok(ReservationClass::ForegroundWrite),
        2 => Ok(ReservationClass::Repair),
        3 => Ok(ReservationClass::Relocation),
        _ => Err(TargetJournalError::CorruptState),
    }
}

fn check_integrity(connection: &Connection) -> Result<(), TargetJournalError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_failure = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?
        .is_some();
    if result == "ok" && !foreign_key_failure {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn copy_digest(value: &[u8]) -> Result<[u8; 32], TargetJournalError> {
    value
        .try_into()
        .map_err(|_| TargetJournalError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, TargetJournalError> {
    i64::try_from(value).map_err(|_| TargetJournalError::InvalidInput)
}

fn to_u64(value: i64) -> Result<u64, TargetJournalError> {
    u64::try_from(value).map_err(|_| TargetJournalError::CorruptState)
}

/// Stable target-journal failures without SQL or path disclosure.
#[derive(Debug, Error)]
pub enum TargetJournalError {
    /// Caller input, policy, time or capacity observation is invalid.
    #[error("target journal input is invalid")]
    InvalidInput,
    /// Existing journal belongs to another marker identity or target generation.
    #[error("target journal identity does not match")]
    IdentityMismatch,
    /// Existing desired capacity policy has a newer authoritative revision.
    #[error("target journal capacity policy is stale")]
    StalePolicy,
    /// The same authoritative policy revision was reused with different values.
    #[error("target journal capacity policy conflicts at one revision")]
    PolicyConflict,
    /// Existing migration history differs from this build.
    #[error("target journal migration history differs")]
    MigrationMismatch,
    /// Journal schema is newer than this build.
    #[error("target journal schema is newer than this build")]
    UnsupportedSchema,
    /// Reuse of an operation identity changed reservation semantics.
    #[error("target journal operation conflicts with prior input")]
    OperationConflict,
    /// Explicit target capacity policy or physical availability rejects the reservation.
    #[error("target capacity is exhausted")]
    CapacityExhausted,
    /// Persisted journal bytes or accounting violate an invariant.
    #[error("target journal state is corrupt")]
    CorruptState,
    /// Cryptographic entropy was unavailable for local capability material.
    #[error("target journal entropy is unavailable")]
    Entropy(#[from] meshspan_domain::EntropyError),
    /// State-directory IO failed.
    #[error("target journal IO failed")]
    Io(#[from] std::io::Error),
    /// SQLite rejected migration, durability or an invariant-preserving transaction.
    #[error("target journal database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{ContractVersion, RequestContext, ReservationClass};
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use super::{
        CapacityObservation, CapacityPolicy, ReserveCapacityRequest, TargetJournal,
        TargetJournalError, journal_path,
    };
    use crate::{TargetMarker, UsageLimit};

    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }

    #[test]
    fn reservations_are_bounded_class_aware_idempotent_and_expirable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let marker = marker(3, 4)?;
        let mut random = FixedRandom(5);
        let mut journal = TargetJournal::open(
            directory.path(),
            marker,
            policy(UsageLimit::Percent(95), 100, 1),
            UnixMicros::new(1),
            &mut random,
        )?;
        let observation = CapacityObservation {
            total_bytes: 1_000,
            available_bytes: 1_000,
        };
        let first_context = context(10, 50)?;
        let first = journal.reserve(reservation_request(
            marker,
            first_context,
            ReservationClass::ForegroundWrite,
            850,
            observation,
            UnixMicros::new(10),
        ))?;
        assert_eq!(
            journal.reserve(reservation_request(
                marker,
                first_context,
                ReservationClass::ForegroundWrite,
                850,
                observation,
                UnixMicros::new(11),
            ))?,
            first
        );
        assert!(matches!(
            journal.reserve(reservation_request(
                marker,
                first_context,
                ReservationClass::ForegroundWrite,
                849,
                observation,
                UnixMicros::new(11),
            )),
            Err(TargetJournalError::OperationConflict)
        ));
        assert!(matches!(
            journal.reserve(reservation_request(
                marker,
                context(11, 60)?,
                ReservationClass::ForegroundWrite,
                51,
                observation,
                UnixMicros::new(11),
            )),
            Err(TargetJournalError::CapacityExhausted)
        ));
        journal.reserve(reservation_request(
            marker,
            context(12, 70)?,
            ReservationClass::Repair,
            100,
            observation,
            UnixMicros::new(12),
        ))?;
        assert_eq!(journal.capacity()?.reserved_bytes, 950);
        assert_eq!(journal.expire_reservations(UnixMicros::new(60))?, 1);
        assert_eq!(journal.capacity()?.reserved_bytes, 100);
        journal.reserve(reservation_request(
            marker,
            context(13, 90)?,
            ReservationClass::ForegroundWrite,
            800,
            observation,
            UnixMicros::new(61),
        ))?;
        assert_eq!(journal.capacity()?.reserved_bytes, 900);
        assert_eq!(
            journal.reserve(reservation_request(
                marker,
                first_context,
                ReservationClass::ForegroundWrite,
                850,
                observation,
                UnixMicros::new(61),
            ))?,
            first
        );
        Ok(())
    }

    #[test]
    fn journal_reopen_binds_marker_and_monotonic_policy_without_new_entropy()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let marker = marker(20, 21)?;
        let mut random = FixedRandom(22);
        let journal = TargetJournal::open(
            directory.path(),
            marker,
            policy(UsageLimit::Percent(95), 1_000, 1),
            UnixMicros::new(1),
            &mut random,
        )?;
        journal.check_integrity()?;
        drop(journal);

        let mut no_entropy = FailingRandom;
        let upgraded = TargetJournal::open(
            directory.path(),
            marker,
            policy(UsageLimit::Bytes(50_000), 2_000, 2),
            UnixMicros::new(2),
            &mut no_entropy,
        )?;
        assert_eq!(upgraded.capacity()?.repair_reserve_bytes, 2_000);
        drop(upgraded);
        assert!(matches!(
            TargetJournal::open(
                directory.path(),
                marker,
                policy(UsageLimit::Percent(95), 1_000, 1),
                UnixMicros::new(3),
                &mut no_entropy,
            ),
            Err(TargetJournalError::StalePolicy)
        ));
        assert!(matches!(
            TargetJournal::open(
                directory.path(),
                marker,
                policy(UsageLimit::Bytes(60_000), 2_000, 2),
                UnixMicros::new(3),
                &mut no_entropy,
            ),
            Err(TargetJournalError::PolicyConflict)
        ));
        let wrong_generation = TargetMarker::new(
            marker.mesh_id(),
            marker.target_id(),
            marker.generation() + 1,
            [90; 32],
        )?;
        assert!(matches!(
            TargetJournal::open(
                directory.path(),
                wrong_generation,
                policy(UsageLimit::Bytes(50_000), 2_000, 3),
                UnixMicros::new(3),
                &mut no_entropy,
            ),
            Err(TargetJournalError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn hostile_reservation_inputs_and_migration_drift_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let marker = marker(30, 31)?;
        let mut random = FixedRandom(32);
        let mut journal = TargetJournal::open(
            directory.path(),
            marker,
            policy(UsageLimit::Percent(95), 100, 1),
            UnixMicros::new(1),
            &mut random,
        )?;
        let observation = CapacityObservation {
            total_bytes: 1_000,
            available_bytes: 1_000,
        };
        for (target, generation, bytes, measured, now) in [
            (
                TargetId::from_bytes([99; 16])?,
                marker.generation(),
                1,
                observation,
                10,
            ),
            (
                marker.target_id(),
                marker.generation() + 1,
                1,
                observation,
                10,
            ),
            (marker.target_id(), marker.generation(), 0, observation, 10),
            (
                marker.target_id(),
                marker.generation(),
                1,
                CapacityObservation {
                    total_bytes: 100,
                    available_bytes: 101,
                },
                10,
            ),
            (marker.target_id(), marker.generation(), 1, observation, 50),
        ] {
            assert!(matches!(
                journal.reserve(super::ReserveCapacityRequest {
                    context: context(40, 50)?,
                    target_id: target,
                    target_generation: generation,
                    class: ReservationClass::ForegroundWrite,
                    bytes,
                    observation: measured,
                    now: UnixMicros::new(now),
                }),
                Err(TargetJournalError::InvalidInput)
            ));
        }
        assert_eq!(journal.capacity()?.reserved_bytes, 0);
        drop(journal);

        let file_path = journal_path(directory.path(), marker.target_id())?;
        let connection = rusqlite::Connection::open(file_path)?;
        connection.execute(
            "UPDATE schema_migrations SET migration_digest = zeroblob(32) WHERE version = 1",
            [],
        )?;
        drop(connection);
        assert!(matches!(
            TargetJournal::open(
                directory.path(),
                marker,
                policy(UsageLimit::Percent(95), 100, 1),
                UnixMicros::new(2),
                &mut random,
            ),
            Err(TargetJournalError::MigrationMismatch)
        ));
        Ok(())
    }

    fn marker(mesh: u8, target: u8) -> Result<TargetMarker, Box<dyn std::error::Error>> {
        Ok(TargetMarker::new(
            MeshId::from_bytes([mesh; 16])?,
            TargetId::from_bytes([target; 16])?,
            1,
            [target.wrapping_add(1); 32],
        )?)
    }

    const fn policy(
        usage_limit: UsageLimit,
        repair_reserve_bytes: u64,
        revision: u64,
    ) -> CapacityPolicy {
        CapacityPolicy {
            usage_limit,
            repair_reserve_bytes,
            revision: Revision::new(revision),
        }
    }

    fn context(operation: u8, deadline: i64) -> Result<RequestContext, Box<dyn std::error::Error>> {
        Ok(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([operation; 16])?,
            deadline: UnixMicros::new(deadline),
            expected_revision: Some(Revision::new(7)),
        })
    }

    const fn reservation_request(
        marker: TargetMarker,
        context: RequestContext,
        class: ReservationClass,
        bytes: u64,
        observation: CapacityObservation,
        now: UnixMicros,
    ) -> ReserveCapacityRequest {
        ReserveCapacityRequest {
            context,
            target_id: marker.target_id(),
            target_generation: marker.generation(),
            class,
            bytes,
            observation,
            now,
        }
    }
}
