// SPDX-License-Identifier: GPL-2.0-only

//! Indexed, bounded update progress reads, revalidating signed persisted candidates.

use meshspan_domain::{ComponentInstanceId, NodeId, PrincipalId, Revision, UnixMicros, WorkId};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest as _, Sha256};

use super::{AuthoritativeRepository, PageLimit, RepositoryError};
use crate::{UpdateManifest, UpdateNodePhase, authenticate_update_manifest};

/// Administrator-pinned public update signer; private keys are never stored here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSignerRecord {
    /// Stable configured identity.
    pub signer_id: ComponentInstanceId,
    /// Current trust configuration sequence.
    pub sequence: u64,
    /// Canonical public verification key, immutable for this identity.
    pub public_key: [u8; 65],
    /// Current explicit enablement.
    pub enabled: bool,
}

/// Durable aggregate progression, independent of local worker liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdateRolloutState {
    /// New restarts may be admitted after current safety checks.
    Running = 1,
    /// No new restarts; reconcile any already in flight.
    Paused = 2,
    /// Every snapshotted node has a verified new process.
    Completed = 3,
    /// Explicitly stopped without rolling back already installed binaries.
    Cancelled = 4,
}

/// Selected candidate and durable aggregate status.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateRolloutRecord {
    /// Stable work identity.
    pub rollout_id: WorkId,
    /// Independently pinned signer identity.
    pub signer_id: ComponentInstanceId,
    /// Authenticated parsed candidate; not local installation proof.
    pub manifest: UpdateManifest,
    /// Exact signed manifest for authenticated distribution to nodes.
    pub canonical_manifest: Vec<u8>,
    /// Exact detached signature.
    pub signature: Vec<u8>,
    /// Original explicit consent to unavoidable service interruption.
    pub allow_service_interruption: bool,
    /// Current aggregate state.
    pub state: UpdateRolloutState,
    /// Sequence changed by every checkpoint/control transition.
    pub sequence: u64,
    /// Principal that chose the candidate.
    pub created_by: PrincipalId,
    /// Last authoritative change revision.
    pub revision: Revision,
}

/// One exact member's update checkpoint; absence of evidence is not success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateNodeRecord {
    /// Assigned node identity.
    pub node_id: NodeId,
    /// Exact snapshotted incarnation.
    pub incarnation: u64,
    /// Current durable phase.
    pub phase: UpdateNodePhase,
    /// Remains true after an ambiguous restart failure until a new process is verified.
    pub restart_pending: bool,
    /// Node-specific compare-and-swap sequence.
    pub sequence: u64,
    /// Signed platform selected by staging; initially absent.
    pub target: Option<String>,
    /// Bound retained local probe evidence; initially absent.
    pub evidence_digest: Option<[u8; 32]>,
    /// Committed report instant, not evidence freshness by itself.
    pub observed_at: Option<UnixMicros>,
}

/// Bounded aggregate projection over indexed rollout checkpoints, not live readiness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UpdateProgressCounts {
    /// Nodes awaiting staging.
    pub pending: u64,
    /// Nodes with staged bytes.
    pub staged: u64,
    /// Nodes restarting.
    pub restarting: u64,
    /// Nodes with a verified replacement process.
    pub verified: u64,
    /// Nodes with a failed checkpoint.
    pub failed: u64,
    /// Restarts whose outcomes must still be reconciled.
    pub unresolved_restarts: u64,
}

impl AuthoritativeRepository {
    /// Count checkpoints without materialising every selected member.
    ///
    /// # Errors
    /// Rejects unknown phases, invalid counts or unavailable storage.
    pub fn update_progress_counts(
        &self,
        id: WorkId,
    ) -> Result<UpdateProgressCounts, RepositoryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT phase, COUNT(*), SUM(restart_pending) FROM update_rollout_nodes WHERE rollout_id=?1 GROUP BY phase",
        )?;
        let rows = statement.query_map([id.as_bytes()], |row| {
            Ok((row.get::<_, u8>(0)?, unsigned(row, 1)?, unsigned(row, 2)?))
        })?;
        let mut counts = UpdateProgressCounts::default();
        for row in rows {
            let (phase, count, unresolved) = row?;
            match phase {
                1 => counts.pending = count,
                2 => counts.staged = count,
                3 => counts.restarting = count,
                4 => counts.verified = count,
                5 => counts.failed = count,
                _ => return Err(RepositoryError::CorruptState),
            }
            counts.unresolved_restarts = counts
                .unresolved_restarts
                .checked_add(unresolved)
                .ok_or(RepositoryError::CorruptState)?;
        }
        Ok(counts)
    }

    /// Reads configured update signers, bounded to the 64-entry trust-policy limit.
    ///
    /// # Errors
    /// Rejects corrupt keys or unavailable storage.
    pub fn update_signers(&self) -> Result<Vec<UpdateSignerRecord>, RepositoryError> {
        let mut statement = self
            .database
            .connection()
            .prepare("SELECT signer_id FROM update_signers ORDER BY signer_id LIMIT 65")?;
        let identities = statement
            .query_map([], |row| row.get::<_, [u8; 16]>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if identities.len() > 64 {
            return Err(RepositoryError::CorruptState);
        }
        identities
            .into_iter()
            .map(|id| {
                signer(
                    self.database.connection(),
                    ComponentInstanceId::from_bytes(id)
                        .map_err(|_| RepositoryError::CorruptState)?,
                )?
                .ok_or(RepositoryError::CorruptState)
            })
            .collect()
    }

    /// Reads and authenticates one retained rollout.
    ///
    /// # Errors
    /// Rejects corrupt signed bytes, identities, states or unavailable storage.
    pub fn update_rollout(
        &self,
        id: WorkId,
    ) -> Result<Option<UpdateRolloutRecord>, RepositoryError> {
        load(self.database.connection(), id)
    }

    /// Finds the sole running/paused rollout through the active-work index.
    ///
    /// # Errors
    /// Rejects corrupt state or unavailable storage.
    pub fn active_update_rollout(&self) -> Result<Option<UpdateRolloutRecord>, RepositoryError> {
        let id: Option<[u8; 16]> = self
            .database
            .connection()
            .query_row(
                "SELECT rollout_id FROM update_rollouts WHERE state IN (1,2)",
                [],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| {
            load(
                self.database.connection(),
                WorkId::from_bytes(id).map_err(|_| RepositoryError::CorruptState)?,
            )?
            .ok_or(RepositoryError::CorruptState)
        })
        .transpose()
    }

    /// Pages exact members by stable node identity; no whole-mesh allocation is required.
    ///
    /// # Errors
    /// Rejects malformed stored progress or unavailable persistence.
    pub fn update_rollout_nodes(
        &self,
        id: WorkId,
        after: Option<NodeId>,
        limit: PageLimit,
    ) -> Result<Vec<UpdateNodeRecord>, RepositoryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT node_id,incarnation,phase,restart_pending,sequence,target,evidence_digest,observed_at
             FROM update_rollout_nodes WHERE rollout_id=?1 AND node_id>?2 ORDER BY node_id LIMIT ?3")?;
        let cursor = after.map_or([0; 16], NodeId::as_bytes);
        let rows = statement.query_map(
            params![
                id.as_bytes().as_slice(),
                cursor.as_slice(),
                i64::try_from(limit.get()).map_err(|_| RepositoryError::InvalidPageLimit)?
            ],
            decode_node,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

pub(super) fn signer(
    tx: &Connection,
    id: ComponentInstanceId,
) -> Result<Option<UpdateSignerRecord>, RepositoryError> {
    let row = tx
        .query_row(
            "SELECT sequence,public_key,enabled FROM update_signers WHERE signer_id=?1",
            [id.as_bytes().as_slice()],
            |row| {
                Ok(UpdateSignerRecord {
                    signer_id: id,
                    sequence: unsigned(row, 0)?,
                    public_key: row.get(1)?,
                    enabled: row.get(2)?,
                })
            },
        )
        .optional()?;
    if let Some(record) = &row {
        meshspan_certificates::NodePublicIdentity::from_sec1(&record.public_key)
            .map_err(|_| RepositoryError::CorruptState)?;
        if record.sequence == 0 {
            return Err(RepositoryError::CorruptState);
        }
    }
    Ok(row)
}

struct StoredRollout {
    signer_id: [u8; 16],
    manifest: Vec<u8>,
    digest: [u8; 32],
    signature: Vec<u8>,
    interruption: bool,
    state: u8,
    sequence: u64,
    actor: [u8; 16],
    revision: u64,
}

pub(super) fn load(
    tx: &Connection,
    id: WorkId,
) -> Result<Option<UpdateRolloutRecord>, RepositoryError> {
    let row = tx
        .query_row(
            "SELECT signer_id,manifest,manifest_digest,signature,allow_service_interruption,
        state,sequence,created_by,revision FROM update_rollouts WHERE rollout_id=?1",
            [id.as_bytes().as_slice()],
            |row| {
                Ok(StoredRollout {
                    signer_id: row.get(0)?,
                    manifest: row.get(1)?,
                    digest: row.get(2)?,
                    signature: row.get(3)?,
                    interruption: row.get(4)?,
                    state: row.get(5)?,
                    sequence: unsigned(row, 6)?,
                    actor: row.get(7)?,
                    revision: unsigned(row, 8)?,
                })
            },
        )
        .optional()?;
    row.map(|stored| {
        let signer_id = ComponentInstanceId::from_bytes(stored.signer_id)
            .map_err(|_| RepositoryError::CorruptState)?;
        let trust = signer(tx, signer_id)?.ok_or(RepositoryError::CorruptState)?;
        let digest: [u8; 32] = Sha256::digest(&stored.manifest).into();
        if digest != stored.digest || stored.sequence == 0 || stored.revision == 0 {
            return Err(RepositoryError::CorruptState);
        }
        let manifest =
            authenticate_update_manifest(&stored.manifest, &stored.signature, &trust.public_key)
                .map_err(|_| RepositoryError::CorruptState)?;
        let state = match stored.state {
            1 => UpdateRolloutState::Running,
            2 => UpdateRolloutState::Paused,
            3 => UpdateRolloutState::Completed,
            4 => UpdateRolloutState::Cancelled,
            _ => return Err(RepositoryError::CorruptState),
        };
        Ok(UpdateRolloutRecord {
            rollout_id: id,
            signer_id,
            manifest,
            canonical_manifest: stored.manifest,
            signature: stored.signature,
            allow_service_interruption: stored.interruption,
            state,
            sequence: stored.sequence,
            created_by: PrincipalId::from_bytes(stored.actor)
                .map_err(|_| RepositoryError::CorruptState)?,
            revision: Revision::new(stored.revision),
        })
    })
    .transpose()
}

pub(super) fn node(
    tx: &Connection,
    id: WorkId,
    node_id: NodeId,
) -> Result<Option<UpdateNodeRecord>, RepositoryError> {
    Ok(tx.query_row("SELECT node_id,incarnation,phase,restart_pending,sequence,target,evidence_digest,observed_at
        FROM update_rollout_nodes WHERE rollout_id=?1 AND node_id=?2",
        params![id.as_bytes().as_slice(),node_id.as_bytes().as_slice()],decode_node).optional()?)
}

fn decode_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<UpdateNodeRecord> {
    let invalid = || rusqlite::Error::InvalidQuery;
    let phase = match row.get::<_, u8>(2)? {
        1 => UpdateNodePhase::Pending,
        2 => UpdateNodePhase::Staged,
        3 => UpdateNodePhase::Restarting,
        4 => UpdateNodePhase::Verified,
        5 => UpdateNodePhase::Failed,
        _ => return Err(invalid()),
    };
    let value = UpdateNodeRecord {
        node_id: NodeId::from_bytes(row.get(0)?).map_err(|_| invalid())?,
        incarnation: unsigned(row, 1)?,
        phase,
        restart_pending: row.get(3)?,
        sequence: unsigned(row, 4)?,
        target: row.get(5)?,
        evidence_digest: row.get(6)?,
        observed_at: row.get::<_, Option<i64>>(7)?.map(UnixMicros::new),
    };
    if value.incarnation == 0 || value.sequence == 0 {
        return Err(invalid());
    }
    Ok(value)
}

fn unsigned(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(column)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}
