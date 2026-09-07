// SPDX-License-Identifier: GPL-2.0-only

use super::{
    AuthoritativeRepository, EntityKind, EntityReference, PageLimit, RepositoryError, apply::to_i64,
};
use crate::{PublishUpdateArtifact, UpdateRolloutState};
use meshspan_domain::{NodeId, Revision, WorkId};
use rusqlite::{Transaction, params};

pub(super) fn publish(
    tx: &Transaction<'_>,
    value: &PublishUpdateArtifact,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let record = super::update_rollout_queries::load(tx, value.rollout_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if !matches!(
        record.state,
        UpdateRolloutState::Running | UpdateRolloutState::Paused
    ) {
        return Err(RepositoryError::InvalidCommand);
    }
    let signer = super::update_rollout_queries::signer(tx, record.signer_id)?
        .ok_or(RepositoryError::CorruptState)?;
    let artifact = record
        .manifest
        .artifact(&value.target)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id=?1 AND state=2 AND retired_at IS NULL AND current_incarnation=?2)",
        params![value.node_id.as_bytes().as_slice(), to_i64(value.incarnation)?], |row| row.get(0))?;
    if !active
        || !signer.enabled
        || artifact.size != value.byte_length
        || artifact.sha256 != value.sha256
    {
        return Err(RepositoryError::InvalidCommand);
    }
    tx.execute("INSERT INTO update_artifact_sources(rollout_id,node_id,incarnation,target,byte_length,sha256,revision)
        VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(rollout_id,target,node_id) DO UPDATE SET
        incarnation=excluded.incarnation, revision=excluded.revision",
        params![value.rollout_id.as_bytes().as_slice(), value.node_id.as_bytes().as_slice(), to_i64(value.incarnation)?,
            value.target, to_i64(value.byte_length)?, value.sha256, to_i64(revision.get())?])?;
    Ok(EntityReference {
        kind: EntityKind::UpdateRollout,
        id: value.rollout_id.as_bytes(),
    })
}

/// Exact advertised source; this is a retrieval hint, never proof that bytes remain available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateArtifactSource {
    /// Node that held the verified candidate.
    pub node_id: NodeId,
    /// Exact advertised incarnation.
    pub incarnation: u64,
}

impl AuthoritativeRepository {
    /// Page active candidate sources without collecting the whole mesh.
    ///
    /// # Errors
    /// Rejects malformed stored identities, absent targets and unavailable storage.
    pub fn update_artifact_sources(
        &self,
        rollout: WorkId,
        target: &str,
        after: Option<NodeId>,
        limit: PageLimit,
    ) -> Result<Vec<UpdateArtifactSource>, RepositoryError> {
        let record = self
            .update_rollout(rollout)?
            .ok_or(RepositoryError::InvalidCommand)?;
        record
            .manifest
            .artifact(target)
            .map_err(|_| RepositoryError::InvalidCommand)?;
        let mut statement = self.database.connection().prepare("SELECT s.node_id,s.incarnation FROM update_artifact_sources s
            JOIN nodes n ON n.node_id=s.node_id AND n.current_incarnation=s.incarnation AND n.state=2 AND n.retired_at IS NULL
            WHERE s.rollout_id=?1 AND s.target=?2 AND s.node_id>?3 ORDER BY s.node_id LIMIT ?4")?;
        statement
            .query_map(
                params![
                    rollout.as_bytes().as_slice(),
                    target,
                    after.map_or([0; 16], NodeId::as_bytes).as_slice(),
                    i64::try_from(limit.get()).map_err(|_| RepositoryError::InvalidCommand)?
                ],
                |row| Ok((row.get::<_, [u8; 16]>(0)?, row.get::<_, i64>(1)?)),
            )?
            .map(|row| {
                let (id, incarnation) = row?;
                let incarnation =
                    u64::try_from(incarnation).map_err(|_| RepositoryError::CorruptState)?;
                if incarnation == 0 {
                    return Err(RepositoryError::CorruptState);
                }
                Ok(UpdateArtifactSource {
                    node_id: NodeId::from_bytes(id).map_err(|_| RepositoryError::CorruptState)?,
                    incarnation,
                })
            })
            .collect()
    }
}
