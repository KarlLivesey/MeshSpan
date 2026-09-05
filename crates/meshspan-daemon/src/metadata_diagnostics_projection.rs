// SPDX-License-Identifier: GPL-2.0-only

//! Allow-listed projections only. Never serialise raw records and redact afterwards.

use meshspan_api_contract::{
    DiagnosticConsensus, DiagnosticConsensusRole, DiagnosticCounter, DiagnosticIdentifier,
    DiagnosticNode, DiagnosticOperation, DiagnosticSection, DiagnosticTarget, OperationState,
    StorageFolderUsageLimit, TopologyNodeRoles, TopologyNodeState, TopologyTargetState,
};
use meshspan_cluster::MetadataAuthorityObservation;
use meshspan_consensus::Role;
use meshspan_metadata::{
    AuthoritativeOperationState, AuthoritativeRepository, PageLimit, StorageUsageLimit,
};

use super::DiagnosticsError as Error;
use crate::create_mesh_setup::format_uuid;

pub(super) fn consensus(value: MetadataAuthorityObservation) -> DiagnosticConsensus {
    DiagnosticConsensus {
        partition_id: identifier(value.partition_id.as_bytes()),
        node_id: identifier(value.node_id.as_bytes()),
        role: match value.role {
            Role::Follower => DiagnosticConsensusRole::Follower,
            Role::Candidate => DiagnosticConsensusRole::Candidate,
            Role::Leader => DiagnosticConsensusRole::Leader,
        },
        known_leader: value.known_leader.map(|node| identifier(node.as_bytes())),
        term: DiagnosticCounter(value.term.to_string()),
        commit_index: DiagnosticCounter(value.commit_index.to_string()),
        applied_index: DiagnosticCounter(value.applied_index.to_string()),
        membership_epoch: DiagnosticCounter(value.membership_epoch.to_string()),
        plan_digest: value
            .plan_digest
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 15])
            .map(|digit| {
                char::from(if digit < 10 {
                    b'0' + digit
                } else {
                    b'a' + digit - 10
                })
            })
            .collect(),
        persistence_blocked: value.persistence_blocked,
        pending_operations: DiagnosticCounter(value.pending_operations.to_string()),
        queued_operations: DiagnosticCounter(value.queued_operations.to_string()),
    }
}

pub(super) fn nodes(
    repository: &AuthoritativeRepository,
) -> Result<DiagnosticSection<DiagnosticNode>, Error> {
    let page = repository
        .topology_nodes(None, limit()?)
        .map_err(|_| Error::Failed)?;
    let items = page
        .items
        .into_iter()
        .map(|record| {
            if record.roles & !7 != 0 {
                return Err(Error::Failed);
            }
            Ok(DiagnosticNode {
                node_id: identifier(record.node_id.as_bytes()),
                host_id: identifier(record.host_id.as_bytes()),
                configured_state: match record.state {
                    1 => TopologyNodeState::Joining,
                    2 => TopologyNodeState::Active,
                    3 => TopologyNodeState::Draining,
                    4 => TopologyNodeState::Retired,
                    _ => return Err(Error::Failed),
                },
                incarnation: DiagnosticCounter(record.incarnation.to_string()),
                roles: TopologyNodeRoles {
                    storage: record.roles & 1 != 0,
                    gateway: record.roles & 2 != 0,
                    metadata_eligible: record.roles & 4 != 0,
                },
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(DiagnosticSection {
        items,
        truncated: page.next.is_some(),
    })
}

pub(super) fn targets(
    repository: &AuthoritativeRepository,
) -> Result<DiagnosticSection<DiagnosticTarget>, Error> {
    let page = repository
        .topology_targets(None, limit()?)
        .map_err(|_| Error::Failed)?;
    let items = page
        .items
        .into_iter()
        .map(|record| {
            Ok(DiagnosticTarget {
                target_id: identifier(record.target_id.as_bytes()),
                node_id: identifier(record.node_id.as_bytes()),
                configured_state: match record.state {
                    1 => TopologyTargetState::Active,
                    2 => TopologyTargetState::Configuring,
                    3 => TopologyTargetState::Draining,
                    4 => TopologyTargetState::Unavailable,
                    5 => TopologyTargetState::Retired,
                    _ => return Err(Error::Failed),
                },
                generation: DiagnosticCounter(record.generation.to_string()),
                usage_limit: match record.usage_limit {
                    StorageUsageLimit::Percent(percent) => {
                        StorageFolderUsageLimit::Percent { percent }
                    }
                    StorageUsageLimit::Bytes(bytes) => StorageFolderUsageLimit::Bytes {
                        bytes: bytes.to_string(),
                    },
                },
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(DiagnosticSection {
        items,
        truncated: page.next.is_some(),
    })
}

pub(super) fn operations(
    repository: &AuthoritativeRepository,
) -> Result<DiagnosticSection<DiagnosticOperation>, Error> {
    let page = repository
        .operation_statuses(None, limit()?)
        .map_err(|_| Error::Failed)?;
    let items = page
        .items
        .into_iter()
        .map(|record| DiagnosticOperation {
            operation_id: identifier(record.operation_id.as_bytes()),
            state: match record.state {
                AuthoritativeOperationState::Running => OperationState::Running,
                AuthoritativeOperationState::Succeeded => OperationState::Succeeded,
                AuthoritativeOperationState::Failed => OperationState::Failed,
            },
            revision: DiagnosticCounter(record.revision.get().to_string()),
            started_at_epoch_micros: record.started_at.get(),
            completed_at_epoch_micros: record.completed_at.map(meshspan_domain::UnixMicros::get),
        })
        .collect();
    Ok(DiagnosticSection {
        items,
        truncated: page.next.is_some(),
    })
}

fn identifier(bytes: [u8; 16]) -> DiagnosticIdentifier {
    DiagnosticIdentifier(format_uuid(bytes))
}
fn limit() -> Result<PageLimit, Error> {
    PageLimit::new(100).map_err(|_| Error::Failed)
}
