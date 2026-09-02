// SPDX-License-Identifier: GPL-2.0-only

//! Fenced admission of exact target routes into ordinary shard repair work.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, EntropyError, OperationId, PrincipalId, RandomSource, TargetId, UnixMicros,
    WorkId, uuid_v8,
};
use meshspan_filesystem::{
    ContentCatalogError, DurableContentCatalog, TargetShardCursor, TargetShardPage,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CommandReceipt,
    CompleteMaintenanceWork, EntityKind, MaintenanceWorkCompletion, QueueMaintenanceWork,
};
use meshspan_work::{DrainScope, WorkDemand, WorkSignals, WorkSubject};
use thiserror::Error;

use crate::MaintenanceMetadataAuthority;

const MAXIMUM_ROUTES_PER_DRAIN_STEP: usize = 64;

/// Current-route catalogue boundary used by target-drain execution.
pub trait TargetShardInventorySource {
    /// Returns one bounded page of current routes on the exact target generation.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and contradictory or corrupt catalogue state.
    fn target_shards(
        &self,
        target_id: TargetId,
        target_generation: u64,
        after: Option<TargetShardCursor>,
        limit: usize,
    ) -> Result<TargetShardPage, ContentCatalogError>;
}

impl TargetShardInventorySource for DurableContentCatalog {
    fn target_shards(
        &self,
        target_id: TargetId,
        target_generation: u64,
        after: Option<TargetShardCursor>,
        limit: usize,
    ) -> Result<TargetShardPage, ContentCatalogError> {
        self.current_target_shards(target_id, target_generation, after, limit)
    }
}

/// Exact claim and timing fences for one bounded target-evacuation step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetDrainExecution {
    /// Idempotency, actor, audit and time context for the drain claim.
    pub claim_context: CommandContext,
    /// Independent context that releases the claim after repair admission.
    pub completion_context: CommandContext,
    /// Next fenced claim generation selected from authoritative job state.
    pub claim: ClaimMaintenanceWork,
    /// Exact drain subject selected by the authoritative dispatcher.
    pub subject: WorkSubject,
    /// Maximum current routes admitted by this attempt.
    pub route_limit: usize,
    /// Earliest authority-agreed instant for another evacuation step.
    pub continuation_at: UnixMicros,
}

/// Durable result of one non-terminal target-drain step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDrainStepReceipt {
    /// Number of exact current routes admitted to ordinary repair work.
    pub queued_repairs: usize,
    /// Whether the bounded route query observed another page.
    pub more_routes: bool,
    /// Receipt releasing the drain claim for its next proof/evacuation step.
    pub completion: CommandReceipt,
}

/// Closed failures before a drain step can safely release its claim.
#[derive(Debug, Error)]
pub enum TargetDrainError {
    /// The target route catalogue was unavailable or contradictory.
    #[error("target drain could not read a trustworthy current-route catalogue")]
    Catalogue(#[from] ContentCatalogError),
    /// A claim, repair admission or continuation could not commit through consensus.
    #[error("target drain metadata transition failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Unique work, operation or audit identities could not be generated.
    #[error("target drain identities could not be generated")]
    Entropy(#[from] EntropyError),
    /// The selected subject, claim, timing or returned receipt contradicted the attempt.
    #[error("target drain execution input or authority receipt was invalid")]
    Invalid,
}

/// Claims one target drain, admits a bounded current-route page to repair, then continues it.
///
/// An empty page is not treated as safe-to-detach. Terminal safety requires a separately
/// committed fresh catalogue proof, so this step always remains non-terminal.
///
/// # Errors
///
/// Rejects contradictory execution input, corrupt catalogue state, entropy failure or any
/// authority transition that cannot be exactly verified.
pub fn execute_target_drain_step<Authority, Catalogue, Random>(
    authority: &Authority,
    catalogue: &Catalogue,
    random: &mut Random,
    execution: &TargetDrainExecution,
) -> Result<TargetDrainStepReceipt, TargetDrainError>
where
    Authority: MaintenanceMetadataAuthority,
    Catalogue: TargetShardInventorySource,
    Random: RandomSource,
{
    let (target_id, target_generation) = validate_execution(execution)?;
    commit_exact(
        authority,
        execution.claim_context,
        &AuthoritativeCommand::ClaimMaintenanceWork(execution.claim),
        EntityKind::MaintenanceWork,
    )?;
    let page =
        catalogue.target_shards(target_id, target_generation, None, execution.route_limit)?;
    for route in page.routes.as_slice() {
        queue_repair(
            authority,
            random,
            execution.claim_context.actor_principal_id,
            execution.claim_context.occurred_at,
            route.candidate,
        )?;
    }
    let progress_digest = drain_progress_digest(target_id, target_generation, &page);
    let completion = commit_exact(
        authority,
        execution.completion_context,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            outcome: MaintenanceWorkCompletion::Continue {
                progress_digest,
                retry_at: execution.continuation_at,
            },
        }),
        EntityKind::MaintenanceWork,
    )?;
    Ok(TargetDrainStepReceipt {
        queued_repairs: page.routes.len(),
        more_routes: page.next.is_some(),
        completion,
    })
}

fn validate_execution(
    execution: &TargetDrainExecution,
) -> Result<(TargetId, u64), TargetDrainError> {
    let WorkSubject::Drain(DrainScope::Target {
        target_id,
        target_generation,
    }) = execution.subject
    else {
        return Err(TargetDrainError::Invalid);
    };
    if target_generation == 0
        || execution.route_limit == 0
        || execution.route_limit > MAXIMUM_ROUTES_PER_DRAIN_STEP
        || execution.claim.claim_generation == 0
        || execution.claim.worker_incarnation == 0
        || execution.claim.fence == 0
        || execution.claim_context.actor_principal_id
            != execution.completion_context.actor_principal_id
        || execution.claim_context.operation_id == execution.completion_context.operation_id
        || execution.claim_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.claim_context.occurred_at > execution.completion_context.occurred_at
        || execution.claim_context.occurred_at >= execution.claim.lease_expires_at
        || execution.completion_context.occurred_at >= execution.claim.lease_expires_at
        || execution.continuation_at <= execution.completion_context.occurred_at
    {
        Err(TargetDrainError::Invalid)
    } else {
        Ok((target_id, target_generation))
    }
}

fn queue_repair<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    random: &mut impl RandomSource,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
    candidate: meshspan_filesystem::ShardRepairCandidate,
) -> Result<(), TargetDrainError> {
    let subject = WorkSubject::Repair {
        volume_id: candidate.volume_id,
        manifest_id: candidate.manifest_id,
        stripe_index: candidate.source_receipt.shard.stripe_index,
        shard_index: candidate.source_receipt.shard.shard_index,
        source_generation: candidate.source_layout_generation,
    };
    let context = random_context(random, actor_principal_id, now)?;
    let work_id = random_work_id(random)?;
    commit_exact(
        authority,
        context,
        &AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id,
            deduplication_key: crate::scrub_finding_scheduler::deduplication_key(
                subject, None, now,
            ),
            subject,
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 1,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: now,
                due_at: Some(now),
            },
            demand: WorkDemand {
                in_flight_bytes: candidate.source_receipt.length,
            },
            next_attempt_at: now,
        }),
        EntityKind::MaintenanceWork,
    )?;
    Ok(())
}

fn commit_exact<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    context: CommandContext,
    command: &AuthoritativeCommand,
    entity_kind: EntityKind,
) -> Result<CommandReceipt, TargetDrainError> {
    let receipt = authority.commit(context, command)?;
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != entity_kind
    {
        Err(TargetDrainError::Invalid)
    } else {
        Ok(receipt)
    }
}

fn drain_progress_digest(
    target_id: TargetId,
    target_generation: u64,
    page: &TargetShardPage,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.target-drain.progress.v1\0");
    digest.update(&target_id.as_bytes());
    digest.update(&target_generation.to_be_bytes());
    for route in page.routes.as_slice() {
        digest.update(&route.cursor.publication_operation_id.as_bytes());
        digest.update(&route.cursor.stripe_index.to_be_bytes());
        digest.update(&route.cursor.shard_index.to_be_bytes());
        digest.update(&route.candidate.source_layout_generation.to_be_bytes());
        digest.update(&route.candidate.source_receipt.operation_id.as_bytes());
    }
    digest.update(&[u8::from(page.next.is_some())]);
    digest.finalize().into()
}

fn random_context(
    random: &mut impl RandomSource,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<CommandContext, TargetDrainError> {
    let mut bytes = [0_u8; 32];
    random.fill_bytes(&mut bytes)?;
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(copy_identifier(&bytes[..16])?))
            .map_err(|_| TargetDrainError::Invalid)?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(copy_identifier(&bytes[16..])?))
            .map_err(|_| TargetDrainError::Invalid)?,
        occurred_at: now,
        expected_revision: None,
    })
}

fn random_work_id(random: &mut impl RandomSource) -> Result<WorkId, TargetDrainError> {
    let mut bytes = [0_u8; 16];
    random.fill_bytes(&mut bytes)?;
    WorkId::from_bytes(uuid_v8(bytes)).map_err(|_| TargetDrainError::Invalid)
}

fn copy_identifier(bytes: &[u8]) -> Result<[u8; 16], TargetDrainError> {
    bytes.try_into().map_err(|_| TargetDrainError::Invalid)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_contracts::{BoundedItems, ShardIdentity, ShardReceipt};
    use meshspan_domain::{ContentManifestId, NodeId, Revision, VolumeId};
    use meshspan_filesystem::{ShardRepairCandidate, TargetShardRoute};
    use meshspan_metadata::{ApplyDisposition, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn exact_target_route_is_claimed_admitted_and_continued()
    -> Result<(), Box<dyn std::error::Error>> {
        let route = target_route()?;
        let catalogue = FixedCatalogue {
            page: TargetShardPage {
                routes: BoundedItems::new(vec![route], 1)?,
                next: Some(route.cursor),
            },
            requests: RefCell::new(Vec::new()),
        };
        let authority = RecordingAuthority::default();
        let mut random = CounterRandom(90);
        let execution = execution()?;

        let receipt = execute_target_drain_step(&authority, &catalogue, &mut random, &execution)?;

        assert_eq!(receipt.queued_repairs, 1);
        assert!(receipt.more_routes);
        assert_eq!(
            catalogue.requests.borrow().as_slice(),
            &[(target(7)?, 4, 1)]
        );
        let commands = authority.commands.borrow();
        assert!(matches!(
            commands[0],
            AuthoritativeCommand::ClaimMaintenanceWork(_)
        ));
        let AuthoritativeCommand::QueueMaintenanceWork(queued) = commands[1] else {
            return Err("drain did not admit an ordinary repair job".into());
        };
        assert_eq!(
            queued.subject,
            WorkSubject::Repair {
                volume_id: route.candidate.volume_id,
                manifest_id: route.candidate.manifest_id,
                stripe_index: route.candidate.source_receipt.shard.stripe_index,
                shard_index: route.candidate.source_receipt.shard.shard_index,
                source_generation: route.candidate.source_layout_generation,
            }
        );
        assert_eq!(
            queued.demand.in_flight_bytes,
            route.candidate.source_receipt.length
        );
        let AuthoritativeCommand::CompleteMaintenanceWork(completed) = commands[2] else {
            return Err("drain claim was not released as continued".into());
        };
        let MaintenanceWorkCompletion::Continue {
            progress_digest,
            retry_at,
        } = completed.outcome
        else {
            return Err("drain became terminal without a safety proof".into());
        };
        assert_ne!(progress_digest, [0; 32]);
        assert_eq!(retry_at, execution.continuation_at);
        Ok(())
    }

    #[test]
    fn empty_page_remains_non_terminal_and_wrong_scope_fails_before_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let catalogue = FixedCatalogue {
            page: TargetShardPage {
                routes: BoundedItems::new(Vec::new(), 1)?,
                next: None,
            },
            requests: RefCell::new(Vec::new()),
        };
        let authority = RecordingAuthority::default();
        let mut random = CounterRandom(90);
        let receipt =
            execute_target_drain_step(&authority, &catalogue, &mut random, &execution()?)?;
        assert_eq!(receipt.queued_repairs, 0);
        assert_eq!(authority.commands.borrow().len(), 2);

        let mut wrong = execution()?;
        wrong.subject = WorkSubject::Drain(DrainScope::Node {
            node_id: NodeId::from_bytes([9; 16])?,
            node_incarnation: 1,
        });
        assert!(matches!(
            execute_target_drain_step(&authority, &catalogue, &mut random, &wrong),
            Err(TargetDrainError::Invalid)
        ));
        assert_eq!(authority.commands.borrow().len(), 2);
        Ok(())
    }

    struct FixedCatalogue {
        page: TargetShardPage,
        requests: RefCell<Vec<(TargetId, u64, usize)>>,
    }

    impl TargetShardInventorySource for FixedCatalogue {
        fn target_shards(
            &self,
            target_id: TargetId,
            target_generation: u64,
            _after: Option<TargetShardCursor>,
            limit: usize,
        ) -> Result<TargetShardPage, ContentCatalogError> {
            self.requests
                .borrow_mut()
                .push((target_id, target_generation, limit));
            Ok(self.page.clone())
        }
    }

    #[derive(Default)]
    struct RecordingAuthority {
        commands: RefCell<Vec<AuthoritativeCommand>>,
    }

    impl MaintenanceMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(CommandReceipt {
                disposition: ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                result_digest: [1; 32],
                committed_revision: Revision::new(1),
                committed_position: LogPosition { index: 1, term: 1 },
                applied_position: LogPosition { index: 1, term: 1 },
                entity: EntityReference {
                    kind: EntityKind::MaintenanceWork,
                    id: [4; 16],
                },
            })
        }
    }

    struct CounterRandom(u8);

    impl RandomSource for CounterRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for (offset, byte) in destination.iter_mut().enumerate() {
                *byte = self.0.wrapping_add(u8::try_from(offset).unwrap_or(u8::MAX));
            }
            self.0 = self.0.wrapping_add(53);
            Ok(())
        }
    }

    fn execution() -> Result<TargetDrainExecution, meshspan_domain::IdentifierError> {
        let actor_principal_id = PrincipalId::from_bytes([5; 16])?;
        Ok(TargetDrainExecution {
            claim_context: context(10, 20, actor_principal_id)?,
            completion_context: context(11, 21, actor_principal_id)?,
            claim: ClaimMaintenanceWork {
                work_id: WorkId::from_bytes([12; 16])?,
                claim_generation: 1,
                worker_node_id: NodeId::from_bytes([13; 16])?,
                worker_incarnation: 1,
                fence: 2,
                lease_expires_at: UnixMicros::new(30),
            },
            subject: WorkSubject::Drain(DrainScope::Target {
                target_id: target(7)?,
                target_generation: 4,
            }),
            route_limit: 1,
            continuation_at: UnixMicros::new(22),
        })
    }

    fn context(
        identity: u8,
        at: i64,
        actor_principal_id: PrincipalId,
    ) -> Result<CommandContext, meshspan_domain::IdentifierError> {
        Ok(CommandContext {
            operation_id: OperationId::from_bytes([identity; 16])?,
            actor_principal_id,
            audit_event_id: AuditEventId::from_bytes([identity + 40; 16])?,
            occurred_at: UnixMicros::new(at),
            expected_revision: None,
        })
    }

    fn target_route() -> Result<TargetShardRoute, meshspan_domain::IdentifierError> {
        Ok(TargetShardRoute {
            cursor: TargetShardCursor {
                publication_operation_id: OperationId::from_bytes([20; 16])?,
                stripe_index: 3,
                shard_index: 2,
            },
            candidate: ShardRepairCandidate {
                volume_id: VolumeId::from_bytes([21; 16])?,
                manifest_id: ContentManifestId::from_bytes([22; 16])?,
                source_layout_generation: 6,
                source_receipt: ShardReceipt {
                    operation_id: OperationId::from_bytes([23; 16])?,
                    shard: ShardIdentity {
                        manifest_digest: [24; 32],
                        stripe_index: 3,
                        shard_index: 2,
                        generation: 1,
                    },
                    length: 4_096,
                    digest: [25; 32],
                    target_id: target(7)?,
                    target_generation: 4,
                },
            },
        })
    }

    fn target(value: u8) -> Result<TargetId, meshspan_domain::IdentifierError> {
        TargetId::from_bytes([value; 16])
    }
}
