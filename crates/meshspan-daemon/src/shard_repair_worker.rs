// SPDX-License-Identifier: GPL-2.0-only

//! Composition of fenced maintenance claims, physical shard repair and authoritative completion.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{CodingScheme, ContractError, ShardReceipt};
use meshspan_filesystem::{
    CommittedProtectedStripe, ContentShardRouter, ProtectedShardRepairer, ShardRepairRequest,
    ShardRepairTransition,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CommandReceipt, CommitShardRepair,
    CompleteMaintenanceWork, MaintenanceWorkCompletion,
};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

/// Exact metadata identities and physical plan for one already-selected repair job.
pub struct ShardRepairExecution<'a> {
    /// Idempotency, actor, audit and time context for the claim command.
    pub claim_context: CommandContext,
    /// Independent context for the authoritative location transition.
    pub effect_context: CommandContext,
    /// Independent context for the exact work-completion link.
    pub completion_context: CommandContext,
    /// Next fenced claim generation selected from authoritative job state.
    pub claim: ClaimMaintenanceWork,
    /// Volume bound into the repair work subject.
    pub volume_id: meshspan_domain::VolumeId,
    /// Immutable manifest bound into the repair work subject.
    pub manifest_id: meshspan_domain::ContentManifestId,
    /// Compare-and-swap generation of the current shard-location catalogue.
    pub source_layout_generation: u64,
    /// Physical reconstruction and destination authority.
    pub physical: ShardRepairRequest,
    /// Complete verified coding geometry and currently known durable receipts.
    pub stripe: &'a CommittedProtectedStripe,
}

/// Durable evidence returned only after the authoritative job becomes terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardRepairExecutionReceipt {
    /// Destination provider's exact durable byte receipt.
    pub replacement_receipt: ShardReceipt,
    /// Authoritative copy-on-write route transition.
    pub effect: CommandReceipt,
    /// Terminal maintenance-job receipt linked to `effect`.
    pub completion: CommandReceipt,
    /// Exact route projection ready for every gateway's local content catalogue.
    pub transition: ShardRepairTransition,
}

/// Closed failure phases; no variant claims completion without its exact committed receipt.
#[derive(Debug, Error)]
pub enum ShardRepairExecutionError {
    /// Claim, effect or completion could not be committed by metadata consensus.
    #[error("repair metadata authority rejected or could not commit a transition")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Reconstruction, capacity reservation or exact provider IO failed.
    #[error("physical shard repair failed before an authoritative location transition")]
    Physical(#[from] ContractError),
    /// Cross-step identities, timing or stripe evidence disagree.
    #[error("repair execution input contradicts its claim or physical plan")]
    InvalidInput,
}

/// Minimal consensus mutation boundary required by a shard-repair worker.
pub trait RepairMetadataAuthority {
    /// Commits or resolves one exact authoritative command.
    ///
    /// # Errors
    ///
    /// Returns only typed consensus/authority failures and never invents a durable receipt.
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl RepairMetadataAuthority for ConsensusAuthenticationAuthority {
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}

/// Replaceable physical reconstruction boundary used by repair orchestration.
pub trait PhysicalShardRepair {
    /// Reconstructs and durably stores exactly the source shard's immutable bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence, insufficient slices, capacity failure and provider errors.
    fn repair_exact(
        &mut self,
        request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
    ) -> Result<ShardReceipt, ContractError>;
}

impl<Router, Coding> PhysicalShardRepair for ProtectedShardRepairer<Router, Coding>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
{
    fn repair_exact(
        &mut self,
        request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
    ) -> Result<ShardReceipt, ContractError> {
        self.repair(request, stripe)
    }
}

/// Runs one repair attempt on a dedicated blocking worker.
///
/// A physical replacement is inert until the effect command commits. If any later response is
/// lost, all provider and metadata mutations retain exact idempotency identities for recovery.
///
/// # Errors
///
/// Rejects contradictory execution input, any physical repair failure, or any claim/effect/
/// completion command that cannot be committed or exactly resolved by metadata consensus.
pub fn execute_shard_repair<Authority, Repairer>(
    authority: &Authority,
    repairer: &mut Repairer,
    execution: &ShardRepairExecution<'_>,
) -> Result<ShardRepairExecutionReceipt, ShardRepairExecutionError>
where
    Authority: RepairMetadataAuthority,
    Repairer: PhysicalShardRepair,
{
    validate_execution(execution)?;
    let replacement_layout_generation = execution
        .source_layout_generation
        .checked_add(1)
        .ok_or(ShardRepairExecutionError::InvalidInput)?;
    authority.commit(
        execution.claim_context,
        &AuthoritativeCommand::ClaimMaintenanceWork(execution.claim),
    )?;
    let replacement_receipt = repairer.repair_exact(execution.physical, execution.stripe)?;
    let effect = authority.commit(
        execution.effect_context,
        &AuthoritativeCommand::CommitShardRepair(CommitShardRepair {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            volume_id: execution.volume_id,
            manifest_id: execution.manifest_id,
            source_layout_generation: execution.source_layout_generation,
            source_receipt: execution.physical.source_receipt,
            replacement_receipt,
        }),
    )?;
    let completion = authority.commit(
        execution.completion_context,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: effect.operation_id,
                effect_revision: effect.committed_revision,
                effect_result_digest: effect.result_digest,
            },
        }),
    )?;
    let transition = ShardRepairTransition {
        effect_operation_id: effect.operation_id,
        source_layout_generation: execution.source_layout_generation,
        replacement_layout_generation,
        source_receipt: execution.physical.source_receipt,
        replacement_receipt,
        committed_revision: effect.committed_revision,
    };
    Ok(ShardRepairExecutionReceipt {
        replacement_receipt,
        effect,
        completion,
        transition,
    })
}

fn validate_execution(
    execution: &ShardRepairExecution<'_>,
) -> Result<(), ShardRepairExecutionError> {
    let claim = execution.claim;
    if execution.source_layout_generation == 0
        || execution.physical.source_receipt.shard.stripe_index
            != execution.stripe.stripe.chunk().chunk_index
        || execution.claim_context.actor_principal_id != execution.effect_context.actor_principal_id
        || execution.claim_context.actor_principal_id
            != execution.completion_context.actor_principal_id
        || execution.claim_context.operation_id == execution.effect_context.operation_id
        || execution.claim_context.operation_id == execution.completion_context.operation_id
        || execution.effect_context.operation_id == execution.completion_context.operation_id
        || execution.claim_context.operation_id == execution.physical.replacement_operation_id
        || execution.effect_context.operation_id == execution.physical.replacement_operation_id
        || execution.completion_context.operation_id == execution.physical.replacement_operation_id
        || execution.claim_context.audit_event_id == execution.effect_context.audit_event_id
        || execution.claim_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.effect_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.claim_context.occurred_at > execution.effect_context.occurred_at
        || execution.effect_context.occurred_at > execution.completion_context.occurred_at
        || execution.physical.observed_at < execution.claim_context.occurred_at
        || execution.physical.deadline > claim.lease_expires_at
        || execution.claim_context.occurred_at >= claim.lease_expires_at
        || execution.effect_context.occurred_at >= claim.lease_expires_at
        || execution.completion_context.occurred_at >= claim.lease_expires_at
    {
        Err(ShardRepairExecutionError::InvalidInput)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_contracts::{BoundedItems, CodingLayout, ShardAcknowledgement, ShardIdentity};
    use meshspan_domain::{
        AuditEventId, ContentManifestId, NodeId, OperationId, PrincipalId, Revision, TargetId,
        UnixMicros, VolumeId, WorkId,
    };
    use meshspan_filesystem::{
        PreparedContentChunk, PreparedProtectedShard, PreparedProtectedStripe,
    };
    use meshspan_metadata::{ApplyDisposition, EntityKind, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn claim_physical_effect_and_completion_keep_exact_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = shard_receipt(20, 21, 0)?;
        let replacement = ShardReceipt {
            operation_id: operation(22)?,
            target_id: target(23)?,
            ..source
        };
        let stripe = committed_stripe(source)?;
        let execution = execution(&stripe, source)?;
        let authority = RecordingAuthority::default();
        let mut repairer = FixedRepairer {
            replacement: Ok(replacement),
        };
        let receipt = execute_shard_repair(&authority, &mut repairer, &execution)?;
        assert_eq!(receipt.replacement_receipt, replacement);
        assert_eq!(receipt.effect.committed_revision, Revision::new(2));
        assert_eq!(receipt.completion.committed_revision, Revision::new(3));
        assert_eq!(receipt.transition.source_receipt, source);
        assert_eq!(receipt.transition.replacement_receipt, replacement);
        let commands = authority.commands.borrow();
        assert!(matches!(
            commands[0],
            AuthoritativeCommand::ClaimMaintenanceWork(_)
        ));
        let AuthoritativeCommand::CommitShardRepair(effect) = commands[1] else {
            return Err("second command was not the repair effect".into());
        };
        assert_eq!(effect.source_receipt, source);
        assert_eq!(effect.replacement_receipt, replacement);
        let AuthoritativeCommand::CompleteMaintenanceWork(completion) = commands[2] else {
            return Err("third command was not completion".into());
        };
        assert_eq!(
            completion.outcome,
            MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: receipt.effect.operation_id,
                effect_revision: receipt.effect.committed_revision,
                effect_result_digest: receipt.effect.result_digest,
            }
        );
        Ok(())
    }

    #[test]
    fn physical_failure_never_submits_an_effect_or_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = shard_receipt(30, 31, 0)?;
        let stripe = committed_stripe(source)?;
        let authority = RecordingAuthority::default();
        let mut repairer = FixedRepairer {
            replacement: Err(ContractError::Unavailable),
        };
        assert!(matches!(
            execute_shard_repair(&authority, &mut repairer, &execution(&stripe, source)?),
            Err(ShardRepairExecutionError::Physical(
                ContractError::Unavailable
            ))
        ));
        assert_eq!(authority.commands.borrow().len(), 1);
        Ok(())
    }

    #[derive(Default)]
    struct RecordingAuthority {
        commands: RefCell<Vec<AuthoritativeCommand>>,
    }

    impl RepairMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
            self.commands.borrow_mut().push(command.clone());
            let revision =
                Revision::new(u64::try_from(self.commands.borrow().len()).unwrap_or(u64::MAX));
            Ok(CommandReceipt {
                disposition: ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                result_digest: [u8::try_from(revision.get()).unwrap_or(u8::MAX); 32],
                committed_revision: revision,
                committed_position: LogPosition {
                    index: revision.get(),
                    term: 1,
                },
                applied_position: LogPosition {
                    index: revision.get(),
                    term: 1,
                },
                entity: EntityReference {
                    kind: EntityKind::MaintenanceWork,
                    id: [7; 16],
                },
            })
        }
    }

    struct FixedRepairer {
        replacement: Result<ShardReceipt, ContractError>,
    }

    impl PhysicalShardRepair for FixedRepairer {
        fn repair_exact(
            &mut self,
            _request: ShardRepairRequest,
            _stripe: &CommittedProtectedStripe,
        ) -> Result<ShardReceipt, ContractError> {
            self.replacement
        }
    }

    fn execution(
        stripe: &CommittedProtectedStripe,
        source: ShardReceipt,
    ) -> Result<ShardRepairExecution<'_>, meshspan_domain::IdentifierError> {
        let worker_node_id = NodeId::from_bytes([8; 16])?;
        Ok(ShardRepairExecution {
            claim_context: context(1, 10)?,
            effect_context: context(2, 20)?,
            completion_context: context(3, 30)?,
            claim: ClaimMaintenanceWork {
                work_id: WorkId::from_bytes([9; 16])?,
                worker_node_id,
                worker_incarnation: 1,
                claim_generation: 1,
                fence: 100,
                lease_expires_at: UnixMicros::new(100),
            },
            volume_id: VolumeId::from_bytes([10; 16])?,
            manifest_id: ContentManifestId::from_bytes([11; 16])?,
            source_layout_generation: 1,
            physical: ShardRepairRequest {
                replacement_operation_id: operation(4)?,
                source_receipt: source,
                replacement_target_id: target(23)?,
                replacement_target_generation: 1,
                authorization_revision: Revision::new(1),
                deadline: UnixMicros::new(100),
                observed_at: UnixMicros::new(10),
            },
            stripe,
        })
    }

    fn committed_stripe(
        receipt: ShardReceipt,
    ) -> Result<CommittedProtectedStripe, Box<dyn std::error::Error>> {
        let request = meshspan_filesystem::ContentPublicationRequest {
            operation_id: operation(40)?,
            volume_id: VolumeId::from_bytes([41; 16])?,
            request_digest: [42; 32],
            manifest_id: ContentManifestId::from_bytes([43; 16])?,
            format_version: 2,
            logical_length: 1,
            authorization_revision: Revision::new(1),
            deadline: UnixMicros::new(100),
            observed_at: UnixMicros::new(1),
        };
        let chunk = PreparedContentChunk {
            chunk_index: 0,
            plaintext_length: 1,
            plaintext_digest: [44; 32],
            ciphertext_length: 17,
            ciphertext_digest: [45; 32],
            storage_layout_digest: [0; 32],
            provider_operation_id: operation(46)?,
        };
        let stripe = PreparedProtectedStripe::from_untrusted(
            request,
            chunk,
            CodingLayout::new(1, 0, 17)?,
            Revision::new(1),
            Revision::new(1),
            meshspan_contracts::VersionedPayload {
                format_version: 1,
                bytes: meshspan_contracts::BoundedBytes::copy_from(&[1], 1)?,
            },
            vec![PreparedProtectedShard {
                shard_index: 0,
                shard_generation: 1,
                provider_operation_id: receipt.operation_id,
                expected_length: receipt.length,
                expected_digest: receipt.digest,
                target_id: receipt.target_id,
                target_generation: receipt.target_generation,
                acknowledgement: ShardAcknowledgement::Required,
                eventual_fallback: ShardAcknowledgement::Required,
            }],
        )?;
        Ok(CommittedProtectedStripe {
            stripe,
            receipts: BoundedItems::new(vec![receipt], 24)?,
        })
    }

    fn context(
        operation_byte: u8,
        at: i64,
    ) -> Result<CommandContext, meshspan_domain::IdentifierError> {
        Ok(CommandContext {
            operation_id: operation(operation_byte)?,
            actor_principal_id: PrincipalId::from_bytes([50; 16])?,
            audit_event_id: AuditEventId::from_bytes([operation_byte + 50; 16])?,
            occurred_at: UnixMicros::new(at),
            expected_revision: None,
        })
    }

    fn shard_receipt(
        operation_byte: u8,
        target_byte: u8,
        shard_index: u16,
    ) -> Result<ShardReceipt, meshspan_domain::IdentifierError> {
        Ok(ShardReceipt {
            operation_id: operation(operation_byte)?,
            shard: ShardIdentity {
                manifest_digest: [60; 32],
                stripe_index: 0,
                shard_index,
                generation: 1,
            },
            length: 17,
            digest: [61; 32],
            target_id: target(target_byte)?,
            target_generation: 1,
        })
    }

    fn operation(value: u8) -> Result<OperationId, meshspan_domain::IdentifierError> {
        OperationId::from_bytes([value; 16])
    }

    fn target(value: u8) -> Result<TargetId, meshspan_domain::IdentifierError> {
        TargetId::from_bytes([value; 16])
    }
}
