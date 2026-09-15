// SPDX-License-Identifier: GPL-2.0-only

//! Retain one authoritative physical selection before any provider admission.

use meshspan_contracts::{ContractError, ContractVersion, RequestContext, ShardPutIntent};
use meshspan_domain::{Revision, UnixMicros};
use meshspan_filesystem::ShardRepairRequest;
use meshspan_metadata::{AuthoritativeCommand, PlanShardRepair};

use super::{RepairAttempt, RepairSource, ShardRepairExecution, StorageTargetRuntime};
use crate::{MaintenanceMetadataAuthority, NativeStorageTarget, OperatingSystemRandom};

impl RepairAttempt {
    pub(super) fn plan(
        &self,
        runtime: &StorageTargetRuntime,
        source: &RepairSource,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<Option<PlanShardRepair>, ()> {
        let retained = runtime
            .maintenance_authority
            .reader()
            .shard_repair_attempt(self.claim.work_id)
            .map_err(|_| ())?;
        let intent = if let Some(retained) = retained {
            if retained.plan.source_receipt != source.candidate.source_receipt
                || retained.plan.source_layout_generation
                    != source.candidate.source_layout_generation
            {
                return Err(());
            }
            retained.plan.intent
        } else {
            let Some(intent) = self.select_intent(runtime, source, targets, now)? else {
                return Ok(None);
            };
            intent
        };
        let context = super::random_maintenance_context(
            &mut OperatingSystemRandom,
            self.claim_context.actor_principal_id,
            self.claim_context.occurred_at,
        )?;
        let plan = PlanShardRepair {
            claim: self.claim,
            source_layout_generation: source.candidate.source_layout_generation,
            source_receipt: source.candidate.source_receipt,
            intent,
            effect_context: super::random_maintenance_context(
                &mut OperatingSystemRandom,
                context.actor_principal_id,
                context.occurred_at,
            )?,
            completion_context: self.completion_context,
        };
        // An unknown result leaves the claim fenced. No provider operation starts until this
        // immutable selection is known committed; the next owner loads it before planning.
        runtime
            .maintenance_authority
            .commit(context, &AuthoritativeCommand::PlanShardRepair(plan))
            .map_err(|_| ())?;
        Ok(Some(plan))
    }

    fn select_intent(
        &self,
        runtime: &StorageTargetRuntime,
        source: &RepairSource,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<Option<ShardPutIntent>, ()> {
        let configuration = runtime
            .native_filesystem
            .maintenance_protection_configuration(targets, source.candidate.volume_id, now)
            .map_err(|_| ())?;
        let revision = runtime
            .maintenance_authority
            .reader()
            .current_revision()
            .map_err(|_| ())?;
        let current_targets = super::super::current_stripe_targets(&source.stripe)?;
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: super::super::random_operation_id(&mut OperatingSystemRandom)?,
            deadline: self.claim.lease_expires_at,
            expected_revision: Some(revision),
        };
        let placement = match configuration.plan_repair(
            &meshspan_placement::FaultAwarePlacement::new(),
            context,
            source.stripe.stripe.coding_layout(),
            source.candidate.source_receipt.shard.shard_index,
            &current_targets,
        ) {
            Ok(placement) => placement,
            Err(ContractError::ResourceExhausted) => return Ok(None),
            Err(_) => return Err(()),
        };
        if placement.topology_revision != configuration.topology_revision()
            || placement.capacity_revision != configuration.capacity_revision()
        {
            return Err(());
        }
        Ok(Some(
            ShardRepairRequest {
                replacement_operation_id: context.operation_id,
                source_receipt: source.candidate.source_receipt,
                replacement_target_id: placement.replacement_target_id,
                replacement_target_generation: placement.replacement_target_generation,
                replacement_shard_generation: source
                    .candidate
                    .source_receipt
                    .shard
                    .generation
                    .checked_add(1)
                    .ok_or(())?,
                authorization_revision: revision,
                deadline: context.deadline,
                observed_at: now,
            }
            .physical_intent(),
        ))
    }

    pub(super) fn execution<'a>(
        &self,
        source: &'a RepairSource,
        plan: &PlanShardRepair,
        authorization_revision: Revision,
    ) -> ShardRepairExecution<'a> {
        ShardRepairExecution {
            claim_context: self.claim_context,
            effect_context: plan.effect_context,
            completion_context: plan.completion_context,
            claim: self.claim,
            volume_id: source.candidate.volume_id,
            manifest_id: source.candidate.manifest_id,
            source_layout_generation: plan.source_layout_generation,
            intent: plan.intent,
            physical: ShardRepairRequest {
                replacement_operation_id: plan.intent.context.operation_id,
                source_receipt: plan.source_receipt,
                replacement_target_id: plan.intent.target_id,
                replacement_target_generation: plan.intent.target_generation,
                replacement_shard_generation: plan.intent.shard.generation,
                authorization_revision,
                deadline: self.claim.lease_expires_at,
                observed_at: self.claim_context.occurred_at,
            },
            stripe: &source.stripe,
        }
    }
}
