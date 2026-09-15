// SPDX-License-Identifier: GPL-2.0-only

//! Resume an immutable repair selection while refreshing only read/write authority and time.

use meshspan_contracts::{
    CodingScheme, ContractError, PutShardRequest, RepairPutAdmission, ReservationClass,
    ShardPutIntent, ShardReceipt, ShardWritePermit, write_permit_mac,
};
use meshspan_domain::{Clock, UnixMicros};

use super::{
    CommittedProtectedStripe, ContentShardRouter, ProtectedShardRepairer, ShardRepairRequest,
    repair_context, validate_replacement_receipt, validate_request, verify_replacement_bytes,
};

impl ShardRepairRequest {
    /// Selects the original physical intent before any provider IO, without claiming admission.
    #[must_use]
    pub const fn physical_intent(self) -> ShardPutIntent {
        ShardPutIntent {
            context: repair_context(self),
            target_id: self.replacement_target_id,
            target_generation: self.replacement_target_generation,
            reservation_class: ReservationClass::Repair,
            maximum_bytes: self.source_receipt.length,
            shard: self.source_receipt.shard,
            expected_length: self.source_receipt.length,
            expected_digest: self.source_receipt.digest,
        }
    }
}

impl<Router: ContentShardRouter, Coding: CodingScheme> ProtectedShardRepairer<Router, Coding> {
    /// Recovers an existing exact write before reconstructing, then resumes only that intent.
    /// Admission completes before input reads, so remote network workers are not held idle.
    /// # Errors
    /// Rejects changed selection, malformed evidence, expired fresh authority, unavailable inputs
    /// and mismatched provider evidence. Lost replies do not authorise a new physical attempt.
    pub fn resume_repair(
        &mut self,
        intent: ShardPutIntent,
        mut request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
        clock: &dyn Clock,
    ) -> Result<ShardReceipt, ContractError> {
        validate_intent(intent, request)?;
        request.observed_at = live_time(request, clock)?;
        validate_request(request, stripe)?;
        let authority = self.repair_authority(request);
        let original =
            match self
                .router
                .prepare_repair_put(intent, authority, request.observed_at)?
            {
                RepairPutAdmission::Verified(receipt) => {
                    validate_replacement_receipt(request, receipt)?;
                    return Ok(receipt);
                }
                RepairPutAdmission::Prepared(original) => original,
            };
        if original.intent() != intent {
            return Err(ContractError::InternalContract);
        }
        let bytes = self.reconstruct_replacement(request, stripe)?;
        verify_replacement_bytes(request.source_receipt, &bytes)?;
        let now = live_time(request, clock)?;
        let receipt = self.router.finish_repair_put(
            PutShardRequest {
                context: original.context,
                reservation: original.reservation,
                shard: original.shard,
                expected_length: original.expected_length,
                expected_digest: original.expected_digest,
                bytes,
            },
            authority,
            now,
        )?;
        validate_replacement_receipt(request, receipt)?;
        Ok(receipt)
    }

    fn repair_authority(&self, request: ShardRepairRequest) -> ShardWritePermit {
        let mut authority = ShardWritePermit {
            operation_id: request.replacement_operation_id,
            mesh_id: self.mesh_id,
            target_id: request.replacement_target_id,
            target_generation: request.replacement_target_generation,
            shard: request.source_receipt.shard,
            reservation_class: ReservationClass::Repair,
            maximum_bytes: request.source_receipt.length,
            authorization_revision: request.authorization_revision,
            expires_at: request.deadline,
            permit_digest: [0; 32],
        };
        authority.permit_digest = write_permit_mac(&self.read_permit_key, authority);
        authority
    }
}

fn validate_intent(
    intent: ShardPutIntent,
    request: ShardRepairRequest,
) -> Result<(), ContractError> {
    intent.validate()?;
    let current = request.physical_intent();
    if intent.context.operation_id != current.context.operation_id
        || intent.target_id != current.target_id
        || intent.target_generation != current.target_generation
        || intent.reservation_class != current.reservation_class
        || intent.maximum_bytes != current.maximum_bytes
        || intent.shard != current.shard
        || intent.expected_length != current.expected_length
        || intent.expected_digest != current.expected_digest
    {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

fn live_time(request: ShardRepairRequest, clock: &dyn Clock) -> Result<UnixMicros, ContractError> {
    let now = clock.now();
    if now < request.observed_at || now.get() < 0 || now >= request.deadline {
        Err(ContractError::DeadlineExceeded)
    } else {
        Ok(now)
    }
}
