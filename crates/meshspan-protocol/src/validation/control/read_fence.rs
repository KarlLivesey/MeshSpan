// SPDX-License-Identifier: GPL-2.0-only

//! Structural bounds only; the service owns fresh-quorum and caller admission checks.

use crate::WireContractError;
use crate::v1::{MetadataReadFenceResult, metadata_read_fence_result::Outcome};
use crate::validation::{valid_digest, valid_identifier, validate_wire_error};

pub(super) fn response(value: &MetadataReadFenceResult) -> Result<(), WireContractError> {
    valid_digest(&value.nonce)?;
    match value
        .outcome
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?
    {
        Outcome::Rejection(error) => validate_wire_error(error),
        Outcome::Fence(fence) => {
            valid_identifier(&fence.partition_id)?;
            valid_identifier(&fence.leader_node_id)?;
            valid_digest(&fence.plan_digest)?;
            valid_digest(&fence.applied_digest)?;
            let applied = fence
                .applied
                .as_ref()
                .ok_or(WireContractError::InvalidMessage)?;
            if fence.term == 0
                || fence.membership_epoch == 0
                || applied.index == 0
                || applied.term != fence.term
            {
                return Err(WireContractError::InvalidMessage);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{LogPosition, MetadataReadFence};

    #[test]
    fn read_fence_rejects_missing_or_incoherent_confirmation() {
        let fence = MetadataReadFence {
            partition_id: vec![1; 16],
            leader_node_id: vec![2; 16],
            term: 4,
            membership_epoch: 2,
            plan_digest: vec![3; 32],
            applied: Some(LogPosition { term: 4, index: 7 }),
            applied_digest: vec![4; 32],
            revision: 6,
        };
        let result = |fence| MetadataReadFenceResult {
            nonce: vec![5; 32],
            outcome: Some(Outcome::Fence(fence)),
        };
        assert!(response(&result(fence.clone())).is_ok());
        for field in 0..9 {
            let mut changed = fence.clone();
            match field {
                0 => changed.partition_id.clear(),
                1 => changed.leader_node_id.clear(),
                2 => changed.term = 0,
                3 => changed.membership_epoch = 0,
                4 => changed.plan_digest.clear(),
                5 => changed.applied = None,
                6 => changed.applied = Some(LogPosition { term: 3, index: 7 }),
                7 => changed.applied_digest.clear(),
                _ => changed.applied = Some(LogPosition { term: 4, index: 0 }),
            }
            assert!(response(&result(changed)).is_err());
        }
        assert!(
            response(&MetadataReadFenceResult {
                nonce: vec![5; 32],
                outcome: None
            })
            .is_err()
        );
        let mut missing_nonce = result(fence);
        missing_nonce.nonce.clear();
        assert!(response(&missing_nonce).is_err());
    }
}
