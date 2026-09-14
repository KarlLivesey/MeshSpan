// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, ContractVersion, RequestContext,
};
use meshspan_domain::{OperationId, RandomSource, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, BackupReclamationCandidate, RecordBackupReclamation,
};
use sha2::{Digest, Sha256};

use super::{
    BackupRetentionAuthority, BackupRetentionError, BackupRetentionInput, context, validate_receipt,
};
use crate::MetadataBackupProviderResolver;

pub(super) fn reclaim(
    authority: &impl BackupRetentionAuthority,
    resolver: &mut impl MetadataBackupProviderResolver,
    random: &mut impl RandomSource,
    input: &BackupRetentionInput,
    copy: &BackupReclamationCandidate,
) -> Result<(), BackupRetentionError> {
    if copy.retirement_revision.get() == 0 {
        return Err(BackupRetentionError::Invalid);
    }
    let destination = authority
        .destination(copy.object.destination_id)?
        .ok_or(BackupRetentionError::Invalid)?;
    if destination.destination_id != copy.object.destination_id
        || destination.binding.provider_generation() != copy.object.provider_generation
    {
        return Err(BackupRetentionError::Invalid);
    }
    let request = delete_request(copy, input)?;
    let expected = BackupDeleteReceipt {
        operation_id: request.context.operation_id,
        object: request.object,
        retirement_revision: request.retirement_revision,
    };
    let mut provider = resolver.resolve(&destination)?;
    if provider.delete_exact(&request, input.now)? != expected {
        return Err(BackupRetentionError::Invalid);
    }
    let context = context(random, input)?;
    let command = AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation {
        receipt: expected,
    });
    let receipt = authority.commit(context, &command)?;
    validate_receipt(receipt, context, &command, copy.object.backup_id)
}

fn delete_request(
    copy: &BackupReclamationCandidate,
    input: &BackupRetentionInput,
) -> Result<BackupDeleteRequest, BackupRetentionError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metadata-backup.delete.v1\0");
    digest.update(copy.object.backup_id.as_bytes());
    digest.update(copy.object.destination_id.as_bytes());
    digest.update(copy.retirement_revision.get().to_be_bytes());
    let hash = digest.finalize();
    let mut operation = [0; 16];
    operation.copy_from_slice(&hash[..16]);
    let timeout = i64::try_from(input.limits.provider_timeout.get())
        .map_err(|_| BackupRetentionError::Invalid)?;
    let deadline = input
        .now
        .get()
        .checked_add(timeout)
        .ok_or(BackupRetentionError::Invalid)?;
    Ok(BackupDeleteRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes(uuid_v8(operation))?,
            deadline: UnixMicros::new(deadline),
            expected_revision: Some(copy.retirement_revision),
        },
        object: copy.object,
        object_reference: copy.object_reference.clone(),
        retirement_revision: copy.retirement_revision,
    })
}
