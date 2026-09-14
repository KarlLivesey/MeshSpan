// SPDX-License-Identifier: GPL-2.0-only

//! Recover exact provider evidence from durable intents, then commit retirement before deletion.

use super::{
    BackupRetentionAuthority, BackupRetentionError, BackupRetentionInput,
    MetadataBackupRetentionWorker, context, validate_receipt,
};
use crate::MetadataBackupProviderResolver;
use meshspan_contracts::{BackupLookupRequest, ContractVersion, RequestContext};
use meshspan_domain::{RandomSource, UnixMicros};
use meshspan_metadata::{
    AbandonedBackupPublication, AuthoritativeCommand, PageLimit, RetireAbandonedBackupCopy,
};

pub(super) struct DiscoveryOutcome {
    pub retired: usize,
    pub failed: usize,
}

impl MetadataBackupRetentionWorker {
    pub(super) fn discover(
        &mut self,
        authority: &impl BackupRetentionAuthority,
        resolver: &mut impl MetadataBackupProviderResolver,
        random: &mut impl RandomSource,
        input: &BackupRetentionInput,
        limit: PageLimit,
    ) -> Result<DiscoveryOutcome, BackupRetentionError> {
        let page = authority.unadmitted(self.discovery_cursor, limit)?;
        self.discovery_cursor = page.next;
        let mut result = DiscoveryOutcome {
            retired: 0,
            failed: 0,
        };
        for candidate in page.items {
            match retire_discovered(authority, resolver, random, input, candidate) {
                Ok(()) => result.retired += 1,
                Err(_) => result.failed += 1,
            }
        }
        Ok(result)
    }
}

fn retire_discovered(
    authority: &impl BackupRetentionAuthority,
    resolver: &mut impl MetadataBackupProviderResolver,
    random: &mut impl RandomSource,
    input: &BackupRetentionInput,
    candidate: AbandonedBackupPublication,
) -> Result<(), BackupRetentionError> {
    let object = candidate.intent.binding.object;
    let destination = authority
        .destination(object.destination_id)?
        .ok_or(BackupRetentionError::Invalid)?;
    if destination.destination_id != object.destination_id
        || destination.binding.provider_generation() != object.provider_generation
    {
        return Err(BackupRetentionError::Invalid);
    }
    let lookup_context = context(random, input)?;
    let deadline = input
        .now
        .get()
        .checked_add(
            i64::try_from(input.limits.provider_timeout.get())
                .map_err(|_| BackupRetentionError::Invalid)?,
        )
        .ok_or(BackupRetentionError::Invalid)?;
    let request = BackupLookupRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: lookup_context.operation_id,
            deadline: UnixMicros::new(deadline),
            expected_revision: Some(candidate.intent.revision),
        },
        object,
    };
    let provider = resolver.resolve(&destination)?;
    let receipt = provider.lookup_exact(&request, input.now)?;
    if receipt.operation_id != request.context.operation_id || receipt.object != object {
        return Err(BackupRetentionError::Invalid);
    }
    let context = context(random, input)?;
    let command = AuthoritativeCommand::RetireAbandonedBackupCopy(RetireAbandonedBackupCopy {
        expected_run_revision: candidate.run_revision,
        receipt,
    });
    let committed = authority.commit(context, &command)?;
    validate_receipt(committed, context, &command, object.backup_id)
}
