// SPDX-License-Identifier: GPL-2.0-only

//! Streaming capability contract for replaceable encrypted metadata-backup destinations.

use std::io::{Read, Write};

use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};

use crate::{ContractError, ContractVersion, ImplementationDescriptor, RequestContext};

/// Maximum UTF-8 bytes in a provider-owned opaque object reference.
pub const MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES: usize = 2_048;

/// Exact immutable encrypted object expected at one destination generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupObjectIdentity {
    /// Stable metadata-backup generation.
    pub backup_id: BackupId,
    /// Configured destination selected by authority.
    pub destination_id: BackupDestinationId,
    /// Exact provider configuration generation.
    pub provider_generation: u64,
    /// Exact complete encrypted-container length.
    pub byte_length: u64,
    /// Digest of the complete encrypted container.
    pub digest: [u8; 32],
}

impl BackupObjectIdentity {
    fn validate(self) -> Result<(), ContractError> {
        if self.provider_generation == 0 || self.byte_length == 0 || self.digest == [0; 32] {
            Err(ContractError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

/// Bounded provider-owned locator which is never interpreted as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupObjectReference(String);

impl BackupObjectReference {
    /// Validates a non-empty bounded UTF-8 provider reference.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive or control-character-bearing values.
    pub fn new(value: String) -> Result<Self, ContractError> {
        if value.is_empty()
            || value.len() > MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES
            || value.chars().any(char::is_control)
        {
            Err(ContractError::InvalidInput)
        } else {
            Ok(Self(value))
        }
    }

    /// Borrows the opaque reference for transport or persistence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the checked wrapper without copying its allocation.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Request to persist one exact encrypted container from a streaming source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupStoreRequest {
    /// Version, operation, deadline and optional authority revision.
    pub context: RequestContext,
    /// Exact immutable object being stored.
    pub object: BackupObjectIdentity,
}

/// Request to read one exact previously stored encrypted container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReadRequest {
    /// Version, operation, deadline and optional authority revision.
    pub context: RequestContext,
    /// Expected immutable object identity.
    pub object: BackupObjectIdentity,
    /// Opaque reference returned by the original durable write.
    pub object_reference: BackupObjectReference,
}

/// Request to independently read and verify a complete stored container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerifyRequest {
    /// Version, operation, deadline and optional authority revision.
    pub context: RequestContext,
    /// Expected immutable object identity.
    pub object: BackupObjectIdentity,
    /// Opaque reference returned by the original durable write.
    pub object_reference: BackupObjectReference,
}

/// Authority to remove one exact retired object, never merely a path or provider location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupDeleteRequest {
    /// Version, operation, deadline and exact catalogue revision.
    pub context: RequestContext,
    /// Exact immutable object identity authorised for removal.
    pub object: BackupObjectIdentity,
    /// Opaque reference returned by the original durable write.
    pub object_reference: BackupObjectReference,
    /// Positive authority revision which made this exact copy unreachable and retired.
    pub retirement_revision: Revision,
}

/// Durable provider evidence for one exact encrypted backup object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupObjectReceipt {
    /// Idempotency identity of the store or verify operation.
    pub operation_id: OperationId,
    /// Exact object stored and independently digested by the provider.
    pub object: BackupObjectIdentity,
    /// Opaque bounded provider locator.
    pub object_reference: BackupObjectReference,
}

/// Exact streamed-read result, independently counted and digested by the provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupReadReceipt {
    /// Idempotency identity of the read operation.
    pub operation_id: OperationId,
    /// Exact complete byte length written to the caller's sink.
    pub byte_length: u64,
    /// Digest independently calculated while streaming to the caller.
    pub digest: [u8; 32],
}

/// Durable removal evidence for one exact retired provider object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupDeleteReceipt {
    /// Idempotency identity of the removal operation.
    pub operation_id: OperationId,
    /// Exact object removed.
    pub object: BackupObjectIdentity,
    /// Authority revision under which removal was admitted.
    pub retirement_revision: Revision,
}

/// Replaceable destination for encrypted metadata-backup objects.
pub trait BackupProvider {
    /// Describes the compiled provider implementation and explicit bounds.
    fn describe(&self) -> ImplementationDescriptor;

    /// Atomically persists exactly the declared stream or publishes no object.
    ///
    /// # Errors
    ///
    /// Rejects malformed/stale input, changed replay, short/long bytes, digest mismatch or IO
    /// failure without returning durable evidence.
    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError>;

    /// Streams one exact object after revalidating its identity and provider reference.
    ///
    /// # Errors
    ///
    /// Rejects malformed/stale input, absence, corruption, deadline or sink failure without
    /// claiming a complete read.
    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError>;

    /// Independently reads, counts and hashes one complete stored object without returning bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed/stale input, absence, corruption, deadline or IO failure.
    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError>;

    /// Removes only one exact object retired by a positive authoritative revision.
    ///
    /// # Errors
    ///
    /// Rejects location-only, stale, mismatched, live or otherwise unauthorised removal.
    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError>;
}

/// Validates the common store-request shape before provider IO.
///
/// # Errors
///
/// Rejects unsupported versions, elapsed deadlines, missing authority revision or malformed
/// object identity.
pub fn validate_backup_store_request(
    request: BackupStoreRequest,
    observed_at: UnixMicros,
) -> Result<(), ContractError> {
    validate_context(request.context, observed_at)?;
    request.object.validate()
}

/// Validates the common read-request shape before provider IO.
///
/// # Errors
///
/// Rejects unsupported versions, elapsed deadlines, missing authority revision or malformed
/// object identity.
pub fn validate_backup_read_request(
    request: &BackupReadRequest,
    observed_at: UnixMicros,
) -> Result<(), ContractError> {
    validate_context(request.context, observed_at)?;
    request.object.validate()
}

/// Validates the common verification-request shape before provider IO.
///
/// # Errors
///
/// Rejects unsupported versions, elapsed deadlines, missing authority revision or malformed
/// object identity.
pub fn validate_backup_verify_request(
    request: &BackupVerifyRequest,
    observed_at: UnixMicros,
) -> Result<(), ContractError> {
    validate_context(request.context, observed_at)?;
    request.object.validate()
}

/// Validates exact revision-bound deletion authority before provider IO.
///
/// # Errors
///
/// Rejects unsupported versions, elapsed deadlines, a missing/mismatched authority revision or
/// malformed object identity.
pub fn validate_backup_delete_request(
    request: &BackupDeleteRequest,
    observed_at: UnixMicros,
) -> Result<(), ContractError> {
    validate_context(request.context, observed_at)?;
    request.object.validate()?;
    if request.retirement_revision.get() == 0
        || request.context.expected_revision != Some(request.retirement_revision)
    {
        Err(ContractError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_context(context: RequestContext, observed_at: UnixMicros) -> Result<(), ContractError> {
    if context.contract_version != ContractVersion::V1_0 {
        return Err(ContractError::UnsupportedVersion);
    }
    if context.deadline <= observed_at {
        return Err(ContractError::DeadlineExceeded);
    }
    if context
        .expected_revision
        .is_none_or(|revision| revision.get() == 0)
    {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};

    use super::{
        BackupDeleteRequest, BackupObjectIdentity, BackupObjectReference, BackupStoreRequest,
        MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, validate_backup_delete_request,
        validate_backup_store_request,
    };
    use crate::{ContractError, ContractVersion, RequestContext};

    #[test]
    fn object_reference_rejects_blank_excessive_and_control_values()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            BackupObjectReference::new(String::new()),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            BackupObjectReference::new("a".repeat(MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES + 1)),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            BackupObjectReference::new("object\nreference".to_owned()),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            BackupObjectReference::new("backup/0001".to_owned())?.as_str(),
            "backup/0001"
        );
        Ok(())
    }

    #[test]
    fn operations_require_exact_live_versioned_authority() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = BackupStoreRequest {
            context: context(Some(9))?,
            object: identity()?,
        };
        assert_eq!(
            validate_backup_store_request(request, UnixMicros::new(19)),
            Ok(())
        );
        let mut missing_revision = request;
        missing_revision.context.expected_revision = None;
        assert_eq!(
            validate_backup_store_request(missing_revision, UnixMicros::new(19)),
            Err(ContractError::InvalidInput)
        );
        let mut zero_revision = request;
        zero_revision.context.expected_revision = Some(Revision::new(0));
        assert_eq!(
            validate_backup_store_request(zero_revision, UnixMicros::new(19)),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            validate_backup_store_request(request, UnixMicros::new(20)),
            Err(ContractError::DeadlineExceeded)
        );
        Ok(())
    }

    #[test]
    fn deletion_requires_the_exact_positive_retirement_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = BackupDeleteRequest {
            context: context(Some(9))?,
            object: identity()?,
            object_reference: BackupObjectReference::new("backup/0001".to_owned())?,
            retirement_revision: Revision::new(9),
        };
        assert_eq!(
            validate_backup_delete_request(&request, UnixMicros::new(19)),
            Ok(())
        );
        request.retirement_revision = Revision::new(8);
        assert_eq!(
            validate_backup_delete_request(&request, UnixMicros::new(19)),
            Err(ContractError::InvalidInput)
        );
        request.retirement_revision = Revision::new(0);
        request.context.expected_revision = Some(Revision::new(0));
        assert_eq!(
            validate_backup_delete_request(&request, UnixMicros::new(19)),
            Err(ContractError::InvalidInput)
        );
        Ok(())
    }

    fn identity() -> Result<BackupObjectIdentity, meshspan_domain::IdentifierError> {
        Ok(BackupObjectIdentity {
            backup_id: BackupId::from_bytes([1; 16])?,
            destination_id: BackupDestinationId::from_bytes([2; 16])?,
            provider_generation: 3,
            byte_length: 4,
            digest: [5; 32],
        })
    }

    fn context(
        expected_revision: Option<u64>,
    ) -> Result<RequestContext, meshspan_domain::IdentifierError> {
        Ok(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([6; 16])?,
            deadline: UnixMicros::new(20),
            expected_revision: expected_revision.map(Revision::new),
        })
    }
}
