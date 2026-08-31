// SPDX-License-Identifier: GPL-2.0-only

//! Types shared by every replaceable capability boundary.

use thiserror::Error;

use meshspan_domain::{OperationId, Revision, UnixMicros};

/// Stable identity of a replaceable capability contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractKind {
    /// Storage-folder or future storage backend.
    StorageProvider,
    /// Public filesystem access protocol adapter.
    AccessConnector,
    /// Public administration API client.
    AdministrationClient,
    /// Authoritative metadata persistence adapter.
    MetadataRepository,
    /// Replicated-log consensus engine.
    ConsensusEngine,
    /// Erasure-coding or replication transform.
    CodingScheme,
    /// Fault-aware placement planner.
    PlacementPolicy,
    /// Typed authentication method handler.
    AuthenticationHandler,
    /// Public-certificate challenge publisher.
    CertificateChallenge,
    /// Redacted metrics, events or notification sink.
    ObservabilitySink,
}

/// Independently versioned semantic contract number.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContractVersion {
    /// Breaking semantic version.
    pub major: u16,
    /// Backward-compatible semantic revision.
    pub minor: u16,
}

impl ContractVersion {
    /// First contract version used by a new boundary.
    pub const V1_0: Self = Self { major: 1, minor: 0 };
}

/// Explicit resource bounds advertised by one implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractLimits {
    /// Largest accepted control message or configuration payload.
    pub maximum_control_bytes: usize,
    /// Largest accepted item count in one bounded operation.
    pub maximum_items: usize,
    /// Largest implementation-owned concurrent work count.
    pub maximum_concurrency: usize,
}

impl ContractLimits {
    /// Validates that every advertised limit permits some useful work.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidInput`] when any limit is zero.
    pub const fn validate(self) -> Result<Self, ContractError> {
        if self.maximum_control_bytes == 0
            || self.maximum_items == 0
            || self.maximum_concurrency == 0
        {
            Err(ContractError::InvalidInput)
        } else {
            Ok(self)
        }
    }
}

/// Static description of one compiled implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImplementationDescriptor {
    /// Stable lowercase implementation identifier.
    pub implementation_id: &'static str,
    /// Capability contract implemented by the component.
    pub contract: ContractKind,
    /// Supported semantic versions in preferred order.
    pub versions: &'static [ContractVersion],
    /// Explicit resource bounds.
    pub limits: ContractLimits,
}

/// Context common to a bounded capability operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestContext {
    /// Exact semantic contract selected for this exchange.
    pub contract_version: ContractVersion,
    /// Stable mutation identity, including reads that resolve a prior mutation.
    pub operation_id: OperationId,
    /// Exclusive authoritative deadline supplied as validated input.
    pub deadline: UnixMicros,
    /// Optional compare-and-swap revision.
    pub expected_revision: Option<Revision>,
}

/// Independently versioned bounded semantic payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedPayload {
    /// Payload format version interpreted only by its owning boundary.
    pub format_version: u32,
    /// Canonical bounded bytes.
    pub bytes: BoundedBytes,
}

/// Owned items whose count was checked before construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedItems<T>(Vec<T>);

impl<T> BoundedItems<T> {
    /// Accepts items only when their count fits the operation-specific maximum.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedItemsError`] when the count is larger than the supplied limit.
    pub fn new(items: Vec<T>, maximum_items: usize) -> Result<Self, BoundedItemsError> {
        if items.len() > maximum_items {
            return Err(BoundedItemsError {
                actual: items.len(),
                maximum: maximum_items,
            });
        }
        Ok(Self(items))
    }

    /// Borrows the validated items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Returns the validated item count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the collection contains no items.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the bound proof and returns the owned items.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

/// Rejection of an item count beyond an operation-specific bound.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("item count {actual} exceeds maximum {maximum}")]
pub struct BoundedItemsError {
    actual: usize,
    maximum: usize,
}

/// Owned bytes whose allocation was checked before construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    /// Takes ownership of bytes only when they fit the operation-specific maximum.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedBytesError`] without copying when the value exceeds the supplied limit.
    pub fn from_vec(value: Vec<u8>, maximum_bytes: usize) -> Result<Self, BoundedBytesError> {
        if value.len() > maximum_bytes {
            return Err(BoundedBytesError {
                actual: value.len(),
                maximum: maximum_bytes,
            });
        }
        Ok(Self(value))
    }

    /// Copies bytes only when they fit the operation-specific maximum.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedBytesError`] when the value is larger than the supplied limit.
    pub fn copy_from(value: &[u8], maximum_bytes: usize) -> Result<Self, BoundedBytesError> {
        if value.len() > maximum_bytes {
            return Err(BoundedBytesError {
                actual: value.len(),
                maximum: maximum_bytes,
            });
        }
        Ok(Self(value.to_vec()))
    }

    /// Borrows the validated bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the checked wrapper without copying its allocation.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Returns the validated byte count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the value contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Rejection of an allocation claim beyond an operation-specific bound.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("byte length {actual} exceeds maximum {maximum}")]
pub struct BoundedBytesError {
    actual: usize,
    maximum: usize,
}

#[cfg(test)]
mod bounded_tests {
    use super::{BoundedBytes, BoundedItems};

    #[test]
    fn bounded_values_reject_only_excessive_allocations() {
        assert!(BoundedBytes::from_vec(vec![1, 2], 1).is_err());
        assert_eq!(
            BoundedBytes::from_vec(vec![1, 2], 2).map(|value| value.len()),
            Ok(2)
        );
        assert!(BoundedBytes::copy_from(&[1, 2], 1).is_err());
        assert_eq!(
            BoundedBytes::copy_from(&[1, 2], 2).map(|value| value.len()),
            Ok(2)
        );
        assert!(BoundedItems::new(vec![1, 2], 1).is_err());
        assert_eq!(
            BoundedItems::new(vec![1, 2], 2).map(|value| value.len()),
            Ok(2)
        );
    }
}

/// Stable failure categories shared across capability implementations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// Input failed structural or semantic validation.
    #[error("capability input is invalid")]
    InvalidInput,
    /// Caller identity or capability is not authorised for the operation.
    #[error("capability is not authorised")]
    Unauthorized,
    /// A revision, epoch, incarnation or capability is stale.
    #[error("capability input is stale")]
    Stale,
    /// An idempotency identity conflicts with different canonical input.
    #[error("operation identity conflicts with an existing request")]
    Conflict,
    /// Requested semantic version is unsupported.
    #[error("contract version is unsupported")]
    UnsupportedVersion,
    /// Exact requested resource does not exist in the selected capability scope.
    #[error("capability resource was not found")]
    NotFound,
    /// Explicit local capacity or admission bounds reject the work.
    #[error("bounded capability capacity is exhausted")]
    ResourceExhausted,
    /// Input or stored bytes fail integrity verification.
    #[error("capability data is corrupt")]
    Corrupt,
    /// The authoritative deadline elapsed before success could be proved.
    #[error("capability deadline elapsed")]
    DeadlineExceeded,
    /// Required authority or resource is temporarily unavailable.
    #[error("capability is unavailable")]
    Unavailable,
    /// An implementation violated its outgoing contract.
    #[error("implementation violated its contract")]
    InternalContract,
}
