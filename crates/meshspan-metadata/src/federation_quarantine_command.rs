// SPDX-License-Identifier: GPL-2.0-only

//! Typed commands for immutable, invisible federated mutation quarantine.

use meshspan_domain::{FederatedMutationAcknowledgement, OperationId, QuarantineId};

use crate::command::CanonicalDigest;

/// Retains one remote-acknowledged mutation which authoritative replay classifies as inadmissible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainFederatedMutationQuarantine {
    /// Stable quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Signed remote acceptance proof, independently reclassified by the repository.
    pub acknowledgement: FederatedMutationAcknowledgement,
}

impl RetainFederatedMutationQuarantine {
    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"retain-federated-mutation-quarantine");
        digest.identifier(self.quarantine_id.as_bytes());
        digest.bytes(&self.acknowledgement.signing_payload());
        digest.bytes(&self.acknowledgement.signature);
    }
}

/// Marks retained quarantine as visible to authorised recovery administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceFederatedMutationQuarantine {
    /// Existing retained quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Exact source operation used as a substitution fence.
    pub source_operation_id: OperationId,
}

impl SurfaceFederatedMutationQuarantine {
    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"surface-federated-mutation-quarantine");
        digest.identifier(self.quarantine_id.as_bytes());
        digest.identifier(self.source_operation_id.as_bytes());
    }
}

/// Authorised terminal recovery choice after quarantine has been surfaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationQuarantineResolution {
    /// Reapply the immutable mutation as a newly authorised operation.
    Restore,
    /// Preserve current namespace state and publish recovered content as a logical copy.
    RestoreAsCopy,
    /// Retain the audit proof but permit payload reclamation.
    Discard,
}

impl FederationQuarantineResolution {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Restore => 1,
            Self::RestoreAsCopy => 2,
            Self::Discard => 3,
        }
    }
}

/// Resolves surfaced quarantine without directly publishing or erasing content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveFederatedMutationQuarantine {
    /// Existing surfaced quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Exact source operation used as a substitution fence.
    pub source_operation_id: OperationId,
    /// Recovery action authorised for later filesystem execution.
    pub resolution: FederationQuarantineResolution,
    /// Bounded human audit explanation.
    pub reason: String,
}

impl ResolveFederatedMutationQuarantine {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"resolve-federated-mutation-quarantine");
        digest.identifier(self.quarantine_id.as_bytes());
        digest.identifier(self.source_operation_id.as_bytes());
        digest.byte(self.resolution.code());
        digest.bytes(self.reason.as_bytes());
    }
}
