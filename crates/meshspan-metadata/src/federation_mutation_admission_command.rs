// SPDX-License-Identifier: GPL-2.0-only

//! Typed command for authoritative admission of one signed federated mutation.

use meshspan_domain::{FederatedMutationAcknowledgement, NamespaceCommitId};

use crate::command::CanonicalDigest;

/// Records that one exact signed remote mutation was admissible at its consensus position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmitFederatedMutation {
    /// Immutable namespace commit whose mutation digest is signed by the acknowledgement.
    pub namespace_commit_id: NamespaceCommitId,
    /// Accepting-swarm proof independently verified and reclassified by the owner state machine.
    pub acknowledgement: FederatedMutationAcknowledgement,
}

impl AdmitFederatedMutation {
    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"admit-federated-mutation");
        digest.identifier(self.namespace_commit_id.as_bytes());
        digest.bytes(&self.acknowledgement.signing_payload());
        digest.bytes(&self.acknowledgement.signature);
    }
}
