// SPDX-License-Identifier: GPL-2.0-only

//! Node-authenticated commands share the authoritative transaction and receipt pipeline.

use crate::{AuthoritativeCommand, CommandContext};
use meshspan_domain::{AuditEventId, NodeId, OperationId, Revision, UnixMicros};

/// Context for a command authenticated as a node rather than a user principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCommandContext {
    /// Stable logical operation identity.
    pub operation_id: OperationId,
    /// Authenticated node responsible for the command.
    pub actor_node_id: NodeId,
    /// Stable audit identity committed with the operation.
    pub audit_event_id: AuditEventId,
    /// Leader-selected instant committed with the command.
    pub occurred_at: UnixMicros,
    /// Optional compare-and-swap revision of authoritative state.
    pub expected_revision: Option<Revision>,
}

/// Truthful actor identity carried by a replicated authoritative entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoritativeCommandContext {
    /// Historical principal command context, with unchanged canonical bytes and digest.
    Principal(CommandContext),
    /// Narrow node-authenticated command context.
    Node(NodeCommandContext),
}

impl AuthoritativeCommandContext {
    /// Stable logical operation identity.
    #[must_use]
    pub fn operation_id(self) -> OperationId {
        match self {
            Self::Principal(c) => c.operation_id,
            Self::Node(c) => c.operation_id,
        }
    }
    /// Stable audit event identity.
    #[must_use]
    pub fn audit_event_id(self) -> AuditEventId {
        match self {
            Self::Principal(c) => c.audit_event_id,
            Self::Node(c) => c.audit_event_id,
        }
    }
    /// Committed leader-selected instant.
    #[must_use]
    pub fn occurred_at(self) -> UnixMicros {
        match self {
            Self::Principal(c) => c.occurred_at,
            Self::Node(c) => c.occurred_at,
        }
    }
    /// Optional state revision fence.
    #[must_use]
    pub fn expected_revision(self) -> Option<Revision> {
        match self {
            Self::Principal(c) => c.expected_revision,
            Self::Node(c) => c.expected_revision,
        }
    }
    /// Canonical digest preserving the historical principal domain.
    #[must_use]
    pub fn request_digest(self, command: &AuthoritativeCommand) -> [u8; 32] {
        match self {
            Self::Principal(c) => command.request_digest(c),
            Self::Node(c) => command.node_request_digest(c),
        }
    }
    pub(crate) fn principal_bytes(self) -> Option<[u8; 16]> {
        match self {
            Self::Principal(c) => Some(c.actor_principal_id.as_bytes()),
            Self::Node(_) => None,
        }
    }
    pub(crate) fn node_bytes(self) -> Option<[u8; 16]> {
        match self {
            Self::Principal(_) => None,
            Self::Node(c) => Some(c.actor_node_id.as_bytes()),
        }
    }
}

/// Exact committed predecessor required to refresh a node presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCapabilityPrior {
    /// Replace an existing current presentation without changing activation history.
    ExistingPresentation {
        /// Current presentation revision.
        revision: Revision,
        /// Current presentation digest.
        capability_digest: [u8; 32],
    },
    /// First presentation after an ordinary activation.
    InitialActivation {
        /// Immutable activation revision.
        revision: Revision,
        /// Immutable activation digest.
        capability_digest: [u8; 32],
    },
    /// Bootstrap or recovery node with no activation or prior presentation.
    InitialAdmittedCertificate {
        /// Exact current certificate revision.
        revision: Revision,
        /// Exact current certificate generation.
        generation: u64,
        /// Exact current certificate fingerprint.
        certificate_fingerprint: [u8; 32],
    },
}

/// Self-report of the validated canonical Hello, ordered by the root consensus authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshNodeCapabilities {
    /// Node whose authenticated presentation is being reported.
    pub node_id: NodeId,
    /// Exact active incarnation.
    pub incarnation: u64,
    /// Exact current certificate generation.
    pub certificate_generation: u64,
    /// Exact current certificate fingerprint.
    pub certificate_fingerprint: [u8; 32],
    /// Digest of the complete validated Hello preimage.
    pub capability_digest: [u8; 32],
    /// Exact authoritative predecessor.
    pub prior: NodeCapabilityPrior,
}

impl RefreshNodeCapabilities {
    pub(crate) fn update_digest(&self, digest: &mut crate::command::CanonicalDigest) {
        digest.unsigned(138);
        digest.identifier(self.node_id.as_bytes());
        digest.unsigned(self.incarnation);
        digest.unsigned(self.certificate_generation);
        digest.bytes(&self.certificate_fingerprint);
        digest.bytes(&self.capability_digest);
        match self.prior {
            NodeCapabilityPrior::ExistingPresentation {
                revision,
                capability_digest,
            } => {
                digest.byte(1);
                digest.unsigned(revision.get());
                digest.bytes(&capability_digest);
            }
            NodeCapabilityPrior::InitialActivation {
                revision,
                capability_digest,
            } => {
                digest.byte(2);
                digest.unsigned(revision.get());
                digest.bytes(&capability_digest);
            }
            NodeCapabilityPrior::InitialAdmittedCertificate {
                revision,
                generation,
                certificate_fingerprint,
            } => {
                digest.byte(3);
                digest.unsigned(revision.get());
                digest.unsigned(generation);
                digest.bytes(&certificate_fingerprint);
            }
        }
    }
}
