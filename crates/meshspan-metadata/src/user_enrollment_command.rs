// SPDX-License-Identifier: GPL-2.0-only

//! Atomic consent, cancellation and first-credential redemption commands.

use crate::CreateAuthenticationMethod;
use crate::command::CanonicalDigest;
use meshspan_domain::{OperationId, PrincipalId, Revision, UnixMicros};

/// Manager consent for one active user's first primary authentication method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueUserEnrollment {
    /// Exact recipient, never inferred from the redeeming connection.
    pub principal_id: PrincipalId,
    /// Principal revision to which the manager consented.
    pub expected_principal_revision: Revision,
    /// Digest of the distinct high-entropy enrollment capability.
    pub token_digest: [u8; 32],
    /// Exclusive capability lifetime, at most one day after issuance.
    pub expires_at: UnixMicros,
}

/// Manager cancellation of invitation use and secret-bearing replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeUserEnrollment {
    /// The operation which issued the invitation.
    pub enrollment_operation_id: OperationId,
    /// Exact current invitation revision observed by the manager.
    pub expected_revision: Revision,
}

/// One-use capability proof bound atomically to an ordinary primary method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemUserEnrollment {
    /// The operation whose committed consent permits this credential.
    pub enrollment_operation_id: OperationId,
    /// Digest verified at the recipient-facing capability boundary.
    pub token_digest: [u8; 32],
    /// Ordinary typed primary credential; no invitation becomes a login method.
    pub method: CreateAuthenticationMethod,
}

impl IssueUserEnrollment {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"issue-user-enrollment-v1");
        digest.identifier(self.principal_id.as_bytes());
        digest.unsigned(self.expected_principal_revision.get());
        digest.bytes(&self.token_digest);
        digest.signed(self.expires_at.get());
    }
}
impl RevokeUserEnrollment {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"revoke-user-enrollment-v1");
        digest.identifier(self.enrollment_operation_id.as_bytes());
        digest.unsigned(self.expected_revision.get());
    }
}
