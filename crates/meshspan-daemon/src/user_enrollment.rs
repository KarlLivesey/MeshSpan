// SPDX-License-Identifier: GPL-2.0-only

//! Short-lived manager consent for an independent user's first primary credential.

mod api;
mod authority;
mod fresh_read;
pub(crate) use fresh_read::refresh as refresh_enrollment_read;
mod protected;
mod redemption;
mod service;

use crate::BrowserSessionAuthority;
use meshspan_domain::{OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, PrincipalRecord, UserEnrollmentRecord,
};
use thiserror::Error;

pub use service::UserEnrollmentService;

/// Replicated authority required by first-credential enrollment.
pub trait UserEnrollmentAuthority: BrowserSessionAuthority {
    /// Establishes a fresh authoritative read and samples time after synchronization.
    /// The returned instant must not precede the request's observed time.
    /// # Errors
    /// Rejects unavailable quorum, stale replica state and invalid fence evidence.
    fn refresh_enrollment_authority(
        &self,
        requested_at: UnixMicros,
    ) -> Result<UnixMicros, UserEnrollmentError>;
    /// Reads the exact invitation. Errors fail closed without exposing capability material.
    /// # Errors
    /// Returns an unavailable or invalid authoritative read.
    fn enrollment(
        &self,
        operation: OperationId,
    ) -> Result<Option<UserEnrollmentRecord>, UserEnrollmentError>;
    /// Reads current recipient state. Errors never imply an active recipient.
    /// # Errors
    /// Returns an unavailable or invalid authoritative read.
    fn enrollment_principal(
        &self,
        principal: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, UserEnrollmentError>;
    /// Checks the original issuer's current manager authority.
    /// # Errors
    /// Returns an unavailable or invalid authoritative read.
    fn enrollment_manager(
        &self,
        principal: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, UserEnrollmentError>;
    /// Resolves the original command time for exact replay.
    /// # Errors
    /// Returns an unavailable or invalid authoritative read.
    fn enrollment_operation_time(
        &self,
        operation: OperationId,
    ) -> Result<Option<UnixMicros>, UserEnrollmentError>;
    /// Commits or resolves one exact typed command through current consensus authority.
    /// # Errors
    /// Rejects unavailable authority, invalid consent and changed operation reuse.
    fn commit_enrollment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, UserEnrollmentError>;
}

/// Closed, secret-free enrollment failure.
#[derive(Debug, Error)]
pub enum UserEnrollmentError {
    /// Malformed bounded public input.
    #[error("user enrollment request is invalid")]
    InvalidRequest,
    /// Capability or current manager/recipient authority is insufficient.
    #[error("user enrollment was rejected")]
    Rejected,
    /// Operation identity is already bound to different input.
    #[error("user enrollment conflicts with committed state")]
    Conflict,
    /// No durable outcome can currently be established.
    #[error("user enrollment authority is unavailable")]
    Unavailable,
    /// Persisted evidence or cryptographic material failed validation.
    #[error("user enrollment failed closed")]
    Failed,
}

pub use protected::{ProtectedUserEnrollmentController, UserEnrollmentController};

pub use api::{UserEnrollmentApiError, user_enrollment_api_router};

#[cfg(test)]
mod tests;
