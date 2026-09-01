// SPDX-License-Identifier: GPL-2.0-only

//! Protected restart hand-off for interactive first-start mesh joining.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use meshspan_api_contract::{
    JoinMeshSetupRequest, JoinMeshSetupResponse, MAX_JOIN_MESH_SETUP_BYTES,
    decode_join_mesh_setup_request, encode_join_mesh_setup_request,
};
use meshspan_domain::{ClaimBundle, JoinGrantBundle};
use thiserror::Error;

use crate::protected_file::{self, ProtectedFileError, PublishMode};
use crate::{ClaimFile, ClaimFileError, SetupStateSnapshot};

/// Persists one claim-bound join request before asking the daemon lifecycle to restart.
pub struct JoinMeshSetupService {
    claim_output_path: PathBuf,
    pending_join_path: PathBuf,
    setup_state: Arc<SetupStateSnapshot>,
    restart: tokio::sync::mpsc::UnboundedSender<()>,
}

impl JoinMeshSetupService {
    /// Creates the interactive hand-off around protected node-local paths.
    #[must_use]
    pub fn new(
        claim_output_path: PathBuf,
        pending_join_path: PathBuf,
        setup_state: Arc<SetupStateSnapshot>,
        restart: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Self {
        Self {
            claim_output_path,
            pending_join_path,
            setup_state,
            restart,
        }
    }

    /// Accepts an exact retry, persists it owner-only, then requests a graceful internal restart.
    ///
    /// # Errors
    ///
    /// Rejects an invalid local claim, invitation, changed retry or unsafe protected state.
    pub fn accept(
        &mut self,
        request: &JoinMeshSetupRequest,
    ) -> Result<JoinMeshSetupResponse, JoinMeshSetupError> {
        verify_claim(request, &self.claim_output_path)?;
        JoinGrantBundle::parse(&request.join_code)
            .map_err(|_| JoinMeshSetupError::InvitationRejected)?;
        let canonical = encode_join_mesh_setup_request(request)
            .map_err(|_| JoinMeshSetupError::InvalidRequest)?;
        persist_exact_intent(&self.pending_join_path, &canonical)?;
        self.setup_state
            .store(meshspan_api_contract::SetupState::Configuring);
        self.restart
            .send(())
            .map_err(|_| JoinMeshSetupError::RestartUnavailable)?;
        Ok(JoinMeshSetupResponse {
            operation_id: request.operation_id.clone(),
            status_url: format!("/api/latest/operations/{}", request.operation_id.as_str()),
        })
    }
}

/// Reads and validates a previously accepted interactive join intent.
///
/// # Errors
///
/// Rejects unsafe, malformed, excessive or no-longer-claim-bound local state.
pub(crate) fn load_pending_join(
    pending_join_path: &Path,
    claim_output_path: &Path,
) -> Result<Option<JoinMeshSetupRequest>, JoinMeshSetupError> {
    let Some(request) = read_pending_join(pending_join_path)? else {
        return Ok(None);
    };
    verify_claim(&request, claim_output_path)?;
    JoinGrantBundle::parse(&request.join_code)
        .map_err(|_| JoinMeshSetupError::InvalidProtectedState)?;
    Ok(Some(request))
}

fn read_pending_join(
    pending_join_path: &Path,
) -> Result<Option<JoinMeshSetupRequest>, JoinMeshSetupError> {
    let bytes = match protected_file::read_bounded(pending_join_path, 2, MAX_JOIN_MESH_SETUP_BYTES)
    {
        Ok(bytes) => bytes,
        Err(ProtectedFileError::Missing) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let request = decode_join_mesh_setup_request(&bytes)
        .map_err(|_| JoinMeshSetupError::InvalidProtectedState)?;
    Ok(Some(request))
}

/// Removes a completed protected join hand-off durably.
///
/// # Errors
///
/// Fails if the owner-only intent cannot be removed and its parent synchronised.
pub(crate) fn remove_pending_join(path: &Path) -> Result<(), JoinMeshSetupError> {
    if read_pending_join(path)?.is_none() {
        return Ok(());
    }
    protected_file::remove(path).map_err(Into::into)
}

fn verify_claim(
    request: &JoinMeshSetupRequest,
    claim_output_path: &Path,
) -> Result<(), JoinMeshSetupError> {
    let presented = ClaimBundle::parse(request.claim.expose_for_verification())
        .map_err(|_| JoinMeshSetupError::ClaimRejected)?;
    let expected = ClaimFile::read(claim_output_path)?;
    if presented.claim_id() != expected.claim_id()
        || !same_digest(presented.secret_digest(), expected.secret_digest())
    {
        return Err(JoinMeshSetupError::ClaimRejected);
    }
    Ok(())
}

fn persist_exact_intent(path: &Path, canonical: &[u8]) -> Result<(), JoinMeshSetupError> {
    match protected_file::read_bounded(path, 2, MAX_JOIN_MESH_SETUP_BYTES) {
        Ok(existing) if same_bytes(&existing, canonical) => Ok(()),
        Ok(_) => Err(JoinMeshSetupError::Conflict),
        Err(ProtectedFileError::Missing) => {
            protected_file::publish(path, canonical, PublishMode::Create).map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    }
}

fn same_digest(left: [u8; 32], right: [u8; 32]) -> bool {
    same_bytes(&left, &right)
}

fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Closed interactive-join failure categories which never expose secret material.
#[derive(Debug, Error)]
pub enum JoinMeshSetupError {
    /// The request could not be represented by the authoritative contract.
    #[error("join setup request is invalid")]
    InvalidRequest,
    /// The presented first-start claim did not match this daemon.
    #[error("first-start claim was rejected")]
    ClaimRejected,
    /// The presented invitation was not canonical or internally authenticated.
    #[error("join invitation was rejected")]
    InvitationRejected,
    /// The operation was already bound to different exact input.
    #[error("join setup operation conflicts with protected state")]
    Conflict,
    /// A persisted join hand-off was malformed or inconsistent.
    #[error("protected join setup state is invalid")]
    InvalidProtectedState,
    /// The in-process lifecycle receiver was unexpectedly unavailable.
    #[error("daemon restart hand-off is unavailable")]
    RestartUnavailable,
    /// The protected claim file failed closed.
    #[error("first-start claim file failed")]
    ClaimFile(#[from] ClaimFileError),
    /// Owner-only intent persistence failed closed.
    #[error("protected join setup state failed")]
    ProtectedFile,
}

impl From<ProtectedFileError> for JoinMeshSetupError {
    fn from(_: ProtectedFileError) -> Self {
        Self::ProtectedFile
    }
}
