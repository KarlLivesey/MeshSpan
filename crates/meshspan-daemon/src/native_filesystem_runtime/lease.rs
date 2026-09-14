// SPDX-License-Identifier: GPL-2.0-only

//! Timestamp admission under native filesystem ownership.

use super::NativeFilesystemRuntimeError;
use meshspan_domain::{AuthenticationService, UnixMicros};
use meshspan_filesystem::{AdapterLeaseRequest, FilesystemAccessContext};
use std::sync::MutexGuard;

pub(super) fn renewal_at_admission<State>(
    _ownership: &MutexGuard<'_, State>,
    mut context: FilesystemAccessContext,
    mut request: AdapterLeaseRequest,
    sample_clock: impl FnOnce() -> Option<UnixMicros>,
) -> Result<(FilesystemAccessContext, AdapterLeaseRequest), NativeFilesystemRuntimeError> {
    match context.authentication_service {
        AuthenticationService::Https | AuthenticationService::HeadlessApi => {
            return Ok((context, request));
        }
        AuthenticationService::Smb => {}
    }
    if request.takeover {
        return Ok((context, request));
    }
    // Ordinary SMB renewal is one attempt: the connector fences uncertainty and never retries
    // altered bytes. Its queued instant is not the executed canonical instant. Sample only
    // after runtime ownership, retaining both operation identity and the intended deadline.
    let admitted_at = sample_clock().ok_or(NativeFilesystemRuntimeError::Unavailable)?;
    if context.now != request.observed_at || admitted_at < context.now {
        return Err(NativeFilesystemRuntimeError::Unavailable);
    }
    context.now = admitted_at;
    request.observed_at = admitted_at;
    Ok((context, request))
}

#[cfg(test)]
#[path = "lease_tests.rs"]
mod tests;
