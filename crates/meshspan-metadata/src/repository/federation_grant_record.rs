// SPDX-License-Identifier: GPL-2.0-only

//! Canonical, complete representation of one federation grant and its authority evidence.

mod codec;

use std::collections::BTreeSet;

use meshspan_domain::{FederationGrant, FederationPolicy};
use thiserror::Error;

use super::{
    FederationGrantRecord, FederationGrantState, FederationGrantTermination,
    FederationGrantTerminationKind,
};

const MAXIMUM_RESTRICTIONS: usize = 64;
const MAXIMUM_REASON_BYTES: usize = 512;

/// Encoding or decoding failure for one federation grant authority record.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationGrantRecordCodecError {
    /// The byte representation is truncated, excessive or semantically inconsistent.
    #[error("federation grant authority record is invalid")]
    Invalid,
    /// The record uses a format this implementation does not understand.
    #[error("federation grant authority record format is unsupported")]
    UnsupportedVersion,
}

impl FederationGrantRecord {
    /// Encodes the complete grant, bilateral restrictions and lifecycle evidence canonically.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent or non-canonical authority instead of emitting ambiguous bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FederationGrantRecordCodecError> {
        validate_record(self)?;
        codec::encode(self)
    }

    /// Decodes and fully validates one canonical grant authority record.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, trailing bytes, broadened policy and invalid lifecycle evidence.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FederationGrantRecordCodecError> {
        let record = codec::decode(bytes)?;
        validate_record(&record)?;
        Ok(record)
    }
}

fn validate_record(record: &FederationGrantRecord) -> Result<(), FederationGrantRecordCodecError> {
    let grant = record.grant;
    let reconstructed = FederationGrant::new(
        grant.grant_id(),
        grant.relationship_id(),
        grant.subject(),
        grant.resource(),
        grant.policy(),
        grant.authority_epoch(),
        grant.valid_from(),
        grant.valid_until(),
    )
    .map_err(|_| FederationGrantRecordCodecError::Invalid)?;
    if reconstructed != grant
        || record.revision.get() == 0
        || grant.subject().home_mesh_id() == grant.resource().authority_mesh_id()
        || !valid_restrictions(record)
        || !valid_lifecycle(record)
    {
        return Err(FederationGrantRecordCodecError::Invalid);
    }
    Ok(())
}

fn valid_restrictions(record: &FederationGrantRecord) -> bool {
    let restrictions = &record.restrictions;
    if !(2..=MAXIMUM_RESTRICTIONS).contains(&restrictions.len())
        || !restrictions
            .windows(2)
            .all(|pair| pair[0].imposing_mesh_id < pair[1].imposing_mesh_id)
    {
        return false;
    }
    let imposing = restrictions
        .iter()
        .map(|restriction| restriction.imposing_mesh_id)
        .collect::<BTreeSet<_>>();
    let required = [
        record.grant.subject().home_mesh_id(),
        record.grant.resource().authority_mesh_id(),
    ];
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    required.iter().all(|mesh_id| imposing.contains(mesh_id))
        && FederationPolicy::intersect(&policies)
            .is_ok_and(|policy| policy == record.grant.policy())
}

fn valid_lifecycle(record: &FederationGrantRecord) -> bool {
    let grant_id = record.grant.grant_id();
    if record.predecessor_grant_id == Some(grant_id)
        || record.successor_grant_id == Some(grant_id)
        || record.predecessor_grant_id.is_some()
            && record.predecessor_grant_id == record.successor_grant_id
    {
        return false;
    }
    match (record.state, record.termination.as_ref()) {
        (FederationGrantState::Active, None) => record.successor_grant_id.is_none(),
        (FederationGrantState::Revoked, Some(termination)) => {
            valid_termination(record, termination)
        }
        _ => false,
    }
}

fn valid_termination(
    record: &FederationGrantRecord,
    termination: &FederationGrantTermination,
) -> bool {
    if termination.revision != record.revision
        || termination.revision.get() == 0
        || termination.terminated_at < record.issued_at
    {
        return false;
    }
    let reason_is_valid = match termination.kind {
        FederationGrantTerminationKind::LegacyReasonUnknown => termination.reason.is_none(),
        _ => termination.reason.as_deref().is_some_and(valid_reason),
    };
    let successor_is_valid = match termination.kind {
        FederationGrantTerminationKind::Renewed | FederationGrantTerminationKind::Restricted => {
            record.successor_grant_id.is_some()
        }
        FederationGrantTerminationKind::Revoked
        | FederationGrantTerminationKind::LegacyReasonUnknown => {
            record.successor_grant_id.is_none()
        }
    };
    reason_is_valid && successor_is_valid
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAXIMUM_REASON_BYTES
        && reason.trim() == reason
        && !reason.chars().any(char::is_control)
}

#[cfg(test)]
#[path = "federation_grant_record_tests.rs"]
mod tests;
