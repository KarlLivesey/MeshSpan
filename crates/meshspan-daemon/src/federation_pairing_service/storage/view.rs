// SPDX-License-Identifier: GPL-2.0-only

use super::{FederationPairingService, PairingError, commands, format_uuid};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    FederationStorageGrantPolicy, FederationStorageGrantQuery, FederationStorageGrantResponse,
    FederationStorageGrantState, FederationStorageGrantSummary, OperationId,
};
use meshspan_domain::{FederationPolicy, UnixMicros};
use meshspan_metadata::{FederationGrantRecord, FederationGrantState};

impl FederationPairingService {
    pub(crate) fn storage_grant(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: &FederationStorageGrantQuery,
    ) -> Result<FederationStorageGrantResponse, PairingError> {
        self.authenticate_storage_read(headers, now)?;
        let reader = self.authority.reader();
        let revision = reader
            .current_revision()
            .map_err(|_| PairingError::Unavailable)?;
        let local = reader
            .local_mesh_id()
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Unavailable)?;
        let record = reader
            .federation_grant(commands::grant_id_from_api(&query.grant_id)?)
            .map_err(|_| PairingError::Unavailable)?;
        let grant = record
            .map(|record| {
                commands::ensure_owned(&record, local)?;
                summary(&record)
            })
            .transpose()?;
        self.authenticate_storage_read(headers, now)?;
        if reader
            .current_revision()
            .map_err(|_| PairingError::Unavailable)?
            != revision
        {
            return Err(PairingError::Conflict);
        }
        let response = FederationStorageGrantResponse {
            metadata_revision: revision.get(),
            grant,
        };
        meshspan_api_contract::encode_federation_storage_grant_response(&response)
            .map_err(|_| PairingError::Failed)?;
        Ok(response)
    }
}

fn summary(record: &FederationGrantRecord) -> Result<FederationStorageGrantSummary, PairingError> {
    let FederationPolicy::Storage(policy) = record.grant.policy() else {
        return Err(PairingError::Failed);
    };
    Ok(FederationStorageGrantSummary {
        grant_id: id(record.grant.grant_id().as_bytes())?,
        relationship_id: id(record.grant.relationship_id().as_bytes())?,
        policy: FederationStorageGrantPolicy {
            maximum_bytes: policy.maximum_storage_bytes().to_string(),
            counts_towards_protection: policy.participation().counts_towards_protection(),
            serves_reads: policy.participation().serves_reads(),
            allow_downstream_delegation: policy.allows_downstream_delegation(),
        },
        state: match record.state {
            FederationGrantState::Active => FederationStorageGrantState::Active,
            FederationGrantState::Revoked if record.successor_grant_id.is_some() => {
                FederationStorageGrantState::Superseded
            }
            FederationGrantState::Revoked => FederationStorageGrantState::Revoked,
        },
        valid_from_epoch_micros: record.grant.valid_from().get(),
        valid_until_epoch_micros: record.grant.valid_until().map(UnixMicros::get),
        successor_grant_id: record
            .successor_grant_id
            .map(|value| id(value.as_bytes()))
            .transpose()?,
        revision: record.revision.get(),
    })
}

fn id(bytes: [u8; 16]) -> Result<OperationId, PairingError> {
    OperationId::parse(&format_uuid(bytes)).ok_or(PairingError::Failed)
}
