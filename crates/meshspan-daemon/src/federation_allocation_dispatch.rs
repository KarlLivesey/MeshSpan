// SPDX-License-Identifier: GPL-2.0-only

//! Signed, revision-bound discovery of allocations behind an approved storage grant.

use super::{FederationSessionRuntimeError, FederationSessions, NativeFederationSession};
use meshspan_cluster::federation_connection_authority;
use meshspan_domain::{FederationGrantId, FederationStorageAllocationId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederationAllocationCursor, FederationAllocationQuery,
    FederationStorageAllocationAuthority, PageLimit,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, decode_backup_allocation_cursor, encode_backup_allocation_cursor,
    federation_backup_allocation_request_digest_payload,
    v1::{
        FederatedBackupAllocation, FederatedBackupAllocationCursor, FederatedBackupAllocationPage,
        FederatedBackupScope, FederationEnvelope, federation_envelope::Message,
    },
};
use meshspan_transport::{FederationPeerRegistry, signed_federation_backup_message};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, FederationSessionRuntimeError>;

impl FederationSessions {
    pub(super) fn prepare_allocation_page(
        &self,
        reader: &AuthoritativeRepository,
        session: &NativeFederationSession,
        envelope: &ValidatedFederationEnvelope,
    ) -> Result<FederationEnvelope> {
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let current = federation_connection_authority(reader, session.relationship, now)?
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let authenticated = self.replay.authenticate_backup_request(
            &FederationPeerRegistry::new([current.peer])?,
            &session.connection,
            envelope,
            now,
        )?;
        let Message::FetchBackupAllocations(request) = authenticated.message() else {
            return Err(FederationSessionRuntimeError::Unavailable);
        };
        let cursor = if request.cursor.is_empty() {
            None
        } else {
            Some(
                decode_backup_allocation_cursor(&request.cursor)
                    .map_err(meshspan_transport::TransportError::from)?,
            )
        };
        let snapshot = cursor
            .as_ref()
            .map_or_else(
                || reader.current_revision(),
                |cursor| Ok(Revision::new(cursor.snapshot_revision)),
            )
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let after = cursor.as_ref().map(allocation_cursor).transpose()?;
        // Eight 16-byte IDs, four revision fences and three bounded integers fit within
        // 256 encoded bytes per route; 512 reserves the signed header and continuation.
        let fitting = session
            .limits
            .wire
            .maximum_control_bytes()
            .saturating_sub(512)
            / 256;
        let limit = usize::try_from(request.limit)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .min(fitting);
        let page = reader
            .federation_storage_allocations_page(FederationAllocationQuery {
                relationship_id: session.relationship,
                remote_mesh_id: authenticated.remote_mesh_id(),
                grant_id: FederationGrantId::from_bytes(exact(&request.grant_id)?)
                    .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
                required_bytes: request.required_bytes,
                observed_at: now,
                snapshot_revision: snapshot,
                after,
                limit: PageLimit::new(limit)
                    .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
            })
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let next_cursor = page
            .next
            .map(|next| {
                encode_backup_allocation_cursor(&FederatedBackupAllocationCursor {
                    format_version: 1,
                    relationship_id: session.relationship.as_bytes().to_vec(),
                    authority_epoch: authenticated.authority_epoch(),
                    grant_id: request.grant_id.clone(),
                    required_bytes: request.required_bytes,
                    snapshot_revision: snapshot.get(),
                    valid_from_unix_micros: next.valid_from.get(),
                    valid_until_unix_micros: next.valid_until.get(),
                    allocation_id: next.allocation_id.as_bytes().to_vec(),
                })
            })
            .transpose()
            .map_err(meshspan_transport::TransportError::from)?
            .unwrap_or_default();
        let response = Message::BackupAllocationPage(FederatedBackupAllocationPage {
            request_digest: Sha256::digest(
                federation_backup_allocation_request_digest_payload(request)
                    .map_err(meshspan_transport::TransportError::from)?,
            )
            .to_vec(),
            authority_revision: snapshot.get(),
            allocations: page.items.into_iter().map(allocation_record).collect(),
            next_cursor,
            signature: Vec::new(),
        });
        let runtime = self.session_runtime_with_limits(session.limits)?;
        let identity = runtime.local_identity(&current, now)?;
        Ok(signed_federation_backup_message(
            &identity,
            authenticated.response_context(super::random()?)?,
            response,
            session.limits.wire,
            now,
        )?
        .envelope()
        .clone())
    }
}

fn allocation_cursor(
    cursor: &FederatedBackupAllocationCursor,
) -> Result<FederationAllocationCursor> {
    Ok(FederationAllocationCursor {
        valid_from: UnixMicros::new(cursor.valid_from_unix_micros),
        valid_until: UnixMicros::new(cursor.valid_until_unix_micros),
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&cursor.allocation_id)?)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
    })
}

fn allocation_record(authority: FederationStorageAllocationAuthority) -> FederatedBackupAllocation {
    let allocation = authority.allocation();
    FederatedBackupAllocation {
        scope: Some(FederatedBackupScope {
            relationship_id: authority.relationship_id().as_bytes().to_vec(),
            remote_mesh_id: authority.remote_mesh_id().as_bytes().to_vec(),
            provider_mesh_id: authority.provider_mesh_id().as_bytes().to_vec(),
            allocation_id: allocation.allocation_id().as_bytes().to_vec(),
            grant_id: authority.grant_id().as_bytes().to_vec(),
            namespace_grant_id: allocation.grant_id().as_bytes().to_vec(),
            provider_node_id: allocation.provider_node_id().as_bytes().to_vec(),
            target_id: allocation.target_id().as_bytes().to_vec(),
            target_generation: allocation.target_generation(),
            relationship_authority_epoch: authority.relationship_authority_epoch(),
            grant_revision: authority.grant_revision().get(),
            allocation_revision: authority.allocation_revision().get(),
        }),
        maximum_bytes: allocation.maximum_bytes(),
        valid_from_unix_micros: authority.valid_from().get(),
        valid_until_unix_micros: authority.valid_until().get(),
    }
}

fn exact(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| FederationSessionRuntimeError::Unavailable)
}
