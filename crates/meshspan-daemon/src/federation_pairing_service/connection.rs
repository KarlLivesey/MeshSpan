// SPDX-License-Identifier: GPL-2.0-only

//! Local approval is durable before network IO; remote replies never bypass current authority.

use super::acceptance::{context, decode_peer, derived_id};
use super::{FederationPairingService, PairingError, auth_error, commit_error, parse_uuid};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    AcceptFederationPairingResponse, ConnectFederationRequest, ConnectFederationResponse,
};
use meshspan_domain::{FederationPairingInvitation, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, BeginFederationConnection, FederationConnectionIntentRecord,
    PrepareFederationConnection,
};

impl FederationPairingService {
    pub(crate) fn begin_connection(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &ConnectFederationRequest,
    ) -> Result<FederationConnectionIntentRecord, PairingError> {
        let actor = crate::authenticate_system_manager(&self.authority, self.gateway, headers, now)
            .map_err(auth_error)?;
        let invitation = FederationPairingInvitation::parse(&request.connection_code)
            .map_err(|_| PairingError::Invalid)?;
        if !invitation.is_current(now)
            || !meshspan_domain::is_valid_federation_endpoint(&request.local_endpoint)
        {
            return Err(PairingError::Invalid);
        }
        let client_operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        // Internal intent is not the public operation's successful connection receipt.
        // Its ID depends only on the client operation, so changing invitations cannot reuse it.
        let operation = OperationId::from_bytes(derived_id(b"begin", client_operation, [0; 16]))
            .map_err(|_| PairingError::Failed)?;
        if let Some(record) = self
            .authority
            .reader()
            .federation_connection_intent(invitation.relationship_id())
            .map_err(|_| PairingError::Unavailable)?
        {
            if record.operation_id != operation
                || record.actor_id != actor.principal_id
                || record.intent.material_verifier != invitation.verifier()
                || record.intent.inviting_mesh_id != invitation.mesh_id()
                || record.intent.remote_endpoint != invitation.endpoint()
                || record.intent.certificate_fingerprint != invitation.certificate_fingerprint()
                || record.intent.expires_at != invitation.expires_at()
                || record.intent.local.peer.endpoint != request.local_endpoint
                || record.intent.local.peer.node_id != self.gateway.node_id
                || record.intent.local.peer.verifying_key
                    != self.federation_identity.signing.verifying_key()
                || !record.intent.local.verify(
                    invitation.relationship_id(),
                    invitation.mesh_id(),
                    invitation.verifier(),
                    now,
                )
            {
                return Err(PairingError::Conflict);
            }
            return Ok(record);
        }
        // A reused operation must reject before contacting (and potentially consuming) another invitation.
        if self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| PairingError::Unavailable)?
            .is_some()
            || self
                .authority
                .reader()
                .resolve_operation(client_operation)
                .map_err(|_| PairingError::Unavailable)?
                .is_some()
        {
            return Err(PairingError::Conflict);
        }
        let intent = BeginFederationConnection {
            relationship_id: invitation.relationship_id(),
            inviting_mesh_id: invitation.mesh_id(),
            material_verifier: invitation.verifier(),
            remote_endpoint: invitation.endpoint().to_owned(),
            certificate_fingerprint: invitation.certificate_fingerprint(),
            expires_at: invitation.expires_at(),
            local: self.signed_peer(&invitation, &request.local_endpoint)?,
        };
        self.authority
            .commit_authoritative(
                context(operation, actor.principal_id, now)?,
                &AuthoritativeCommand::BeginFederationConnection(intent),
            )
            .map_err(commit_error)?;
        self.authority
            .reader()
            .federation_connection_intent(invitation.relationship_id())
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Failed)
    }

    pub(crate) fn finish_connection(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &ConnectFederationRequest,
        response: &AcceptFederationPairingResponse,
    ) -> Result<ConnectFederationResponse, PairingError> {
        // Re-admission also binds the current caller and input to the retained intent after IO.
        let record = self.begin_connection(headers, now, request)?;
        let intent = &record.intent;
        let relationship = crate::create_mesh_setup::format_uuid(intent.relationship_id.as_bytes());
        let remote = decode_peer(&response.peer_record)?;
        if response.operation_id != request.operation_id
            || response.relationship_id.as_str() != relationship
            || response.committed_revision == 0
            || remote.peer.mesh_id != intent.inviting_mesh_id
            || remote.peer.endpoint != intent.remote_endpoint
            || !remote.verify(
                intent.relationship_id,
                intent.inviting_mesh_id,
                intent.material_verifier,
                now,
            )
        {
            return Err(PairingError::Invalid);
        }
        let command = PrepareFederationConnection {
            relationship_id: intent.relationship_id,
            inviting_mesh_id: intent.inviting_mesh_id,
            material_verifier: intent.material_verifier,
            expected_invitation_revision: None,
            local: intent.local.clone(),
            remote,
        };
        let operation = OperationId::from_bytes(derived_id(
            b"prepare",
            record.operation_id,
            intent.relationship_id.as_bytes(),
        ))
        .map_err(|_| PairingError::Failed)?;
        let previous = self
            .authority
            .reader()
            .federation_pairing_connection(intent.relationship_id)
            .map_err(|_| PairingError::Unavailable)?;
        if let Some(previous) = previous {
            if previous.operation_id != operation
                || previous.prepared_by != record.actor_id
                || previous.connection != command
            {
                return Err(PairingError::Conflict);
            }
        } else {
            self.authority
                .commit_authoritative(
                    context(operation, record.actor_id, now)?,
                    &AuthoritativeCommand::PrepareFederationConnection(command),
                )
                .map_err(commit_error)?;
        }
        let prepared = self
            .authority
            .reader()
            .federation_pairing_connection(intent.relationship_id)
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Failed)?;
        let client_operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let receipt = self.approve_prepared(&prepared, now, client_operation)?;
        Ok(ConnectFederationResponse {
            operation_id: request.operation_id.clone(),
            relationship_id: meshspan_api_contract::OperationId::parse(&relationship)
                .ok_or(PairingError::Failed)?,
            committed_revision: receipt.committed_revision.get(),
        })
    }
}
