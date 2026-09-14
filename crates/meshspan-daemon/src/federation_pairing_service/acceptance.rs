// SPDX-License-Identifier: GPL-2.0-only

//! Invitation admission and replayable, separately committed relationship approval.

use super::{FederationPairingService, PairingError, auth_error, commit_error, parse_uuid};
use crate::SystemManagerAuthority;
use axum::http::{
    HeaderMap,
    header::{AUTHORIZATION, COOKIE},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meshspan_api_contract::{AcceptFederationPairingRequest, AcceptFederationPairingResponse};
use meshspan_domain::{
    AuditEventId, FederationPairingInvitation, OperationId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, CommandContext, CommandReceipt,
    EntityKind, FederationPairingConnectionRecord, FederationPairingInvitationRecord,
    FederationPairingInvitationState, FederationPairingPeer, FederationRelationshipState,
    PrepareFederationConnection, SignedFederationPairingPeer,
};
use sha2::{Digest, Sha256};

impl FederationPairingService {
    /// Checks the code and its issuing administrator before consuming any request body.
    pub(crate) fn authenticate_invitation(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), PairingError> {
        self.admit_invitation(headers, now).map(|_| ())
    }

    pub(crate) fn accept(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &AcceptFederationPairingRequest,
    ) -> Result<AcceptFederationPairingResponse, PairingError> {
        let (invitation, issued) = self.admit_invitation(headers, now)?;
        let remote = decode_peer(&request.peer_record)?;
        if !remote.verify(
            invitation.relationship_id(),
            invitation.mesh_id(),
            invitation.verifier(),
            now,
        ) {
            return Err(PairingError::Invalid);
        }
        let client_operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let operation = derived_id(
            b"accept",
            client_operation,
            invitation.relationship_id().as_bytes(),
        );
        let record = self.prepare_acceptance(&invitation, &issued, remote, operation, now)?;
        // Preparation is not approval: the existing relationship model requires a later revision.
        self.require_issuer(&issued, now)?;
        let approval = OperationId::from_bytes(derived_id(
            b"approve",
            record.operation_id,
            invitation.relationship_id().as_bytes(),
        ))
        .map_err(|_| PairingError::Failed)?;
        let receipt = self.approve_prepared(&record, now, approval)?;
        let response = AcceptFederationPairingResponse {
            operation_id: request.operation_id.clone(),
            relationship_id: meshspan_api_contract::OperationId::parse(
                &crate::create_mesh_setup::format_uuid(invitation.relationship_id().as_bytes()),
            )
            .ok_or(PairingError::Failed)?,
            peer_record: URL_SAFE_NO_PAD.encode(
                meshspan_metadata::encode_federation_pairing_peer(&record.connection.local)
                    .map_err(|_| PairingError::Failed)?,
            ),
            committed_revision: receipt.committed_revision.get(),
        };
        meshspan_api_contract::encode_accept_federation_pairing_response(&response)
            .map_err(|_| PairingError::Failed)?;
        Ok(response)
    }

    fn admit_invitation(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<
        (
            FederationPairingInvitation,
            FederationPairingInvitationRecord,
        ),
        PairingError,
    > {
        if headers.contains_key(COOKIE) || headers.get_all(AUTHORIZATION).iter().count() != 1 {
            return Err(PairingError::Unauthenticated);
        }
        let code = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("MeshSpan-Pairing "))
            .ok_or(PairingError::Unauthenticated)?;
        let invitation =
            FederationPairingInvitation::parse(code).map_err(|_| PairingError::Unauthenticated)?;
        let record = self
            .authority
            .reader()
            .federation_pairing_invitation(invitation.relationship_id())
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Unauthenticated)?;
        if !invitation.is_current(now)
            || record.state == FederationPairingInvitationState::Cancelled
            || record.mesh_id != invitation.mesh_id()
            || record.invitation.issuing_node_id != self.gateway.node_id
            || record.invitation.material_verifier != invitation.verifier()
        {
            return Err(PairingError::Unauthenticated);
        }
        self.require_issuer(&record, now)?;
        Ok((invitation, record))
    }

    fn require_issuer(
        &self,
        record: &FederationPairingInvitationRecord,
        now: UnixMicros,
    ) -> Result<(), PairingError> {
        if !self
            .authority
            .principal_is_system_manager(record.issued_by, now)
            .map_err(auth_error)?
        {
            return Err(PairingError::Forbidden);
        }
        Ok(())
    }

    fn prepare_acceptance(
        &self,
        invitation: &FederationPairingInvitation,
        issued: &FederationPairingInvitationRecord,
        remote: SignedFederationPairingPeer,
        operation: [u8; 16],
        now: UnixMicros,
    ) -> Result<FederationPairingConnectionRecord, PairingError> {
        let operation = OperationId::from_bytes(operation).map_err(|_| PairingError::Failed)?;
        if let Some(record) = self
            .authority
            .reader()
            .federation_pairing_connection(invitation.relationship_id())
            .map_err(|_| PairingError::Unavailable)?
        {
            if record.operation_id != operation
                || record.prepared_by != issued.issued_by
                || record.connection.remote != remote
                || record.connection.material_verifier != invitation.verifier()
            {
                return Err(PairingError::Conflict);
            }
            return Ok(record);
        }
        let local = self.signed_peer(invitation, invitation.endpoint())?;
        let command =
            AuthoritativeCommand::PrepareFederationConnection(PrepareFederationConnection {
                relationship_id: invitation.relationship_id(),
                inviting_mesh_id: invitation.mesh_id(),
                material_verifier: invitation.verifier(),
                expected_invitation_revision: Some(issued.revision),
                local,
                remote,
            });
        let context = context(operation, issued.issued_by, now)?;
        self.authority
            .commit_authoritative(context, &command)
            .map_err(commit_error)?;
        self.authority
            .reader()
            .federation_pairing_connection(invitation.relationship_id())
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Failed)
    }

    pub(super) fn signed_peer(
        &self,
        invitation: &FederationPairingInvitation,
        endpoint: &str,
    ) -> Result<SignedFederationPairingPeer, PairingError> {
        let identity = &self.federation_identity;
        let peer = FederationPairingPeer {
            mesh_id: self
                .authority
                .reader()
                .local_mesh_id()
                .map_err(|_| PairingError::Unavailable)?
                .ok_or(PairingError::Failed)?,
            node_id: self.gateway.node_id,
            name: self
                .authority
                .reader()
                .local_mesh_name()
                .map_err(|_| PairingError::Unavailable)?
                .ok_or(PairingError::Failed)?,
            endpoint: endpoint.to_owned(),
            certificate_der: identity
                .certificate
                .certificate_chain()
                .first()
                .ok_or(PairingError::Failed)?
                .clone(),
            verifying_key: identity.signing.verifying_key(),
            valid_from: identity.valid_from,
            valid_until: identity.valid_until,
        };
        let signature = identity.signing.sign_pairing(peer.pairing_digest(
            invitation.relationship_id(),
            invitation.mesh_id(),
            invitation.verifier(),
        ));
        Ok(SignedFederationPairingPeer { peer, signature })
    }

    pub(super) fn approve_prepared(
        &self,
        record: &FederationPairingConnectionRecord,
        now: UnixMicros,
        operation: OperationId,
    ) -> Result<CommandReceipt, PairingError> {
        let value = &record.connection;
        if !value.local.verify(
            value.relationship_id,
            value.inviting_mesh_id,
            value.material_verifier,
            now,
        ) {
            return Err(PairingError::Conflict);
        }
        let relationship = self
            .authority
            .reader()
            .federation_relationship(value.relationship_id)
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Failed)?;
        if relationship.authority_epoch != 1
            || !matches!(
                relationship.state,
                FederationRelationshipState::Proposed | FederationRelationshipState::Active
            )
        {
            return Err(PairingError::Conflict);
        }
        let previous = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|_| PairingError::Unavailable)?;
        let occurred_at = previous.map_or(now, |value| value.started_at);
        let context = context(operation, record.prepared_by, occurred_at)?;
        let command =
            AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
                relationship_id: value.relationship_id,
                expected_authority_epoch: 1,
                local_identity: value.local.peer.trust_identity(),
                remote_identity: value.remote.peer.trust_identity(),
                governance_proof: None,
            });
        let receipt = self
            .authority
            .commit_authoritative(context, &command)
            .map_err(commit_error)?;
        if receipt.operation_id != operation
            || receipt.request_digest != command.request_digest(context)
            || receipt.entity.kind != EntityKind::FederationRelationship
            || receipt.entity.id != value.relationship_id.as_bytes()
            || receipt.committed_revision <= record.revision
            || receipt.result_digest == [0; 32]
        {
            return Err(PairingError::Failed);
        }
        Ok(receipt)
    }
}

pub(super) fn decode_peer(encoded: &str) -> Result<SignedFederationPairingPeer, PairingError> {
    if encoded.len() > 24576 {
        return Err(PairingError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PairingError::Invalid)?;
    let peer = meshspan_metadata::decode_federation_pairing_peer(&bytes)
        .map_err(|_| PairingError::Invalid)?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            peer.peer.certificate_der.clone(),
        ))
        .map_err(|_| PairingError::Invalid)?;
    Ok(peer)
}

pub(super) fn derived_id(phase: &[u8], operation: OperationId, relationship: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.federation.connection.operation.v1\0");
    digest.update(phase);
    digest.update(operation.as_bytes());
    digest.update(relationship);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(id)
}

pub(super) fn context(
    operation: OperationId,
    actor: meshspan_domain::PrincipalId,
    now: UnixMicros,
) -> Result<CommandContext, PairingError> {
    Ok(CommandContext {
        operation_id: operation,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes(derived_id(b"audit", operation, actor.as_bytes()))
            .map_err(|_| PairingError::Failed)?,
        occurred_at: now,
        expected_revision: None,
    })
}
