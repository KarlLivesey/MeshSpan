// SPDX-License-Identifier: GPL-2.0-only

//! Current-manager issuance backed by the real consensus and protected authentication root.

mod acceptance;
mod connection;
mod storage;

use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{
    AuthenticationRootLoadingService, ConsensusAuthenticationAuthority, GatewaySessionIdentity,
    IdentityAdministrator, LocalWrappingKey, RotatingHttpsIdentity,
    SystemManagerAuthenticationError, authenticate_system_manager,
};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateFederationPairingInvitationRequest, CreateFederationPairingInvitationResponse,
};
use meshspan_domain::{
    AuditEventId, DurationMicros, FederationPairingInvitation, FederationPairingIssuance,
    FederationRelationshipId, OperationId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    FederationPairingInvitationRecord, FederationPairingInvitationState,
    IssueFederationPairingInvitation,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) struct FederationPairingService {
    authority: ConsensusAuthenticationAuthority,
    roots: AuthenticationRootLoadingService<ConsensusAuthenticationAuthority, LocalWrappingKey>,
    gateway: GatewaySessionIdentity,
    https_identity: RotatingHttpsIdentity,
    federation_identity: crate::local_federation_identity::LocalFederationIdentity,
}

pub(crate) struct PairingGateway {
    pub(crate) gateway: GatewaySessionIdentity,
    pub(crate) https: RotatingHttpsIdentity,
    pub(crate) federation: crate::local_federation_identity::LocalFederationIdentity,
}

impl FederationPairingService {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        root_authority: ConsensusAuthenticationAuthority,
        decryptor: LocalWrappingKey,
        identity: PairingGateway,
    ) -> Self {
        Self {
            authority,
            roots: AuthenticationRootLoadingService::new(root_authority, decryptor),
            gateway: identity.gateway,
            https_identity: identity.https,
            federation_identity: identity.federation,
        }
    }

    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), PairingError> {
        authenticate_system_manager(&self.authority, self.gateway, headers, now)
            .map(|_| ())
            .map_err(auth_error)
    }

    pub(crate) fn issue(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &CreateFederationPairingInvitationRequest,
    ) -> Result<CreateFederationPairingInvitationResponse, PairingError> {
        let administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(auth_error)?;
        if !(60..=3600).contains(&request.valid_for_seconds) {
            return Err(PairingError::Invalid);
        }
        let operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let previous = self.previous(operation, administrator)?;
        let (invitation, command, context) =
            self.prepare(administrator, operation, request, previous.as_ref())?;
        let receipt = match self.authority.commit_authoritative(context, &command) {
            Ok(value) => value,
            Err(error) => self
                .authority
                .reader()
                .resolve_operation(operation)
                .map_err(|_| PairingError::Unavailable)?
                .ok_or_else(|| commit_error(error))?,
        };
        validate_receipt(context, &command, receipt, invitation.relationship_id())?;
        let response = CreateFederationPairingInvitationResponse {
            operation_id: request.operation_id.clone(),
            invitation_id: format_uuid(invitation.relationship_id().as_bytes()),
            connection_code: invitation.expose_encoded().to_string(),
            expires_at_epoch_micros: invitation.expires_at().get(),
            committed_revision: receipt.committed_revision.get(),
        };
        meshspan_api_contract::encode_create_federation_pairing_response(&response)
            .map_err(|_| PairingError::Failed)?;
        Ok(response)
    }

    pub(crate) fn cancel(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &meshspan_api_contract::CancelFederationPairingInvitationRequest,
    ) -> Result<meshspan_api_contract::CancelFederationPairingInvitationResponse, PairingError>
    {
        let mut administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(auth_error)?;
        let operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let id = FederationRelationshipId::from_bytes(
            parse_uuid(request.invitation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let previous = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| PairingError::Unavailable)?;
        if previous.is_some() {
            let original = self
                .authority
                .reader()
                .operation_status(operation)
                .map_err(|_| PairingError::Unavailable)?
                .ok_or(PairingError::Failed)?;
            if original.actor_principal_id != Some(administrator.principal_id) {
                return Err(PairingError::Conflict);
            }
            administrator.now = original.started_at;
        }
        let context = cancellation_context(administrator, operation)?;
        let command = AuthoritativeCommand::CancelFederationPairingInvitation(
            meshspan_metadata::CancelFederationPairingInvitation {
                relationship_id: id,
                expected_invitation_revision: meshspan_domain::Revision::new(
                    request.expected_invitation_revision,
                ),
                reason: request.reason.clone(),
            },
        );
        let receipt = match previous {
            Some(receipt) => receipt,
            None => self
                .authority
                .commit_authoritative(context, &command)
                .map_err(commit_error)?,
        };
        validate_receipt(context, &command, receipt, id)?;
        Ok(
            meshspan_api_contract::CancelFederationPairingInvitationResponse {
                operation_id: request.operation_id.clone(),
                invitation_id: request.invitation_id.clone(),
                committed_revision: receipt.committed_revision.get(),
            },
        )
    }

    fn previous(
        &self,
        operation: OperationId,
        administrator: IdentityAdministrator,
    ) -> Result<Option<FederationPairingInvitationRecord>, PairingError> {
        let Some(receipt) = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| PairingError::Unavailable)?
        else {
            return Ok(None);
        };
        if receipt.entity.kind != EntityKind::FederationPairingInvitation {
            return Err(PairingError::Conflict);
        }
        let id = FederationRelationshipId::from_bytes(receipt.entity.id)
            .map_err(|_| PairingError::Failed)?;
        let record = self
            .authority
            .reader()
            .federation_pairing_invitation(id)
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Failed)?;
        if record.issued_by != administrator.principal_id
            || record.issuance_operation_id != operation
            || record.state != FederationPairingInvitationState::Open
        {
            return Err(PairingError::Conflict);
        }
        Ok(Some(record))
    }

    fn prepare(
        &self,
        administrator: IdentityAdministrator,
        operation: OperationId,
        request: &CreateFederationPairingInvitationRequest,
        previous: Option<&FederationPairingInvitationRecord>,
    ) -> Result<
        (
            FederationPairingInvitation,
            AuthoritativeCommand,
            CommandContext,
        ),
        PairingError,
    > {
        let mesh_id = self
            .authority
            .reader()
            .local_mesh_id()
            .map_err(|_| PairingError::Unavailable)?
            .ok_or(PairingError::Unavailable)?;
        let keys = match previous {
            Some(record) => self
                .roots
                .load_generation(record.invitation.issuance_key_generation),
            None => self.roots.load_latest(),
        }
        .map_err(|_| PairingError::Unavailable)?;
        let (key, generation) = keys.into_federation_pairing_issuance();
        let issued_at = previous.map_or(administrator.now, |record| record.issued_at);
        let expires_at = issued_at
            .checked_add(DurationMicros::new(
                u64::from(request.valid_for_seconds) * 1_000_000,
            ))
            .ok_or(PairingError::Invalid)?;
        let (issuing_node_id, pin) = match previous {
            Some(record) => (
                record.invitation.issuing_node_id,
                record.invitation.certificate_fingerprint,
            ),
            None => (
                self.gateway.node_id,
                self.https_identity
                    .certificate_fingerprint()
                    .map_err(|_| PairingError::Unavailable)?,
            ),
        };
        let invitation = FederationPairingInvitation::issue(
            &key,
            &FederationPairingIssuance {
                mesh_id,
                principal_id: administrator.principal_id,
                operation_id: operation,
                issued_at,
                expires_at,
                endpoint: &request.pairing_endpoint,
                certificate_fingerprint: pin,
            },
        )
        .map_err(|_| PairingError::Invalid)?;
        let command = AuthoritativeCommand::IssueFederationPairingInvitation(
            IssueFederationPairingInvitation {
                relationship_id: invitation.relationship_id(),
                issuing_node_id,
                issuance_key_generation: generation,
                material_verifier: invitation.verifier(),
                endpoint: request.pairing_endpoint.clone(),
                certificate_fingerprint: pin,
                expires_at,
            },
        );
        let mut hash = Sha256::new();
        hash.update(b"meshspan.federation.pairing.issuance-audit.v1\0");
        hash.update(operation.as_bytes());
        let mut audit = [0; 16];
        audit.copy_from_slice(&hash.finalize()[..16]);
        let context = CommandContext {
            operation_id: operation,
            actor_principal_id: administrator.principal_id,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
                .map_err(|_| PairingError::Failed)?,
            occurred_at: issued_at,
            expected_revision: None,
        };
        Ok((invitation, command, context))
    }
}

fn validate_receipt(
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: CommandReceipt,
    id: FederationRelationshipId,
) -> Result<(), PairingError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::FederationPairingInvitation
        || receipt.entity.id != id.as_bytes()
    {
        return Err(PairingError::Conflict);
    }
    if receipt.result_digest == [0; 32] || receipt.committed_revision.get() == 0 {
        return Err(PairingError::Failed);
    }
    Ok(())
}

fn cancellation_context(
    administrator: IdentityAdministrator,
    operation: OperationId,
) -> Result<CommandContext, PairingError> {
    let mut hash = Sha256::new();
    hash.update(b"meshspan.federation.pairing.cancellation-audit.v1\0");
    hash.update(operation.as_bytes());
    let mut audit = [0; 16];
    audit.copy_from_slice(&hash.finalize()[..16]);
    Ok(CommandContext {
        operation_id: operation,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
            .map_err(|_| PairingError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum PairingError {
    #[error("federation pairing input is invalid")]
    Invalid,
    #[error("federation pairing authentication rejected")]
    Unauthenticated,
    #[error("federation pairing requires current manager authority")]
    Forbidden,
    #[error("federation pairing conflicts with committed state")]
    Conflict,
    #[error("federation pairing authority unavailable")]
    Unavailable,
    #[error("federation pairing evidence is invalid")]
    Failed,
}

fn auth_error(error: SystemManagerAuthenticationError) -> PairingError {
    match error {
        SystemManagerAuthenticationError::Rejected => PairingError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => PairingError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => PairingError::Unavailable,
        SystemManagerAuthenticationError::Failed => PairingError::Failed,
    }
}

fn commit_error(error: meshspan_cluster::MetadataAuthorityRequestError) -> PairingError {
    use meshspan_cluster::MetadataAuthorityRequestError as Error;
    match error {
        Error::Rejected | Error::Conflict => PairingError::Conflict,
        Error::Unavailable | Error::NotLeader { .. } => PairingError::Unavailable,
        Error::Unsupported | Error::Failed => PairingError::Failed,
    }
}
