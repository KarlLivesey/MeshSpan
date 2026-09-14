// SPDX-License-Identifier: GPL-2.0-only

//! Real TLS/signature admission into provider-only backup MAC and current metadata checks.

#[path = "backup_capability_proof/execution.rs"]
mod execution;

use super::{
    Certificates, ConnectionPair, MetadataAuthorities, NOW, loopback, roots, transport_limits,
};
use ed25519_dalek::SigningKey;
use meshspan_cluster::{
    FederationBackupCapabilityError, FederationBackupCapabilityService,
    FederationBackupIssueRequest, federation_connection_authority,
};
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupObjectReference, BackupReadRequest,
    BackupStoreRequest, BackupVerifyRequest, ContractError, ContractVersion,
    FederatedBackupRequest, FederatedBackupScope, FederatedStoragePermitMacKey, RequestContext,
    verify_federated_backup_permit_mac,
};
use meshspan_data_plane::{
    decode_federated_backup_permit, encode_federated_backup_permit, encode_federated_backup_request,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, DurationMicros, OperationId, Revision, UnixMicros,
};
use meshspan_metadata::LocalDatabase;
use meshspan_protocol::{
    ValidatedFederationEnvelope,
    v1::{
        ExecuteFederatedBackup, FederationEnvelope, ProtocolVersion, federation_envelope::Message,
    },
};
use meshspan_transport::{
    AuthenticatedFederationBackupRequest, FederationExchangeContext, FederationLocalIdentity,
    FederationPeerRegistry, FederationReplayGuard, StreamKind, accept_stream, open_stream,
    receive_federation, send_federation, server_endpoint, signed_federation_backup_message,
};
use std::error::Error;

#[tokio::test]
async fn backup_capabilities_round_trip_all_actions_and_revoke_without_capacity_holds()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new().await?;
    let retained = fixture.prove_actions().await?;
    fixture.authorities.server.revoke(90)?;
    // Keep the already authenticated connection/requests deliberately: a previously valid
    // signature and provider MAC must not hide a newly committed revocation.
    let identity = fixture.provider_identity()?;
    let service = fixture.service(&identity);
    for authenticated in &retained {
        assert!(matches!(
            service.authorise(authenticated, NOW),
            Err(FederationBackupCapabilityError::Contract(
                ContractError::Unauthorized
            ))
        ));
    }
    fixture.connections.close_and_wait().await;
    fixture.server.wait_idle().await;
    Ok(())
}

struct Fixture {
    certificates: Certificates,
    client_key: SigningKey,
    server_key: SigningKey,
    authorities: MetadataAuthorities,
    connections: ConnectionPair,
    server: quinn::Endpoint,
    scope: FederatedBackupScope,
    permit_key: FederatedStoragePermitMacKey,
    provider_binding: meshspan_transport::FederationLocalIdentityBinding,
}

#[tokio::test]
async fn rotated_federation_identity_fences_retained_backup_requests() -> Result<(), Box<dyn Error>>
{
    for owner in [
        meshspan_metadata::FederationIdentityOwner::Remote,
        meshspan_metadata::FederationIdentityOwner::Local,
    ] {
        let mut fixture = Fixture::new().await?;
        let request = requests()?.remove(0);
        let retained = fixture.prove_action(&request).await?;
        let current = fixture.authorities.server.repository().current_revision()?;
        let next = current.next()?;
        let actor = fixture.authorities.server.administrator_id;
        let command = meshspan_metadata::AuthoritativeCommand::RotateFederationTrustIdentity(
            meshspan_metadata::RotateFederationTrustIdentity {
                relationship_id: fixture.scope.relationship_id,
                expected_authority_epoch: fixture.scope.relationship_authority_epoch,
                owner,
                identity: super::trust_identity_with_generation(
                    2,
                    &fixture.certificates.rotated_client,
                    &SigningKey::from_bytes(&[161; 32]),
                ),
            },
        );
        super::apply(
            &mut fixture.authorities.server.repository,
            next.get(),
            super::context(160, actor, next.get(), current.get())?,
            &command,
        )?;
        let identity = fixture.provider_identity()?;
        assert!(
            matches!(
                fixture.service(&identity).authorise(&retained, NOW),
                Err(FederationBackupCapabilityError::Contract(
                    ContractError::Stale
                ))
            ),
            "retired {owner:?} identity retained backup execution authority"
        );
        fixture.connections.close_and_wait().await;
        fixture.server.wait_idle().await;
    }
    Ok(())
}

impl Fixture {
    async fn new() -> Result<Self, Box<dyn Error>> {
        let certificates = Certificates::new()?;
        let limits = transport_limits()?;
        let server = server_endpoint(
            loopback(),
            certificates.server_credentials()?,
            roots(&certificates.authority)?,
            limits,
        )?;
        let connections = ConnectionPair::establish(
            &server,
            certificates.client_credentials()?,
            roots(&certificates.authority)?,
            limits,
        )
        .await?;
        let client_key = SigningKey::from_bytes(&[4; 32]);
        let server_key = SigningKey::from_bytes(&[5; 32]);
        let mut authorities = MetadataAuthorities::active(&certificates, &client_key, &server_key)?;
        let grants = authorities.issue_server_grants(70, &[false])?;
        let grant = *grants.first().ok_or("missing recovery-only grant")?;
        let grant_revision = authorities.server.repository().current_revision()?;
        let (allocation, provider_node) =
            authorities.issue_server_storage_allocation(75, grant, grant_revision)?;
        let provider_binding = federation_connection_authority(
            authorities.server.repository(),
            authorities.relationship_id,
            NOW,
        )?
        .ok_or("missing provider authority")?
        .local_identity;
        let scope = FederatedBackupScope {
            relationship_id: authorities.relationship_id,
            remote_mesh_id: authorities.client_mesh,
            provider_mesh_id: authorities.server_mesh,
            allocation_id: allocation.allocation_id(),
            grant_id: grant,
            namespace_grant_id: grant,
            provider_node_id: provider_node,
            target_id: allocation.target_id(),
            target_generation: allocation.target_generation(),
            relationship_authority_epoch: provider_binding.authority_epoch,
            grant_revision,
            allocation_revision: authorities.server.repository().current_revision()?,
        };
        Ok(Self {
            certificates,
            client_key,
            server_key,
            authorities,
            connections,
            server,
            scope,
            permit_key: FederatedStoragePermitMacKey::from_bytes([215; 32])?,
            provider_binding,
        })
    }

    fn provider_identity(&self) -> Result<FederationLocalIdentity<'_>, Box<dyn Error>> {
        Ok(FederationLocalIdentity::authenticate(
            self.provider_binding,
            &self.certificates.server,
            &self.server_key,
            NOW,
        )?)
    }

    fn service<'a>(
        &'a self,
        identity: &'a FederationLocalIdentity<'a>,
    ) -> FederationBackupCapabilityService<'a, 'a> {
        FederationBackupCapabilityService::new(
            self.authorities.server.repository(),
            self.scope.provider_node_id,
            identity,
            &self.permit_key,
        )
    }

    async fn prove_actions(
        &self,
    ) -> Result<Vec<AuthenticatedFederationBackupRequest>, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let local = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            self.scope.provider_node_id,
            NOW,
        )?;
        let mut retained = Vec::new();
        for request in requests()? {
            retained.push(self.prove_action(&request).await?);
        }
        // Issuance/admission does not reserve capacity. Execution's composed provider owns it.
        assert!(
            local
                .federated_storage_usage(self.scope.allocation_id)?
                .is_none()
        );
        Ok(retained)
    }

    async fn authenticate(
        &self,
        message: Message,
        context: FederationExchangeContext,
    ) -> Result<AuthenticatedFederationBackupRequest, Box<dyn Error>> {
        let client = federation_connection_authority(
            self.authorities.client.repository(),
            self.scope.relationship_id,
            NOW,
        )?
        .ok_or("missing consumer authority")?;
        let server = federation_connection_authority(
            self.authorities.server.repository(),
            self.scope.relationship_id,
            NOW,
        )?
        .ok_or("missing provider authority")?;
        let identity = FederationLocalIdentity::authenticate(
            client.local_identity,
            &self.certificates.client,
            &self.client_key,
            NOW,
        )?;
        let signed = signed_federation_backup_message(
            &identity,
            context,
            message,
            transport_limits()?.wire,
            NOW,
        )?;
        let envelope = deliver(
            &self.connections.client,
            &self.connections.server,
            signed.envelope(),
        )
        .await?;
        Ok(
            FederationPeerRegistry::new([server.peer])?.authenticate_backup_request(
                &self.connections.server,
                &envelope,
                NOW,
                &mut replay()?,
            )?,
        )
    }

    async fn prove_action(
        &self,
        request: &FederatedBackupRequest,
    ) -> Result<AuthenticatedFederationBackupRequest, Box<dyn Error>> {
        let wire_request = encode_federated_backup_request(self.scope, request, NOW)?;
        let authenticated = self
            .authenticate(
                Message::RequestBackupCapability(wire_request),
                context(request, 121)?,
            )
            .await?;
        let identity = self.provider_identity()?;
        let service = self.service(&identity);
        let issued = service.issue(&FederationBackupIssueRequest {
            authenticated: &authenticated,
            response_nonce: [122; 32],
            capability_nonce: [123; 32],
            expires_at: UnixMicros::new(1_800_000),
            observed_at: NOW,
            limits: transport_limits()?.wire,
        })?;
        assert_eq!(&issued.permit().request, request);
        assert_eq!(issued.permit().scope, self.scope);
        assert!(verify_federated_backup_permit_mac(
            &self.permit_key,
            issued.permit()
        ));
        self.prove_response(&authenticated, issued.outbound().envelope(), request)
            .await?;
        let wire_permit = encode_federated_backup_permit(issued.permit(), NOW)?;
        assert_eq!(
            decode_federated_backup_permit(&wire_permit, NOW)?,
            *issued.permit()
        );
        let execute = self
            .authenticate(
                Message::ExecuteBackup(ExecuteFederatedBackup {
                    permit: Some(wire_permit.clone()),
                    signature: Vec::new(),
                }),
                context(request, 124)?,
            )
            .await?;
        let admitted = service.authorise(&execute, NOW)?;
        assert_eq!(admitted.request(), request);
        assert_eq!(
            admitted.authority().allocation().allocation_id(),
            self.scope.allocation_id
        );
        assert!(!admitted.authority().participation().serves_reads());
        let mut tampered = wire_permit;
        tampered.permit_digest = vec![125; 32];
        let forged = self
            .authenticate(
                Message::ExecuteBackup(ExecuteFederatedBackup {
                    permit: Some(tampered),
                    signature: Vec::new(),
                }),
                context(request, 126)?,
            )
            .await?;
        assert!(matches!(
            service.authorise(&forged, NOW),
            Err(FederationBackupCapabilityError::Contract(
                ContractError::Unauthorized
            ))
        ));
        Ok(execute)
    }

    async fn prove_response(
        &self,
        request: &AuthenticatedFederationBackupRequest,
        envelope: &FederationEnvelope,
        expected: &FederatedBackupRequest,
    ) -> Result<(), Box<dyn Error>> {
        let delivered =
            deliver(&self.connections.server, &self.connections.client, envelope).await?;
        let current = federation_connection_authority(
            self.authorities.client.repository(),
            self.scope.relationship_id,
            NOW,
        )?
        .ok_or("missing consumer authority")?;
        let identity = FederationLocalIdentity::authenticate(
            current.local_identity,
            &self.certificates.client,
            &self.client_key,
            NOW,
        )?;
        let outbound = signed_federation_backup_message(
            &identity,
            context(expected, 121)?,
            Message::RequestBackupCapability(encode_federated_backup_request(
                self.scope, expected, NOW,
            )?),
            transport_limits()?.wire,
            NOW,
        )?;
        let authenticated = FederationPeerRegistry::new([current.peer])?
            .authenticate_backup_response(
                &self.connections.client,
                &delivered,
                &outbound.expectation()?,
                NOW,
                &mut replay()?,
            )?;
        let Message::BackupCapability(response) = authenticated.message() else {
            return Err("missing backup capability".into());
        };
        assert_eq!(
            response.request_digest,
            request.capability_request_digest()?
        );
        let permit =
            decode_federated_backup_permit(response.permit.as_ref().ok_or("missing permit")?, NOW)?;
        assert_eq!(&permit.request, expected);
        Ok(())
    }
}

fn requests() -> Result<Vec<FederatedBackupRequest>, Box<dyn Error>> {
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([100; 16])?,
        deadline: UnixMicros::new(1_900_000),
        expected_revision: Some(Revision::new(50)),
    };
    let object = BackupObjectIdentity {
        backup_id: BackupId::from_bytes([101; 16])?,
        destination_id: BackupDestinationId::from_bytes([102; 16])?,
        provider_generation: 3,
        byte_length: 20,
        digest: [103; 32],
    };
    let object_reference = BackupObjectReference::new("opaque-backup-reference".to_owned())?;
    Ok(vec![
        FederatedBackupRequest::Store(BackupStoreRequest { context, object }),
        FederatedBackupRequest::Read(BackupReadRequest {
            context: RequestContext {
                operation_id: OperationId::from_bytes([104; 16])?,
                ..context
            },
            object,
            object_reference: object_reference.clone(),
        }),
        FederatedBackupRequest::Verify(BackupVerifyRequest {
            context: RequestContext {
                operation_id: OperationId::from_bytes([105; 16])?,
                ..context
            },
            object,
            object_reference: object_reference.clone(),
        }),
        FederatedBackupRequest::Delete(BackupDeleteRequest {
            context: RequestContext {
                operation_id: OperationId::from_bytes([106; 16])?,
                ..context
            },
            object,
            object_reference,
            retirement_revision: Revision::new(50),
        }),
    ])
}

fn context(
    request: &FederatedBackupRequest,
    nonce: u8,
) -> Result<FederationExchangeContext, Box<dyn Error>> {
    Ok(FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 0 },
        [120; 16],
        request.context().operation_id.as_bytes(),
        [119; 16],
        request.context().deadline,
        [nonce; 32],
    )?)
}

fn replay() -> Result<FederationReplayGuard, Box<dyn Error>> {
    Ok(FederationReplayGuard::new(
        32,
        DurationMicros::new(1_000_000),
    )?)
}

async fn deliver(
    sender: &quinn::Connection,
    receiver: &quinn::Connection,
    envelope: &FederationEnvelope,
) -> Result<ValidatedFederationEnvelope, Box<dyn Error>> {
    let limits = transport_limits()?.wire;
    let send = async {
        let (mut send, _) = open_stream(sender, StreamKind::Federation).await?;
        send_federation(&mut send, envelope, limits).await?;
        send.finish()?;
        Ok::<_, Box<dyn Error>>(())
    };
    let receive = async {
        let mut stream = accept_stream(receiver).await?;
        assert_eq!(stream.kind, StreamKind::Federation);
        Ok::<_, Box<dyn Error>>(receive_federation(&mut stream.receive, limits).await?)
    };
    let ((), envelope) = tokio::try_join!(send, receive)?;
    Ok(envelope)
}
