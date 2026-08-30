// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative metadata, bilateral grant and admission fixtures for the two-swarm proof.

use std::error::Error;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use meshspan_cluster::{
    FederationAuthoritativeCommandOutcome, FederationAuthoritativeCommandResolveFuture,
    FederationAuthoritativeCommandSubmission, FederationAuthoritativeCommandSubmitError,
    FederationAuthoritativeCommandSubmitFuture, FederationAuthoritativeCommandSubmitter,
    FederationMutationAcceptanceRequest,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuthenticationMethodId, AuthenticationService, FederationAccess,
    FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationResourceScope, MeshId, OperationId, PartitionId, PrincipalId, Revision, Rights,
    SessionId, UnixMicros, VolumeId,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, ChangePrincipalState,
    CreateAuthenticationMethod, CreateUser, FederatedActorKind, FederatedActorState,
    FederationGrantRecord, FederationGrantRestriction, FederationRemoteAuthoritySnapshot,
    IssueAuthenticationSession, IssueFederationGrant, LocalDatabase, LogPosition,
    NewAuthenticationCredential, PartitionDatabase, PrincipalLifecycleState,
    RecordFederatedActorAttestation, RecordName, SessionAccessRequest, SessionAuthenticationFactor,
    TotpAlgorithm,
};
use tempfile::{TempDir, tempdir};

use super::super::MetadataAuthorities;
use super::SYNC_NOW;

const USER_SEED: u8 = 91;
const GRANT_SEED: u8 = 92;
pub(super) const VOLUME_SEED: u8 = 93;
const TOKEN_DIGEST: [u8; 32] = [94; 32];

pub(super) struct FederationFixture {
    _client_cache_directory: TempDir,
    _server_cache_directory: TempDir,
    pub(super) client_cache: LocalDatabase,
    pub(super) server_cache: LocalDatabase,
    pub(super) user: PrincipalId,
    pub(super) grant: FederationGrantId,
    pub(super) volume: VolumeId,
    pub(super) relationship: meshspan_domain::FederationRelationshipId,
    owner_mesh: MeshId,
    pub(super) owner_database_path: PathBuf,
    pub(super) owner_administrator: PrincipalId,
    pub(super) home_gateway: meshspan_domain::NodeId,
}

impl FederationFixture {
    pub(super) fn prepare(
        authorities: &mut MetadataAuthorities,
        home_key: &SigningKey,
    ) -> Result<Self, Box<dyn Error>> {
        let user = PrincipalId::from_bytes([USER_SEED; 16])?;
        let grant = FederationGrantId::from_bytes([GRANT_SEED; 16])?;
        let volume = VolumeId::from_bytes([VOLUME_SEED; 16])?;
        configure_authoritative_state(authorities, home_key, user, grant, volume)?;
        let caches = AuthorityCaches::open(authorities, grant)?;
        assert_home_authority_observation(authorities, &caches.server, grant)?;
        Ok(Self {
            _client_cache_directory: caches.client_directory,
            _server_cache_directory: caches.server_directory,
            client_cache: caches.client,
            server_cache: caches.server,
            user,
            grant,
            volume,
            relationship: authorities.relationship_id,
            owner_mesh: authorities.client_mesh,
            owner_database_path: authorities
                .client
                .directory
                .path()
                .join("partition.sqlite3"),
            owner_administrator: authorities.client.administrator_id,
            home_gateway: authorities.server.node_id,
        })
    }

    pub(super) fn acceptance_request(
        &self,
        now: i64,
        gateway: meshspan_domain::NodeId,
    ) -> FederationMutationAcceptanceRequest {
        FederationMutationAcceptanceRequest {
            relationship_id: self.relationship,
            grant_id: self.grant,
            session: SessionAccessRequest {
                token_digest: TOKEN_DIGEST,
                required_assurance: AssuranceLevel::SingleFactor,
                gateway_node_id: gateway,
                gateway_incarnation: 1,
                now: UnixMicros::new(now),
            },
            now: UnixMicros::new(now),
        }
    }

    pub(super) fn resource(&self) -> FederationResourceScope {
        FederationResourceScope::Volume {
            owner_mesh_id: self.owner_mesh,
            volume_id: self.volume,
        }
    }

    pub(super) fn suspend_home_user(
        &mut self,
        authorities: &mut MetadataAuthorities,
        home_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        apply_next(
            &mut authorities.server.repository,
            authorities.server.administrator_id,
            31,
            &AuthoritativeCommand::ChangePrincipalState(ChangePrincipalState {
                principal_id: self.user,
                state: PrincipalLifecycleState::Suspended,
                reason: "Disconnected writer suspended".to_owned(),
                owner_transfers: BoundedItems::new(Vec::new(), 0)?,
            }),
        )?;
        let attestation = signed_attestation(
            authorities,
            self.user,
            FederatedActorState::Suspended,
            2,
            home_key,
        )?;
        apply_next(
            &mut authorities.client.repository,
            authorities.client.administrator_id,
            32,
            &AuthoritativeCommand::RecordFederatedActorAttestation(attestation),
        )
    }
}

fn configure_authoritative_state(
    authorities: &mut MetadataAuthorities,
    home_key: &SigningKey,
    user: PrincipalId,
    grant: FederationGrantId,
    volume: VolumeId,
) -> Result<(), Box<dyn Error>> {
    apply_next(
        &mut authorities.server.repository,
        authorities.server.administrator_id,
        10,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: user,
            name: RecordName::new("Disconnected writer")?,
        }),
    )?;
    issue_home_session(authorities, user)?;
    let record = grant_record(authorities, grant, volume)?;
    issue_grant(
        &mut authorities.server.repository,
        authorities.server.administrator_id,
        12,
        &record,
    )?;
    let attestation =
        signed_attestation(authorities, user, FederatedActorState::Active, 1, home_key)?;
    apply_next(
        &mut authorities.client.repository,
        authorities.client.administrator_id,
        13,
        &AuthoritativeCommand::RecordFederatedActorAttestation(attestation),
    )?;
    issue_grant(
        &mut authorities.client.repository,
        authorities.client.administrator_id,
        14,
        &record,
    )
}

fn issue_home_session(
    authorities: &mut MetadataAuthorities,
    user: PrincipalId,
) -> Result<(), Box<dyn Error>> {
    apply_next(
        &mut authorities.server.repository,
        user,
        11,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([96; 16])?,
            principal_id: user,
            label: "API key".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([98; 16])?,
                key_digest: [99; 32],
                scopes: AuthenticationService::Https.api_key_login_scope(),
                valid_from: UnixMicros::new(1),
            },
        }),
    )?;
    let api_revision = authorities.server.repository.current_revision()?;
    apply_next(
        &mut authorities.server.repository,
        user,
        12,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([97; 16])?,
            principal_id: user,
            label: "TOTP".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Totp {
                secret_ciphertext: vec![100; 64],
                algorithm: TotpAlgorithm::Sha256,
                digits: 6,
                period_seconds: 30,
                accepted_step_window: 1,
            },
        }),
    )?;
    let totp_revision = authorities.server.repository.current_revision()?;
    apply_next(
        &mut authorities.server.repository,
        user,
        13,
        &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([95; 16])?,
            principal_id: user,
            token_digest: TOKEN_DIGEST,
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![
                    SessionAuthenticationFactor::ApiKey {
                        method_id: AuthenticationMethodId::from_bytes([96; 16])?,
                        credential_generation: 1,
                        method_revision: api_revision,
                        key_id: ApiKeyId::from_bytes([98; 16])?,
                    },
                    SessionAuthenticationFactor::Totp {
                        method_id: AuthenticationMethodId::from_bytes([97; 16])?,
                        credential_generation: 1,
                        method_revision: totp_revision,
                        accepted_step: 0,
                    },
                ],
                8,
            )?,
            expires_at: UnixMicros::new(2_500_000),
        }),
    )
}

struct AuthorityCaches {
    client_directory: TempDir,
    server_directory: TempDir,
    client: LocalDatabase,
    server: LocalDatabase,
}

impl AuthorityCaches {
    fn open(
        authorities: &MetadataAuthorities,
        grant: FederationGrantId,
    ) -> Result<Self, Box<dyn Error>> {
        let client_directory = tempdir()?;
        let server_directory = tempdir()?;
        let mut client = LocalDatabase::open(
            &client_directory.path().join("remote.sqlite3"),
            authorities.client.node_id,
            UnixMicros::new(1),
        )?;
        let mut server = LocalDatabase::open(
            &server_directory.path().join("remote.sqlite3"),
            authorities.server.node_id,
            UnixMicros::new(1),
        )?;
        install_remote_snapshot(
            &mut client,
            &authorities.server.repository,
            authorities.relationship_id,
            grant,
        )?;
        install_remote_snapshot(
            &mut server,
            &authorities.client.repository,
            authorities.relationship_id,
            grant,
        )?;
        Ok(Self {
            client_directory,
            server_directory,
            client,
            server,
        })
    }
}

fn assert_home_authority_observation(
    authorities: &MetadataAuthorities,
    observed_authority: &LocalDatabase,
    grant: FederationGrantId,
) -> Result<(), Box<dyn Error>> {
    let local_grant = authorities
        .server
        .repository
        .active_federation_grant(grant)?
        .ok_or("home grant missing")?;
    let observed_grant = observed_authority
        .remote_federation_grant_authority(authorities.relationship_id, grant)?
        .ok_or("owner grant observation missing")?;
    assert_eq!(local_grant.grant, observed_grant.grant.grant);
    assert_eq!(local_grant.restrictions, observed_grant.grant.restrictions);
    let local_connection = meshspan_cluster::federation_connection_authority(
        &authorities.server.repository,
        authorities.relationship_id,
        SYNC_NOW,
    )?
    .ok_or("home connection authority missing")?;
    assert_relationship_orientation(&observed_grant.relationship, &local_connection);
    assert_identity_orientation(&observed_grant.relationship, &local_connection);
    Ok(())
}

fn assert_relationship_orientation(
    observed: &meshspan_metadata::FederationTransportAuthority,
    local: &meshspan_cluster::FederationConnectionAuthority,
) {
    assert_eq!(
        observed.relationship.local_mesh_id,
        local.peer.remote_mesh_id
    );
    assert_eq!(
        observed.relationship.remote_mesh_id,
        local.peer.local_mesh_id
    );
    assert_eq!(observed.relationship.kind, local.relationship_kind);
    assert_eq!(
        observed.relationship.governance_direction,
        local.governance_direction
    );
}

fn assert_identity_orientation(
    observed: &meshspan_metadata::FederationTransportAuthority,
    local: &meshspan_cluster::FederationConnectionAuthority,
) {
    assert_eq!(
        observed.local_identity.identity.verifying_key,
        local.peer.verifying_key
    );
    assert_eq!(
        observed.remote_identity.identity.verifying_key,
        local.local_identity.verifying_key
    );
    let observed_peer = observed.local_identity.identity;
    assert_eq!(
        (
            observed_peer.generation,
            observed_peer.certificate_fingerprint,
            observed_peer.valid_from,
            observed_peer.valid_until,
        ),
        (
            local.peer.identity_generation,
            local.peer.certificate_fingerprint,
            local.peer.valid_from,
            local.peer.valid_until,
        )
    );
    let observed_home = observed.remote_identity.identity;
    assert_eq!(
        (
            observed_home.generation,
            observed_home.certificate_fingerprint,
            observed_home.valid_from,
            observed_home.valid_until,
        ),
        (
            local.local_identity.identity_generation,
            local.local_identity.certificate_fingerprint,
            local.local_identity.valid_from,
            local.local_identity.valid_until,
        )
    );
}

fn grant_record(
    authorities: &MetadataAuthorities,
    grant_id: FederationGrantId,
    volume_id: VolumeId,
) -> Result<FederationGrantRecord, Box<dyn Error>> {
    let policy = FederationPolicy::Namespace(meshspan_domain::NamespaceFederationPolicy::new(
        FederationAccess::new(
            Rights::TRAVERSE
                .union(Rights::READ_DATA)
                .union(Rights::WRITE_DATA),
            false,
        ),
        None,
    ));
    let restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: authorities.client_mesh,
            policy,
        },
        FederationGrantRestriction {
            imposing_mesh_id: authorities.server_mesh,
            policy,
        },
    ];
    Ok(FederationGrantRecord {
        grant: FederationGrant::new(
            grant_id,
            authorities.relationship_id,
            FederationGrantRoute::direct(authorities.client_mesh, authorities.server_mesh)?,
            None,
            FederationResourceScope::Volume {
                owner_mesh_id: authorities.client_mesh,
                volume_id,
            },
            policy,
            1,
            UnixMicros::new(1),
            Some(UnixMicros::new(2_500_000)),
        )?,
        restrictions,
        state: meshspan_metadata::FederationGrantState::Active,
        issued_at: UnixMicros::new(12),
        termination: None,
        predecessor_grant_id: None,
        successor_grant_id: None,
        revision: Revision::new(1),
    })
}

fn issue_grant(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
    occurred_at: i64,
    record: &FederationGrantRecord,
) -> Result<(), Box<dyn Error>> {
    apply_next(
        repository,
        administrator,
        occurred_at,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: record.grant.clone(),
            restrictions: BoundedItems::new(record.restrictions.clone(), 2)?,
        }),
    )
}

fn signed_attestation(
    authorities: &MetadataAuthorities,
    user: PrincipalId,
    state: FederatedActorState,
    identity_revision: u64,
    home_key: &SigningKey,
) -> Result<RecordFederatedActorAttestation, Box<dyn Error>> {
    let mut attestation = RecordFederatedActorAttestation {
        relationship_id: authorities.relationship_id,
        home_mesh_id: authorities.server_mesh,
        principal_id: user,
        kind: FederatedActorKind::User,
        name: RecordName::new("Disconnected writer")?,
        state,
        identity_revision,
        authority_epoch: 1,
        signer_generation: 1,
        signature: [0; 64],
    };
    attestation.signature = home_key.sign(&attestation.signing_payload()).to_bytes();
    Ok(attestation)
}

fn install_remote_snapshot(
    cache: &mut LocalDatabase,
    remote: &AuthoritativeRepository,
    relationship_id: meshspan_domain::FederationRelationshipId,
    grant_id: FederationGrantId,
) -> Result<(), Box<dyn Error>> {
    let authority_revision = remote.current_revision()?;
    let relationship = remote
        .federation_transport_authority(relationship_id)?
        .ok_or("missing remote relationship")?;
    let grant = remote
        .active_federation_grant(grant_id)?
        .ok_or("missing remote grant")?;
    cache.install_remote_federation_authority(
        &FederationRemoteAuthoritySnapshot {
            after_revision: Revision::ZERO,
            authority_revision,
            relationship,
            grants: vec![grant],
        },
        UnixMicros::new(15),
    )?;
    Ok(())
}

fn apply_next(
    repository: &mut AuthoritativeRepository,
    actor: PrincipalId,
    occurred_at: i64,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn Error>> {
    let current = repository.current_revision()?;
    let next = current.next()?;
    repository.apply_committed(
        LogPosition {
            index: next.get(),
            term: 1,
        },
        meshspan_metadata::CommandContext {
            operation_id: OperationId::from_bytes([u8::try_from(next.get())?; 16])?,
            actor_principal_id: actor,
            audit_event_id: meshspan_domain::AuditEventId::from_bytes(
                [u8::try_from(next.get())?.saturating_add(150); 16],
            )?,
            occurred_at: UnixMicros::new(occurred_at),
            expected_revision: Some(current),
        },
        command,
    )?;
    Ok(())
}

#[derive(Clone)]
pub(super) struct DatabaseCommitSubmitter {
    database_path: PathBuf,
    partition_id: PartitionId,
}

impl DatabaseCommitSubmitter {
    pub(super) fn new(database_path: impl Into<PathBuf>, partition_id: PartitionId) -> Self {
        Self {
            database_path: database_path.into(),
            partition_id,
        }
    }

    fn resolve_now(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<FederationAuthoritativeCommandOutcome>,
        FederationAuthoritativeCommandSubmitError,
    > {
        let repository = open_repository(&self.database_path, self.partition_id)?;
        repository
            .resolve_federated_mutation_admission(operation_id)
            .map(|resolved| {
                resolved.map(|value| FederationAuthoritativeCommandOutcome {
                    receipt: value.receipt,
                    admission: value.admission,
                })
            })
            .map_err(|_| FederationAuthoritativeCommandSubmitError::Rejected)
    }
}

impl FederationAuthoritativeCommandSubmitter for DatabaseCommitSubmitter {
    fn resolve(
        &self,
        operation_id: OperationId,
    ) -> FederationAuthoritativeCommandResolveFuture<'_> {
        Box::pin(async move { self.resolve_now(operation_id) })
    }

    fn submit(
        &self,
        submission: FederationAuthoritativeCommandSubmission,
    ) -> FederationAuthoritativeCommandSubmitFuture<'_> {
        Box::pin(async move {
            let mut repository = open_repository(&self.database_path, self.partition_id)?;
            let current = repository
                .current_revision()
                .map_err(|_| FederationAuthoritativeCommandSubmitError::Rejected)?;
            let next = current
                .next()
                .map_err(|_| FederationAuthoritativeCommandSubmitError::Rejected)?;
            repository
                .apply_committed(
                    LogPosition {
                        index: next.get(),
                        term: 1,
                    },
                    submission.context,
                    &submission.command,
                )
                .map_err(|_| FederationAuthoritativeCommandSubmitError::Rejected)?;
            drop(repository);
            self.resolve_now(submission.context.operation_id)?
                .ok_or(FederationAuthoritativeCommandSubmitError::Rejected)
        })
    }
}

fn open_repository(
    database_path: &Path,
    partition_id: PartitionId,
) -> Result<AuthoritativeRepository, FederationAuthoritativeCommandSubmitError> {
    PartitionDatabase::open(database_path, partition_id, SYNC_NOW)
        .map(AuthoritativeRepository::new)
        .map_err(|_| FederationAuthoritativeCommandSubmitError::Unavailable)
}
