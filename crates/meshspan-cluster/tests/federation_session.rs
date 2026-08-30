// SPDX-License-Identifier: GPL-2.0-only

//! Real Quinn proof for metadata-reloaded federation session admission, rotation and revocation.

#[path = "federation_session/authority_page_proof.rs"]
mod authority_page_proof;
#[path = "federation_session/branch_page_proof.rs"]
mod branch_page_proof;
#[path = "federation_session/history_sync_proof.rs"]
mod history_sync_proof;
#[path = "federation_session/storage_capability_proof.rs"]
mod storage_capability_proof;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use meshspan_cluster::{
    FederationAcceptRequest, FederationAuthorityPageQuery, FederationAuthorityPageSource,
    FederationAuthorityPageSourceError, FederationDialRequest, FederationSessionError,
    FederationSessionRuntime,
};
use meshspan_domain::{
    AuditEventId, DurationMicros, FederationGrantId, FederationRelationshipId,
    FederationRelationshipKind, FederationStorageAllocation, FederationStorageAllocationId, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId, TargetId, UnixMicros,
};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    CommandContext, FederationGovernanceDirection, FederationIdentityOwner,
    FederationTrustIdentity, IssueFederationStorageAllocation, LogPosition, PartitionDatabase,
    ProposeFederationRelationship, RecordName, RevokeFederationRelationship,
    RotateFederationTrustIdentity,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_transport::{
    FederationHelloConfig, FederationHelloContext, FederationNegotiationConfig,
    FederationReplayGuard, FederationWelcomeNonces, NodeCredentials, TransportError,
    TransportLimits, client_endpoint, connect, server_endpoint,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use authority_page_proof::{
    prove_initial_authority, prove_rotated_authority, storage_grant_command,
};
use storage_capability_proof::{
    prove_protection_only_read_fails_closed, prove_revoked_storage_inventory_fails_closed,
    prove_storage_capability_exchange,
};

const CERTIFICATE_NAME: &str = "meshspan.internal";
const NOW: UnixMicros = UnixMicros::new(1_500_000);

#[tokio::test]
async fn current_metadata_authority_admits_rotates_then_revokes_a_real_federation_session()
-> Result<(), Box<dyn Error>> {
    let certificates = Certificates::new()?;
    let limits = transport_limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority)?,
        limits,
    )?;
    let initial_connections = ConnectionPair::establish(
        &server,
        certificates.client_credentials()?,
        roots(&certificates.authority)?,
        limits,
    )
    .await?;
    let client_key = SigningKey::from_bytes(&[4; 32]);
    let server_key = SigningKey::from_bytes(&[5; 32]);
    let mut authorities = MetadataAuthorities::active(&certificates, &client_key, &server_key)?;
    let client_runtime = runtime(&certificates.client, &client_key, limits.wire)?;
    let server_runtime = runtime(&certificates.server, &server_key, limits.wire)?;
    let initial_runtimes = SessionRuntimes::new(&client_runtime, &server_runtime);
    let initial_proof = authorities.proof(
        initial_runtimes,
        &initial_connections,
        SessionExpectation::new(6, 3, 1),
    );
    prove_initial_authority(&initial_proof).await?;

    let rotated_client_key = SigningKey::from_bytes(&[10; 32]);
    authorities.rotate_remote(50, &certificates.rotated_client, &rotated_client_key)?;
    prove_retired_remote_identity_fails_closed(&authorities.proof(
        initial_runtimes,
        &initial_connections,
        SessionExpectation::new(10, 4, 2),
    ))
    .await?;
    authorities.rotate_local(55, &certificates.rotated_client, &rotated_client_key)?;
    let expected_grants = authorities.issue_server_grants(70, &[true, false])?;
    let rotated_client_runtime = runtime(
        &certificates.rotated_client,
        &rotated_client_key,
        limits.wire,
    )?;
    let rotated_connections = ConnectionPair::establish(
        &server,
        certificates.rotated_client_credentials()?,
        roots(&certificates.authority)?,
        limits,
    )
    .await?;
    let rotated_runtimes = SessionRuntimes::new(&rotated_client_runtime, &server_runtime);
    let stale_cursor = {
        let rotated_proof = authorities.proof(
            rotated_runtimes,
            &rotated_connections,
            SessionExpectation::new(14, 6, 2),
        );
        prove_rotated_authority(&rotated_proof, &expected_grants).await?
    };
    let (allocation, provider_node_id) = prove_server_storage(
        &mut authorities,
        rotated_runtimes,
        &rotated_connections,
        &expected_grants,
    )
    .await?;
    authorities.issue_server_grants(80, &[true])?;
    assert!(matches!(
        authorities
            .server
            .repository()
            .authority_page(FederationAuthorityPageQuery {
                relationship_id: authorities.relationship_id,
                after_revision: 3,
                cursor: stale_cursor,
                limit: 1,
                authority_revision: Revision::new(6),
            }),
        Err(FederationAuthorityPageSourceError::Unavailable)
    ));
    revoke_and_prove_fencing(
        &mut authorities,
        rotated_runtimes,
        &rotated_connections,
        allocation,
        provider_node_id,
    )
    .await?;

    initial_connections.close_and_wait().await;
    rotated_connections.close_and_wait().await;
    server.wait_idle().await;
    Ok(())
}

async fn prove_server_storage(
    authorities: &mut MetadataAuthorities,
    runtimes: SessionRuntimes<'_>,
    connections: &ConnectionPair,
    grants: &[FederationGrantId],
) -> Result<(FederationStorageAllocation, NodeId), Box<dyn Error>> {
    let [read_grant, protection_grant] = grants else {
        return Err("storage proof requires exactly two grants".into());
    };
    let (allocation, provider_node_id) =
        authorities.issue_server_storage_allocation(75, *read_grant, Revision::new(5))?;
    let (protection_only_allocation, protection_provider_node_id) =
        authorities.issue_server_storage_allocation(78, *protection_grant, Revision::new(6))?;
    let proof = authorities.proof(runtimes, connections, SessionExpectation::new(76, 8, 2));
    Box::pin(prove_storage_capability_exchange(
        &proof,
        allocation,
        provider_node_id,
    ))
    .await?;
    prove_protection_only_read_fails_closed(
        &proof,
        protection_only_allocation,
        protection_provider_node_id,
    )
    .await?;
    Ok((allocation, provider_node_id))
}

async fn revoke_and_prove_fencing(
    authorities: &mut MetadataAuthorities,
    runtimes: SessionRuntimes<'_>,
    connections: &ConnectionPair,
    allocation: FederationStorageAllocation,
    provider_node_id: NodeId,
) -> Result<(), Box<dyn Error>> {
    authorities.revoke(60)?;
    let proof = authorities.proof(runtimes, connections, SessionExpectation::new(18, 8, 2));
    prove_revoked_storage_inventory_fails_closed(&proof, allocation, provider_node_id).await?;
    prove_revoked_session_fails_closed(&proof).await
}

#[derive(Clone, Copy)]
struct SessionRuntimes<'a> {
    client: &'a FederationSessionRuntime<'a>,
    server: &'a FederationSessionRuntime<'a>,
}

impl<'a> SessionRuntimes<'a> {
    const fn new(
        client: &'a FederationSessionRuntime<'a>,
        server: &'a FederationSessionRuntime<'a>,
    ) -> Self {
        Self { client, server }
    }
}

#[derive(Clone, Copy)]
struct SessionExpectation {
    seed: u8,
    remote_authority_revision: u64,
    remote_identity_generation: u64,
}

impl SessionExpectation {
    const fn new(
        seed: u8,
        remote_authority_revision: u64,
        remote_identity_generation: u64,
    ) -> Self {
        Self {
            seed,
            remote_authority_revision,
            remote_identity_generation,
        }
    }
}

struct ConnectionPair {
    client_endpoint: quinn::Endpoint,
    client: quinn::Connection,
    server: quinn::Connection,
}

impl ConnectionPair {
    async fn establish(
        server_endpoint: &quinn::Endpoint,
        credentials: NodeCredentials,
        roots: RootCertStore,
        limits: TransportLimits,
    ) -> Result<Self, Box<dyn Error>> {
        let client_endpoint = client_endpoint(loopback(), credentials, roots, limits)?;
        let server_address = server_endpoint.local_addr()?;
        let incoming = async {
            server_endpoint
                .accept()
                .await
                .ok_or(TransportError::InvalidConfiguration)?
                .await
                .map_err(TransportError::from)
        };
        let (client, server) = tokio::try_join!(
            connect(&client_endpoint, server_address, CERTIFICATE_NAME),
            incoming
        )?;
        Ok(Self {
            client_endpoint,
            client,
            server,
        })
    }

    async fn close_and_wait(&self) {
        self.client.close(0_u32.into(), b"proof complete");
        self.server.close(0_u32.into(), b"proof complete");
        self.client_endpoint.wait_idle().await;
    }
}

struct MetadataAuthorities {
    client: MetadataAuthority,
    server: MetadataAuthority,
    relationship_id: FederationRelationshipId,
    client_mesh: MeshId,
    server_mesh: MeshId,
}

impl MetadataAuthorities {
    fn active(
        certificates: &Certificates,
        client_key: &SigningKey,
        server_key: &SigningKey,
    ) -> Result<Self, Box<dyn Error>> {
        let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
        let client_mesh = MeshId::from_bytes([2; 16])?;
        let server_mesh = MeshId::from_bytes([3; 16])?;
        let client = MetadataAuthority::active(
            AuthorityIdentity {
                seed: 20,
                local_certificate: &certificates.client,
                local_key: client_key,
                remote_certificate: &certificates.server,
                remote_key: server_key,
            },
            relationship_id,
            client_mesh,
            server_mesh,
        )?;
        let server = MetadataAuthority::active(
            AuthorityIdentity {
                seed: 40,
                local_certificate: &certificates.server,
                local_key: server_key,
                remote_certificate: &certificates.client,
                remote_key: client_key,
            },
            relationship_id,
            server_mesh,
            client_mesh,
        )?;
        Ok(Self {
            client,
            server,
            relationship_id,
            client_mesh,
            server_mesh,
        })
    }

    fn proof<'a>(
        &'a self,
        runtimes: SessionRuntimes<'a>,
        connections: &'a ConnectionPair,
        expectation: SessionExpectation,
    ) -> SessionProof<'a> {
        SessionProof {
            client_runtime: runtimes.client,
            server_runtime: runtimes.server,
            client_connection: &connections.client,
            server_connection: &connections.server,
            client_authority: self.client.repository(),
            server_authority: self.server.repository(),
            relationship_id: self.relationship_id,
            server_mesh: self.server_mesh,
            client_mesh: self.client_mesh,
            session_seed: expectation.seed,
            expected_remote_authority_revision: expectation.remote_authority_revision,
            expected_remote_identity_generation: expectation.remote_identity_generation,
        }
    }

    fn rotate_local(
        &mut self,
        seed: u8,
        certificate: &CertificateDer<'_>,
        signing_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        self.client.rotate_local(seed, certificate, signing_key)
    }

    fn rotate_remote(
        &mut self,
        seed: u8,
        certificate: &CertificateDer<'_>,
        signing_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        self.server.rotate_remote(seed, certificate, signing_key)
    }

    fn revoke(&mut self, seed: u8) -> Result<(), Box<dyn Error>> {
        self.server.revoke(seed)
    }

    fn issue_server_grants(
        &mut self,
        seed: u8,
        read_participation: &[bool],
    ) -> Result<Vec<FederationGrantId>, Box<dyn Error>> {
        self.server.issue_storage_grants(
            seed,
            read_participation,
            self.client_mesh,
            self.server_mesh,
        )
    }

    fn issue_server_storage_allocation(
        &mut self,
        seed: u8,
        grant_id: FederationGrantId,
        expected_grant_revision: Revision,
    ) -> Result<(FederationStorageAllocation, NodeId), Box<dyn Error>> {
        self.server
            .issue_storage_allocation(seed, grant_id, expected_grant_revision)
    }
}

struct SessionProof<'a> {
    client_runtime: &'a FederationSessionRuntime<'a>,
    server_runtime: &'a FederationSessionRuntime<'a>,
    client_connection: &'a quinn::Connection,
    server_connection: &'a quinn::Connection,
    client_authority: &'a AuthoritativeRepository,
    server_authority: &'a AuthoritativeRepository,
    relationship_id: FederationRelationshipId,
    server_mesh: MeshId,
    client_mesh: MeshId,
    session_seed: u8,
    expected_remote_authority_revision: u64,
    expected_remote_identity_generation: u64,
}

async fn prove_admitted_session(proof: &SessionProof<'_>) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let dial = proof.client_runtime.dial(
        proof.client_connection,
        proof.client_authority,
        dial_request(proof.relationship_id, proof.session_seed)?,
        &mut client_replay,
    );
    let accept = proof.server_runtime.accept(
        proof.server_connection,
        proof.server_authority,
        accept_request(proof.session_seed.saturating_add(1))?,
        &mut server_replay,
    );
    let (client_session, server_session) = tokio::try_join!(dial, accept)?;
    assert_eq!(client_session.relationship_id, proof.relationship_id);
    assert_eq!(client_session.remote_mesh_id, proof.server_mesh);
    assert_eq!(
        client_session.remote_authority_revision,
        proof.expected_remote_authority_revision
    );
    assert_eq!(server_session.relationship_id, proof.relationship_id);
    assert_eq!(server_session.remote_mesh_id, proof.client_mesh);
    assert_eq!(
        server_session.remote_identity_generation,
        proof.expected_remote_identity_generation
    );
    assert_eq!(
        client_session.version,
        ProtocolVersion { major: 1, minor: 1 }
    );
    assert_eq!(server_session.version, client_session.version);
    Ok(())
}

async fn prove_retired_remote_identity_fails_closed(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let dial_request = dial_request(proof.relationship_id, proof.session_seed)?;
    let accept_request = accept_request(proof.session_seed.saturating_add(1))?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.dial(
                proof.client_connection,
                proof.client_authority,
                dial_request,
                &mut client_replay,
            ),
            proof.server_runtime.accept(
                proof.server_connection,
                proof.server_authority,
                accept_request,
                &mut server_replay,
            )
        )
    };
    let (dial, accept) = tokio::time::timeout(Duration::from_secs(2), attempts).await?;
    assert!(dial.is_err());
    assert!(matches!(accept, Err(FederationSessionError::Transport(_))));
    Ok(())
}

async fn prove_revoked_session_fails_closed(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let dial_request = dial_request(proof.relationship_id, proof.session_seed)?;
    let accept_request = accept_request(proof.session_seed.saturating_add(1))?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.dial(
                proof.client_connection,
                proof.client_authority,
                dial_request,
                &mut client_replay,
            ),
            proof.server_runtime.accept(
                proof.server_connection,
                proof.server_authority,
                accept_request,
                &mut server_replay,
            )
        )
    };
    let (dial, accept) = tokio::time::timeout(Duration::from_secs(2), attempts).await?;
    assert!(dial.is_err());
    assert!(matches!(
        accept,
        Err(FederationSessionError::AuthorityUnavailable)
    ));
    Ok(())
}

struct MetadataAuthority {
    _directory: tempfile::TempDir,
    repository: AuthoritativeRepository,
    administrator_id: PrincipalId,
    relationship_id: FederationRelationshipId,
    node_id: NodeId,
}

impl MetadataAuthority {
    fn active(
        identity: AuthorityIdentity<'_>,
        relationship_id: FederationRelationshipId,
        local_mesh_id: MeshId,
        remote_mesh_id: MeshId,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let partition_id = PartitionId::from_bytes([identity.seed; 16])?;
        let administrator_id = PrincipalId::from_bytes([identity.seed.saturating_add(1); 16])?;
        let database = PartitionDatabase::open(
            &directory.path().join("partition.sqlite3"),
            partition_id,
            UnixMicros::new(0),
        )?;
        let mut repository = AuthoritativeRepository::new(database);
        let node_id = NodeId::from_bytes([identity.seed.saturating_add(5); 16])?;
        apply_bootstrap(
            &mut repository,
            identity.seed,
            administrator_id,
            local_mesh_id,
        )?;
        apply_relationship(
            &mut repository,
            identity,
            administrator_id,
            relationship_id,
            remote_mesh_id,
        )?;
        Ok(Self {
            _directory: directory,
            repository,
            administrator_id,
            relationship_id,
            node_id,
        })
    }

    const fn repository(&self) -> &AuthoritativeRepository {
        &self.repository
    }

    fn revoke(&mut self, seed: u8) -> Result<(), Box<dyn Error>> {
        let current = self.repository.current_revision()?;
        let next = current.next()?;
        apply(
            &mut self.repository,
            next.get(),
            context(seed, self.administrator_id, next.get(), current.get())?,
            &AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
                relationship_id: self.relationship_id,
                expected_authority_epoch: 1,
                authority_epoch: 2,
                reason: "Proof revocation".to_owned(),
            }),
        )
    }

    fn issue_storage_grants(
        &mut self,
        seed: u8,
        read_participation: &[bool],
        consumer_mesh_id: MeshId,
        provider_mesh_id: MeshId,
    ) -> Result<Vec<FederationGrantId>, Box<dyn Error>> {
        let mut grant_ids = Vec::with_capacity(read_participation.len());
        let grant_count = u8::try_from(read_participation.len())?;
        for (index, serves_reads) in read_participation.iter().copied().enumerate() {
            let offset = u8::try_from(index)?;
            let grant_id = FederationGrantId::from_bytes([seed.saturating_add(offset); 16])?;
            let current = self.repository.current_revision()?;
            let next = current.next()?;
            apply(
                &mut self.repository,
                next.get(),
                context(
                    seed.saturating_add(grant_count).saturating_add(offset),
                    self.administrator_id,
                    next.get(),
                    current.get(),
                )?,
                &storage_grant_command(
                    grant_id,
                    self.relationship_id,
                    consumer_mesh_id,
                    provider_mesh_id,
                    serves_reads,
                )?,
            )?;
            grant_ids.push(grant_id);
        }
        Ok(grant_ids)
    }

    fn issue_storage_allocation(
        &mut self,
        seed: u8,
        grant_id: FederationGrantId,
        expected_grant_revision: Revision,
    ) -> Result<(FederationStorageAllocation, NodeId), Box<dyn Error>> {
        let allocation = FederationStorageAllocation::new(
            FederationStorageAllocationId::from_bytes([seed; 16])?,
            grant_id,
            self.node_id,
            TargetId::from_bytes([seed.saturating_add(1); 16])?,
            1,
            50,
            UnixMicros::new(1_000_000),
            UnixMicros::new(2_500_000),
        )?;
        let current = self.repository.current_revision()?;
        let next = current.next()?;
        apply(
            &mut self.repository,
            next.get(),
            context(
                seed.saturating_add(2),
                self.administrator_id,
                next.get(),
                current.get(),
            )?,
            &AuthoritativeCommand::IssueFederationStorageAllocation(
                IssueFederationStorageAllocation {
                    allocation,
                    expected_grant_revision,
                },
            ),
        )?;
        Ok((allocation, self.node_id))
    }

    fn rotate_local(
        &mut self,
        seed: u8,
        certificate: &CertificateDer<'_>,
        signing_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        self.rotate(
            seed,
            FederationIdentityOwner::Local,
            certificate,
            signing_key,
        )
    }

    fn rotate_remote(
        &mut self,
        seed: u8,
        certificate: &CertificateDer<'_>,
        signing_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        self.rotate(
            seed,
            FederationIdentityOwner::Remote,
            certificate,
            signing_key,
        )
    }

    fn rotate(
        &mut self,
        seed: u8,
        owner: FederationIdentityOwner,
        certificate: &CertificateDer<'_>,
        signing_key: &SigningKey,
    ) -> Result<(), Box<dyn Error>> {
        apply(
            &mut self.repository,
            4,
            context(seed, self.administrator_id, 4, 3)?,
            &AuthoritativeCommand::RotateFederationTrustIdentity(RotateFederationTrustIdentity {
                relationship_id: self.relationship_id,
                expected_authority_epoch: 1,
                owner,
                identity: trust_identity_with_generation(2, certificate, signing_key),
            }),
        )
    }
}

#[derive(Clone, Copy)]
struct AuthorityIdentity<'a> {
    seed: u8,
    local_certificate: &'a CertificateDer<'a>,
    local_key: &'a SigningKey,
    remote_certificate: &'a CertificateDer<'a>,
    remote_key: &'a SigningKey,
}

fn apply_bootstrap(
    repository: &mut AuthoritativeRepository,
    seed: u8,
    administrator_id: PrincipalId,
    mesh_id: MeshId,
) -> Result<(), Box<dyn Error>> {
    apply(
        repository,
        1,
        context(seed.saturating_add(2), administrator_id, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id,
            mesh_name: RecordName::new("Local swarm")?,
            administrator_id,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([seed.saturating_add(3); 16])?,
            host_id: HostId::from_bytes([seed.saturating_add(4); 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([seed.saturating_add(5); 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )
}

fn apply_relationship(
    repository: &mut AuthoritativeRepository,
    identity: AuthorityIdentity<'_>,
    administrator_id: PrincipalId,
    relationship_id: FederationRelationshipId,
    remote_mesh_id: MeshId,
) -> Result<(), Box<dyn Error>> {
    apply(
        repository,
        2,
        context(identity.seed.saturating_add(6), administrator_id, 2, 1)?,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id,
            remote_name: RecordName::new("Remote swarm")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply(
        repository,
        3,
        context(identity.seed.saturating_add(7), administrator_id, 3, 2)?,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            local_identity: trust_identity(identity.local_certificate, identity.local_key),
            remote_identity: trust_identity(identity.remote_certificate, identity.remote_key),
            governance_proof: None,
        }),
    )
}

fn trust_identity(
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
) -> FederationTrustIdentity {
    trust_identity_with_generation(1, certificate, signing_key)
}

fn trust_identity_with_generation(
    generation: u64,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: meshspan_transport::certificate_fingerprint(certificate),
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(3_000_000),
    }
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn Error>> {
    repository.apply_committed(LogPosition { index, term: 1 }, context, command)?;
    Ok(())
}

fn context(
    seed: u8,
    actor: PrincipalId,
    revision: u64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([seed; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([seed.saturating_add(1); 16])?,
        occurred_at: UnixMicros::new(i64::try_from(revision)?),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}

fn runtime<'a>(
    certificate: &'a CertificateDer<'_>,
    signing_key: &'a SigningKey,
    limits: WireLimits,
) -> Result<FederationSessionRuntime<'a>, TransportError> {
    Ok(FederationSessionRuntime::new(
        certificate.as_ref(),
        signing_key,
        FederationHelloConfig::new(versions(), vec![1], limits, 64)?,
        FederationNegotiationConfig::new(versions(), limits, 64)?,
    ))
}

fn dial_request(
    relationship_id: FederationRelationshipId,
    seed: u8,
) -> Result<FederationDialRequest, TransportError> {
    Ok(FederationDialRequest {
        relationship_id,
        context: FederationHelloContext::new(
            [seed; 16],
            [seed.saturating_add(1); 16],
            [seed.saturating_add(2); 16],
            UnixMicros::new(2_000_000),
            [seed.saturating_add(3); 32],
            [seed.saturating_add(4); 32],
        )?,
        now: NOW,
    })
}

fn accept_request(seed: u8) -> Result<FederationAcceptRequest, TransportError> {
    Ok(FederationAcceptRequest {
        nonces: FederationWelcomeNonces::new(
            [seed.saturating_add(20); 32],
            [seed.saturating_add(21); 32],
        )?,
        now: NOW,
    })
}

fn replay_guard() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(32, DurationMicros::new(1_000_000))
}

fn versions() -> Vec<ProtocolVersion> {
    vec![
        ProtocolVersion { major: 1, minor: 0 },
        ProtocolVersion { major: 1, minor: 1 },
    ]
}

struct Certificates {
    authority: CertificateDer<'static>,
    server: CertificateDer<'static>,
    server_key: Vec<u8>,
    client: CertificateDer<'static>,
    client_key: Vec<u8>,
    rotated_client: CertificateDer<'static>,
    rotated_client_key: Vec<u8>,
}

impl Certificates {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        let authority_key = KeyPair::generate()?;
        let authority = parameters.self_signed(&authority_key)?;
        let authority_der = authority.der().clone();
        let issuer = Issuer::new(parameters, authority_key);
        let (server, server_key) = leaf(&issuer)?;
        let (client, client_key) = leaf(&issuer)?;
        let (rotated_client, rotated_client_key) = leaf(&issuer)?;
        Ok(Self {
            authority: authority_der,
            server,
            server_key,
            client,
            client_key,
            rotated_client,
            rotated_client_key,
        })
    }

    fn server_credentials(&self) -> Result<NodeCredentials, TransportError> {
        credentials(&self.server, &self.server_key)
    }

    fn client_credentials(&self) -> Result<NodeCredentials, TransportError> {
        credentials(&self.client, &self.client_key)
    }

    fn rotated_client_credentials(&self) -> Result<NodeCredentials, TransportError> {
        credentials(&self.rotated_client, &self.rotated_client_key)
    }
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
) -> Result<(CertificateDer<'static>, Vec<u8>), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()])?;
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    let key = KeyPair::generate()?;
    let certificate: Certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.der().clone(), key.serialize_der()))
}

fn credentials(
    certificate: &CertificateDer<'static>,
    private_key: &[u8],
) -> Result<NodeCredentials, TransportError> {
    NodeCredentials::new(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(private_key.to_vec()).into(),
    )
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    Ok(roots)
}

fn transport_limits() -> Result<TransportLimits, Box<dyn Error>> {
    let wire = WireLimits::new(64 * 1_024, 64 * 1_024, 256, 4_096)?;
    Ok(TransportLimits::new(
        wire,
        128,
        64 * 1_024,
        4 * 1_024 * 1_024,
    )?)
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}
