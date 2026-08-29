// SPDX-License-Identifier: GPL-2.0-only

//! Real Quinn proof for metadata-reloaded federation session admission and revocation.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use meshspan_cluster::{
    FederationAcceptRequest, FederationDialRequest, FederationSessionError,
    FederationSessionRuntime,
};
use meshspan_domain::{
    AuditEventId, DurationMicros, FederationRelationshipId, FederationRelationshipKind, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    CommandContext, FederationGovernanceDirection, FederationTrustIdentity, LogPosition,
    PartitionDatabase, ProposeFederationRelationship, RecordName, RevokeFederationRelationship,
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

const CERTIFICATE_NAME: &str = "meshspan.internal";
const NOW: UnixMicros = UnixMicros::new(1_500_000);

#[tokio::test]
async fn current_metadata_authority_admits_then_revokes_a_real_federation_session()
-> Result<(), Box<dyn Error>> {
    let certificates = Certificates::new()?;
    let limits = transport_limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority)?,
        limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority)?,
        limits,
    )?;
    let server_address = server.local_addr()?;
    let incoming = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    let (client_connection, server_connection) =
        tokio::try_join!(connect(&client, server_address, CERTIFICATE_NAME), incoming)?;

    let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
    let client_mesh = MeshId::from_bytes([2; 16])?;
    let server_mesh = MeshId::from_bytes([3; 16])?;
    let client_key = SigningKey::from_bytes(&[4; 32]);
    let server_key = SigningKey::from_bytes(&[5; 32]);
    let client_authority = MetadataAuthority::active(
        AuthorityIdentity {
            seed: 20,
            local_certificate: &certificates.client,
            local_key: &client_key,
            remote_certificate: &certificates.server,
            remote_key: &server_key,
        },
        relationship_id,
        client_mesh,
        server_mesh,
    )?;
    let mut server_authority = MetadataAuthority::active(
        AuthorityIdentity {
            seed: 40,
            local_certificate: &certificates.server,
            local_key: &server_key,
            remote_certificate: &certificates.client,
            remote_key: &client_key,
        },
        relationship_id,
        server_mesh,
        client_mesh,
    )?;
    let client_runtime = runtime(&certificates.client, &client_key, limits.wire)?;
    let server_runtime = runtime(&certificates.server, &server_key, limits.wire)?;

    {
        let proof = SessionProof {
            client_runtime: &client_runtime,
            server_runtime: &server_runtime,
            client_connection: &client_connection,
            server_connection: &server_connection,
            client_authority: client_authority.repository(),
            server_authority: server_authority.repository(),
            relationship_id,
            server_mesh,
            client_mesh,
        };
        prove_admitted_session(&proof).await?;
    }
    server_authority.revoke(60)?;
    {
        let proof = SessionProof {
            client_runtime: &client_runtime,
            server_runtime: &server_runtime,
            client_connection: &client_connection,
            server_connection: &server_connection,
            client_authority: client_authority.repository(),
            server_authority: server_authority.repository(),
            relationship_id,
            server_mesh,
            client_mesh,
        };
        prove_revoked_session_fails_closed(&proof).await?;
    }

    client_connection.close(0_u32.into(), b"proof complete");
    server_connection.close(0_u32.into(), b"proof complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
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
}

async fn prove_admitted_session(proof: &SessionProof<'_>) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let dial = proof.client_runtime.dial(
        proof.client_connection,
        proof.client_authority,
        dial_request(proof.relationship_id, 6)?,
        &mut client_replay,
    );
    let accept = proof.server_runtime.accept(
        proof.server_connection,
        proof.server_authority,
        accept_request(7)?,
        &mut server_replay,
    );
    let (client_session, server_session) = tokio::try_join!(dial, accept)?;
    assert_eq!(client_session.relationship_id, proof.relationship_id);
    assert_eq!(client_session.remote_mesh_id, proof.server_mesh);
    assert_eq!(client_session.remote_authority_revision, 3);
    assert_eq!(server_session.relationship_id, proof.relationship_id);
    assert_eq!(server_session.remote_mesh_id, proof.client_mesh);
    assert_eq!(server_session.remote_identity_generation, 1);
    assert_eq!(
        client_session.version,
        ProtocolVersion { major: 1, minor: 1 }
    );
    assert_eq!(server_session.version, client_session.version);
    Ok(())
}

async fn prove_revoked_session_fails_closed(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let dial_request = dial_request(proof.relationship_id, 8)?;
    let accept_request = accept_request(9)?;
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
        })
    }

    const fn repository(&self) -> &AuthoritativeRepository {
        &self.repository
    }

    fn revoke(&mut self, seed: u8) -> Result<(), Box<dyn Error>> {
        apply(
            &mut self.repository,
            4,
            context(seed, self.administrator_id, 4, 3)?,
            &AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
                relationship_id: self.relationship_id,
                expected_authority_epoch: 1,
                authority_epoch: 2,
                reason: "Proof revocation".to_owned(),
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
    FederationTrustIdentity {
        generation: 1,
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
        Ok(Self {
            authority: authority_der,
            server,
            server_key,
            client,
            client_key,
        })
    }

    fn server_credentials(&self) -> Result<NodeCredentials, TransportError> {
        credentials(&self.server, &self.server_key)
    }

    fn client_credentials(&self) -> Result<NodeCredentials, TransportError> {
        credentials(&self.client, &self.client_key)
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
