// SPDX-License-Identifier: GPL-2.0-only

//! Real directory-backup lifecycle over authenticated Quinn/mTLS streams.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use meshspan_backup::DirectoryBackupProvider;
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupReadRequest, BackupStoreRequest,
    BackupVerifyRequest, ContractError, ContractVersion, RequestContext,
};
use meshspan_data_plane::{
    BackupPlaneError, RemoteBackupAuthorisation, RemoteBackupAuthority, RemoteBackupRouter,
    RemoteBackupService, delete_backup, read_backup, store_backup, verify_backup,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, MeshId, NodeId, OperationId, PartitionId, Revision, UnixMicros,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{ErrorCode, ProtocolVersion, RequestHeader};
use meshspan_test_certificates::CertificateAuthority;
use meshspan_transport::{
    AuthenticatedPeer, NodeCredentials, PeerBinding, PeerRegistry, TransportLimits, accept_stream,
    certificate_fingerprint, client_endpoint, connect, server_endpoint,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CERTIFICATE_NAME: &str = "meshspan.internal";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mtls_stream_proves_exact_remote_backup_lifecycle() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let limits = wire_limits()?;
    let transport_limits = TransportLimits::new(limits, 32, 64 * 1_024, 1024 * 1_024)?;
    let certificates = Certificates::new()?;
    let server_node = node(1)?;
    let client_node = node(2)?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let address = server.local_addr()?;
    let incoming = async {
        server
            .accept()
            .await
            .ok_or(meshspan_transport::TransportError::InvalidConfiguration)?
            .await
            .map_err(meshspan_transport::TransportError::from)
    };
    let (client_connection, server_connection) =
        tokio::try_join!(connect(&client, address, CERTIFICATE_NAME), incoming)?;
    let client_peer = authenticate(
        &server_connection,
        client_node,
        &certificates.client_certificate,
    )?;
    authenticate(
        &client_connection,
        server_node,
        &certificates.server_certificate,
    )?;

    let router = RemoteBackupRouter::new([fixture.service(client_node)?], 16)?;
    assert_eq!(router.destination_count(), 1);
    tokio::try_join!(
        serve_lifecycle(&server_connection, &router, client_peer, limits),
        prove_client_lifecycle(&client_connection, &fixture, client_node, limits),
    )?;
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

async fn serve_lifecycle(
    connection: &quinn::Connection,
    router: &RemoteBackupRouter<DirectoryBackupProvider, TestAuthority>,
    peer: AuthenticatedPeer,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    for index in 0..6 {
        router
            .serve_stream(
                accept_stream(connection).await?,
                peer,
                limits,
                UnixMicros::new(20 + index),
            )
            .await?;
    }
    Ok(())
}

async fn prove_client_lifecycle(
    connection: &quinn::Connection,
    fixture: &Fixture,
    client_node: NodeId,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let store = fixture.store_request(1)?;
    let mut rejected_source = fixture.payload.as_slice();
    assert!(matches!(
        store_backup(
            connection,
            request_header(fixture.mesh, node(99)?, store.context.operation_id)?,
            store,
            &mut rejected_source,
            limits,
            UnixMicros::new(10),
        )
        .await,
        Err(BackupPlaneError::Remote(ErrorCode::Unauthorised))
    ));

    let mut source = fixture.payload.as_slice();
    let stored = store_backup(
        connection,
        request_header(fixture.mesh, client_node, store.context.operation_id)?,
        store,
        &mut source,
        limits,
        UnixMicros::new(10),
    )
    .await?;
    let verify = fixture.verify_request(3, stored.object_reference.clone())?;
    let verified = verify_backup(
        connection,
        request_header(fixture.mesh, client_node, verify.context.operation_id)?,
        &verify,
        limits,
        UnixMicros::new(10),
    )
    .await?;
    assert_eq!(verified.operation_id, verify.context.operation_id);
    assert_eq!(verified.object, stored.object);
    assert_eq!(verified.object_reference, stored.object_reference);
    let read = fixture.read_request(2, stored.object_reference.clone())?;
    let mut destination = Vec::new();
    let receipt = read_backup(
        connection,
        request_header(fixture.mesh, client_node, read.context.operation_id)?,
        &read,
        &mut destination,
        limits,
        UnixMicros::new(10),
    )
    .await?;
    assert_eq!(destination, fixture.payload);
    assert_eq!(receipt.digest, fixture.object.digest);

    let delete = fixture.delete_request(4, stored.object_reference)?;
    delete_backup(
        connection,
        request_header(fixture.mesh, client_node, delete.context.operation_id)?,
        &delete,
        limits,
        UnixMicros::new(10),
    )
    .await?;
    let missing = fixture.verify_request(5, delete.object_reference)?;
    assert!(matches!(
        verify_backup(
            connection,
            request_header(fixture.mesh, client_node, missing.context.operation_id)?,
            &missing,
            limits,
            UnixMicros::new(10),
        )
        .await,
        Err(BackupPlaneError::Remote(ErrorCode::NotFound))
    ));
    Ok(())
}

struct Fixture {
    temporary: TempDir,
    mesh: MeshId,
    destination: BackupDestinationId,
    object: BackupObjectIdentity,
    payload: Vec<u8>,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let payload = b"encrypted metadata backup across bounded frames".to_vec();
        let digest = Sha256::digest(&payload).into();
        let destination = BackupDestinationId::from_bytes([8; 16])?;
        Ok(Self {
            temporary: TempDir::new()?,
            mesh: MeshId::from_bytes([9; 16])?,
            destination,
            object: BackupObjectIdentity {
                backup_id: BackupId::from_bytes([7; 16])?,
                destination_id: destination,
                provider_generation: 3,
                byte_length: payload.len() as u64,
                digest,
            },
            payload,
        })
    }

    fn service(
        &self,
        client_node: NodeId,
    ) -> Result<RemoteBackupService<DirectoryBackupProvider, TestAuthority>, Box<dyn Error>> {
        let storage_path = self.temporary.path().join("storage");
        fs::create_dir(&storage_path)?;
        let provider = DirectoryBackupProvider::open(
            &storage_path,
            self.destination,
            3,
            1024 * 1024,
            UnixMicros::new(1),
        )?;
        Ok(RemoteBackupService::new(
            provider,
            TestAuthority { client_node },
            self.mesh,
            self.destination,
            3,
        )?)
    }

    fn store_request(&self, operation: u8) -> Result<BackupStoreRequest, Box<dyn Error>> {
        Ok(BackupStoreRequest {
            context: context(operation, 5)?,
            object: self.object,
        })
    }

    fn read_request(
        &self,
        operation: u8,
        object_reference: meshspan_contracts::BackupObjectReference,
    ) -> Result<BackupReadRequest, Box<dyn Error>> {
        Ok(BackupReadRequest {
            context: context(operation, 5)?,
            object: self.object,
            object_reference,
        })
    }

    fn verify_request(
        &self,
        operation: u8,
        object_reference: meshspan_contracts::BackupObjectReference,
    ) -> Result<BackupVerifyRequest, Box<dyn Error>> {
        Ok(BackupVerifyRequest {
            context: context(operation, 5)?,
            object: self.object,
            object_reference,
        })
    }

    fn delete_request(
        &self,
        operation: u8,
        object_reference: meshspan_contracts::BackupObjectReference,
    ) -> Result<BackupDeleteRequest, Box<dyn Error>> {
        Ok(BackupDeleteRequest {
            context: context(operation, 6)?,
            object: self.object,
            object_reference,
            retirement_revision: Revision::new(6),
        })
    }
}

#[derive(Clone, Copy)]
struct TestAuthority {
    client_node: NodeId,
}

impl RemoteBackupAuthority for TestAuthority {
    fn authorise(
        &self,
        peer: AuthenticatedPeer,
        request: RemoteBackupAuthorisation<'_>,
        _observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let expected_revision = match request {
            RemoteBackupAuthorisation::Store(request) => request.context.expected_revision,
            RemoteBackupAuthorisation::Read(request) => request.context.expected_revision,
            RemoteBackupAuthorisation::Verify(request) => request.context.expected_revision,
            RemoteBackupAuthorisation::Delete(request) => {
                if request.retirement_revision != Revision::new(6) {
                    return Err(ContractError::Unauthorized);
                }
                request.context.expected_revision
            }
        };
        if peer.node_id() == self.client_node
            && matches!(expected_revision, Some(revision) if revision.get() == 5 || revision.get() == 6)
        {
            Ok(())
        } else {
            Err(ContractError::Unauthorized)
        }
    }
}

fn context(operation: u8, revision: u64) -> Result<RequestContext, Box<dyn Error>> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([operation; 16])?,
        deadline: UnixMicros::new(1_000),
        expected_revision: Some(Revision::new(revision)),
    })
}

struct Certificates {
    authority: CertificateDer<'static>,
    server_certificate: CertificateDer<'static>,
    server_key: Vec<u8>,
    client_certificate: CertificateDer<'static>,
    client_key: Vec<u8>,
}

impl Certificates {
    fn new() -> Result<Self, Box<dyn Error>> {
        let authority = CertificateAuthority::new()?;
        let (server_certificate, server_key) =
            certificate_parts(authority.issue_node(CERTIFICATE_NAME)?);
        let (client_certificate, client_key) =
            certificate_parts(authority.issue_node(CERTIFICATE_NAME)?);
        Ok(Self {
            authority: CertificateDer::from(authority.certificate_der().to_vec()),
            server_certificate,
            server_key,
            client_certificate,
            client_key,
        })
    }

    fn server_credentials(&self) -> Result<NodeCredentials, meshspan_transport::TransportError> {
        credentials(&self.server_certificate, &self.server_key)
    }

    fn client_credentials(&self) -> Result<NodeCredentials, meshspan_transport::TransportError> {
        credentials(&self.client_certificate, &self.client_key)
    }
}

fn credentials(
    certificate: &CertificateDer<'static>,
    key: &[u8],
) -> Result<NodeCredentials, meshspan_transport::TransportError> {
    NodeCredentials::new(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(key.to_vec()).into(),
    )
}

fn certificate_parts(
    issued: meshspan_test_certificates::IssuedCertificate,
) -> (CertificateDer<'static>, Vec<u8>) {
    let (certificate, private_key) = issued.into_parts();
    (CertificateDer::from(certificate), private_key)
}

fn authenticate(
    connection: &quinn::Connection,
    node_id: NodeId,
    certificate: &CertificateDer<'static>,
) -> Result<AuthenticatedPeer, Box<dyn Error>> {
    let registry = PeerRegistry::new([PeerBinding {
        node_id,
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(certificate),
    }])?;
    Ok(registry.authenticate_connection(connection)?)
}

fn request_header(
    mesh_id: MeshId,
    sender: NodeId,
    operation: OperationId,
) -> Result<RequestHeader, Box<dyn Error>> {
    let partition = PartitionId::from_bytes([3; 16])?;
    Ok(RequestHeader {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        mesh_id: mesh_id.as_bytes().to_vec(),
        partition_id: partition.as_bytes().to_vec(),
        routing_epoch: 1,
        sender_node_id: sender.as_bytes().to_vec(),
        sender_incarnation: 1,
        request_id: operation.as_bytes().to_vec(),
        operation_id: operation.as_bytes().to_vec(),
        deadline_unix_micros: 1_000,
        trace_id: operation.as_bytes().to_vec(),
    })
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    Ok(roots)
}

fn wire_limits() -> Result<WireLimits, Box<dyn Error>> {
    Ok(WireLimits::new(64 * 1_024, 8, 256, 4_096)?)
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn node(value: u8) -> Result<NodeId, Box<dyn Error>> {
    NodeId::from_bytes([value; 16]).map_err(Into::into)
}
