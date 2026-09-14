// SPDX-License-Identifier: GPL-2.0-only

//! Real mutual-TLS QUIC exchange using the exact installed recovery leaf and local key.
//! This isolated loopback identity proof is not replacement-cluster service admission.

use std::{fs, path::Path};

use meshspan_daemon::{LocalNodeIdentity, LocalWrappingKey};
use meshspan_domain::NodeId;
use meshspan_metadata::{
    RecoveryKeyRecipient, RecoveryNodeCertificate, verify_recovery_key_bundle,
};
use meshspan_transport::{NodeCredentials, PeerBinding, PeerRegistry, TransportLimits};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest as _, Sha256};

use super::{Error, WAIT_LIMIT};

pub(super) async fn prove(directory: &Path) -> Result<(), Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&directory.join("identity.pk8"), "replacement.invalid")?;
    let wrapping = LocalWrappingKey::open(&directory.join("wrapping.x25519"))?;
    let root = fs::read(directory.join("root.der"))?;
    let node = NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?;
    let verified = verify_recovery_key_bundle(
        &mut fs::File::open(directory.join("installed.bundle"))?,
        &root,
        RecoveryKeyRecipient {
            node_id: node,
            identity_public_key: identity.public_key_sec1().try_into()?,
            wrapping_public_key: wrapping.public_key(),
        },
        |secret, envelope| wrapping.decrypt_secret(secret, envelope),
    )?;
    let certificate = verified.node_certificate();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root))?;
    let limits = TransportLimits::new(
        meshspan_protocol::WireLimits::new(64 * 1024, 64 * 1024, 256, 4096)?,
        8,
        64 * 1024,
        256 * 1024,
    )?;
    let server = meshspan_transport::server_endpoint(
        "127.0.0.1:0".parse()?,
        credentials(directory, certificate)?,
        roots.clone(),
        limits,
    )?;
    let client = meshspan_transport::client_endpoint(
        "127.0.0.1:0".parse()?,
        credentials(directory, certificate)?,
        roots,
        limits,
    )?;
    let peers = PeerRegistry::new([PeerBinding {
        node_id: node,
        incarnation: 1,
        certificate_fingerprint: Sha256::digest(certificate.certificate_der()).into(),
    }])?;
    let certificate_name = certificate.dns_name();
    let exchange = async {
        let (inbound, outbound) = tokio::try_join!(
            serve(&server, &peers),
            request(&client, server.local_addr()?, &certificate_name, &peers),
        )?;
        inbound.close(0_u32.into(), b"proof complete");
        outbound.close(0_u32.into(), b"proof complete");
        Ok::<_, Box<dyn Error>>(())
    };
    let result = tokio::time::timeout(WAIT_LIMIT, exchange).await;
    server.close(0_u32.into(), b"proof complete");
    client.close(0_u32.into(), b"proof complete");
    result??;
    Ok(())
}

fn credentials(
    directory: &Path,
    certificate: &RecoveryNodeCertificate,
) -> Result<NodeCredentials, Box<dyn Error>> {
    Ok(NodeCredentials::new(
        vec![
            CertificateDer::from(certificate.certificate_der().to_vec()),
            CertificateDer::from(certificate.issuer_der().to_vec()),
        ],
        PrivatePkcs8KeyDer::from(fs::read(directory.join("identity.pk8"))?).into(),
    )?)
}

async fn serve(
    server: &quinn::Endpoint,
    peers: &PeerRegistry,
) -> Result<quinn::Connection, Box<dyn Error>> {
    let connection = server.accept().await.ok_or("listener closed")?.await?;
    peers.authenticate_connection(&connection)?;
    let (mut send, mut receive) = connection.accept_bi().await?;
    assert_eq!(receive.read_to_end(64).await?, b"recovery certificate");
    send.write_all(b"verified").await?;
    send.finish()?;
    send.stopped().await?;
    Ok(connection)
}

async fn request(
    client: &quinn::Endpoint,
    address: std::net::SocketAddr,
    name: &str,
    peers: &PeerRegistry,
) -> Result<quinn::Connection, Box<dyn Error>> {
    let connection = meshspan_transport::connect(client, address, name).await?;
    peers.authenticate_connection(&connection)?;
    let (mut send, mut receive) = connection.open_bi().await?;
    send.write_all(b"recovery certificate").await?;
    send.finish()?;
    assert_eq!(receive.read_to_end(64).await?, b"verified");
    Ok(connection)
}
