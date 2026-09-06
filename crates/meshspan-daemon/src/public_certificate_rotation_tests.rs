// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{EntropyError, RandomSource, Revision};
use meshspan_metadata::{
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{
    HttpsServer, LocalWrappingKey, PublicCertificateInstallOutcome,
    PublicCertificateLoadingService, PublicCertificateRotationError, RotatingHttpsIdentity,
    SecretGenerationAuthority, SecretGenerationAuthorityError,
};

const CERTIFICATE_NAME: &str = "files.example.test";

#[test]
fn recipient_rewrap_advances_delivery_without_changing_the_certificate_revision()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let authority = CertificateAuthority::new()?;
    let certificate = authority.issue_node(CERTIFICATE_NAME)?;
    let different = authority.issue_node(CERTIFICATE_NAME)?;
    let initial = reference(1);
    let rewrapped = SecretGenerationReference {
        generation: 2,
        ..initial
    };
    let changed = SecretGenerationReference {
        generation: 3,
        ..initial
    };
    let records = vec![
        certificate_record(initial, &certificate, local.public_key(), 17)?,
        certificate_record(rewrapped, &certificate, local.public_key(), 41)?,
        certificate_record(changed, &different, local.public_key(), 61)?,
    ];
    let loading = PublicCertificateLoadingService::new(FakeAuthority(records), &local);
    let first = loading.load(initial)?;
    let identity = RotatingHttpsIdentity::new(Revision::new(7), &first)?;
    let original_pin = identity.certificate_fingerprint()?;
    assert_eq!(
        identity.install(Revision::new(7), &loading.load(rewrapped)?)?,
        PublicCertificateInstallOutcome::Installed
    );
    assert_eq!(
        identity.current()?.ok_or("missing selection")?.generation,
        rewrapped
    );
    assert_eq!(identity.certificate_fingerprint()?, original_pin);
    assert_eq!(
        identity.install(Revision::new(7), &first).err(),
        Some(PublicCertificateRotationError::StaleRevision)
    );
    assert_eq!(
        identity
            .install(Revision::new(7), &loading.load(changed)?)
            .err(),
        Some(PublicCertificateRotationError::ConflictingRevision)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_listener_rotates_new_handshakes_without_breaking_existing_sessions()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let authority = CertificateAuthority::new()?;
    let first = authority.issue_node(CERTIFICATE_NAME)?;
    let second = authority.issue_node(CERTIFICATE_NAME)?;
    let first_der = first.certificate_der().to_vec();
    let second_der = second.certificate_der().to_vec();
    let first_reference = reference(1);
    let second_reference = reference(2);
    let records = vec![
        certificate_record(first_reference, &first, local.public_key(), 17)?,
        certificate_record(second_reference, &second, local.public_key(), 41)?,
    ];
    let loading = PublicCertificateLoadingService::new(FakeAuthority(records), &local);
    let first_loaded = loading.load(first_reference)?;
    let identity = RotatingHttpsIdentity::new(Revision::new(7), &first_loaded)?;
    let server = HttpsServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        identity.server_config(),
        Router::new().route("/", get(|| async { "ready" })),
    )
    .await?;
    let address = server.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run_until(async move {
        drop(shutdown_rx.await);
    }));
    let client_config = client_config(authority.certificate_der())?;

    let first_session = connect(address, Arc::clone(&client_config)).await?;
    assert_eq!(peer_leaf(&first_session)?, first_der);
    assert_eq!(
        identity.certificate_fingerprint()?,
        <[u8; 32]>::from(Sha256::digest(&first_der))
    );

    let second_loaded = loading.load(second_reference)?;
    assert_eq!(
        identity.install(Revision::new(8), &second_loaded)?,
        PublicCertificateInstallOutcome::Installed
    );
    assert_eq!(peer_leaf(&first_session)?, first_der);
    let second_session = connect(address, Arc::clone(&client_config)).await?;
    assert_eq!(peer_leaf(&second_session)?, second_der);
    assert_eq!(
        identity.certificate_fingerprint()?,
        <[u8; 32]>::from(Sha256::digest(&second_der))
    );
    let current = identity.current()?.ok_or("rotated identity missing")?;
    assert_eq!(current.revision, Revision::new(8));
    assert_eq!(current.generation, second_reference);

    assert_eq!(
        identity.install(Revision::new(8), &second_loaded)?,
        PublicCertificateInstallOutcome::AlreadyCurrent
    );
    assert_eq!(
        identity.install(Revision::new(8), &first_loaded).err(),
        Some(PublicCertificateRotationError::ConflictingRevision)
    );
    assert_eq!(
        identity.install(Revision::new(6), &first_loaded).err(),
        Some(PublicCertificateRotationError::StaleRevision)
    );

    drop(first_session);
    drop(second_session);
    assert!(shutdown_tx.send(()).is_ok());
    server_task.await??;
    Ok(())
}

async fn connect(
    address: SocketAddr,
    client_config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>, Box<dyn Error>> {
    let connector = TlsConnector::from(client_config);
    let name = ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    Ok(connector
        .connect(name, TcpStream::connect(address).await?)
        .await?)
}

fn peer_leaf(stream: &TlsStream<TcpStream>) -> Result<Vec<u8>, Box<dyn Error>> {
    let certificates = stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or("server did not provide a certificate")?;
    Ok(certificates
        .first()
        .ok_or("server certificate chain was empty")?
        .as_ref()
        .to_vec())
}

fn client_config(authority: &[u8]) -> Result<Arc<ClientConfig>, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(authority.to_vec()))?;
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn certificate_record(
    reference: SecretGenerationReference,
    certificate: &meshspan_certificates::IssuedCertificate,
    recipient: WrappingPublicKey,
    seed: u8,
) -> Result<SecretGenerationRecord, Box<dyn Error>> {
    let bundle = PublicCertificateBundle::new(
        vec![certificate.certificate_der().to_vec()],
        certificate.private_key().to_vec(),
    )?;
    let context = SecretContext::new(
        PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
        reference.secret_id,
        reference.generation,
    )?;
    let (secret, recipients) = encrypt_secret(
        context,
        &bundle.encode()?,
        &[recipient],
        &mut FixedRandom(seed),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

const fn reference(seed: u8) -> SecretGenerationReference {
    SecretGenerationReference {
        secret_id: [seed; 16],
        generation: 1,
    }
}

#[derive(Clone)]
struct FakeAuthority(Vec<SecretGenerationRecord>);

impl SecretGenerationAuthority for FakeAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok(self
            .0
            .iter()
            .find(|record| record.secret.context() == context)
            .cloned())
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
