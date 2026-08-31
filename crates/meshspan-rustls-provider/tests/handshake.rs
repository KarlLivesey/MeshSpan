// SPDX-License-Identifier: GPL-2.0-only

//! Real in-memory TLS 1.3 mutual-authentication proof for the provider profile.

use std::error::Error;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _};
use p256::pkcs8::EncodePrivateKey;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyUsagePurpose, PublicKeyData, SerialNumber, SigningKey,
};
use rustls::client::ClientConnection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ServerConnection, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

const CERTIFICATE_NAME: &str = "node.meshspan.test";

#[test]
fn real_tls13_mutual_authentication_round_trip() -> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let roots = roots(&certificates.authority)?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()?;
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![certificates.server.certificate],
            PrivatePkcs8KeyDer::from(certificates.server.private_key).into(),
        )?;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![certificates.client.certificate],
            PrivatePkcs8KeyDer::from(certificates.client.private_key).into(),
        )?;
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(CERTIFICATE_NAME)?.to_owned(),
    )?;
    let mut server = ServerConnection::new(Arc::new(server_config))?;

    complete_handshake(&mut client, &mut server)?;
    client.writer().write_all(b"provider handshake proof")?;
    client_to_server(&mut client, &mut server)?;
    let mut received = [0; 24];
    server.reader().read_exact(&mut received)?;
    assert_eq!(&received, b"provider handshake proof");
    assert_eq!(
        client.negotiated_cipher_suite().map(|suite| suite.suite()),
        Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,)
    );
    Ok(())
}

fn complete_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..16 {
        client_to_server(client, server)?;
        server_to_client(server, client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("TLS handshake did not converge within its proof bound".into())
}

fn client_to_server(
    sender: &mut ClientConnection,
    receiver: &mut ServerConnection,
) -> Result<(), Box<dyn Error>> {
    let mut encoded = Vec::new();
    while sender.wants_write() {
        sender.write_tls(&mut encoded)?;
    }
    if !encoded.is_empty() {
        receiver.read_tls(&mut Cursor::new(encoded))?;
        receiver.process_new_packets()?;
    }
    Ok(())
}

fn server_to_client(
    sender: &mut ServerConnection,
    receiver: &mut ClientConnection,
) -> Result<(), Box<dyn Error>> {
    let mut encoded = Vec::new();
    while sender.wants_write() {
        sender.write_tls(&mut encoded)?;
    }
    if !encoded.is_empty() {
        receiver.read_tls(&mut Cursor::new(encoded))?;
        receiver.process_new_packets()?;
    }
    Ok(())
}

struct Certificates {
    authority: CertificateDer<'static>,
    server: Leaf,
    client: Leaf,
}

struct Leaf {
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
}

fn certificates() -> Result<Certificates, Box<dyn Error>> {
    let authority_key = TestKey::from_seed([1; 32])?;
    let mut authority_parameters = CertificateParams::new(Vec::<String>::new())?;
    authority_parameters.serial_number = Some(SerialNumber::from(1_u64));
    authority_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    let authority_certificate = authority_parameters.self_signed(&authority_key)?;
    let authority = authority_certificate.der().clone();
    let issuer = Issuer::new(authority_parameters, authority_key);
    Ok(Certificates {
        authority,
        server: leaf(&issuer, [2; 32], 2)?,
        client: leaf(&issuer, [3; 32], 3)?,
    })
}

fn leaf(issuer: &Issuer<'_, TestKey>, seed: [u8; 32], serial: u64) -> Result<Leaf, Box<dyn Error>> {
    let key = TestKey::from_seed(seed)?;
    let mut parameters = CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()])?;
    parameters.serial_number = Some(SerialNumber::from(serial));
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    let certificate: Certificate = parameters.signed_by(&key, issuer)?;
    Ok(Leaf {
        certificate: certificate.der().clone(),
        private_key: key.private_key,
    })
}

fn roots(authority: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(authority.clone())?;
    Ok(roots)
}

struct TestKey {
    key: p256::ecdsa::SigningKey,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl TestKey {
    fn from_seed(seed: [u8; 32]) -> Result<Self, Box<dyn Error>> {
        let key = p256::ecdsa::SigningKey::from_slice(&seed)?;
        let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let private_key = key.to_pkcs8_der()?.as_bytes().to_vec();
        Ok(Self {
            key,
            public_key,
            private_key,
        })
    }
}

impl PublicKeyData for TestKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for TestKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: p256::ecdsa::DerSignature = self
            .key
            .try_sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_vec())
    }
}
