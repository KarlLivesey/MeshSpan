// SPDX-License-Identifier: GPL-2.0-only

//! Real in-memory TLS 1.3 mutual-authentication proof for the provider profile.

use std::error::Error;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use meshspan_test_certificates::CertificateAuthority;
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
    let authority = CertificateAuthority::new()?;
    let server = authority.issue_node(CERTIFICATE_NAME)?.into_parts();
    let client = authority.issue_node(CERTIFICATE_NAME)?.into_parts();
    Ok(Certificates {
        authority: CertificateDer::from(authority.certificate_der().to_vec()),
        server: Leaf {
            certificate: CertificateDer::from(server.0),
            private_key: server.1,
        },
        client: Leaf {
            certificate: CertificateDer::from(client.0),
            private_key: client.1,
        },
    })
}

fn roots(authority: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(authority.clone())?;
    Ok(roots)
}
