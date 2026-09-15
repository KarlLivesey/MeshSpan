// SPDX-License-Identifier: GPL-2.0-only

use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection};

#[test]
fn outbound_acme_config_handshakes_with_independent_p384_issuer()
-> Result<(), Box<dyn std::error::Error>> {
    let root = include_bytes!(
        "../../meshspan-rustls-provider/tests/fixtures/external/local-p384-root.der"
    );
    let leaf = include_bytes!(
        "../../meshspan-rustls-provider/tests/fixtures/external/local-p384-leaf.der"
    );
    let key = include_bytes!(
        "../../meshspan-rustls-provider/tests/fixtures/external/local-p384-leaf-key.der"
    );
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec()))?;
    let mut config = super::acme_client_config(roots)?.as_ref().clone();
    config.time_provider = Arc::new(FixtureTime);
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("files.example.test")?,
    )?;
    // The server still signs its TLS transcript with the intentionally narrow P-256 key.
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.to_vec())],
                PrivatePkcs8KeyDer::from(key.to_vec()).into(),
            )?;
    let mut server = ServerConnection::new(Arc::new(server_config))?;
    handshake(&mut client, &mut server)?;
    server.writer().write_all(b"independent issuer accepted")?;
    let mut records = Vec::new();
    server.write_tls(&mut records)?;
    client.read_tls(&mut Cursor::new(records))?;
    client.process_new_packets()?;
    let mut received = [0; 27];
    client.reader().read_exact(&mut received)?;
    assert_eq!(&received, b"independent issuer accepted");
    Ok(())
}

fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..16 {
        let mut request = Vec::new();
        client.write_tls(&mut request)?;
        server.read_tls(&mut Cursor::new(request))?;
        server.process_new_packets()?;
        let mut response = Vec::new();
        server.write_tls(&mut response)?;
        client.read_tls(&mut Cursor::new(response))?;
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("independent issuer handshake exceeded its flight bound".into())
}

#[derive(Debug)]
struct FixtureTime;

impl rustls::time_provider::TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            1_789_420_000,
        )))
    }
}
