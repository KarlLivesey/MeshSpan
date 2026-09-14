// SPDX-License-Identifier: GPL-2.0-only

//! Real TLS admission and protocol separation on the dedicated federation socket.

use super::{CERTIFICATE_NAME, certificates, limits, loopback, roots};
use crate::{FederationEndpoint, TransportError, client_endpoint, connect};
use std::{error::Error, time::Duration};

#[tokio::test]
async fn federation_endpoint_starts_closed_and_replaces_trust_without_rebinding()
-> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let server =
        FederationEndpoint::bind(loopback(), certificates.server_credentials()?, limits()?)?;
    let client =
        FederationEndpoint::bind(loopback(), certificates.client_credentials()?, limits()?)?;
    let original = server.local_addr()?;
    assert!(matches!(
        client.connect(original, CERTIFICATE_NAME).await,
        Err(TransportError::InvalidConfiguration)
    ));
    client.replace_trust(roots(&certificates.authority_certificate)?)?;
    server.replace_trust(roots(&certificates.authority_certificate)?)?;
    let first = connections(&client, &server).await?;
    server.replace_trust(rustls::RootCertStore::empty())?;
    assert!(matches!(
        server.connect(client.local_addr()?, CERTIFICATE_NAME).await,
        Err(TransportError::InvalidConfiguration)
    ));
    // Trust changes gate admission; the domain owner, not TLS, retires existing sessions.
    assert!(first.0.close_reason().is_none());
    assert!(first.1.close_reason().is_none());
    server.replace_trust(roots(&certificates.authority_certificate)?)?;
    let second = connections(&client, &server).await?;
    assert_eq!(server.local_addr()?, original);
    assert!(second.0.close_reason().is_none());
    client.close();
    server.close();
    Ok(())
}

#[tokio::test]
async fn federation_endpoint_rejects_node_protocol_even_with_trusted_certificate()
-> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let server =
        FederationEndpoint::bind(loopback(), certificates.server_credentials()?, limits()?)?;
    server.replace_trust(roots(&certificates.authority_certificate)?)?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits()?,
    )?;
    let rejected = async {
        let incoming = server
            .accept()
            .await
            .ok_or("missing incoming TLS handshake")?;
        let result = incoming.await;
        let Err(quinn::ConnectionError::TransportError(error)) = result else {
            return Err("expected a TLS protocol-negotiation rejection".into());
        };
        // QUIC crypto error 0x100 + TLS no_application_protocol alert (120).
        assert_eq!(u64::from(error.code), 0x178);
        Ok::<(), Box<dyn Error>>(())
    };
    let address = server.local_addr()?;
    let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(connect(&client, address, CERTIFICATE_NAME), rejected)
    })
    .await?;
    incoming?;
    assert!(matches!(outgoing, Err(TransportError::Connection(_))));
    client.close(0_u32.into(), b"test completed");
    server.close();
    Ok(())
}

async fn connections(
    client: &FederationEndpoint,
    server: &FederationEndpoint,
) -> Result<(quinn::Connection, quinn::Connection), Box<dyn Error>> {
    let address = server.local_addr()?;
    let incoming = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(client.connect(address, CERTIFICATE_NAME), incoming)
    })
    .await??)
}
