// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::time::Duration;

use meshspan_test_certificates::{CertificateAuthority, NodeIdentityKey, NodePublicIdentity};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::*;
use crate::identity::connection_certificate_fingerprint;
use crate::tests::{limits, loopback, roots};

const NAME: &str = "meshspan.internal";

#[test]
fn credential_sizes_are_rejected_before_certificate_preparation() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    for chain in [
        Vec::new(),
        vec![Vec::new()],
        vec![vec![1; 65_537]],
        vec![vec![1]; 9],
    ] {
        assert!(fixture.credentials(&chain).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn live_rotation_updates_both_directions_without_rebinding_or_breaking_old_streams()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let local = fixture.transport(1, &fixture.first)?;
    let peer_identity = fixture.authority.issue_node(NAME)?;
    let peer = RotatingNodeTransport::new(
        fixture.config(1)?,
        NodeCredentials::new(
            vec![CertificateDer::from(
                peer_identity.certificate_der().to_vec(),
            )],
            PrivatePkcs8KeyDer::from(peer_identity.private_key().to_vec()).into(),
        )?,
    )?;
    let address = local.server_endpoint()?.local_addr()?;
    let initial_client_address = client_address(&local)?;
    let outbound = connections(&local, &peer).await?;
    let inbound = connections(&peer, &local).await?;
    round_trip(&outbound, b"before outbound rotation").await?;
    round_trip(&inbound, b"before inbound rotation").await?;
    let old = local.current()?;
    let installed = local.install(2, fixture.credentials(&fixture.next)?)?;
    assert_eq!(local.server_endpoint()?.local_addr()?, address);
    assert_eq!(client_address(&local)?, initial_client_address);
    assert_eq!(installed.generation, 2);
    assert_ne!(
        installed.certificate_fingerprint,
        old.certificate_fingerprint
    );
    for _ in 0..2 {
        let fresh_outbound = connections(&local, &peer).await?;
        let fresh_inbound = connections(&peer, &local).await?;
        assert_eq!(
            connection_certificate_fingerprint(&fresh_outbound.1)?,
            installed.certificate_fingerprint
        );
        assert_eq!(
            connection_certificate_fingerprint(&fresh_inbound.0)?,
            installed.certificate_fingerprint
        );
        round_trip(&fresh_outbound, b"new outbound generation").await?;
        round_trip(&fresh_inbound, b"new inbound generation").await?;
    }
    assert_eq!(
        connection_certificate_fingerprint(&outbound.1)?,
        old.certificate_fingerprint
    );
    assert_eq!(
        connection_certificate_fingerprint(&inbound.0)?,
        old.certificate_fingerprint
    );
    round_trip(&outbound, b"old connection still usable").await?;
    round_trip(&inbound, b"old inbound still usable").await?;
    assert_eq!(
        local.install(2, fixture.credentials(&fixture.next)?)?,
        installed
    );
    Ok(())
}

#[tokio::test]
async fn invalid_replacements_leave_the_exact_generation_and_handshake_usable()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let local = fixture.transport(2, &fixture.next)?;
    let installed = local.current()?;
    for generation in [0, 1, 2] {
        assert!(
            local
                .install(generation, fixture.credentials(&fixture.first)?)
                .is_err()
        );
        assert_eq!(local.current()?, installed);
    }
    let other_key = fixture.authority.issue_node(NAME)?;
    let changed_identity = NodeCredentials::new(
        vec![CertificateDer::from(other_key.certificate_der().to_vec())],
        PrivatePkcs8KeyDer::from(other_key.private_key().to_vec()).into(),
    )?;
    assert!(local.install(3, changed_identity).is_err());
    let mismatched = NodeCredentials::new(
        fixture
            .next
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
        PrivatePkcs8KeyDer::from(other_key.private_key().to_vec()).into(),
    )?;
    assert!(local.install(3, mismatched).is_err());
    let wrong_name = fixture
        .authority
        .sign_node_identity(&fixture.key, "other.internal")?;
    assert!(
        local
            .install(3, fixture.credentials(&[wrong_name])?)
            .is_err()
    );
    let untrusted = CertificateAuthority::new()?.sign_node_identity(&fixture.key, NAME)?;
    assert!(
        local
            .install(3, fixture.credentials(&[untrusted])?)
            .is_err()
    );
    assert_eq!(local.current()?, installed);
    let peer = fixture.transport(1, &fixture.first)?;
    let connections = connections(&peer, &local).await?;
    assert_eq!(
        connection_certificate_fingerprint(&connections.0)?,
        installed.certificate_fingerprint
    );
    round_trip(&connections, b"failed candidates changed nothing").await?;
    Ok(())
}

async fn connections(
    client: &RotatingNodeTransport,
    server: &RotatingNodeTransport,
) -> Result<(quinn::Connection, quinn::Connection), Box<dyn Error>> {
    let address = server.server_endpoint()?.local_addr()?;
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(client.connect(address, NAME), async {
            server
                .server_endpoint()?
                .accept()
                .await
                .ok_or(TransportError::InvalidConfiguration)?
                .await
                .map_err(TransportError::from)
        },)
    })
    .await??)
}

async fn round_trip(
    connections: &(quinn::Connection, quinn::Connection),
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let send = async {
            let (mut send, mut receive) = connections.0.open_bi().await?;
            send.write_all(bytes).await?;
            send.finish()?;
            assert_eq!(receive.read_to_end(128).await?, bytes);
            Ok::<_, Box<dyn Error>>(())
        };
        let receive = async {
            let (mut send, mut receive) = connections.1.accept_bi().await?;
            let received = receive.read_to_end(128).await?;
            assert_eq!(received, bytes);
            send.write_all(&received).await?;
            send.finish()?;
            Ok::<_, Box<dyn Error>>(())
        };
        tokio::try_join!(send, receive)
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn shutdown_releases_both_udp_addresses_before_returning() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let transport = fixture.transport(1, &fixture.first)?;
    let server = transport.server_endpoint()?.local_addr()?;
    let client = client_address(&transport)?;
    shutdown_transport(transport).await?;
    let _server = std::net::UdpSocket::bind(server)?;
    let _client = std::net::UdpSocket::bind(client)?;
    Ok(())
}

#[tokio::test]
async fn rejected_second_bind_releases_first_socket_synchronously() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let reserved = std::net::UdpSocket::bind(loopback())?;
    let first = reserved.local_addr()?;
    drop(reserved);
    let occupied = std::net::UdpSocket::bind(loopback())?;
    let mut config = fixture.config(1)?;
    config.server_address = first;
    config.client_address = occupied.local_addr()?;
    assert!(RotatingNodeTransport::new(config, fixture.credentials(&fixture.first)?).is_err());
    let _rebound = std::net::UdpSocket::bind(first)?;
    Ok(())
}

#[tokio::test]
async fn abandoned_preparation_releases_both_sockets_and_invalidates_clones()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let prepared =
        RotatingNodeTransport::prepare(fixture.config(1)?, fixture.credentials(&fixture.first)?)?;
    let clone = prepared.transport().clone();
    let server = clone.server_endpoint()?.local_addr()?;
    let client = client_address(&clone)?;
    drop(prepared);
    assert!(clone.server_endpoint().is_err());
    let _server = std::net::UdpSocket::bind(server)?;
    let _client = std::net::UdpSocket::bind(client)?;
    Ok(())
}

#[tokio::test]
async fn canceled_waiter_preserves_driver_drain_and_rejects_new_connections()
-> Result<(), Box<dyn Error>> {
    use std::future::{Future as _, poll_fn};
    use std::task::Poll;

    let fixture = Fixture::new()?;
    let transport = fixture.transport(1, &fixture.first)?;
    let address = transport.server_endpoint()?.local_addr()?;
    let clone = transport.clone();
    let mut first = Box::pin(transport.shutdown());
    let pending = poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await;
    assert!(
        pending,
        "shutdown must observe the scheduled drivers before returning"
    );
    drop(first);
    let mut second = Box::pin(clone.shutdown());
    let pending = poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx).is_pending())).await;
    assert!(
        pending,
        "canceling one waiter must retain the driver's shared join state"
    );
    assert!(clone.server_endpoint().is_err());
    assert!(matches!(
        clone.connect(address, NAME).await,
        Err(TransportError::InvalidConfiguration)
    ));
    tokio::time::timeout(Duration::from_secs(2), second).await??;
    transport.shutdown().await?;
    let _rebound = std::net::UdpSocket::bind(address)?;
    Ok(())
}

async fn shutdown_transport(transport: RotatingNodeTransport) -> Result<(), TransportError> {
    transport.shutdown().await?;
    drop(transport);
    Ok(())
}

fn client_address(
    transport: &RotatingNodeTransport,
) -> Result<std::net::SocketAddr, Box<dyn Error>> {
    let endpoints = transport
        .endpoints
        .lock()
        .map_err(|_| "endpoint state poisoned")?;
    Ok(endpoints
        .as_ref()
        .ok_or("transport closed")?
        .client
        .local_addr()?)
}

struct Fixture {
    authority: CertificateAuthority,
    key: NodeIdentityKey,
    first: Vec<Vec<u8>>,
    next: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let authority = CertificateAuthority::new()?;
        let key = NodeIdentityKey::generate()?;
        let first = vec![authority.sign_node_identity(&key, NAME)?];
        let online = authority.issue_online_authority()?;
        let public = NodePublicIdentity::from_sec1(key.public_key_sec1())?;
        let next = vec![
            online.sign_node_public_identity(&public, NAME)?,
            online.certificate_der().to_vec(),
        ];
        Ok(Self {
            authority,
            key,
            first,
            next,
        })
    }

    fn credentials(&self, chain: &[Vec<u8>]) -> Result<NodeCredentials, TransportError> {
        NodeCredentials::new(
            chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivatePkcs8KeyDer::from(self.key.private_key_pkcs8().to_vec()).into(),
        )
    }

    fn config(&self, generation: u64) -> Result<NodeTransportConfig, Box<dyn Error>> {
        Ok(NodeTransportConfig {
            server_address: loopback(),
            client_address: loopback(),
            certificate_name: NAME.to_owned(),
            certificate_generation: generation,
            peer_roots: roots(&CertificateDer::from(
                self.authority.certificate_der().to_vec(),
            ))?,
            limits: limits()?,
        })
    }

    fn transport(
        &self,
        generation: u64,
        chain: &[Vec<u8>],
    ) -> Result<RotatingNodeTransport, Box<dyn Error>> {
        Ok(RotatingNodeTransport::new(
            self.config(generation)?,
            self.credentials(chain)?,
        )?)
    }
}
