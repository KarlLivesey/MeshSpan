// SPDX-License-Identifier: GPL-2.0-only

//! The identities established by the public pairing flow authenticate real native QUIC sessions.

use super::{RunningAuthority, TestResult, authority};
use crate::federation_sessions::{FederationSessionConfiguration, FederationSessions};
use meshspan_domain::{AuditEventId, FederationRelationshipId, OperationId, PartitionId};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, PartitionDatabase,
    RevokeFederationRelationship,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[path = "federation_backup_session_tests.rs"]
mod backup;

pub(super) struct SessionHosts {
    inviter: Arc<FederationSessions>,
    joiner: Arc<FederationSessions>,
    backup_targets: crate::federation_sessions::FederationBackupTargets,
}

impl SessionHosts {
    pub(super) fn new(inviter: &RunningAuthority, joiner: &RunningAuthority) -> TestResult<Self> {
        let backup_targets = crate::federation_sessions::FederationBackupTargets::default();
        Ok(Self {
            inviter: Arc::new(host(inviter, false, backup_targets.clone())?),
            joiner: Arc::new(host(
                joiner,
                true,
                crate::federation_sessions::FederationBackupTargets::default(),
            )?),
            backup_targets,
        })
    }

    pub(super) fn inviter_address(&self) -> TestResult<SocketAddr> {
        Ok(self.inviter.local_addr()?)
    }
    pub(super) fn joiner_origin(&self) -> TestResult<String> {
        Ok(format!("https://{}", self.joiner.local_addr()?))
    }
    pub(super) fn close(&self) {
        self.inviter.close();
        self.joiner.close();
    }

    pub(super) async fn verify(
        &self,
        inviter: &RunningAuthority,
        joiner: &RunningAuthority,
        relationship: FederationRelationshipId,
    ) -> TestResult<()> {
        assert_eq!(self.inviter.refresh_trust().await?, vec![relationship]);
        assert!(self.joiner.refresh_trust().await?.is_empty());
        let original_address = self.inviter.local_addr()?;
        let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(self.inviter.dial(relationship), self.joiner.accept())
        })
        .await??;
        for session in [&outgoing, &incoming] {
            assert_eq!(session.limits.wire.maximum_control_bytes(), 8192);
            assert_eq!(session.limits.wire.maximum_data_frame_bytes(), 16384);
            assert_eq!(session.limits.maximum_bidirectional_streams, 3);
            assert_eq!(session.relationship, relationship);
        }
        let outgoing = outgoing.connection;
        let incoming = incoming.connection;
        assert_eq!(outgoing.remote_address(), self.joiner.local_addr()?);
        assert_eq!(incoming.remote_address(), original_address);
        outgoing.close(0_u32.into(), b"test link interruption");
        tokio::time::timeout(Duration::from_secs(2), incoming.closed()).await?;
        self.joiner.refresh_trust().await?;
        self.verify_lifecycle(inviter, joiner, relationship, original_address)
            .await
    }

    async fn verify_lifecycle(
        &self,
        inviter: &RunningAuthority,
        joiner: &RunningAuthority,
        relationship: FederationRelationshipId,
        original_address: SocketAddr,
    ) -> TestResult<()> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(Arc::clone(&self.inviter).run_until(
            stopped,
            crate::runtime_observations::RuntimeObservations::default(),
        ));
        let result = async {
            // No manual dial or trust refresh: the production owner must reconnect and retire it.
            let accepted =
                tokio::time::timeout(Duration::from_secs(7), self.joiner.accept()).await??;
            assert_eq!(accepted.connection.remote_address(), original_address);
            verify_authority_exchange(joiner, &accepted.connection, relationship).await?;
            backup::verify_capability(inviter, joiner, &accepted, self)
                .await
                .map_err(|error| format!("federation backup capability proof: {error}"))?;
            revoke(inviter, relationship)?;
            let reason =
                tokio::time::timeout(Duration::from_secs(7), accepted.connection.closed()).await?;
            let quinn::ConnectionError::ApplicationClosed(reason) = reason else {
                return Err("revocation did not close the session explicitly".into());
            };
            assert_eq!(reason.reason.as_ref(), b"federation authority changed");
            assert!(self.inviter.dial(relationship).await.is_err());
            Ok(())
        }
        .await;
        stop.send(true)?;
        tokio::time::timeout(Duration::from_secs(3), running).await???;
        result
    }
}

async fn verify_authority_exchange(
    joiner: &RunningAuthority,
    connection: &quinn::Connection,
    relationship: FederationRelationshipId,
) -> TestResult<()> {
    use meshspan_cluster::FederationAuthorityFetchRequest;
    use meshspan_domain::DurationMicros;
    use meshspan_transport::{
        FederationExchangeContext, FederationHelloConfig, FederationNegotiationConfig,
        FederationReplayGuard, StreamKind, open_stream,
    };
    let now = crate::api_http::current_time().ok_or("clock")?;
    let identity = crate::local_federation_identity::LocalFederationIdentity::open_or_create(
        &joiner.directory.path().join("federation-identity.v1"),
        now,
    )?;
    let reader = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &joiner.directory.path().join("partition.sqlite3"),
        now,
    )?);
    let version = meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 };
    let limits = meshspan_protocol::WireLimits::new(64 * 1024, 64 * 1024, 256, 4096)?;
    let runtime = identity.signing.session(
        identity
            .certificate
            .certificate_chain()
            .first()
            .ok_or("certificate")?,
        FederationHelloConfig::new(vec![version], Vec::new(), limits, 128)?,
        FederationNegotiationConfig::new(vec![version], limits, 128)?,
    );
    let mut replay = FederationReplayGuard::new(64, DurationMicros::new(30_000_000))?;
    let mut request = FederationAuthorityFetchRequest {
        relationship_id: relationship,
        context: FederationExchangeContext::new(
            version,
            [181; 16],
            [182; 16],
            [183; 16],
            now.checked_add(DurationMicros::new(5_000_000))
                .ok_or("deadline")?,
            [184; 32],
        )?,
        after_revision: 0,
        cursor: Vec::new(),
        limit: 32,
        now,
    };
    // A valid stream prefix without its control frame must not hold a metadata reader
    // or prevent a second stream's independently signed request from completing.
    let (mut stalled, _stalled_response) = open_stream(connection, StreamKind::Federation).await?;
    let page = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.fetch_authority_page(connection, &reader, request.clone(), &mut replay),
    )
    .await??;
    verify_authority_projection(&page, relationship)?;
    verify_oversized_frame_rejected(connection).await?;
    // The server's replay window spans application streams; a new stream is not a reset.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            runtime.fetch_authority_page(connection, &reader, request.clone(), &mut replay)
        )
        .await?
        .is_err()
    );
    request.context.request_id = [185; 16];
    request.context.operation_id = [186; 16];
    request.context.replay_nonce = [187; 32];
    let next = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.fetch_authority_page(connection, &reader, request, &mut replay),
    )
    .await??;
    assert_eq!(
        next.records(),
        page.records(),
        "replay rejection must not kill the session"
    );
    verify_session_stream_budget(connection).await?;
    stalled.reset(0_u32.into())?;
    Ok(())
}

async fn verify_session_stream_budget(connection: &quinn::Connection) -> TestResult<()> {
    use meshspan_transport::{StreamKind, open_stream};
    // The first stalled stream is still owned by the caller. These occupy the other
    // two agreed slots; the transport itself advertised room for 128 streams.
    let (mut second, _second_response) = open_stream(connection, StreamKind::Federation).await?;
    let (mut third, _third_response) = open_stream(connection, StreamKind::Federation).await?;
    let (_excess, mut rejected) = open_stream(connection, StreamKind::Federation).await?;
    let result = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut [0; 1])).await?;
    assert!(matches!(result, Err(quinn::ReadError::Reset(code)) if code == 1_u32.into()));
    second.reset(0_u32.into())?;
    third.reset(0_u32.into())?;
    Ok(())
}

fn verify_authority_projection(
    page: &meshspan_transport::AuthenticatedFederationAuthorityPage,
    relationship: FederationRelationshipId,
) -> TestResult<()> {
    use meshspan_domain::MeshId;
    assert_eq!(page.records().len(), 1);
    assert!(page.next_cursor().is_empty());
    let record = meshspan_metadata::FederationTransportAuthority::from_canonical_bytes(
        &page
            .records()
            .first()
            .ok_or("authority record")?
            .canonical_bytes,
    )?;
    assert_eq!(record.relationship.relationship_id, relationship);
    assert_eq!(
        record.relationship.local_mesh_id,
        MeshId::from_bytes([9; 16])?
    );
    assert_eq!(
        record.relationship.remote_mesh_id,
        MeshId::from_bytes([91; 16])?
    );
    assert_eq!(
        record.relationship.state,
        meshspan_metadata::FederationRelationshipState::Active
    );
    assert_eq!(record.authority_revision.get(), page.authority_revision());
    Ok(())
}

async fn verify_oversized_frame_rejected(connection: &quinn::Connection) -> TestResult<()> {
    let (mut send, mut receive) =
        meshspan_transport::open_stream(connection, meshspan_transport::StreamKind::Federation)
            .await?;
    // Above the peer-negotiated 8 KiB ceiling, but below the server's 64 KiB offer.
    // The length alone must reject admission; no payload or FIN is needed.
    send.write_all(&8193_u32.to_be_bytes()).await?;
    let result = tokio::time::timeout(Duration::from_secs(2), receive.read(&mut [0; 1]))
        .await
        .map_err(|_| "oversized negotiated frame was not rejected before payload IO")?;
    assert!(matches!(result, Ok(None) | Err(quinn::ReadError::Reset(_))));
    Ok(())
}

fn host(
    fixture: &RunningAuthority,
    smaller_offer: bool,
    targets: crate::federation_sessions::FederationBackupTargets,
) -> TestResult<FederationSessions> {
    let now = crate::api_http::current_time().ok_or("clock")?;
    let configuration = FederationSessionConfiguration {
        private_network: Arc::default(),
        database_path: fixture.directory.path().join("partition.sqlite3"),
        reader: AuthoritativeRepository::new(PartitionDatabase::open(
            &fixture.directory.path().join("partition.sqlite3"),
            PartitionId::from_bytes([2; 16])?,
            now,
        )?),
        identity: crate::local_federation_identity::LocalFederationIdentity::open_or_create(
            &fixture.directory.path().join("federation-identity.v1"),
            now,
        )?,
        node: fixture.node_id,
        backups: crate::federation_sessions::FederationBackupProviderConfiguration {
            targets,
            authority_database: fixture.directory.path().join("partition.sqlite3"),
            local_database: fixture.directory.path().join("local.sqlite3"),
            node: fixture.node_id,
        },
    };
    let bind = "127.0.0.1:0".parse()?;
    if !smaller_offer {
        return Ok(configuration.bind(bind)?);
    }
    let wire = meshspan_protocol::WireLimits::new(8192, 16384, 256, 4096)?;
    Ok(FederationSessions::new(
        configuration,
        bind,
        meshspan_transport::TransportLimits::new(wire, 3, 64 * 1024, 4 * 1024 * 1024)?,
    )?)
}

fn revoke(fixture: &RunningAuthority, relationship: FederationRelationshipId) -> TestResult<()> {
    authority(fixture)?.commit_authoritative(
        CommandContext {
            operation_id: OperationId::from_bytes([71; 16])?,
            actor_principal_id: fixture.administrator_id,
            audit_event_id: AuditEventId::from_bytes([72; 16])?,
            occurred_at: crate::api_http::current_time().ok_or("clock")?,
            expected_revision: None,
        },
        &AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
            relationship_id: relationship,
            expected_authority_epoch: 1,
            authority_epoch: 2,
            reason: "Revoke live native session".into(),
        }),
    )?;
    Ok(())
}
