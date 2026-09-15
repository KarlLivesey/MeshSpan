// SPDX-License-Identifier: GPL-2.0-only

//! Real admission cancellation and lost-result recovery through the exact put protocol.

use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use meshspan_contracts::{
    ContractError, ShardPutResolution, StorageIoKind, StorageIoObservation, StorageIoObserver,
};
use meshspan_data_plane::ShardUploadClient;
use meshspan_domain::Clock;
use meshspan_storage::{SharedStorageProvider, TargetMarker};
use meshspan_transport::AuthenticatedPeer;

use super::*;

#[derive(Default)]
struct ObservedWrites {
    count: AtomicUsize,
    durable: tokio::sync::Notify,
}

impl StorageIoObserver for ObservedWrites {
    fn observe_storage_io(&self, observation: StorageIoObservation) {
        if observation.kind == StorageIoKind::Write && !observation.failed {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.durable.notify_one();
        }
    }
}

struct TestClock(Cell<i64>);
impl Clock for TestClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.get())
    }
}

pub(super) async fn prove(
    connections: (&quinn::Connection, &quinn::Connection),
    service: RemoteShardService<FolderShardStore>,
    peer: AuthenticatedPeer,
    fixture: &Fixture,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let observed = Arc::new(ObservedWrites::default());
    let marker = service.provider().target_marker();
    let provider =
        SharedStorageProvider::new(service.into_provider()).with_io_observer(observed.clone());
    let server = ResolutionServer {
        connection: connections.1,
        service: shared_service(provider, fixture)?,
        marker,
        fixture,
        peer,
        limits,
        observed: observed.clone(),
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::try_join!(
            server.run(),
            prove_client(connections.0, fixture, limits, &observed)
        )
    })
    .await??;
    assert_eq!(
        observed.count.load(Ordering::SeqCst),
        1,
        "resolution must not perform another put"
    );
    Ok(())
}

struct ResolutionServer<'a> {
    connection: &'a quinn::Connection,
    service: RemoteShardService<SharedStorageProvider<FolderShardStore>>,
    marker: TargetMarker,
    fixture: &'a Fixture,
    peer: AuthenticatedPeer,
    limits: WireLimits,
    observed: Arc<ObservedWrites>,
}

impl ResolutionServer<'_> {
    async fn run(mut self) -> Result<(), Box<dyn Error>> {
        let stream = accept_stream(self.connection).await?;
        assert!(matches!(
            self.service
                .serve_stream(stream, self.peer, self.limits, UnixMicros::new(20))
                .await,
            Err(DataPlaneError::Transport(_))
        ));
        let stream = accept_stream(self.connection).await?;
        match self
            .service
            .serve_stream(stream, self.peer, self.limits, UnixMicros::new(21))
            .await
        {
            Ok(()) | Err(DataPlaneError::Transport(_)) => {}
            Err(error) => return Err(error.into()),
        }
        drop(self.service);
        let provider = reopen(self.fixture, self.marker)?;
        self.service = shared_service(
            SharedStorageProvider::new(provider).with_io_observer(self.observed),
            self.fixture,
        )?;
        for _ in 0..4 {
            let stream = accept_stream(self.connection).await?;
            self.service
                .serve_stream(stream, self.peer, self.limits, UnixMicros::new(6_000_000))
                .await?;
        }
        let stream = accept_stream(self.connection).await?;
        assert!(matches!(
            self.service
                .serve_stream(stream, self.peer, self.limits, UnixMicros::new(6_000_000))
                .await,
            Err(DataPlaneError::Transport(_))
        ));
        Ok(())
    }
}

async fn prove_client(
    connection: &quinn::Connection,
    fixture: &Fixture,
    limits: WireLimits,
    observed: &ObservedWrites,
) -> Result<(), Box<dyn Error>> {
    let bytes = BoundedBytes::copy_from(b"repair bytes after a lost acknowledgement", 1024)?;
    let mut authority = fixture.write_permit(bytes.len())?;
    authority.operation_id = OperationId::from_bytes([81; 16])?;
    authority.shard.manifest_digest = [81; 32];
    authority.expires_at = UnixMicros::new(5_000_000);
    authority.permit_digest =
        write_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, authority);
    let mut header = request_header(fixture.mesh, node(2)?, authority.operation_id)?;
    header.deadline_unix_micros = authority.expires_at.get();
    let clock = TestClock(Cell::new(20));
    let client = ShardUploadClient::new(connection, limits, &clock);
    let prepared = client
        .prepare_upload(header.clone(), authority, &bytes)
        .await?;
    let original = prepared.identity();
    assert_eq!(original.reservation.target_id, fixture.target);
    assert_eq!(original.reservation.target_generation, 3);
    assert_eq!(original.context.expected_revision, Some(Revision::new(5)));
    assert_eq!(original.context.deadline, UnixMicros::new(5_000_000));
    assert_eq!(original.expected_length, bytes.len() as u64);
    assert_eq!(
        original.expected_digest,
        *blake3::hash(bytes.as_slice()).as_bytes()
    );
    assert_eq!(original.shard, authority.shard);
    assert_eq!(observed.count.load(Ordering::SeqCst), 0);
    drop(prepared);
    clock.0.set(21);
    let prepared = client
        .prepare_upload(header.clone(), authority, &bytes)
        .await?;
    assert_eq!(
        prepared.identity(),
        original,
        "reservation replay must retain the exact admission"
    );
    tokio::select! {
        biased;
        () = observed.durable.notified() => {}
        result = client.finish_upload(prepared, &bytes) => {
            return Err(format!("expected cancellation at durable-write signal, got {result:?}").into());
        }
    }
    authority.authorization_revision = Revision::new(6);
    authority.expires_at = UnixMicros::new(8_000_000);
    authority.permit_digest =
        write_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, authority);
    header.deadline_unix_micros = authority.expires_at.get();
    clock.0.set(6_000_000);
    prove_resolution(&client, header.clone(), original, authority).await?;
    authority.operation_id = OperationId::from_bytes([82; 16])?;
    authority.shard.manifest_digest = [82; 32];
    authority.permit_digest =
        write_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, authority);
    header.operation_id = authority.operation_id.as_bytes().to_vec();
    let prepared = client.prepare_upload(header, authority, &bytes).await?;
    clock.0.set(8_000_000);
    assert!(matches!(
        client.finish_upload(prepared, &bytes).await,
        Err(DataPlaneError::Contract(ContractError::DeadlineExceeded))
    ));
    Ok(())
}

async fn prove_resolution(
    client: &ShardUploadClient<'_>,
    header: RequestHeader,
    original: meshspan_contracts::ShardPutIdentity,
    authority: ShardWritePermit,
) -> Result<(), Box<dyn Error>> {
    let resolved = client
        .resolve_upload(header.clone(), original, authority)
        .await?;
    assert_eq!(
        resolved,
        ShardPutResolution::Verified(meshspan_contracts::ShardReceipt {
            operation_id: original.context.operation_id,
            shard: original.shard,
            length: original.expected_length,
            digest: original.expected_digest,
            target_id: original.reservation.target_id,
            target_generation: original.reservation.target_generation,
        })
    );
    assert_eq!(
        client
            .resolve_upload(header.clone(), original, authority)
            .await?,
        resolved
    );
    let mut forged = authority;
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        client
            .resolve_upload(header.clone(), original, forged)
            .await,
        Err(DataPlaneError::Remote(ErrorCode::Unauthorised))
    ));
    let mut changed = original;
    changed.context.expected_revision = Some(Revision::new(4));
    assert!(matches!(
        client
            .resolve_upload(header.clone(), changed, authority)
            .await,
        Err(DataPlaneError::Remote(ErrorCode::Conflict))
    ));
    Ok(())
}

fn shared_service(
    provider: SharedStorageProvider<FolderShardStore>,
    fixture: &Fixture,
) -> Result<RemoteShardService<SharedStorageProvider<FolderShardStore>>, Box<dyn Error>> {
    Ok(RemoteShardService::new(
        provider,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        fixture.mesh,
        node(1)?,
        fixture.target,
        3,
        1024,
    )?)
}

fn reopen(fixture: &Fixture, marker: TargetMarker) -> Result<FolderShardStore, Box<dyn Error>> {
    let folder = RegisteredFolder::reopen(
        &fixture.temporary.path().join("storage"),
        FolderRegistration {
            mesh_id: fixture.mesh,
            target_id: fixture.target,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        },
        marker.fingerprint(),
    )?;
    Ok(FolderShardStore::reopen(
        folder,
        &fixture.temporary.path().join("state"),
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            fixture.mesh,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        UnixMicros::new(6_000_000),
        &mut FixedRandom,
    )?)
}
