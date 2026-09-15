// SPDX-License-Identifier: GPL-2.0-only

//! Expired and forgotten admission resumes through real authenticated wire and reopened packs.

use super::*;
use meshspan_contracts::{ContractVersion, RequestContext, ShardPutIntent, ShardReceipt};
use meshspan_data_plane::RepairShardUpload;

pub(super) async fn prove(
    connections: (&quinn::Connection, &quinn::Connection),
    provider: (
        RemoteShardService<SharedStorageProvider<FolderShardStore>>,
        TargetMarker,
    ),
    peer: AuthenticatedPeer,
    fixture: &Fixture,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let (service, marker) = provider;
    let observed = Arc::new(ObservedWrites::default());
    let service = shared_service(
        service.into_provider().with_io_observer(observed.clone()),
        fixture,
    )?;
    let server = Box::pin(serve(
        connections.1,
        (service, marker),
        peer,
        fixture,
        limits,
        &observed,
    ));
    let client = Box::pin(client(connections.0, fixture, limits, &observed));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::try_join!(server, client)
    })
    .await??;
    assert_eq!(
        observed.count.load(Ordering::SeqCst),
        1,
        "one original physical repair write"
    );
    Ok(())
}

async fn serve(
    connection: &quinn::Connection,
    provider: (
        RemoteShardService<SharedStorageProvider<FolderShardStore>>,
        TargetMarker,
    ),
    peer: AuthenticatedPeer,
    fixture: &Fixture,
    limits: WireLimits,
    observed: &Arc<ObservedWrites>,
) -> Result<(), Box<dyn Error>> {
    let (mut service, marker) = provider;
    for (time, cancelled) in [(9_000_000, true), (15_000_000, false)] {
        let stream = accept_stream(connection).await?;
        let result = service
            .serve_stream(stream, peer, limits, UnixMicros::new(time))
            .await;
        if cancelled {
            assert!(matches!(result, Err(DataPlaneError::Transport(_))));
        } else {
            match result {
                Ok(()) | Err(DataPlaneError::Transport(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        drop(service);
        service = shared_service(
            SharedStorageProvider::new(reopen(fixture, marker, UnixMicros::new(time + 1))?)
                .with_io_observer(observed.clone()),
            fixture,
        )?;
    }
    for _ in 0..5 {
        let stream = accept_stream(connection).await?;
        service
            .serve_stream(stream, peer, limits, UnixMicros::new(21_000_000))
            .await?;
    }
    Ok(())
}

async fn client(
    connection: &quinn::Connection,
    fixture: &Fixture,
    limits: WireLimits,
    observed: &ObservedWrites,
) -> Result<(), Box<dyn Error>> {
    let bytes = BoundedBytes::copy_from(b"repair resumes the same exact bytes", 1024)?;
    let mut authority = fixture.write_permit(bytes.len())?;
    authority.operation_id = OperationId::from_bytes([91; 16])?;
    authority.shard.manifest_digest = [91; 32];
    authority.reservation_class = ReservationClass::Repair;
    authority.expires_at = UnixMicros::new(14_000_000);
    sign(&mut authority)?;
    let mut header = request_header(fixture.mesh, node(2)?, authority.operation_id)?;
    header.deadline_unix_micros = authority.expires_at.get();
    let intent = ShardPutIntent {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: authority.operation_id,
            deadline: authority.expires_at,
            expected_revision: Some(Revision::new(5)),
        },
        target_id: fixture.target,
        target_generation: 3,
        reservation_class: ReservationClass::Repair,
        maximum_bytes: bytes.len() as u64,
        shard: authority.shard,
        expected_length: bytes.len() as u64,
        expected_digest: *blake3::hash(bytes.as_slice()).as_bytes(),
    };
    let clock = TestClock(Cell::new(9_000_000));
    let client = ShardUploadClient::new(connection, limits, &clock);
    let RepairShardUpload::Prepared(prepared) = client
        .resume_repair_upload(header.clone(), intent, authority)
        .await?
    else {
        return Err("new repair was unexpectedly verified".into());
    };
    let original = prepared.identity();
    assert_eq!(original.intent(), intent);
    drop(prepared);
    clock.0.set(15_000_000);
    authority.expires_at = UnixMicros::new(20_000_000);
    authority.authorization_revision = Revision::new(6);
    sign(&mut authority)?;
    header.deadline_unix_micros = authority.expires_at.get();
    let RepairShardUpload::Prepared(prepared) = client
        .resume_repair_upload(header.clone(), intent, authority)
        .await?
    else {
        return Err("incomplete repair was unexpectedly verified".into());
    };
    assert_eq!(
        prepared.identity(),
        original,
        "the intent recovers the actual original admission"
    );
    tokio::select! {
        biased;
        () = observed.durable.notified() => {}
        result = client.finish_upload(prepared, &bytes) => {
            return Err(format!("expected lost write acknowledgement, got {result:?}").into());
        }
    }
    clock.0.set(21_000_000);
    authority.expires_at = UnixMicros::new(26_000_000);
    sign(&mut authority)?;
    header.deadline_unix_micros = authority.expires_at.get();
    verify_recovered(&client, header, intent, authority).await?;
    let mut read = fixture.read_permit()?;
    read.shard = intent.shard;
    read.expires_at = authority.expires_at;
    read.permit_digest = read_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, read);
    let mut header = request_header(fixture.mesh, node(2)?, read.operation_id)?;
    header.deadline_unix_micros = read.expires_at.get();
    assert_eq!(
        get_shard(connection, header, read, 1024, limits).await?,
        bytes
    );
    Ok(())
}

async fn verify_recovered(
    client: &ShardUploadClient<'_>,
    header: RequestHeader,
    intent: ShardPutIntent,
    authority: ShardWritePermit,
) -> Result<(), Box<dyn Error>> {
    let expected = ShardReceipt {
        operation_id: intent.context.operation_id,
        shard: intent.shard,
        length: intent.expected_length,
        digest: intent.expected_digest,
        target_id: intent.target_id,
        target_generation: intent.target_generation,
    };
    for _ in 0..2 {
        let RepairShardUpload::Verified(receipt) = client
            .resume_repair_upload(header.clone(), intent, authority)
            .await?
        else {
            return Err("committed repair requested another upload".into());
        };
        assert_eq!(receipt, expected);
    }
    let mut forged = authority;
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        client
            .resume_repair_upload(header.clone(), intent, forged)
            .await,
        Err(DataPlaneError::Remote(ErrorCode::Unauthorised))
    ));
    assert!(matches!(
        client
            .resume_repair_upload(
                header,
                ShardPutIntent {
                    expected_digest: [92; 32],
                    ..intent
                },
                authority
            )
            .await,
        Err(DataPlaneError::Remote(ErrorCode::Conflict))
    ));
    Ok(())
}

fn sign(authority: &mut ShardWritePermit) -> Result<(), Box<dyn Error>> {
    authority.permit_digest =
        write_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, *authority);
    Ok(())
}
