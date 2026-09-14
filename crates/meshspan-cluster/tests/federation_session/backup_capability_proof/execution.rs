// SPDX-License-Identifier: GPL-2.0-only

//! Signed operations through real QUIC frames and a real, namespaced directory provider.

use super::{Fixture, NOW, context, replay, requests, transport_limits};
use meshspan_backup::{DirectoryBackupProvider, NamespacedBackupProvider};
use meshspan_cluster::{
    FederationBackupIssueRequest, FederationBackupStreamContext, federation_connection_authority,
};
use meshspan_contracts::{
    BackupProvider, FederatedBackupRequest, federated_provider_backup_identity,
};
use meshspan_data_plane::{encode_federated_backup_permit, encode_federated_backup_request};
use meshspan_domain::{Clock, UnixMicros};
use meshspan_protocol::v1::{
    DataFrame, ExecuteFederatedBackup, federated_backup_result::Outcome,
    federation_envelope::Message,
};
use meshspan_transport::{
    FederationLocalIdentity, FederationPeerRegistry, OutboundFederationBackupMessage, StreamKind,
    accept_stream, open_stream, receive_data_frame, receive_federation, send_data_frame,
    send_federation, signed_federation_backup_message,
};
use sha2::{Digest, Sha256};
use std::error::Error;

const PAYLOAD: &[u8] = b"encrypted-backup-123";
type Provider = NamespacedBackupProvider<DirectoryBackupProvider>;

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        NOW
    }
}

#[tokio::test]
async fn signed_backup_streams_store_replay_read_verify_delete_and_recover_a_short_upload()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new().await?;
    let directory = tempfile::tempdir()?;
    let mut actions = requests()?;
    for request in &mut actions {
        update_object(request);
    }
    let store = actions.first().ok_or("missing store")?.clone();
    let mut lookup_context = store.context();
    lookup_context.operation_id = meshspan_domain::OperationId::from_bytes([159; 16])?;
    actions.insert(
        3,
        FederatedBackupRequest::Lookup(meshspan_contracts::BackupLookupRequest {
            context: lookup_context,
            object: store.object(),
        }),
    );
    let physical = federated_provider_backup_identity(fixture.scope, store.object())?;
    let directory_provider = DirectoryBackupProvider::open(
        directory.path(),
        physical.destination_id,
        physical.provider_generation,
        20,
        NOW,
    )?;
    let provider =
        NamespacedBackupProvider::new(fixture.scope, store.object(), directory_provider)?;
    let (fixture, provider, failed) = cycle(fixture, provider, &store, &PAYLOAD[..10]).await?;
    assert!(matches!(failed, Outcome::Rejection(_)));
    let (fixture, provider, corrupt) = cycle(fixture, provider, &store, &[0; 20]).await?;
    assert!(matches!(corrupt, Outcome::Rejection(_)));
    let extra = [PAYLOAD, b"x"].concat();
    let (fixture, provider, excessive) = cycle(fixture, provider, &store, &extra).await?;
    assert!(matches!(excessive, Outcome::Rejection(_)));
    let (fixture, provider, stored) = cycle(fixture, provider, &store, PAYLOAD).await?;
    let Outcome::Stored(receipt) = &stored else {
        return Err("store did not return a durable receipt".into());
    };
    let reference =
        meshspan_contracts::BackupObjectReference::new(receipt.object_reference.clone())?;
    let (mut fixture, mut provider, replayed) = cycle(fixture, provider, &store, PAYLOAD).await?;
    assert_eq!(replayed, stored);
    (fixture, provider) = prove_capacity_denial(fixture, provider, &store).await?;
    for request in actions.iter_mut().skip(1) {
        match request {
            FederatedBackupRequest::Read(value) => value.object_reference = reference.clone(),
            FederatedBackupRequest::Verify(value) => value.object_reference = reference.clone(),
            FederatedBackupRequest::Delete(value) => value.object_reference = reference.clone(),
            FederatedBackupRequest::Lookup(_) => {}
            FederatedBackupRequest::Store(_) => return Err("unexpected second store".into()),
        }
        let (next_fixture, next_provider, outcome) =
            cycle(fixture, provider, request, PAYLOAD).await?;
        assert!(matches!(
            (request, outcome),
            (FederatedBackupRequest::Read(_), Outcome::Read(_))
                | (FederatedBackupRequest::Verify(_), Outcome::Verified(_))
                | (FederatedBackupRequest::Delete(_), Outcome::Deleted(_))
                | (FederatedBackupRequest::Lookup(_), Outcome::LookedUp(_))
        ));
        fixture = next_fixture;
        provider = next_provider;
    }
    // Local owner verification establishes actual removal, not just a signed claim.
    let FederatedBackupRequest::Verify(verify) = actions.get(2).ok_or("missing verify")? else {
        return Err("wrong action".into());
    };
    assert_eq!(
        provider.verify_exact(verify, NOW),
        Err(meshspan_contracts::ContractError::NotFound)
    );
    fixture.connections.close_and_wait().await;
    fixture.server.wait_idle().await;
    Ok(())
}

async fn prove_capacity_denial(
    fixture: Fixture,
    provider: Provider,
    original: &FederatedBackupRequest,
) -> Result<(Fixture, Provider), Box<dyn Error>> {
    let FederatedBackupRequest::Store(mut request) = original.clone() else {
        return Err("expected store".into());
    };
    request.context.operation_id = meshspan_domain::OperationId::from_bytes([155; 16])?;
    request.object.backup_id = meshspan_domain::BackupId::from_bytes([156; 16])?;
    let (fixture, provider, outcome) = cycle(
        fixture,
        provider,
        &FederatedBackupRequest::Store(request),
        PAYLOAD,
    )
    .await?;
    let Outcome::Rejection(error) = outcome else {
        return Err("capacity exhaustion was not rejected".into());
    };
    assert_eq!(
        error.code,
        i32::from(meshspan_protocol::v1::ErrorCode::Exhausted)
    );
    Ok((fixture, provider))
}

fn update_object(request: &mut FederatedBackupRequest) {
    let (context, object) = match request {
        FederatedBackupRequest::Store(value) => (&mut value.context, &mut value.object),
        FederatedBackupRequest::Read(value) => (&mut value.context, &mut value.object),
        FederatedBackupRequest::Verify(value) => (&mut value.context, &mut value.object),
        FederatedBackupRequest::Delete(value) => (&mut value.context, &mut value.object),
        FederatedBackupRequest::Lookup(value) => (&mut value.context, &mut value.object),
    };
    context.deadline = UnixMicros::new(2_400_000);
    object.byte_length = PAYLOAD.len() as u64;
    object.digest = Sha256::digest(PAYLOAD).into();
}

async fn prepare(
    fixture: &Fixture,
    request: &FederatedBackupRequest,
) -> Result<OutboundFederationBackupMessage, Box<dyn Error>> {
    let authenticated = fixture
        .authenticate(
            Message::RequestBackupCapability(encode_federated_backup_request(
                fixture.scope,
                request,
                NOW,
            )?),
            context(request, 131)?,
        )
        .await?;
    let provider_identity = fixture.provider_identity()?;
    let issued = fixture
        .service(&provider_identity)
        .issue(&FederationBackupIssueRequest {
            authenticated: &authenticated,
            response_nonce: [132; 32],
            capability_nonce: [133; 32],
            expires_at: UnixMicros::new(2_300_000),
            observed_at: NOW,
            limits: transport_limits()?.wire,
        })?;
    let current = federation_connection_authority(
        fixture.authorities.client.repository(),
        fixture.scope.relationship_id,
        NOW,
    )?
    .ok_or("missing consumer authority")?;
    let identity = FederationLocalIdentity::authenticate(
        current.local_identity,
        &fixture.certificates.client,
        &fixture.client_key,
        NOW,
    )?;
    Ok(signed_federation_backup_message(
        &identity,
        context(request, 134)?,
        Message::ExecuteBackup(ExecuteFederatedBackup {
            permit: Some(encode_federated_backup_permit(issued.permit(), NOW)?),
            signature: Vec::new(),
        }),
        transport_limits()?.wire,
        NOW,
    )?)
}

async fn cycle(
    fixture: Fixture,
    provider: Provider,
    request: &FederatedBackupRequest,
    source: &[u8],
) -> Result<(Fixture, Provider, Outcome), Box<dyn Error>> {
    let outbound = prepare(&fixture, request).await?;
    let current = federation_connection_authority(
        fixture.authorities.client.repository(),
        fixture.scope.relationship_id,
        NOW,
    )?
    .ok_or("missing consumer authority")?;
    let registry = FederationPeerRegistry::new([current.peer])?;
    let connection = fixture.connections.client.clone();
    let runtime = tokio::runtime::Handle::current();
    let worker = tokio::task::spawn_blocking(move || {
        let mut provider = provider;
        let result = serve(&fixture, &mut provider, &runtime).map_err(|error| error.to_string());
        (fixture, provider, result)
    });
    let result = client(&connection, &registry, &outbound, request, source).await;
    let (fixture, provider, served) = worker.await?;
    served?;
    Ok((fixture, provider, result?))
}

fn serve(
    fixture: &Fixture,
    provider: &mut Provider,
    runtime: &tokio::runtime::Handle,
) -> Result<(), Box<dyn Error>> {
    let limits = transport_limits()?.wire;
    let (stream, envelope) = runtime.block_on(async {
        let mut stream = accept_stream(&fixture.connections.server).await?;
        let envelope = receive_federation(&mut stream.receive, limits).await?;
        Ok::<_, Box<dyn Error>>((stream, envelope))
    })?;
    let current = federation_connection_authority(
        fixture.authorities.server.repository(),
        fixture.scope.relationship_id,
        NOW,
    )?
    .ok_or("missing provider authority")?;
    let authenticated = FederationPeerRegistry::new([current.peer])?.authenticate_backup_request(
        &fixture.connections.server,
        &envelope,
        NOW,
        &mut replay()?,
    )?;
    let identity = fixture.provider_identity()?;
    fixture.service(&identity).execute_stream(
        &authenticated,
        provider,
        stream,
        &FederationBackupStreamContext {
            runtime,
            clock: &FixedClock,
            limits,
            ready_nonce: [135; 32],
            result_nonce: [136; 32],
        },
    )?;
    Ok(())
}

async fn client(
    connection: &quinn::Connection,
    registry: &FederationPeerRegistry,
    outbound: &OutboundFederationBackupMessage,
    request: &FederatedBackupRequest,
    source: &[u8],
) -> Result<Outcome, Box<dyn Error>> {
    let limits = transport_limits()?.wire;
    let (mut send, mut receive) = open_stream(connection, StreamKind::Federation).await?;
    send_federation(&mut send, outbound.envelope(), limits).await?;
    if !matches!(request, FederatedBackupRequest::Store(_)) {
        send.finish()?;
    }
    let mut replay = replay()?;
    let ready = receive_federation(&mut receive, limits).await?;
    let ready = registry.authenticate_backup_response(
        connection,
        &ready,
        &outbound.expectation()?,
        NOW,
        &mut replay,
    )?;
    if let Message::BackupReady(value) = ready.message()
        && let Some(rejection) = &value.rejection
    {
        // This branch is before any data send: actual provider capacity rejected admission.
        assert_eq!(
            rejection.code,
            i32::from(meshspan_protocol::v1::ErrorCode::Exhausted)
        );
        return Ok(Outcome::Rejection(*rejection));
    }
    let expected = ready.result_expectation()?;
    match request {
        FederatedBackupRequest::Store(_) => {
            for (index, bytes) in source.chunks(5).enumerate() {
                send_data_frame(
                    &mut send,
                    &DataFrame {
                        offset: (index * 5) as u64,
                        bytes: bytes.to_vec(),
                    },
                    limits,
                )
                .await?;
            }
            send.finish()?;
        }
        FederatedBackupRequest::Read(_) => {
            let mut bytes = Vec::new();
            while bytes.len() < PAYLOAD.len() {
                let frame = receive_data_frame(&mut receive, limits).await?.into_inner();
                assert_eq!(frame.offset, bytes.len() as u64);
                bytes.extend_from_slice(&frame.bytes);
            }
            assert_eq!(bytes, PAYLOAD);
        }
        FederatedBackupRequest::Verify(_)
        | FederatedBackupRequest::Delete(_)
        | FederatedBackupRequest::Lookup(_) => {}
    }
    let result = receive_federation(&mut receive, limits).await?;
    let result =
        registry.authenticate_backup_response(connection, &result, &expected, NOW, &mut replay)?;
    let Message::BackupResult(result) = result.message() else {
        return Err("missing authenticated result".into());
    };
    result
        .outcome
        .clone()
        .ok_or_else(|| "missing outcome".into())
}
