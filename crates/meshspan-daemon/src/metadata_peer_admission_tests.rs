// SPDX-License-Identifier: GPL-2.0-only

//! Real owner/SQL admission projection tests; certificate issuance has separate acceptance.

use super::*;
use meshspan_domain::Clock as _;
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, MetadataCommand, RequestHeader, VersionedPayload,
    control_envelope::Message, metadata_command::Command,
};
use meshspan_transport::PeerBinding;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_peer_admission_uses_retained_owner_and_rechecks_live_certificate()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RunningAuthority::start().await?;
    let file = fixture.directory.path().join("partition.sqlite3");
    let writer = rusqlite::Connection::open(&file)?;
    let now = crate::OperatingSystemClock.now();
    // Existing bootstrap is synthetic; give its public projection finite current validity.
    assert_eq!(
        writer.execute(
            "UPDATE node_certificates SET valid_until = ?1 WHERE node_id = ?2",
            rusqlite::params![
                now.get() + 60_000_000,
                fixture.node_id.as_bytes().as_slice()
            ]
        )?,
        1
    );
    let (peer, envelope) = admission_request(&fixture)?;
    let first = assert_admitted(&fixture.handle, peer, &envelope).await?;
    let moved = fixture.directory.path().join("held-partition.sqlite3");
    // Test-only path fault: a reopen cannot find this database. No writes occur while moved.
    std::fs::rename(&file, &moved)?;
    let outcome = repeated_reads_without_path(&fixture, peer, &envelope, first).await;
    let restore = std::fs::rename(&moved, &file);
    restore?;
    outcome?;
    // Model a newly applied certificate projection using a second real connection. This
    // checks live reads, not the separately tested certificate issuance/consensus command.
    let replacement = vec![79_u8; 64];
    let fingerprint: [u8; 32] = Sha256::digest(&replacement).into();
    assert_eq!(
        writer.execute(
            "UPDATE node_certificates SET certificate_der = ?1,
        certificate_fingerprint = ?2, revision = revision + 1 WHERE node_id = ?3",
            rusqlite::params![
                replacement,
                fingerprint.as_slice(),
                fixture.node_id.as_bytes().as_slice()
            ]
        )?,
        1
    );
    assert_denied(&fixture.handle, peer, &envelope).await?;
    let replacement_peer = PeerBinding {
        certificate_fingerprint: fingerprint,
        ..peer
    };
    assert_admitted(&fixture.handle, replacement_peer, &envelope).await?;
    assert_eq!(
        writer.execute(
            "UPDATE node_certificates SET state = 3 WHERE node_id = ?1",
            [fixture.node_id.as_bytes().as_slice()]
        )?,
        1
    );
    assert_denied(&fixture.handle, replacement_peer, &envelope).await?;
    drop(writer);
    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_fence_rechecks_certificate_retired_after_quorum_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::appliance_runtime::metadata_read_fence_service::{
        ReadFenceAdmissionGate, read_fence_with_admission_gate,
    };

    let fixture = RunningAuthority::start().await?;
    let writer = rusqlite::Connection::open(fixture.directory.path().join("partition.sqlite3"))?;
    let now = crate::OperatingSystemClock.now();
    assert_eq!(
        writer.execute(
            "UPDATE node_certificates SET valid_until = ?1 WHERE node_id = ?2",
            rusqlite::params![
                now.get() + 60_000_000,
                fixture.node_id.as_bytes().as_slice()
            ],
        )?,
        1
    );
    let (peer, envelope) = admission_request(&fixture)?;
    let (confirmed, ready) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let outcome = {
        let pending = read_fence_with_admission_gate(
            &fixture.handle,
            peer,
            envelope.header.as_ref().ok_or("missing header")?,
            ReadFenceAdmissionGate {
                confirmed,
                released,
            },
        );
        tokio::pin!(pending);
        let fence = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                result = &mut pending => Err(format!("read returned before release: {result:?}")),
                result = ready => result.map_err(|_| "fence confirmation signal closed".to_owned()),
            }
        })
        .await??;
        assert_eq!(fence.partition_id, PartitionId::from_bytes([2; 16])?);
        assert_eq!(fence.leader_node_id, fixture.node_id);
        assert!(fence.applied.index > 0);
        // Apply a retirement projection after the real quorum fence has returned, while
        // response admission is paused. This is not a wire or catch-up simulation.
        assert_eq!(
            writer.execute(
                "UPDATE node_certificates SET state = 3 WHERE node_id = ?1",
                [fixture.node_id.as_bytes().as_slice()],
            )?,
            1
        );
        release
            .send(())
            .map_err(|()| "response admission stopped before release")?;
        tokio::time::timeout(std::time::Duration::from_secs(5), pending).await?
    };
    drop(writer);
    fixture.shutdown().await?;
    assert_eq!(outcome, Err(ErrorCode::Unauthorised));
    Ok(())
}

async fn repeated_reads_without_path(
    fixture: &RunningAuthority,
    peer: PeerBinding,
    envelope: &ControlEnvelope,
    expected: meshspan_cluster::MetadataReadFence,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = fixture.directory.path().join("partition.sqlite3");
    assert!(!file.try_exists()?);
    assert!(PartitionDatabase::open_existing(&file, crate::OperatingSystemClock.now()).is_err());
    for _ in 0..8 {
        assert_eq!(
            assert_admitted(&fixture.handle, peer, envelope).await?,
            expected
        );
    }
    Ok(())
}

fn admission_request(
    fixture: &RunningAuthority,
) -> Result<(PeerBinding, ControlEnvelope), Box<dyn std::error::Error>> {
    let reader = fixture.reader.as_ref().ok_or("missing fixture reader")?;
    let certificate = reader
        .active_node_certificate(fixture.node_id)?
        .ok_or("missing fixture certificate")?;
    let peer = PeerBinding {
        node_id: fixture.node_id,
        incarnation: certificate.incarnation,
        certificate_fingerprint: certificate.certificate_fingerprint,
    };
    let now = crate::OperatingSystemClock.now();
    let context = command_context(fixture.administrator_id, 70, 71, now.get(), None)?;
    let command = user_creation(72, "Admission only")?;
    Ok((
        peer,
        ControlEnvelope {
            header: Some(RequestHeader {
                mesh_id: reader
                    .local_mesh_id()?
                    .ok_or("missing mesh")?
                    .as_bytes()
                    .to_vec(),
                partition_id: reader.partition_id().as_bytes().to_vec(),
                sender_node_id: peer.node_id.as_bytes().to_vec(),
                sender_incarnation: peer.incarnation,
                operation_id: context.operation_id.as_bytes().to_vec(),
                deadline_unix_micros: now.get() + 9_000_000,
                ..RequestHeader::default()
            }),
            message: Some(Message::MetadataCommand(MetadataCommand {
                expected_revision: None,
                request_digest: command.request_digest(context).to_vec(),
                command: Some(Command::IdentityAccess(VersionedPayload {
                    format_version: u32::from(meshspan_metadata::METADATA_COMMAND_VERSION),
                    canonical_bytes: meshspan_metadata::encode_authoritative_command(
                        context, &command,
                    )?,
                })),
            })),
        },
    ))
}

async fn assert_admitted(
    authority: &MetadataAuthorityHandle,
    peer: PeerBinding,
    envelope: &ControlEnvelope,
) -> Result<meshspan_cluster::MetadataReadFence, Box<dyn std::error::Error>> {
    let header = envelope.header.as_ref().ok_or("missing header")?;
    let admitted =
        crate::metadata_forwarding::admission::prepare(authority, peer, envelope.clone())
            .await
            .map_err(|code| format!("command admission: {code:?}"))?;
    assert_eq!(
        admitted.context.operation_id.as_bytes().as_slice(),
        header.operation_id
    );
    assert!(matches!(
        admitted.command,
        AuthoritativeCommand::CreateUser(_)
    ));
    crate::appliance_runtime::metadata_read_fence_service::read_fence(authority, peer, header)
        .await
        .map_err(|code| format!("read-fence admission: {code:?}").into())
}

async fn assert_denied(
    authority: &MetadataAuthorityHandle,
    peer: PeerBinding,
    envelope: &ControlEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        crate::metadata_forwarding::admission::prepare(authority, peer, envelope.clone()).await,
        Err(
            crate::metadata_forwarding::admission::AdmissionError::Protocol(
                ErrorCode::Unauthorised
            )
        )
    ));
    assert_eq!(
        crate::appliance_runtime::metadata_read_fence_service::read_fence(
            authority,
            peer,
            envelope.header.as_ref().ok_or("missing header")?
        )
        .await,
        Err(ErrorCode::Unauthorised)
    );
    Ok(())
}
