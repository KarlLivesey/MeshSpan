// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[tokio::test]
async fn peer_admission_reads_current_mesh_without_appending_and_stops_with_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([31; 16])?;
    let driver = driver(&directory.path().join("admission.sqlite3"), local)?;
    let partition = driver.persistence().partition_id();
    let (authority, runtime) = spawn_metadata_authority(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
    )?;
    let empty = authority
        .peer_admission(local, MetadataPeerAdmissionPurpose::ReadFence)
        .await?;
    assert_eq!(empty.mesh_id, None);
    assert_eq!(empty.partition_id, partition);
    assert_eq!(empty.certificate, None);
    assert_eq!(empty.details, MetadataPeerAdmissionDetails::ReadFence);
    authority.begin_election().await?;
    let (context, command) = command(local, [32; 16])?;
    let receipt = authority.commit_or_resolve(context, command).await?;
    let before = authority.observe().await?;
    for _ in 0..4 {
        let state = authority
            .peer_admission(local, MetadataPeerAdmissionPurpose::Command)
            .await?;
        assert_eq!(state.mesh_id, Some(MeshId::from_bytes([32; 16])?));
        assert_eq!(state.partition_id, partition);
        assert_eq!(
            state
                .certificate
                .as_ref()
                .map(|certificate| certificate.node_id),
            Some(local)
        );
        assert_eq!(
            state.details,
            MetadataPeerAdmissionDetails::Command {
                is_voter: true,
                registration: None
            }
        );
    }
    assert_eq!(authority.observe().await?, before);
    assert_eq!(before.applied_index, receipt.committed_position.index);
    authority.shutdown().await?;
    runtime.await??;
    assert_eq!(
        authority
            .peer_admission(local, MetadataPeerAdmissionPurpose::ReadFence)
            .await,
        Err(MetadataAuthorityRequestError::Unavailable)
    );
    Ok(())
}

#[tokio::test]
async fn peer_admission_rejects_full_ingress_and_a_lost_responder()
-> Result<(), Box<dyn std::error::Error>> {
    let node = NodeId::from_bytes([1; 16])?;
    let (events, mut receiver) = mpsc::channel(1);
    let authority = MetadataAuthorityHandle { events };
    authority.begin_election().await?;
    assert_eq!(
        authority
            .peer_admission(node, MetadataPeerAdmissionPurpose::ReadFence)
            .await,
        Err(MetadataAuthorityRequestError::Unavailable)
    );
    assert!(matches!(
        receiver.recv().await,
        Some(AuthorityEvent::BeginElection)
    ));
    let read = authority.peer_admission(node, MetadataPeerAdmissionPurpose::ReadFence);
    tokio::pin!(read);
    let respond = tokio::select! {
        result = &mut read => return Err(format!("unexpected admission {result:?}").into()),
        event = receiver.recv() => match event {
            Some(AuthorityEvent::PeerAdmission(request)) => {
                assert_eq!(request.node_id, node);
                assert_eq!(request.purpose, MetadataPeerAdmissionPurpose::ReadFence);
                request.respond
            }
            _ => return Err("missing admission request".into()),
        }
    };
    drop(respond);
    assert_eq!(read.await, Err(MetadataAuthorityRequestError::Unavailable));
    Ok(())
}

#[tokio::test]
async fn peer_admission_timeout_and_cancellation_do_not_leave_live_waiters()
-> Result<(), Box<dyn std::error::Error>> {
    let node = NodeId::from_bytes([1; 16])?;
    let (events, mut receiver) = mpsc::channel(1);
    let authority = MetadataAuthorityHandle { events };
    assert_eq!(
        authority
            .peer_admission(node, MetadataPeerAdmissionPurpose::ReadFence)
            .await,
        Err(MetadataAuthorityRequestError::Unavailable)
    );
    let Some(AuthorityEvent::PeerAdmission(timed_out)) = receiver.recv().await else {
        return Err("missing timed out request".into());
    };
    assert!(timed_out.respond.is_closed());
    let cancelled = {
        let read = authority.peer_admission(node, MetadataPeerAdmissionPurpose::ReadFence);
        tokio::pin!(read);
        tokio::select! {
            result = &mut read => return Err(format!("unexpected admission {result:?}").into()),
            event = receiver.recv() => match event {
                Some(AuthorityEvent::PeerAdmission(request)) => request,
                _ => return Err("missing cancelled request".into()),
            }
        }
    };
    assert!(cancelled.respond.is_closed());
    Ok(())
}
