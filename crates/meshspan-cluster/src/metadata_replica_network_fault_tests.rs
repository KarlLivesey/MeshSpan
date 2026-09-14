// SPDX-License-Identifier: GPL-2.0-only

use crate::metadata_replica_wire::encode_page;
use crate::{MetadataReplicaTransferError, reject_metadata_replica_page};
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, ErrorCode, FetchMetadataReplicaPage, MetadataReplicaPageHeader,
};
use meshspan_protocol::{WireLimits, decode_metadata_replica_body, encode_metadata_replica_body};
use meshspan_transport::{AcceptedStream, send_data_control, send_data_frame};

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Response {
    Valid,
    WrongRequest,
    WrongCursor,
    BadBodyDigest,
    BadEntryDigest,
    WrongOffset,
    Truncated,
    Trailing,
    OversizedFrame,
    Rejected,
    ReboundSource,
}

#[tokio::test]
async fn metadata_replica_real_quinn_bulk_roundtrip_and_hostile_responses() -> TestResult {
    let TransferFixture {
        state,
        source: _source,
        client,
        mut incoming,
    } = TransferFixture::new().await?;
    let cursor = state.replica.cursor()?;
    // This fixture proves framing of large records, not semantic application of these test bytes.
    let page = MetadataReplicaPage {
        after: cursor,
        entries: vec![LogEntry::new(
            LogPosition { term: 1, index: 1 },
            OperationId::from_bytes([82; 16])?,
            1,
            vec![0x5a; 256 * 1024],
        )?],
    };
    for response in [
        Response::Valid,
        Response::WrongRequest,
        Response::WrongCursor,
        Response::BadBodyDigest,
        Response::BadEntryDigest,
        Response::WrongOffset,
        Response::Truncated,
        Response::Trailing,
        Response::OversizedFrame,
        Response::Rejected,
        Response::ReboundSource,
    ] {
        let fetch = client.fetch_metadata_replica_page(
            state.voter,
            cursor,
            OperationId::from_bytes([83; 16])?,
            UnixMicros::new(100),
        );
        let expected = page.clone();
        let serve = async {
            let mut incoming = incoming.recv().await.ok_or("missing stream")?;
            let Some(Message::FetchMetadataReplicaPage(request)) =
                receive_data_control(&mut incoming.stream.receive, incoming.limits)
                    .await?
                    .into_inner()
                    .message
            else {
                return Err("wrong request".into());
            };
            incoming.stream.receive.read_to_end(0).await?;
            if response == Response::ReboundSource {
                let mut route = client
                    .peer_routes()?
                    .into_iter()
                    .find(|route| route.node_id == state.voter)
                    .ok_or("source route missing")?;
                route.incarnation += 1;
                client.upsert_peer(&route)?;
            }
            let bytes = tokio::task::spawn_blocking(move || encode_page(&expected)).await??;
            send_response(incoming.stream, request, bytes, incoming.limits, response).await
        };
        let (result, sent) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(fetch, serve)
        })
        .await?;
        // A rejected response can reset a sender mid-frame; only transport errors are acceptable.
        if let Err(error) = sent {
            assert!(
                response != Response::Valid
                    && error
                        .downcast_ref::<meshspan_transport::TransportError>()
                        .is_some(),
                "unexpected sender error: {error}"
            );
        }
        match response {
            Response::Valid => assert_eq!(result?.page.entries, page.entries),
            Response::Rejected => assert!(
                matches!(result, Err(MetadataReplicaTransferError::Remote(code)) if code == i32::from(ErrorCode::Unauthorised))
            ),
            Response::Truncated => assert!(matches!(
                result,
                Err(MetadataReplicaTransferError::Transport(_))
            )),
            Response::WrongRequest
            | Response::WrongCursor
            | Response::BadBodyDigest
            | Response::BadEntryDigest
            | Response::WrongOffset
            | Response::Trailing
            | Response::OversizedFrame
            | Response::ReboundSource => assert!(
                matches!(result, Err(MetadataReplicaTransferError::Rejected)),
                "wrong error for {response:?}"
            ),
        }
    }
    Ok(())
}

async fn send_response(
    mut stream: AcceptedStream,
    request: FetchMetadataReplicaPage,
    mut bytes: Vec<u8>,
    limits: WireLimits,
    response: Response,
) -> TestResult {
    if response == Response::Rejected {
        reject_metadata_replica_page(
            stream,
            request.header.ok_or("header")?.request_id,
            ErrorCode::Unauthorised,
            limits,
        )
        .await?;
        return Ok(());
    }
    if response == Response::BadEntryDigest {
        let mut body = decode_metadata_replica_body(&bytes)?;
        body.entries[0].command_digest[0] ^= 1;
        bytes = encode_metadata_replica_body(&body)?;
    }
    let mut header = MetadataReplicaPageHeader {
        request_id: request.header.ok_or("header")?.request_id,
        after: request.after,
        byte_length: bytes.len() as u64,
        digest: Sha256::digest(&bytes).to_vec(),
        maximum_frame_bytes: 64 * 1024,
        rejection: None,
    };
    match response {
        Response::WrongRequest => header.request_id = vec![99; 16],
        Response::WrongCursor => header.after.as_mut().ok_or("cursor")?.membership_epoch += 1,
        Response::BadBodyDigest => header.digest[0] ^= 1,
        Response::Truncated => {
            bytes.pop().ok_or("empty body")?;
        }
        Response::OversizedFrame => header.maximum_frame_bytes = 1,
        Response::Valid
        | Response::BadEntryDigest
        | Response::WrongOffset
        | Response::Trailing
        | Response::Rejected
        | Response::ReboundSource => {}
    }
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::MetadataReplicaPageHeader(header)),
        },
        limits,
    )
    .await?;
    if matches!(response, Response::WrongRequest | Response::WrongCursor) {
        stream.send.finish()?;
        return Ok(());
    }
    for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
        let offset = if response == Response::WrongOffset {
            1
        } else {
            (index * 64 * 1024) as u64
        };
        send_data_frame(
            &mut stream.send,
            &DataFrame {
                offset,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    if response == Response::Trailing {
        stream.send.write_all(&[7]).await?;
    }
    stream.send.finish()?;
    Ok(())
}
