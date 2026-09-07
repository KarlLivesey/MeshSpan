// SPDX-License-Identifier: GPL-2.0-only

//! Raw executable upload: bounded asynchronous transport feeds one owned blocking verifier.

use super::{Error, UpdateApi, now, respond};
use crate::update_artifact_store::{ArtifactStoreError, TRANSFER_FRAME_BYTES, UpdateArtifactStore};
use axum::{
    body::{Body, Bytes, HttpBody},
    extract::{Path, Request, State},
    http::{HeaderMap, Response},
};
use meshspan_api_contract::{OperationId, encode_stage_update_artifact_response};
use meshspan_domain::WorkId;
use std::{
    io::{self, Read},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

const TRANSFER_DEADLINE: Duration = Duration::from_mins(30);

pub(super) async fn upload(
    State(state): State<Arc<UpdateApi>>,
    Path((rollout, target)): Path<(String, String)>,
    request: Request,
) -> Response<Body> {
    respond(
        upload_request(&state, rollout, target, request).await,
        &state.digest,
    )
}

async fn upload_request(
    state: &UpdateApi,
    rollout: String,
    target: String,
    request: Request,
) -> Result<Vec<u8>, Error> {
    let transfer_permit = state
        .artifact_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable)?;
    let headers = request.headers().clone();
    let initial_headers = headers.clone();
    let selected_target = target.clone();
    let (rollout_id, record, operation) = state
        .job(state.admit()?, move |service| {
            service.authenticate(&initial_headers, now()?, true)?;
            let rollout_id = WorkId::from_bytes(crate::update_service::parse(&rollout)?)
                .map_err(|_| Error::Invalid)?;
            let record = service.candidate(rollout_id)?;
            let artifact = record
                .manifest
                .artifact(&selected_target)
                .map_err(|_| Error::Invalid)?;
            let operation = upload_headers(&initial_headers, artifact.size)?;
            Ok((rollout_id, record, operation))
        })
        .await?;
    if request.uri().query().is_some() {
        return Err(Error::Invalid);
    }
    let directory = state.state_directory.clone();
    let platform = target.clone();
    let (chunks, receive_chunks) = mpsc::channel(2);
    let (completed, completion) = oneshot::channel();
    let deadline = Instant::now() + TRANSFER_DEADLINE;
    {
        let mut jobs = state.jobs.lock().map_err(|_| Error::Failed)?;
        while let Some(result) = jobs.try_join_next() {
            result.map_err(|_| Error::Failed)?;
        }
        jobs.spawn_blocking(move || {
            let _permit = transfer_permit;
            let result = (|| {
                let store = UpdateArtifactStore::open(&directory)?;
                let mut reader = UploadReader {
                    chunks: receive_chunks,
                    current: Bytes::new(),
                    finished: false,
                    deadline,
                };
                store.stage(&record.manifest, &platform, &mut reader)
            })()
            .map_err(|error| store_error(&error));
            // Request cancellation cannot undo a fsynced file. Its immutable hash allows retry.
            let _cancelled = completed.send(result);
        });
    }
    tokio::time::timeout(TRANSFER_DEADLINE, async {
        forward(request.into_body(), chunks).await?;
        completion.await.map_err(|_| Error::Failed)??;
        Ok::<(), Error>(())
    })
    .await
    .map_err(|_| Error::Unavailable)??;
    state
        .job(state.admit()?, move |service| {
            let administrator = service.authenticate(&headers, now()?, true)?;
            let receipt = service.publish_artifact(administrator, operation, rollout_id, target)?;
            service.authenticate(&headers, now()?, true)?;
            encode_stage_update_artifact_response(&receipt).map_err(|_| Error::Failed)
        })
        .await
}

fn upload_headers(headers: &HeaderMap, expected: u64) -> Result<OperationId, Error> {
    if !crate::api_http::has_content_type(headers, "application/octet-stream") {
        return Err(Error::MediaType);
    }
    if headers.contains_key("content-encoding") || headers.contains_key("transfer-encoding") {
        return Err(Error::Invalid);
    }
    let length = one_header(headers, "content-length")?;
    if length != expected.to_string() {
        return Err(Error::Invalid);
    }
    OperationId::parse(one_header(headers, "meshspan-operation-id")?).ok_or(Error::Invalid)
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Error> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(Error::Invalid)?
        .to_str()
        .map_err(|_| Error::Invalid)?;
    if values.next().is_some() {
        return Err(Error::Invalid);
    }
    Ok(value)
}

enum UploadChunk {
    Bytes(Bytes),
    Finish,
}

async fn forward(mut body: Body, chunks: mpsc::Sender<UploadChunk>) -> Result<(), Error> {
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
    {
        let frame = frame.map_err(|_| Error::Invalid)?;
        let bytes = frame.into_data().map_err(|_| Error::Invalid)?;
        // Hyper delivers bounded receive frames; also bound arbitrary composed Body producers.
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(Error::BodyTooLarge);
        }
        for offset in (0..bytes.len()).step_by(TRANSFER_FRAME_BYTES) {
            let end = (offset + TRANSFER_FRAME_BYTES).min(bytes.len());
            chunks
                .send(UploadChunk::Bytes(bytes.slice(offset..end)))
                .await
                .map_err(|_| Error::Unavailable)?;
        }
    }
    chunks
        .send(UploadChunk::Finish)
        .await
        .map_err(|_| Error::Unavailable)
}

struct UploadReader {
    chunks: mpsc::Receiver<UploadChunk>,
    current: Bytes,
    finished: bool,
    deadline: Instant,
}

impl Read for UploadReader {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if destination.is_empty() || self.finished {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.chunks.blocking_recv() {
                Some(UploadChunk::Bytes(bytes)) => self.current = bytes,
                Some(UploadChunk::Finish) => {
                    self.finished = true;
                    return Ok(0);
                }
                None => return Err(io::ErrorKind::ConnectionAborted.into()),
            }
        }
        let length = destination.len().min(self.current.len());
        destination[..length].copy_from_slice(&self.current.split_to(length));
        Ok(length)
    }
}

fn store_error(error: &ArtifactStoreError) -> Error {
    match error {
        ArtifactStoreError::Invalid => Error::Invalid,
        ArtifactStoreError::Unsafe => Error::Failed,
        ArtifactStoreError::Io(_) => Error::Unavailable,
    }
}
