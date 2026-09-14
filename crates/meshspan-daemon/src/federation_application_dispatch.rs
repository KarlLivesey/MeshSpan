// SPDX-License-Identifier: GPL-2.0-only

//! Bounded application work on authenticated federation sessions, separate from handshakes.

use super::{FederationSessionRuntimeError, FederationSessions, NativeFederationSession};
use crate::runtime_observations::RuntimeObservations;
use meshspan_cluster::{FederationAuthorityPageServeRequest, federation_connection_authority};
use meshspan_contracts::{LifecycleKind, LifecycleOutcome};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::{ValidatedFederationEnvelope, v1::federation_envelope::Message};
use meshspan_transport::{
    FederationPeerRegistry, OutboundFederationAuthorityPage, StreamKind, classify_stream,
    receive_federation, send_federation,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinSet};

type Result<T> = std::result::Result<T, FederationSessionRuntimeError>;
const CONTROL_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Network waits consume bounded stream state, not a metadata-reader worker.
pub(super) struct ApplicationBudget {
    streams: Arc<Semaphore>,
    metadata: Arc<Semaphore>,
}

impl ApplicationBudget {
    pub(super) fn for_host() -> Self {
        let workers = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        Self {
            streams: Arc::new(Semaphore::new(workers.saturating_mul(8))),
            metadata: Arc::new(Semaphore::new(workers)),
        }
    }
}

/// Readers are borrowed only by admitted blocking jobs. Their pool never exceeds that worker
/// budget; opening/integrity checks happen once per concurrent reader, not on every request.
pub(super) struct AuthorityReaders {
    database_path: PathBuf,
    idle: Mutex<Vec<AuthoritativeRepository>>,
}

impl AuthorityReaders {
    pub(super) fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            idle: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn with_reader<T>(
        &self,
        work: impl FnOnce(&AuthoritativeRepository) -> Result<T>,
    ) -> Result<T> {
        let available = self
            .idle
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .pop();
        let reader = match available {
            Some(reader) => reader,
            None => AuthoritativeRepository::new(
                PartitionDatabase::open_existing(
                    &self.database_path,
                    crate::api_http::current_time()
                        .ok_or(FederationSessionRuntimeError::Unavailable)?,
                )
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
            ),
        };
        let result = work(&reader);
        self.idle
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .push(reader);
        result
    }
}

impl FederationSessions {
    pub(super) async fn serve_application_streams(
        self: Arc<Self>,
        session: NativeFederationSession,
        budget: Arc<ApplicationBudget>,
        observations: RuntimeObservations,
    ) -> Result<()> {
        let mut jobs = JoinSet::new();
        let session_slots = Arc::new(Semaphore::new(
            usize::try_from(session.limits.maximum_bidirectional_streams)
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
        ));
        loop {
            tokio::select! {
                accepted = session.connection.accept_bi() => {
                    let Ok((mut send, mut receive)) = accepted else { break; };
                    let permits = Arc::clone(&budget.streams).try_acquire_owned()
                        .and_then(|host| Arc::clone(&session_slots).try_acquire_owned().map(|peer| (host, peer)));
                    let Ok(permits) = permits else {
                        let reset = send.reset(1_u32.into());
                        let stopped = receive.stop(1_u32.into());
                        // Already-closed streams need no further cancellation. Record failed
                        // rejection IO without abandoning other admitted workers.
                        if reset.is_err() || stopped.is_err() {
                            observations.record_lifecycle(LifecycleKind::FederationSessions, LifecycleOutcome::Failed, Duration::ZERO);
                        }
                        continue;
                    };
                    let owner = Arc::clone(&self);
                    let session = session.clone();
                    let budget = Arc::clone(&budget);
                    jobs.spawn(async move {
                        let _permits = permits;
                        let started = Instant::now();
                        let result = owner.serve_control_request(session, send, receive, &budget).await;
                        (result, started.elapsed())
                    });
                }
                ended = jobs.join_next(), if !jobs.is_empty() => {
                    if let Some(ended) = ended { observe_job(&observations, ended); }
                }
            }
        }
        // Closing the session wakes frame IO. Observe every admitted job, including its
        // blocking metadata preparation; do not drop a JoinHandle on a response timeout.
        while let Some(ended) = jobs.join_next().await {
            observe_job(&observations, ended);
        }
        Ok(())
    }

    async fn serve_control_request(
        self: Arc<Self>,
        session: NativeFederationSession,
        send: quinn::SendStream,
        receive: quinn::RecvStream,
        budget: &ApplicationBudget,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + CONTROL_EXCHANGE_TIMEOUT;
        let (mut stream, envelope) = tokio::time::timeout_at(deadline, async {
            let mut stream = classify_stream(send, receive).await?;
            if stream.kind != StreamKind::Federation {
                return Err(FederationSessionRuntimeError::Unavailable);
            }
            let envelope = receive_federation(&mut stream.receive, session.limits.wire).await?;
            Ok((stream, envelope))
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        let header = envelope
            .as_inner()
            .header
            .as_ref()
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        if header.version != Some(super::SESSION_VERSION)
            || header.relationship_id != session.relationship.as_bytes()
            || header.deadline_unix_micros <= now.get()
            || !matches!(
                envelope.as_inner().message,
                Some(
                    Message::FetchAuthority(_)
                        | Message::RequestBackupCapability(_)
                        | Message::FetchBackupAllocations(_)
                        | Message::ExecuteBackup(_)
                )
            )
        {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        if matches!(envelope.as_inner().message, Some(Message::ExecuteBackup(_))) {
            return self.execute_backup(session, stream, envelope).await;
        }
        let remaining = u64::try_from(header.deadline_unix_micros - now.get())
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let deadline = deadline.min(tokio::time::Instant::now() + Duration::from_micros(remaining));
        let permit = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                permit = Arc::clone(&budget.metadata).acquire_owned() => {
                    permit.map_err(|_| FederationSessionRuntimeError::Unavailable)
                }
                _ = session.connection.closed() => Err(FederationSessionRuntimeError::Unavailable),
            }
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        let owner = Arc::clone(&self);
        let wire = session.limits.wire;
        let response = tokio::task::spawn_blocking(move || {
            owner
                .application_readers
                .with_reader(|reader| match envelope.as_inner().message {
                    Some(Message::FetchAuthority(_)) => owner
                        .prepare_authority_request(reader, &session, &envelope)
                        .map(|response| response.envelope().clone()),
                    Some(Message::RequestBackupCapability(_)) => {
                        owner.prepare_backup_capability(reader, &session, &envelope)
                    }
                    Some(Message::FetchBackupAllocations(_)) => {
                        owner.prepare_allocation_page(reader, &session, &envelope)
                    }
                    _ => Err(FederationSessionRuntimeError::Unavailable),
                })
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        drop(permit);
        if tokio::time::Instant::now() >= deadline {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        tokio::time::timeout_at(deadline, send_federation(&mut stream.send, &response, wire))
            .await
            .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        stream
            .send
            .finish()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        Ok(())
    }

    fn prepare_authority_request(
        &self,
        reader: &AuthoritativeRepository,
        session: &NativeFederationSession,
        envelope: &ValidatedFederationEnvelope,
    ) -> Result<OutboundFederationAuthorityPage> {
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let current = federation_connection_authority(reader, session.relationship, now)?
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let fetch = self.replay.authenticate_authority_fetch(
            &FederationPeerRegistry::new([current.peer])?,
            &session.connection,
            envelope,
            now,
        )?;
        let (response, _) = self
            .session_runtime_with_limits(session.limits)?
            .prepare_authority_page(
                reader,
                reader,
                &fetch,
                FederationAuthorityPageServeRequest {
                    response_replay_nonce: super::random()?,
                    now,
                },
            )?;
        Ok(response)
    }
}

fn observe_job(
    observations: &RuntimeObservations,
    ended: std::result::Result<(Result<()>, Duration), tokio::task::JoinError>,
) {
    let (success, duration) = match ended {
        Ok((result, duration)) => (result.is_ok(), duration),
        Err(_) => (false, Duration::ZERO),
    };
    observations.record_lifecycle(
        LifecycleKind::FederationSessions,
        if success {
            LifecycleOutcome::Completed
        } else {
            LifecycleOutcome::Failed
        },
        duration,
    );
}
