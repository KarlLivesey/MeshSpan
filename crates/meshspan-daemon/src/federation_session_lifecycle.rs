// SPDX-License-Identifier: GPL-2.0-only

//! One lifecycle owner for bounded parallel handshakes, retry, revocation and shutdown.

use super::{FederationSessionRuntimeError, FederationSessions, NativeFederationSession};
use crate::runtime_observations::RuntimeObservations;
use meshspan_contracts::{LifecycleKind, LifecycleOutcome};
use meshspan_domain::FederationRelationshipId;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinSet};

struct HandshakeOutcome {
    dialled: Option<FederationRelationshipId>,
    result: Result<NativeFederationSession, FederationSessionRuntimeError>,
    duration: Duration,
}

/// Tracks in-flight work and the last attempted peer, so failed early peers cannot starve later ones.
#[derive(Default)]
struct DialAttempts {
    pending: BTreeSet<FederationRelationshipId>,
    last_started: Option<FederationRelationshipId>,
}

impl DialAttempts {
    fn candidates(
        &self,
        mut routes: Vec<FederationRelationshipId>,
    ) -> Vec<FederationRelationshipId> {
        // Authority pages supply ID order; the cursor remains useful if that peer is removed.
        if let Some(after) = self.last_started {
            let start = routes.partition_point(|id| *id <= after);
            routes.rotate_left(start);
        }
        routes
    }

    fn started(&mut self, id: FederationRelationshipId) {
        self.pending.insert(id);
        self.last_started = Some(id);
    }
}

impl FederationSessions {
    pub(crate) async fn run_until(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
        observations: RuntimeObservations,
    ) -> Result<(), FederationSessionRuntimeError> {
        let host = self;
        let mut attempts = DialAttempts::default();
        let mut tasks = JoinSet::new();
        let mut sessions = JoinSet::new();
        let application_slots = Arc::new(super::applications::ApplicationBudget::for_host());
        // This limits simultaneous expensive handshakes, not established connections.
        let maximum =
            std::thread::available_parallelism().map_or(8, |value| value.get().saturating_mul(8));
        let mut refresh = tokio::time::interval(Duration::from_secs(5));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let result = async {
            loop {
                if *stop.borrow() { break; }
                tokio::select! {
                    changed = stop.changed() => { if changed.is_err() || *stop.borrow() { break; } }
                    _ = refresh.tick() => {
                        refresh_and_dial(&host, &mut tasks, &mut attempts, maximum, &observations).await?;
                    }
                    incoming = host.endpoint.accept(), if tasks.len() < maximum => {
                        let incoming = incoming.ok_or(FederationSessionRuntimeError::Unavailable)?;
                        let owner = Arc::clone(&host);
                        tasks.spawn(async move {
                            let start = Instant::now();
                            let result = owner.accept_incoming(incoming).await;
                            HandshakeOutcome { dialled: None, result, duration: start.elapsed() }
                        });
                    }
                    completed = tasks.join_next(), if !tasks.is_empty() => {
                        let completed = completed.ok_or(FederationSessionRuntimeError::Unavailable)?
                            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
                        if let Some(id) = completed.dialled { attempts.pending.remove(&id); }
                        observe(&observations, completed.result.is_ok(), completed.duration);
                        if let Ok(session) = completed.result {
                            sessions.spawn(Arc::clone(&host).serve_application_streams(
                                session, Arc::clone(&application_slots), observations.clone(),
                            ));
                        }
                    }
                    completed = sessions.join_next(), if !sessions.is_empty() => {
                        let success = matches!(completed, Some(Ok(Ok(()))));
                        observe(&observations, success, Duration::ZERO);
                    }
                }
            }
            Ok(())
        }.await;
        host.close();
        tasks.abort_all();
        let mut shutdown_failed = false;
        while let Some(ended) = tasks.join_next().await {
            if let Err(error) = ended
                && !error.is_cancelled()
            {
                shutdown_failed = true;
            }
        }
        // Endpoint closure wakes all accepted streams. Let each session drain and observe
        // its metadata workers rather than aborting owners of blocking work.
        while let Some(ended) = sessions.join_next().await {
            observe(&observations, matches!(ended, Ok(Ok(()))), Duration::ZERO);
        }
        host.endpoint.wait_idle().await;
        if shutdown_failed {
            Err(FederationSessionRuntimeError::Unavailable)
        } else {
            result
        }
    }

    fn has_session(
        &self,
        id: FederationRelationshipId,
    ) -> Result<bool, FederationSessionRuntimeError> {
        let live = self
            .live
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        Ok(live
            .get(&id)
            .is_some_and(|value| value.connection.close_reason().is_none()))
    }

    fn withdraw_trust(&self) -> Result<(), FederationSessionRuntimeError> {
        self.endpoint
            .replace_trust(rustls::RootCertStore::empty())?;
        self.roots
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .clear();
        let mut live = self
            .live
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        for value in live.values() {
            value
                .connection
                .close(0_u32.into(), b"federation authority unavailable");
        }
        live.clear();
        Ok(())
    }
}

async fn refresh_and_dial(
    host: &Arc<FederationSessions>,
    tasks: &mut JoinSet<HandshakeOutcome>,
    attempts: &mut DialAttempts,
    maximum: usize,
    observations: &RuntimeObservations,
) -> Result<(), FederationSessionRuntimeError> {
    let start = Instant::now();
    let result = host.refresh_trust().await;
    observe(observations, result.is_ok(), start.elapsed());
    let Ok(outbound) = result else {
        return host.withdraw_trust();
    };
    for id in attempts.candidates(outbound) {
        if tasks.len() >= maximum {
            break;
        }
        if attempts.pending.contains(&id) || host.has_session(id)? {
            continue;
        }
        attempts.started(id);
        let owner = Arc::clone(host);
        tasks.spawn(async move {
            let start = Instant::now();
            let result = owner.dial(id).await;
            HandshakeOutcome {
                dialled: Some(id),
                result,
                duration: start.elapsed(),
            }
        });
    }
    Ok(())
}

fn observe(observations: &RuntimeObservations, success: bool, duration: Duration) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_early_peers_cannot_starve_later_relationships()
    -> Result<(), Box<dyn std::error::Error>> {
        let ids = [1, 2, 3, 4].map(|id| FederationRelationshipId::from_bytes([id; 16]));
        let [first, second, third, fourth] = ids;
        let routes = vec![first?, second?, third?, fourth?];
        let mut attempts = DialAttempts::default();
        for expected in [&routes[..2], &routes[2..], &routes[..2]] {
            let selected = attempts.candidates(routes.clone());
            assert_eq!(&selected[..2], expected);
            for id in selected.into_iter().take(2) {
                attempts.started(id);
                // Both attempts fail: the next pass must still advance to later peers.
                attempts.pending.remove(&id);
            }
        }
        Ok(())
    }
}
