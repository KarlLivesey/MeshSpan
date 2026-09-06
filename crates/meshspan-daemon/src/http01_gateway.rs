// SPDX-License-Identifier: GPL-2.0-only

//! Read-only HTTP proof delivery from replicated checkpoints, with one bounded leader fallback.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use meshspan_acme::{Http01Challenge, Http01Payload};
use meshspan_cluster::MetadataAuthorityHandle;
use meshspan_domain::{
    Clock as _, DurationMicros, NodeId, OperationId, RandomSource as _, UnixMicros,
};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::v1::{ControlEnvelope, FetchHttp01Challenge, control_envelope::Message};
use tokio::sync::Semaphore;

use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{OperatingSystemClock, OperatingSystemRandom};

mod peer;
pub(crate) use peer::Http01PeerReader;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const LOOKUP_LIFETIME: DurationMicros = DurationMicros::new(2_000_000);
const MAXIMUM_LOOKUPS: usize = 16;

/// Public material only: requests cannot select private keys or arbitrary metadata records.
#[derive(Clone)]
pub(crate) struct Http01Gateway {
    local: Http01Challenge,
    reader: Arc<Mutex<AuthoritativeRepository>>,
    authority: MetadataAuthorityHandle,
    network: Option<Arc<PrivateConsensusRuntime>>,
    admission: Arc<Semaphore>,
}

impl Http01Gateway {
    pub(crate) fn new(
        local: Http01Challenge,
        reader: AuthoritativeRepository,
        authority: MetadataAuthorityHandle,
        network: Option<Arc<PrivateConsensusRuntime>>,
    ) -> Self {
        Self {
            local,
            reader: Arc::new(Mutex::new(reader)),
            authority,
            network,
            admission: Arc::new(Semaphore::new(MAXIMUM_LOOKUPS)),
        }
    }

    pub(crate) async fn response(
        &self,
        token: &str,
        now: UnixMicros,
    ) -> Result<Option<Vec<u8>>, ()> {
        // Malformed anonymous requests must not acquire a worker or send a private RPC.
        Http01Payload::validate_token(token).map_err(|_| ())?;
        if let Some(body) = self.local.response(token, now).map_err(|_| ())? {
            return Ok(Some(body));
        }
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| ())?;
        let reader = Arc::clone(&self.reader);
        let queried_token = token.to_owned();
        tokio::time::timeout(LOOKUP_TIMEOUT, async {
            let (proof, _permit) = tokio::task::spawn_blocking(move || {
                // The permit stays with blocking IO even if the HTTP client disconnects.
                let reader = reader.lock().map_err(|_| ())?;
                let proof = reader
                    .public_http01_response(&queried_token, OperatingSystemClock.now())
                    .map_err(|_| ())?;
                Ok::<_, ()>((proof, permit))
            })
            .await
            .map_err(|_| ())??;
            if let Some((body, expiry)) = proof {
                return Ok((OperatingSystemClock.now() < expiry).then_some(body));
            }
            self.lookup_leader(token).await
        })
        .await
        .map_err(|_| ())?
    }

    async fn lookup_leader(&self, token: &str) -> Result<Option<Vec<u8>>, ()> {
        let observation = self.authority.observe().await.map_err(|_| ())?;
        if observation.known_leader == Some(observation.node_id) {
            return Ok(None);
        }
        // A just-restarted gateway can serve HTTPS before receiving its first leader hint.
        // Only that discovery case queries the durable voter set (at most 18 in a joint plan),
        // never every storage node. Responders do not forward, so there are no relay loops.
        let candidates = match observation.known_leader {
            Some(leader) => BTreeSet::from([leader]),
            None => self.discovery_voters().await?,
        };
        let network = self.network.as_ref().ok_or(())?.network()?;
        let mut failed = false;
        for candidate in candidates
            .into_iter()
            .filter(|node| *node != observation.node_id)
        {
            match fetch_proof(&network, candidate, token).await {
                Ok(Some(body)) => return Ok(Some(body)),
                Ok(None) => {}
                Err(()) => failed = true,
            }
        }
        if failed { Err(()) } else { Ok(None) }
    }

    async fn discovery_voters(&self) -> Result<BTreeSet<NodeId>, ()> {
        let reader = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || {
            reader
                .lock()
                .map_err(|_| ())?
                .load_active_consensus_quorum_plan()
                .map_err(|_| ())?
                .map(|plan| plan.voters())
                .ok_or(())
        })
        .await
        .map_err(|_| ())?
    }
}

async fn fetch_proof(
    network: &meshspan_cluster::ConsensusNetwork,
    peer: NodeId,
    token: &str,
) -> Result<Option<Vec<u8>>, ()> {
    let mut random = [0_u8; 16];
    OperatingSystemRandom
        .fill_bytes(&mut random)
        .map_err(|_| ())?;
    let operation_id = OperationId::from_bytes(random).map_err(|_| ())?;
    let deadline = OperatingSystemClock
        .now()
        .checked_add(LOOKUP_LIFETIME)
        .ok_or(())?;
    let request = ControlEnvelope {
        header: Some(
            network
                .control_header(operation_id, deadline.get())
                .map_err(|_| ())?,
        ),
        message: Some(Message::FetchHttp01Challenge(FetchHttp01Challenge {
            token: token.to_owned(),
        })),
    };
    let response = network
        .request_control(peer, &request)
        .await
        .map_err(|_| ())?;
    if response
        .as_inner()
        .header
        .as_ref()
        .is_none_or(|header| header.operation_id != random)
    {
        return Err(());
    }
    let Some(Message::Http01ChallengeResult(proof)) = &response.as_inner().message else {
        return Err(());
    };
    if proof.token != token {
        return Err(());
    }
    Ok(proof.key_authorization.clone().filter(|_| {
        proof
            .expires_at_unix_micros
            .is_some_and(|expiry| OperatingSystemClock.now().get() < expiry)
    }))
}
