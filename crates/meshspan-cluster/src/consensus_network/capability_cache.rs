// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe preimages for committed activation digests; this cache never grants membership.

use meshspan_domain::UnixMicros;
use meshspan_metadata::{CachedNodeCapabilityPresentation, LocalDatabase};
use meshspan_protocol::{decode_control_frame, encode_control_frame};

use super::{
    Arc, BTreeMap, CachedConsensusTransferSupport, ConsensusNetwork, ConsensusNetworkError,
    ControlEnvelope, MAXIMUM_CONTROL_BYTES, MAXIMUM_DATA_BYTES, MAXIMUM_ITEMS, MAXIMUM_TEXT_BYTES,
    MeshId, Message, NodeHello, NodeId, ObservedConsensusTransferSupport, PathBuf, PeerBinding,
    WireLimits, node_capability_digest,
};

/// Prepared local cache input. Construct on the daemon's bounded blocking worker before network IO.
pub struct ConsensusCapabilityCacheConfig {
    path: PathBuf,
    restored: Vec<CachedConsensusTransferSupport>,
}

impl ConsensusCapabilityCacheConfig {
    /// Opens/migrates the node-local cache and strictly validates every retained preimage.
    ///
    /// # Errors
    /// Rejects another local node's database, malformed/noncanonical Hello bytes and digest or
    /// identity substitutions. Current activation/certificate authority is checked at admission.
    pub fn open(
        path: PathBuf,
        local_node: NodeId,
        now: UnixMicros,
    ) -> Result<Self, ConsensusNetworkError> {
        let database = LocalDatabase::open(&path, local_node, now)
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let restored = database
            .node_capability_presentations()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .iter()
            .map(validate_presentation)
            .collect::<Result<_, _>>()?;
        Ok(Self { path, restored })
    }

    pub(super) fn into_parts(self) -> RestoredCapabilityCache {
        let mut latest = BTreeMap::new();
        let mut preimages = BTreeMap::new();
        for cached in self.restored {
            preimages.insert(
                (
                    cached.binding.node_id,
                    cached.binding.incarnation,
                    cached.observed.capability_digest,
                ),
                cached.clone(),
            );
            latest.insert(cached.binding.node_id, cached);
        }
        RestoredCapabilityCache {
            path: Arc::new(self.path),
            latest,
            preimages,
        }
    }
}

pub(super) struct RestoredCapabilityCache {
    pub path: Arc<PathBuf>,
    pub latest: BTreeMap<NodeId, CachedConsensusTransferSupport>,
    pub preimages: BTreeMap<(NodeId, u64, [u8; 32]), CachedConsensusTransferSupport>,
}

/// Exact presentation derived from the running node's configured transport identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeCapabilityPresentation {
    /// Current configured node, incarnation and selected certificate.
    pub binding: PeerBinding,
    /// Exact selected certificate generation.
    pub certificate_generation: u64,
    /// Digest and support derived from the validated local Hello.
    pub observed: ObservedConsensusTransferSupport,
}

impl ConsensusNetwork {
    /// Derives a self-report from the actual configured transport, never caller-supplied claims.
    ///
    /// # Errors
    /// Rejects unavailable current certificate state.
    pub fn local_capability_presentation(
        &self,
    ) -> Result<LocalNodeCapabilityPresentation, ConsensusNetworkError> {
        let certificate = self.local_certificate()?;
        let hello = self.hello()?;
        Ok(LocalNodeCapabilityPresentation {
            binding: PeerBinding {
                node_id: self.local_node_id,
                incarnation: self.local_incarnation,
                certificate_fingerprint: certificate.certificate_fingerprint,
            },
            certificate_generation: certificate.generation,
            observed: ObservedConsensusTransferSupport {
                capability_digest: node_capability_digest(&hello),
                support: hello.consensus_transfer,
            },
        })
    }

    /// Reads exact cached evidence for a current authoritative presentation digest without IO.
    ///
    /// # Errors
    /// Rejects unavailable registry state. Missing, stale or mismatched evidence returns unknown.
    pub fn consensus_transfer_support_for(
        &self,
        expected: PeerBinding,
        capability_digest: [u8; 32],
    ) -> Result<Option<ObservedConsensusTransferSupport>, ConsensusNetworkError> {
        if expected.node_id == self.local_node_id {
            let local = self.local_capability_presentation()?;
            return Ok((local.binding == expected
                && local.observed.capability_digest == capability_digest)
                .then_some(local.observed));
        }
        let peers = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let cached = peers.transfer_preimages.get(&(
            expected.node_id,
            expected.incarnation,
            capability_digest,
        ));
        Ok(cached
            .filter(|cached| {
                cached.mesh_id == self.mesh_id
                    && cached.binding == expected
                    && peers.registry.matches_binding(expected)
            })
            .map(|cached| cached.observed.clone()))
    }

    /// Retains the authoritative digest and the latest candidate after a refresh is resolved.
    ///
    /// # Errors
    /// Rejects malformed bounds or local persistence failure; the owned worker is always observed.
    pub async fn retain_capability_preimages(
        &self,
        node: NodeId,
        incarnation: u64,
        committed_digest: [u8; 32],
    ) -> Result<(), ConsensusNetworkError> {
        // Serialize persistence and memory publication. Never retain a peer registry lock across IO.
        let _update = self.capability_cache_updates.lock().await;
        let candidate = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .transfer_support
            .get(&node)
            .map_or((incarnation, committed_digest), |cached| {
                (
                    cached.binding.incarnation,
                    cached.observed.capability_digest,
                )
            });
        if let Some(path) = &self.capability_cache_path {
            let path = Arc::clone(path);
            let local = self.local_node_id;
            let worker = Arc::clone(&self.bulk_codecs)
                .acquire_owned()
                .await
                .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
            tokio::task::spawn_blocking(move || {
                let _worker = worker;
                let mut database = LocalDatabase::open(&path, local, cache_now()?)
                    .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
                database
                    .retain_node_capability_presentations(
                        node,
                        incarnation,
                        committed_digest,
                        candidate,
                    )
                    .map_err(|_| ConsensusNetworkError::InvalidConfiguration)
            })
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)??;
        }
        self.peers
            .write()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .transfer_preimages
            .retain(|(cached_node, cached_incarnation, digest), _| {
                *cached_node != node
                    || (*cached_incarnation == incarnation && *digest == committed_digest)
                    || (*cached_incarnation == candidate.0 && *digest == candidate.1)
            });
        Ok(())
    }

    pub(super) async fn record_transfer_support(
        &self,
        peer: meshspan_transport::AuthenticatedPeer,
        hello: &NodeHello,
    ) -> Result<(), ConsensusNetworkError> {
        let _update = self.capability_cache_updates.lock().await;
        let binding = PeerBinding {
            node_id: peer.node_id(),
            incarnation: peer.incarnation(),
            certificate_fingerprint: peer.certificate_fingerprint(),
        };
        let observed = ObservedConsensusTransferSupport {
            capability_digest: node_capability_digest(hello),
            support: hello.consensus_transfer,
        };
        {
            let peers = self
                .peers
                .read()
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
            peers.registry.revalidate(peer)?;
            if peers
                .transfer_support
                .get(&binding.node_id)
                .is_some_and(|cached| cached.binding == binding && cached.observed == observed)
                && peers.transfer_preimages.contains_key(&(
                    binding.node_id,
                    binding.incarnation,
                    observed.capability_digest,
                ))
            {
                return Ok(());
            }
        }
        if let Some(path) = &self.capability_cache_path {
            let presentation = CachedNodeCapabilityPresentation {
                node_id: binding.node_id,
                incarnation: binding.incarnation,
                certificate_fingerprint: binding.certificate_fingerprint,
                capability_digest: observed.capability_digest,
                canonical_hello: encode_control_frame(
                    &ControlEnvelope {
                        header: None,
                        message: Some(Message::NodeHello(hello.clone())),
                    },
                    self.wire_limits,
                )?,
            };
            self.persist_presentation(Arc::clone(path), presentation)
                .await?;
        }
        let mut peers = self
            .peers
            .write()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        peers.registry.revalidate(peer)?;
        let cached = CachedConsensusTransferSupport {
            mesh_id: self.mesh_id,
            binding,
            observed,
        };
        if peers.transfer_preimages.len() >= 4096
            && !peers.transfer_preimages.contains_key(&(
                binding.node_id,
                binding.incarnation,
                cached.observed.capability_digest,
            ))
        {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        peers.transfer_preimages.insert(
            (
                binding.node_id,
                binding.incarnation,
                cached.observed.capability_digest,
            ),
            cached.clone(),
        );
        peers.transfer_support.insert(binding.node_id, cached);
        Ok(())
    }

    async fn persist_presentation(
        &self,
        path: Arc<PathBuf>,
        presentation: CachedNodeCapabilityPresentation,
    ) -> Result<(), ConsensusNetworkError> {
        let local_node = self.local_node_id;
        let worker = Arc::clone(&self.bulk_codecs)
            .acquire_owned()
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
        tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
            let now = UnixMicros::new(
                i64::try_from(now.as_micros())
                    .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?,
            );
            let mut database = LocalDatabase::open(&path, local_node, now)
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
            database
                .cache_node_capability_presentation(&presentation)
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)
        })
        .await
        .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
    }
}

fn validate_presentation(
    value: &CachedNodeCapabilityPresentation,
) -> Result<CachedConsensusTransferSupport, ConsensusNetworkError> {
    let limits = WireLimits::new(
        MAXIMUM_CONTROL_BYTES,
        MAXIMUM_DATA_BYTES,
        MAXIMUM_ITEMS,
        MAXIMUM_TEXT_BYTES,
    )?;
    let envelope = decode_control_frame(&value.canonical_hello, limits)?;
    let Some(Message::NodeHello(hello)) = envelope.as_inner().message.as_ref() else {
        return Err(ConsensusNetworkError::InvalidTraffic);
    };
    if envelope.as_inner().header.is_some()
        || encode_control_frame(envelope.as_inner(), limits)? != value.canonical_hello
        || hello.node_id.as_slice() != value.node_id.as_bytes()
        || hello.incarnation != value.incarnation
        || node_capability_digest(hello) != value.capability_digest
    {
        return Err(ConsensusNetworkError::InvalidTraffic);
    }
    Ok(CachedConsensusTransferSupport {
        mesh_id: MeshId::from_bytes(
            hello
                .mesh_id
                .as_slice()
                .try_into()
                .map_err(|_| ConsensusNetworkError::InvalidTraffic)?,
        )?,
        binding: PeerBinding {
            node_id: value.node_id,
            incarnation: value.incarnation,
            certificate_fingerprint: value.certificate_fingerprint,
        },
        observed: ObservedConsensusTransferSupport {
            capability_digest: value.capability_digest,
            support: hello.consensus_transfer,
        },
    })
}

#[cfg(test)]
#[path = "capability_cache_tests.rs"]
mod tests;

fn cache_now() -> Result<UnixMicros, ConsensusNetworkError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
    Ok(UnixMicros::new(i64::try_from(now.as_micros()).map_err(
        |_| ConsensusNetworkError::InvalidConfiguration,
    )?))
}
