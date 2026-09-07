// SPDX-License-Identifier: GPL-2.0-only

//! Replicated update trust and rollout transitions; installation stays in the daemon.

use meshspan_domain::{ComponentInstanceId, NodeId, UnixMicros, WorkId};

/// Advertise a node-local executable only after its signed bytes have been fsynced.
/// Consumers still authenticate the peer and verify the complete bytes before using them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishUpdateArtifact {
    /// Immutable candidate selection.
    pub rollout_id: WorkId,
    /// Source holding the verified executable.
    pub node_id: NodeId,
    /// Exact active source incarnation.
    pub incarnation: u64,
    /// Platform selected from the signed manifest.
    pub target: String,
    /// Exact signed executable length.
    pub byte_length: u64,
    /// Canonical lowercase signed SHA-256.
    pub sha256: String,
}

/// Explicit administrator-managed trust, never imported implicitly from a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureUpdateSigner {
    /// Stable configured signer identity.
    pub signer_id: ComponentInstanceId,
    /// Exact prior configuration sequence, or zero to create.
    pub expected_sequence: u64,
    /// Canonical uncompressed P-256 SEC1 public key.
    pub public_key: [u8; 65],
    /// Whether this signer may admit or continue an update.
    pub enabled: bool,
}

/// Selects a signed candidate once and snapshots the currently active mesh members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartUpdateRollout {
    /// Stable work identity for exact retries and progress.
    pub rollout_id: WorkId,
    /// Independently configured signer and exact trust sequence.
    pub signer_id: ComponentInstanceId,
    /// Trust must not change between selection and admission.
    pub signer_sequence: u64,
    /// Exact bounded canonical JSON, authenticated before parsing.
    pub manifest: Vec<u8>,
    /// Detached domain-separated P-256 DER signature.
    pub signature: Vec<u8>,
    /// Explicit initial consent when available redundancy cannot mask a restart.
    pub allow_service_interruption: bool,
}

/// Closed per-node state. A failed probe never counts as a verified restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdateNodePhase {
    /// Waiting for staging; assigned at plan creation or an explicit safe retry.
    Pending = 1,
    /// Exact bytes and all applicable compatibility checks have passed locally.
    Staged = 2,
    /// The coordinator admitted this node as the one active restart.
    Restarting = 3,
    /// The new process passed identity, build, catch-up and service probes.
    Verified = 4,
    /// A bounded probe failed; the whole rollout pauses.
    Failed = 5,
}

/// A coordinator checkpoint, not a public client permission to restart arbitrary nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvanceUpdateNode {
    /// Exact selected rollout.
    pub rollout_id: WorkId,
    /// Current assigned node.
    pub node_id: NodeId,
    /// Exact current incarnation; removed/replaced nodes cannot inherit progress.
    pub incarnation: u64,
    /// Compare-and-swap sequence of this node's last checkpoint.
    pub expected_sequence: u64,
    /// Next transition after the owning daemon has completed its applicable probes.
    pub phase: UpdateNodePhase,
    /// Signed target selected by the node; cannot change after staging.
    pub target: String,
    /// Digest of retained exact probe/staging evidence, not a claim that a timeout succeeded.
    pub evidence_digest: [u8; 32],
    /// Fresh authenticated readiness observations, required only for restart admission.
    pub restart_readiness: Option<UpdateRestartReadiness>,
}

/// Compact sufficient witness, not the entire mesh's health inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateRestartReadiness {
    /// Exact root stable/joint quorum proof used by the coordinator.
    pub quorum_plan_digest: [u8; 32],
    /// Authoritative observation instant; admission requires at most 30 seconds of age.
    pub observed_at: UnixMicros,
    /// Ordered distinct ready participants: at most eighteen joint voters and one gateway.
    pub ready_nodes: Vec<UpdateReadyNode>,
}

/// Current authenticated identity and catch-up position returned by a node probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateReadyNode {
    /// Probed identity.
    pub node_id: NodeId,
    /// Exact current identity incarnation.
    pub incarnation: u64,
    /// Applied root log index observed by the probe.
    pub applied_index: u64,
}

/// Explicit manager control over a durable rollout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdateRolloutControl {
    /// Stop new node restarts; an in-flight restart must still be reconciled.
    Pause = 1,
    /// Retry a paused rollout; failed nodes return to pending, not verified.
    Resume = 2,
    /// Cancel only after no restart remains in flight. Never rolls back installed binaries.
    Cancel = 3,
}

/// Exact-revision control operation; automatic completion is derived from all node checkpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlUpdateRollout {
    /// Work identity.
    pub rollout_id: WorkId,
    /// Exact last rollout sequence.
    pub expected_sequence: u64,
    /// Requested transition.
    pub action: UpdateRolloutControl,
}
