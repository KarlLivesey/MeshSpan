// SPDX-License-Identifier: GPL-2.0-only

//! Manager-owned software trust and rollout selection, distinct from installation evidence.

use crate::OperationId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Canonical update resource identity, independent of a mutation's retry identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UpdateIdentifier(
    /// UUID text, validated again when converted to a domain identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub String,
);

/// Explicit manager action; clients cannot submit installation or readiness claims here.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateAction {
    /// Pin an independently obtained publisher verification key, or disable an existing pin.
    ConfigureSigner {
        /// Stable identity; the key cannot change under this identity.
        signer_id: UpdateIdentifier,
        /// Zero creates; otherwise an exact compare-and-swap sequence.
        #[schemars(range(min = 0, max = 9_007_199_254_740_990_u64))]
        expected_sequence: u64,
        /// Canonical standard-base64 uncompressed P-256 SEC1 public key, never a private key.
        #[schemars(length(equal = 88), pattern(r"^[A-Za-z0-9+/]{87}=$"))]
        public_key: String,
        /// Explicit trust enablement. Disabling pauses an active rollout from this signer.
        enabled: bool,
    },
    /// Admit the exact signed manifest; this does not upload or install executable bytes.
    SelectCandidate {
        /// New stable rollout identity.
        rollout_id: UpdateIdentifier,
        /// Previously pinned publisher identity.
        signer_id: UpdateIdentifier,
        /// Exact enabled trust revision seen by the manager.
        #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
        signer_sequence: u64,
        /// Standard-base64 canonical signed JSON, at most 16 KiB after decoding.
        #[schemars(length(min = 4, max = 21_848), pattern(r"^[A-Za-z0-9+/]+={0,2}$"))]
        manifest: String,
        /// Standard-base64 detached DER ECDSA signature, at most 72 decoded bytes.
        #[schemars(length(min = 4, max = 96), pattern(r"^[A-Za-z0-9+/]+={0,2}$"))]
        signature: String,
        /// Explicit consent required when remaining members cannot preserve service.
        allow_service_interruption: bool,
    },
    /// Change desired progression without asserting a successful restart or rollback.
    Control {
        /// Exact selected rollout.
        rollout_id: UpdateIdentifier,
        /// Last observed aggregate sequence.
        #[schemars(range(min = 1, max = 9_007_199_254_740_990_u64))]
        expected_sequence: u64,
        /// Cancellation does not undo already verified installations.
        control: UpdateControl,
    },
}

/// Closed manager controls; resume probes ambiguous restarts rather than replacing again.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateControl {
    /// Stop admitting new restarts.
    Pause,
    /// Continue a paused rollout under current trust and safety checks.
    Resume,
    /// Stop selected work once no restart outcome is unresolved.
    Cancel,
}

/// Retain the complete request unchanged when a connection loses the outcome.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManageUpdateRequest {
    /// Stable mutation identity.
    pub operation_id: OperationId,
    /// One explicit action, with no implicit defaults.
    pub action: UpdateAction,
}

/// Original durable manager-command receipt; not an installation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManageUpdateResponse {
    /// Original mutation identity.
    pub operation_id: OperationId,
    /// Affected signer or rollout identity.
    pub resource_id: UpdateIdentifier,
    /// Original authoritative revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Public trust material. No signing secret is accepted or returned.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSignerStatus {
    /// Pinned identity.
    pub signer_id: UpdateIdentifier,
    /// Current trust sequence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Canonical public SEC1 bytes in standard base64.
    #[schemars(length(equal = 88), pattern(r"^[A-Za-z0-9+/]{87}=$"))]
    pub public_key: String,
    /// Whether new candidate admission may use this pin.
    pub enabled: bool,
}

/// Durable rollout aggregate, not a gateway liveness observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// Eligible for staging and restart admission.
    Running,
    /// New restarts paused; outstanding outcomes still need reconciliation.
    Paused,
    /// Every selected member has a verified new process.
    Completed,
    /// Cancelled without rolling back installed members.
    Cancelled,
}

/// Exact phase counts encoded as decimal strings for large meshes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProgress {
    /// Members awaiting staging.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub pending: String,
    /// Members with a staged candidate.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub staged: String,
    /// Members with a restart in progress.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub restarting: String,
    /// Members with a verified new process.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub verified: String,
    /// Failed checkpoints, not permission to retry replacement blindly.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub failed: String,
    /// Ambiguous restarts which must be resolved before another restart or cancellation.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub unresolved_restarts: String,
}

/// Selected candidate status without executable paths or private host details.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRolloutStatus {
    /// Executables admitted by the signed manifest; upload bytes are verified independently.
    #[schemars(length(min = 1, max = 4))]
    pub artifacts: Vec<crate::UpdateArtifactDescriptor>,
    /// Exact work identity, usable to inspect a completed or cancelled rollout.
    pub rollout_id: UpdateIdentifier,
    /// Publisher trust identity.
    pub signer_id: UpdateIdentifier,
    /// Signed package version.
    #[schemars(
        length(min = 5, max = 29),
        pattern(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
    )]
    pub version: String,
    /// Signed source commit, not a claim that the running process matches it.
    #[schemars(length(equal = 40), pattern(r"^[0-9a-f]{40}$"))]
    pub source_commit: String,
    /// Current aggregate sequence for manager controls.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Committed desired progression.
    pub state: UpdateState,
    /// Original explicit consent, never inferred from topology.
    pub allow_service_interruption: bool,
    /// Indexed local checkpoint counts; concurrent progress may advance the aggregate.
    pub progress: UpdateProgress,
}

/// Bounded administration response; null is no selected/known rollout, never completion.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatesResponse {
    /// At most 64 independently configured publisher identities.
    #[schemars(length(max = 64))]
    pub signers: Vec<UpdateSignerStatus>,
    /// Active rollout, or the exact requested retained rollout.
    pub rollout: Option<UpdateRolloutStatus>,
    /// Whether this build has an operating installer, separate from candidate admission.
    pub installation_available: bool,
}
