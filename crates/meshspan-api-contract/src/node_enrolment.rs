// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator join-grant and anonymous node-enrolment models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, SetupName};

const UUID_PATTERN: &str =
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

/// One role pre-authorised for a joining daemon.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NodeJoinRole {
    /// May register storage folders and retain encrypted shards.
    Storage,
    /// May expose user-facing access connectors.
    Gateway,
    /// May catch up as a metadata learner and later become voter-eligible.
    MetadataEligible,
}

/// Administrator request for one bounded node join invitation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeJoinGrantRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// HTTPS origin the joining daemon contacts; the UI normally supplies its current origin.
    #[schemars(length(min = 12, max = 512), pattern(r"^https://[a-z0-9.\-\[\]:]+$"))]
    pub enrolment_endpoint: String,
    /// Non-empty deduplicated role set.
    #[schemars(length(min = 1, max = 3))]
    pub allowed_roles: Vec<NodeJoinRole>,
    /// Maximum successful node admissions.
    #[schemars(range(min = 1, max = 1_000))]
    pub maximum_uses: u16,
    /// Requested lifetime in whole seconds.
    #[schemars(range(min = 60, max = 604_800))]
    pub valid_for_seconds: u32,
}

/// One exactly replayable join-grant issuance result.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeJoinGrantResponse {
    /// Exact operation whose committed result was resolved.
    pub operation_id: OperationId,
    /// Self-contained secret invitation returned only by this operation.
    #[schemars(
        length(min = 250, max = 1_250),
        pattern(r"^meshspan-join-v2\.[0-9a-f]+(?:\.[0-9a-f]+){4}$"),
        extend("readOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    pub join_code: String,
    /// Exclusive authoritative expiry as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Exact committed role set.
    #[schemars(length(min = 1, max = 3))]
    pub allowed_roles: Vec<NodeJoinRole>,
    /// Exact committed use ceiling.
    #[schemars(range(min = 1, max = 1_000))]
    pub maximum_uses: u16,
}

/// Existing or newly created physical host selected by a joining daemon.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum NodeJoinHost {
    /// Create one physical host failure-domain record atomically with admission.
    New {
        /// Human-facing host name.
        name: SetupName,
    },
    /// Add another daemon process to an already enrolled physical host.
    Existing {
        /// Existing host identity.
        #[schemars(length(equal = 36), pattern(UUID_PATTERN))]
        host_id: String,
    },
}

/// One node-owned identity presentation for pre-authorised enrolment.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolNodeRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Self-contained administrator-issued invitation.
    #[schemars(
        length(min = 250, max = 1_250),
        pattern(r"^meshspan-join-v2\.[0-9a-f]+(?:\.[0-9a-f]+){4}$"),
        extend("writeOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    pub join_code: String,
    /// New or existing physical host binding.
    pub host: NodeJoinHost,
    /// Human-facing daemon name.
    pub node_name: SetupName,
    /// Requested role subset.
    #[schemars(length(min = 1, max = 3))]
    pub requested_roles: Vec<NodeJoinRole>,
    /// Canonical uncompressed P-256 SEC1 public identity bytes as lowercase hex.
    #[schemars(length(equal = 130), pattern(r"^04[0-9a-f]{128}$"))]
    pub node_identity_public_key_hex: String,
    /// P-256 signature over the exact canonical enrolment transcript as lowercase DER hex.
    #[schemars(length(min = 128, max = 144), pattern(r"^[0-9a-f]+$"))]
    pub identity_proof_signature_hex: String,
    /// Canonical X25519 public secret-wrapping key as lowercase hex.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub wrapping_public_key_hex: String,
    /// Private QUIC endpoint advertised after certificate installation.
    #[schemars(length(min = 3, max = 512), pattern(r"^[a-z0-9.\-\[\]:]+$"))]
    pub private_endpoint: String,
}

/// One enrolled peer returned to a joining daemon for authenticated bootstrap.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentBootstrapPeer {
    /// Permanent peer node identity.
    #[schemars(length(equal = 36), pattern(UUID_PATTERN))]
    pub node_id: String,
    /// Current private QUIC endpoint.
    #[schemars(length(min = 3, max = 512))]
    pub private_endpoint: String,
    /// Current leaf certificate DER as lowercase hex.
    #[schemars(length(min = 2, max = 131_072), pattern(r"^[0-9a-f]+$"))]
    pub certificate_der_hex: String,
}

/// Exact replayable result of consuming one join-grant use.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolNodeResponse {
    /// Exact operation whose committed result was resolved.
    pub operation_id: OperationId,
    /// Target mesh proven by the invitation and response chain.
    #[schemars(length(equal = 36), pattern(UUID_PATTERN))]
    pub mesh_id: String,
    /// Permanent identity derived from the submitted public key.
    #[schemars(length(equal = 36), pattern(UUID_PATTERN))]
    pub node_id: String,
    /// Issued node leaf certificate DER as lowercase hex.
    #[schemars(length(min = 2, max = 131_072), pattern(r"^[0-9a-f]+$"))]
    pub node_certificate_der_hex: String,
    /// Root-signed online authority certificate DER as lowercase hex.
    #[schemars(length(min = 2, max = 16_384), pattern(r"^[0-9a-f]+$"))]
    pub online_authority_certificate_der_hex: String,
    /// Offline mesh root certificate DER as lowercase hex.
    #[schemars(length(min = 2, max = 16_384), pattern(r"^[0-9a-f]+$"))]
    pub root_certificate_der_hex: String,
    /// Current enrolled bootstrap peers, never including the joining node.
    #[schemars(length(min = 1, max = 1_024))]
    pub bootstrap_peers: Vec<EnrolmentBootstrapPeer>,
}
