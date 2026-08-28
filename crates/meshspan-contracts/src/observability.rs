// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable non-authoritative observability-sink contract.

use meshspan_domain::{NodeId, OperationId, UnixMicros};

use crate::{BoundedItems, ComponentLifecycle, ContractError, VersionedPayload};

/// Stable severity of one already-redacted event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSeverity {
    /// Diagnostic detail disabled by default.
    Debug,
    /// Expected operational information.
    Information,
    /// Degraded behaviour that is currently recoverable.
    Warning,
    /// Failed work requiring automated retry or operator attention.
    Error,
    /// Safety, integrity or availability invariant is at immediate risk.
    Critical,
}

/// Bounded event carrying no authority and no raw secret or file content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedEvent {
    /// Authoritative or explicitly monotonic-derived occurrence time.
    pub occurred_at: UnixMicros,
    /// Node that emitted the observation.
    pub node_id: NodeId,
    /// Optional operation correlation identity.
    pub operation_id: Option<OperationId>,
    /// Closed severity used for local routing.
    pub severity: EventSeverity,
    /// Independently versioned canonical redacted event fields.
    pub fields: VersionedPayload,
}

/// Receipt proving the exact bounded batch accepted by a sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservabilityReceipt {
    /// Number of events durably accepted or explicitly acknowledged.
    pub accepted_events: usize,
    /// Digest of the complete ordered batch.
    pub batch_digest: [u8; 32],
}

/// Redacted telemetry destination that can never affect authoritative decisions.
pub trait ObservabilitySink: ComponentLifecycle {
    /// Emits one allocation-checked event batch.
    ///
    /// # Errors
    ///
    /// Rejects unsupported event formats, excessive batches and unavailable destinations.
    fn emit(
        &mut self,
        events: &BoundedItems<RedactedEvent>,
    ) -> Result<ObservabilityReceipt, ContractError>;
}
