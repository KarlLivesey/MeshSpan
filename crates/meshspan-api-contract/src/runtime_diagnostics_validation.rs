// SPDX-License-Identifier: GPL-2.0-only

//! Outgoing bundle validation includes structural bounds and observation consistency.

use crate::metadata_diagnostics::counter;
use crate::{
    BoundaryError, DiagnosticObservationTime, DiagnosticRuntimeEventCode, DiagnosticTargetIdentity,
    DiagnosticsBundleResponse, RuntimeDiagnosticsResponse,
};

/// Validates bounded runtime evidence and the complete nested metadata response.
///
/// # Errors
/// Rejects invalid structure, counters, ordering, identities, bounds or contradictory samples.
pub fn encode_diagnostics_bundle_response(
    value: &DiagnosticsBundleResponse,
) -> Result<Vec<u8>, BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    let json = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(VALIDATOR.get_or_init(|| {
            compile(&crate::schema::response_schema::<DiagnosticsBundleResponse>())
        }))?,
        &json,
    )?;
    crate::encode_metadata_diagnostics_response(&value.metadata)?;
    if let Some(runtime) = &value.runtime {
        validate_runtime(runtime)?;
    }
    let bytes = serde_json::to_vec(&json).map_err(|_| BoundaryError::EncodeMismatch)?;
    if bytes.len() > crate::MAX_DIAGNOSTICS_BUNDLE_BYTES {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(bytes)
}

fn validate_runtime(value: &RuntimeDiagnosticsResponse) -> Result<(), BoundaryError> {
    let uptime = counter(&value.uptime_millis)?;
    let sequence = counter(&value.observation_sequence)?;
    for field in [
        &value.dropped_updates,
        &value.target_check_evictions,
        &value.event_evictions,
        &value.target_probe_passes,
        &value.target_probe_failures,
    ] {
        counter(field)?;
    }
    if counter(&value.reconciliation_failures)? > counter(&value.reconciliation_cycles)? {
        return Err(BoundaryError::EncodeMismatch);
    }
    if let Some(cycle) = &value.storage_reconciliation {
        validate_time(&cycle.observation, uptime, sequence)?;
        for field in [
            &cycle.duration_millis,
            &cycle.configured_folders,
            &cycle.open_targets,
            &cycle.pending_return_scans,
            &cycle.failed_steps,
        ] {
            counter(field)?;
        }
    }
    let mut targets = std::collections::BTreeSet::new();
    for check in &value.target_checks {
        validate_target(&check.target)?;
        validate_time(&check.observation, uptime, sequence)?;
        counter(&check.duration_millis)?;
        if !targets.insert((&check.target.target_id.0, &check.target.generation.0)) {
            return Err(BoundaryError::EncodeMismatch);
        }
    }
    let mut previous = None;
    for event in &value.recent_events {
        validate_time(&event.observation, uptime, sequence)?;
        let current = counter(&event.observation.sequence)?;
        if previous.is_some_and(|previous| current >= previous) {
            return Err(BoundaryError::EncodeMismatch);
        }
        previous = Some(current);
        let is_target = matches!(
            event.code,
            DiagnosticRuntimeEventCode::TargetProbeFailed
                | DiagnosticRuntimeEventCode::TargetProbeRecovered
        );
        if is_target != event.target.is_some() {
            return Err(BoundaryError::EncodeMismatch);
        }
        if let Some(target) = &event.target {
            validate_target(target)?;
        }
    }
    Ok(())
}

fn validate_time(
    value: &DiagnosticObservationTime,
    uptime: u64,
    sequence: u64,
) -> Result<(), BoundaryError> {
    let observed = counter(&value.sequence)?;
    if observed == 0 || observed > sequence || counter(&value.age_millis)? > uptime {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(())
}

fn validate_target(value: &DiagnosticTargetIdentity) -> Result<(), BoundaryError> {
    if counter(&value.generation)? == 0 {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(())
}
