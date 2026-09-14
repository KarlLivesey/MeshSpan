// SPDX-License-Identifier: GPL-2.0-only

//! Exact-package state attestation collection, distinct from key-only and shard-copy evidence.

use super::Error;
use crate::protected_file;
use meshspan_domain::Clock as _;
use meshspan_recovery_bundle::RecoveryStateTransfer;
use std::{ffi::OsString, path::Path};

pub(in super::super) fn collect_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, expected, report] = arguments else {
        return Err(Error::StateCollectionArguments);
    };
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::super::open_authority(&bundle, Path::new(code))?;
    let encoded =
        protected_file::read_bounded(Path::new(expected), 1, 512).map_err(|_| Error::Input)?;
    let expected = RecoveryStateTransfer::decode(authority.root_certificate_der(), &encoded)
        .map_err(|_| Error::Authority)?;
    let node = crate::create_mesh_setup::format_uuid(expected.claims().node_id.as_bytes());
    let digest = crate::update_candidate::hex(&expected.claims().state_digest);
    let message = expected
        .installation_message()
        .map_err(|_| Error::Authority)?;
    let bytes =
        protected_file::read_bounded(Path::new(report), 1, 16 * 1024).map_err(|_| Error::Input)?;
    let signature = meshspan_api_contract::decode_recovery_state_installation_signature(
        &bytes,
        &node,
        &digest,
        &crate::update_candidate::hex(&message),
    )
    .map_err(|_| Error::Input)?;
    let mut repository = super::open_repository(Path::new(prepared))?;
    let receipt = repository.record_recovery_state_installation(
        &authority,
        &expected,
        &signature,
        crate::OperatingSystemClock.now(),
    )?;
    super::print_report(&serde_json::json!({
        "recorded": true, "node_id": node, "state_sha256": digest,
        "recorded_at_unix_micros": receipt.recorded_at.get().to_string(),
        "service_started": false, "admission_ready": false,
        "scope": "Exact expected state installation attestation; not current readiness or authority to serve"
    }))
}
