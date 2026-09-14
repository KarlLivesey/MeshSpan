// SPDX-License-Identifier: GPL-2.0-only

//! Durable, idempotent collection of node attestations; never a live activation command.

use super::RecoveryPreparationError as Error;
use crate::protected_file;
use meshspan_domain::{Clock as _, NodeId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use std::{ffi::OsString, io::Write as _, path::Path};

pub(crate) fn collect_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, node, report] = arguments else {
        return Err(Error::CollectionArguments);
    };
    let node = node
        .to_str()
        .and_then(|value| crate::create_mesh_setup::parse_uuid(value).ok())
        .and_then(|value| NodeId::from_bytes(value).ok())
        .ok_or(Error::Input)?;
    let bytes =
        protected_file::read_bounded(Path::new(report), 1, 16 * 1024).map_err(|_| Error::Input)?;
    let signature = meshspan_api_contract::decode_recovery_installation_signature(&bytes)
        .map_err(|_| Error::Input)?;
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::open_authority(&bundle, Path::new(code))?;
    // Do not create a database or accept an unsafe file in place of the existing preparation.
    let _guard = protected_file::open_read(Path::new(prepared)).map_err(|_| Error::Workspace)?;
    let mut repo = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(Path::new(prepared), crate::OperatingSystemClock.now())
            .map_err(|_| Error::Workspace)?,
    );
    let receipt = repo
        .record_recovery_key_installation(
            &authority,
            node,
            &signature,
            crate::OperatingSystemClock.now(),
        )
        .map_err(|_| Error::Material)?;
    let report = serde_json::json!({
        "recorded": true,
        "node_id": crate::create_mesh_setup::format_uuid(receipt.node_id.as_bytes()),
        "sha256": crate::update_candidate::hex(&receipt.bundle_digest),
        "recorded_at_unix_micros": receipt.recorded_at.get().to_string(),
        "service_started": false,
        "admission_ready": false,
        "scope": "One selected node's verified installation attestation; not target readiness or service admission",
    });
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| Error::Worker)?;
    output.write_all(b"\n").map_err(|_| Error::Worker)
}
