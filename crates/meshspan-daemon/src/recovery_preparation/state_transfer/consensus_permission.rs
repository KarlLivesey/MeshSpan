// SPDX-License-Identifier: GPL-2.0-only

//! Publish the coordinator's durable, exact-state consensus permission; never start services.

use super::Error;
use crate::protected_file::{self, PublishMode};
use meshspan_domain::Clock as _;
use meshspan_recovery_bundle::RecoveryStateTransfer;
use std::{ffi::OsString, fs, io, path::Path};

pub(in super::super) fn authorize_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, packages, output] = arguments else {
        return Err(Error::ConsensusPermissionArguments);
    };
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::super::open_authority(&bundle, Path::new(code))?;
    let mut repository = super::open_repository(Path::new(prepared))?;
    let plan = repository
        .staged_recovery_replacement_plan(&authority)?
        .ok_or(Error::Material)?;
    let mut expected = Vec::with_capacity(plan.nodes.len());
    for node in &plan.nodes {
        // Selected IDs determine the bounded set; directory entries are not trusted selection.
        let name = crate::create_mesh_setup::format_uuid(node.node_id.as_bytes());
        let encoded = protected_file::read_bounded(
            &Path::new(packages).join(name).join(super::AUTHORIZATION),
            1,
            512,
        )
        .map_err(|_| Error::Input)?;
        let transfer = RecoveryStateTransfer::decode(authority.root_certificate_der(), &encoded)
            .map_err(|_| Error::Authority)?;
        if transfer.claims().node_id != node.node_id {
            return Err(Error::Authority);
        }
        expected.push(transfer);
    }
    let permission = repository.authorize_recovery_consensus(
        &authority,
        &expected,
        crate::OperatingSystemClock.now(),
    )?;
    let encoded = permission.encode().map_err(|_| Error::Material)?;
    publish_exact(Path::new(output), &encoded)?;
    super::print_report(&serde_json::json!({
        "consensus_authorized": true, "service_started": false, "admission_ready": false,
        "node_count": plan.nodes.len(),
        "state_sha256": crate::update_candidate::hex(&permission.claims().state_digest),
        "scope": "Offline-root permission for the exact installed replacement consensus group; not applied membership or file-service readiness"
    }))
}

fn publish_exact(output: &Path, encoded: &[u8]) -> Result<(), Error> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            let saved = protected_file::read_bounded(output, 1, 512).map_err(|_| Error::Input)?;
            if saved.as_slice() != encoded {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            protected_file::publish(output, encoded, PublishMode::Create)
                .map_err(|_| Error::Workspace)
        }
        Err(_) => Err(Error::Workspace),
    }
}

pub(in super::super) fn admit_command(arguments: &[OsString]) -> Result<(), Error> {
    let [directory, permission] = arguments else {
        return Err(Error::ConsensusAdmissionArguments);
    };
    let encoded =
        protected_file::read_bounded(Path::new(permission), 1, 512).map_err(|_| Error::Input)?;
    let revision = crate::DaemonLocalState::admit_recovery_state(
        Path::new(directory),
        &encoded,
        crate::OperatingSystemClock.now(),
    )
    .map_err(|_| Error::Material)?;
    super::print_report(&serde_json::json!({
        "consensus_admitted": true, "service_started": false, "admission_ready": false,
        "revision": revision.get().to_string(),
        "scope": "Replacement consensus membership installed; normal daemon startup is authorised, current storage and file-service readiness remain separate"
    }))
}
