// SPDX-License-Identifier: GPL-2.0-only

//! One-shot transfer rejection in the dedicated Stage 3 process-proof runtime.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use super::NodeRuntimeError;

pub(super) fn reject_first_transfer(state_path: &Path) -> Result<bool, NodeRuntimeError> {
    record_fault(
        state_path,
        "MESHSPAN_TEST_REJECT_FIRST_SNAPSHOT",
        "rejected-snapshot.marker",
        b"rejected first authenticated snapshot before installation\n",
    )
}

pub(super) fn lose_install_reply(state_path: &Path) -> Result<bool, NodeRuntimeError> {
    record_fault(
        state_path,
        "MESHSPAN_TEST_LOSE_SNAPSHOT_INSTALL_REPLY",
        "lost-snapshot-reply.marker",
        b"closed installation reply receiver before durable installation\n",
    )
}

fn record_fault(
    state_path: &Path,
    variable: &str,
    extension: &str,
    evidence: &[u8],
) -> Result<bool, NodeRuntimeError> {
    match std::env::var_os(variable) {
        None => return Ok(false),
        Some(value) if value == "true" => {}
        Some(_) => return Err(NodeRuntimeError::InvalidConfiguration),
    }
    let marker = state_path.with_extension(extension);
    match OpenOptions::new().write(true).create_new(true).open(marker) {
        Ok(mut file) => {
            file.write_all(evidence)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}
