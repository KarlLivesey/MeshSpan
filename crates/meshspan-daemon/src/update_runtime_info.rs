// SPDX-License-Identifier: GPL-2.0-only

//! Read-only executable compatibility report and bounded in-process-owned child probe.

use crate::{UpdateCandidateError, update_candidate::local_target};
use meshspan_metadata::{LocalDatabase, PartitionDatabase, UpdateManifest};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const MAXIMUM_REPORT_BYTES: usize = 8192;
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

#[cfg(test)]
#[path = "update_runtime_info_tests.rs"]
mod tests;

pub(crate) fn print_report() -> Result<(), UpdateCandidateError> {
    let report = report()?;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| UpdateCandidateError::Worker)?;
    output
        .write_all(b"\n")
        .map_err(|_| UpdateCandidateError::Worker)
}

fn report() -> Result<Value, UpdateCandidateError> {
    let api =
        meshspan_api_contract::generate_openapi().map_err(|_| UpdateCandidateError::Worker)?;
    Ok(json!({
        "format":1, "licence":"GPL-2.0-only", "version":env!("CARGO_PKG_VERSION"),
        "target":env!("MESHSPAN_BUILD_TARGET"), "api_sha256":api.digest().strip_prefix("sha256:").ok_or(UpdateCandidateError::Worker)?,
        "private_protocol_major":1, "metadata_command_version":meshspan_metadata::METADATA_COMMAND_VERSION,
        "partition_schema_target":PartitionDatabase::supported_schema_version(),
        "local_schema_target":LocalDatabase::supported_schema_version(),
    }))
}

/// The caller must authenticate/hash the executable before calling this function.
/// Uses a socket with a remaining-time read timeout: output cannot fill a disk or
/// force an unbounded allocation, and a trickling child cannot extend the deadline.
pub(crate) fn probe(
    executable: &Path,
    manifest: &UpdateManifest,
) -> Result<Value, UpdateCandidateError> {
    let deadline = Instant::now() + PROBE_DEADLINE;
    let (mut output, writer) = UnixStream::pair().map_err(|_| UpdateCandidateError::Worker)?;
    let mut child = Command::new(executable)
        .arg("update-runtime-info")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| UpdateCandidateError::Artifact)?;
    let result = read_report(&mut output, deadline).and_then(|bytes| {
        let exit = wait_for_exit(&mut child, deadline)?;
        if !exit.success() {
            return Err(UpdateCandidateError::Artifact);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| UpdateCandidateError::Artifact)?;
        let canonical = serde_json::to_vec(&value).map_err(|_| UpdateCandidateError::Artifact)?;
        if bytes.strip_suffix(b"\n").unwrap_or(&bytes) != canonical {
            return Err(UpdateCandidateError::Artifact);
        }
        validate(&value, manifest)?;
        Ok(value)
    });
    drop(output);
    reap(&mut child)?;
    result
}

fn reap(child: &mut Child) -> Result<(), UpdateCandidateError> {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return Ok(());
    }
    let killed = child.kill();
    // Even a raced/failed kill must observe the child result; dropping Child does not reap it.
    let exited = child.wait().map_err(|_| UpdateCandidateError::Worker)?;
    if killed.is_err() && !exited.success() {
        return Err(UpdateCandidateError::Worker);
    }
    Ok(())
}

fn read_report(
    output: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, UpdateCandidateError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(UpdateCandidateError::Worker)?;
        output
            .set_read_timeout(Some(remaining))
            .map_err(|_| UpdateCandidateError::Worker)?;
        let count = output
            .read(&mut buffer)
            .map_err(|_| UpdateCandidateError::Artifact)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() + count > MAXIMUM_REPORT_BYTES {
            return Err(UpdateCandidateError::Artifact);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn wait_for_exit(child: &mut Child, deadline: Instant) -> Result<ExitStatus, UpdateCandidateError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| UpdateCandidateError::Worker)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(UpdateCandidateError::Worker);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate(value: &Value, manifest: &UpdateManifest) -> Result<(), UpdateCandidateError> {
    // Until a candidate supplies a tested migration admission path, only unchanged
    // persistence/command formats may stage. A signed range alone is not migration proof.
    let schema = PartitionDatabase::supported_schema_version();
    if !manifest.accepts_partition(schema, 1)
        || manifest
            .target_partition_schema()
            .map_err(|_| UpdateCandidateError::Manifest)?
            != schema
    {
        return Err(UpdateCandidateError::Artifact);
    }
    let mut expected = report()?;
    // OS/architecture alone cannot turn a dynamically linked GNU build into a musl artefact.
    expected["target"] = json!(local_target()?);
    expected["version"] = json!(
        manifest
            .version()
            .map_err(|_| UpdateCandidateError::Manifest)?
    );
    expected["api_sha256"] = json!(
        manifest
            .api_sha256()
            .map_err(|_| UpdateCandidateError::Manifest)?
    );
    if *value != expected {
        return Err(UpdateCandidateError::Artifact);
    }
    Ok(())
}
