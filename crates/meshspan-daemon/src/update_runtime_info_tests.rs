// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_certificates::{NodeIdentityKey, UPDATE_SIGNATURE_DOMAIN};

#[test]
fn runtime_probe_requires_the_exact_signed_build_and_unchanged_persistence_formats()
-> Result<(), Box<dyn std::error::Error>> {
    let mut report = report()?;
    report["target"] = json!(local_target()?);
    let manifest = manifest(&report)?;
    validate(&report, &manifest)?;
    for (field, replacement) in [
        ("version", json!("9.9.9")),
        ("licence", json!("MIT")),
        ("api_sha256", json!("0".repeat(64))),
        ("target", json!("invalid-target")),
        ("private_protocol_major", json!(2)),
        ("metadata_command_version", json!(0)),
        ("partition_schema_target", json!(0)),
        ("local_schema_target", json!(999)),
        ("format", json!("1")),
        ("unexpected", json!(true)),
    ] {
        let mut changed = report.clone();
        changed[field] = replacement;
        assert!(
            validate(&changed, &manifest).is_err(),
            "accepted changed {field}"
        );
    }
    let mut changed = report;
    changed["partition_schema_target"] = json!(PartitionDatabase::supported_schema_version() + 1);
    assert!(validate(&changed, &self::manifest(&changed)?).is_err());
    Ok(())
}

#[test]
fn runtime_report_reader_bounds_output_and_rejects_an_expired_probe()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = UnixStream::pair()?;
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let writing = scope.spawn(move || writer.write_all(&vec![b'x'; MAXIMUM_REPORT_BYTES + 1]));
        let result = read_report(&mut reader, Instant::now() + PROBE_DEADLINE);
        drop(reader);
        writing.join().map_err(|_| "report writer panicked")??;
        assert!(result.is_err());
        Ok(())
    })?;
    let (mut reader, _writer) = UnixStream::pair()?;
    assert!(read_report(&mut reader, Instant::now()).is_err());
    Ok(())
}

fn manifest(report: &Value) -> Result<UpdateManifest, Box<dyn std::error::Error>> {
    let key = NodeIdentityKey::generate()?;
    let bytes = serde_json::to_vec(&json!({
        "format":1, "licence":"GPL-2.0-only", "version":report["version"],
        "source_commit":"a".repeat(40), "api_sha256":report["api_sha256"],
        "compatibility":{"private_protocol_major":1,
            "partition_schema_min":PartitionDatabase::supported_schema_version(),
            "partition_schema_max":PartitionDatabase::supported_schema_version(),
            "partition_schema_target":report["partition_schema_target"], "rollback_supported":false},
        "artifacts":[{"target":local_target()?, "size":"3",
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],
    }))?;
    let mut transcript = UPDATE_SIGNATURE_DOMAIN.to_vec();
    transcript.extend_from_slice(&bytes);
    Ok(meshspan_metadata::authenticate_update_manifest(
        &bytes,
        &key.sign_enrolment_transcript(&transcript)?,
        key.public_key_sec1(),
    )?)
}
