// SPDX-License-Identifier: GPL-2.0-only

use crate::update_artifact_store::UpdateArtifactStore;
use meshspan_certificates::{NodeIdentityKey, UPDATE_SIGNATURE_DOMAIN};
use meshspan_metadata::{UpdateManifest, authenticate_update_manifest};
use std::{
    fs,
    io::{self, Read},
};

const DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const TARGET: &str = "aarch64-apple-darwin";

#[test]
fn update_artifact_store_publishes_only_exact_bytes_and_reverifies_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let manifest = manifest()?;
    let store = UpdateArtifactStore::open(directory.path())?;
    let destination = directory.path().join("update-artifacts").join(DIGEST);
    for mut invalid in [&b"ab"[..], &b"abd"[..], &b"abcd"[..]] {
        assert!(store.stage(&manifest, TARGET, &mut invalid).is_err());
        assert!(!destination.exists());
    }
    store.stage(&manifest, TARGET, &mut &b"abc"[..])?;
    assert_eq!(fs::read(&destination)?, b"abc");
    store.stage(&manifest, TARGET, &mut &b"abc"[..])?;
    let reopened = UpdateArtifactStore::open(directory.path())?;
    let mut bytes = Vec::new();
    reopened
        .open_verified(&manifest, TARGET)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"abc");
    fs::write(&destination, b"abd")?;
    assert!(reopened.open_verified(&manifest, TARGET).is_err());
    assert!(reopened.stage(&manifest, TARGET, &mut &b"abc"[..]).is_err());
    Ok(())
}

#[test]
fn update_artifact_store_never_publishes_an_interrupted_transfer()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let manifest = manifest()?;
    let store = UpdateArtifactStore::open(directory.path())?;
    assert!(store.stage(&manifest, TARGET, &mut Interrupted).is_err());
    assert_eq!(
        fs::read_dir(directory.path().join("update-artifacts"))?.count(),
        0
    );
    Ok(())
}

struct Interrupted;
impl Read for Interrupted {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::ConnectionAborted.into())
    }
}

fn manifest() -> Result<UpdateManifest, Box<dyn std::error::Error>> {
    let key = NodeIdentityKey::generate()?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"format":1,"licence":"GPL-2.0-only","version":"0.1.0",
        "source_commit":"a".repeat(40),"api_sha256":"b".repeat(64),
        "compatibility":{"private_protocol_major":1,"partition_schema_min":1,"partition_schema_max":1,"partition_schema_target":1,"rollback_supported":false},
        "artifacts":[{"target":TARGET,"size":"3","sha256":DIGEST}]}),
    )?;
    let mut transcript = UPDATE_SIGNATURE_DOMAIN.to_vec();
    transcript.extend_from_slice(&bytes);
    Ok(authenticate_update_manifest(
        &bytes,
        &key.sign_enrolment_transcript(&transcript)?,
        key.public_key_sec1(),
    )?)
}
