// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use meshspan_domain::{EntropyError, JoinGrantBundle, MeshId, RandomSource};

use crate::{HeadlessDaemonConfig, HeadlessDaemonConfigError};

#[test]
fn complete_configuration_preserves_native_paths_and_typed_join_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let grant = JoinGrantBundle::generate(
        MeshId::from_bytes([9; 16])?,
        "https://node.meshspan.local:8443",
        [10; 32],
        &mut SequentialRandom(1),
    )?;
    let encoded = grant.expose_encoded();
    let config = HeadlessDaemonConfig::parse([
        OsString::from("--storage-path"),
        OsString::from("/data/one"),
        OsString::from("--join-code"),
        OsString::from(encoded.as_str()),
        OsString::from("--daemon-state-dir"),
        OsString::from("/state/instance"),
        OsString::from("--https-listen"),
        OsString::from("127.0.0.1:9443"),
        OsString::from("--smb-listen"),
        OsString::from("127.0.0.1:1445"),
        OsString::from("--claim-output"),
        OsString::from("/run/meshspan/claim"),
        OsString::from("--storage-path"),
        OsString::from("/data/two"),
    ])?;

    assert_eq!(
        config.storage().daemon_state_dir(),
        Path::new("/state/instance")
    );
    assert_eq!(
        config.storage().storage_paths(),
        [Path::new("/data/one"), Path::new("/data/two")]
    );
    assert_eq!(config.https_listen(), "127.0.0.1:9443".parse()?);
    assert_eq!(config.smb_listen(), "127.0.0.1:1445".parse()?);
    assert_eq!(
        config.claim_output(),
        Some(Path::new("/run/meshspan/claim"))
    );
    let parsed_grant = config
        .join_grant()
        .ok_or(HeadlessDaemonConfigError::InvalidJoinGrant)?;
    assert_eq!(parsed_grant.join_grant_id(), grant.join_grant_id());
    assert_eq!(parsed_grant.secret_digest(), grant.secret_digest());
    assert_eq!(parsed_grant.mesh_id(), grant.mesh_id());
    assert_eq!(
        parsed_grant.enrolment_endpoint(),
        grant.enrolment_endpoint()
    );
    Ok(())
}

#[test]
fn defaults_to_all_interfaces_public_listeners() -> Result<(), HeadlessDaemonConfigError> {
    let config = parse(["--daemon-state-dir", "/state", "--storage-path", "/data"])?;
    assert_eq!(
        config.https_listen(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8_443)
    );
    assert_eq!(
        config.smb_listen(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 445)
    );
    assert!(config.claim_output().is_none());
    assert!(config.join_grant().is_none());
    Ok(())
}

#[test]
fn malformed_duplicate_and_secret_substitution_inputs_fail_closed() {
    for arguments in [
        vec!["--daemon-state-dir", "/state"],
        vec!["--storage-path", "/data"],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--storage-path",
            "/data",
        ],
        vec!["--daemon-state-dir", "/same", "--storage-path", "/same"],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--https-listen",
            "localhost:443",
        ],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--smb-listen",
            "localhost:445",
        ],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--join-code",
            "meshspan-claim-v1.invalid",
        ],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--join-code",
        ],
        vec![
            "--daemon-state-dir",
            "/state",
            "--storage-path",
            "/data",
            "--unknown",
            "value",
        ],
    ] {
        assert!(parse(arguments).is_err());
    }
}

fn parse<I, S>(arguments: I) -> Result<HeadlessDaemonConfig, HeadlessDaemonConfigError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    HeadlessDaemonConfig::parse(arguments.into_iter().map(Into::into))
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
