// SPDX-License-Identifier: GPL-2.0-only

//! Two actual replacement installations must acknowledge one common frozen state.

use super::{Error, ProcessFixture, recovery_keys::hex};
use meshspan_daemon::{LocalNodeIdentity, LocalWrappingKey, OperatingSystemClock};
use meshspan_domain::Clock as _;
use meshspan_metadata::{AuthoritativeRepository, ConsensusStoreError, PartitionDatabase};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryStateTransfer};
use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    process::Command,
};

const GATEWAY: &str = "abababab-abab-8bab-abab-abababababab";
const STORAGE: &str = "bcbcbcbc-bcbc-8cbc-bcbc-bcbcbcbcbcbc";

#[test]
fn replacement_identities_fit_the_public_enrolment_contract() -> Result<(), Box<dyn Error>> {
    // Recovery IDs become bootstrap peers when a fresh node joins the recovered swarm.
    // Check the real fixture constants before running the expensive recovery workflow.
    for node in [GATEWAY, STORAGE] {
        let response = serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000001",
            "mesh_id": "00000000-0000-4000-8000-000000000002",
            "node_id": "00000000-0000-4000-8000-000000000003",
            "root_partition_id": "00000000-0000-4000-8000-000000000004",
            "routing_epoch": 1,
            "node_certificate_der_hex": "abcd",
            "online_authority_certificate_der_hex": "abcd",
            "root_certificate_der_hex": "abcd",
            "bootstrap_peers": [{"node_id": node, "incarnation": "1",
                "private_endpoint": "127.0.0.1:443", "certificate_der_hex": "abcd"}]
        });
        meshspan_api_contract::decode_enrol_node_response(&serde_json::to_vec(&response)?)?;
    }
    Ok(())
}

pub(super) async fn prove(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    original: &Path,
    authority: &RecoveredAuthority,
) -> Result<(), Box<dyn Error>> {
    let directory = original.join("two-node-state");
    let reservations = prepare_inputs(original, &directory)?;
    verify_source_media(root, original, &directory)?;
    accepted(super::recovery_keys::preparation_command(
        root, backup, digest, &directory,
    ))
    .await?;
    super::recovery_live_storage::prepare(root, &directory, backup).await?;
    let expected = export_and_verify(root, &directory, backup, authority).await?;
    install_set(root, &directory, authority, &expected).await?;
    let unavailable = directory.join("unavailable-original-storage");
    fs::rename(&root.storage_path, &unavailable)?;
    let served = super::recovery_consensus_permission::issue(
        root,
        &directory,
        authority,
        &expected,
        reservations,
    )
    .await;
    fs::rename(unavailable, &root.storage_path)?;
    served?;
    rejects_mixed_set(root, &directory, backup, authority, &expected).await?;
    Ok(())
}

async fn export_and_verify(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    authority: &RecoveredAuthority,
) -> Result<[RecoveryStateTransfer; 2], Box<dyn Error>> {
    let packages = directory.join("packages");
    let mut export = Command::new(&root.daemon_binary);
    export
        .arg("export-recovery-state-set")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(&packages);
    let report = accepted(export).await?;
    assert_eq!(report["exported"], true);
    assert_eq!(report["node_count"], 2);
    assert!(!packages.join("staging").exists());
    assert!(!packages.join("state.msb").exists());
    assert_eq!(fs::read_dir(&packages)?.count(), 2);
    let expected = [
        transfer(&packages.join(GATEWAY), authority)?,
        transfer(&packages.join(STORAGE), authority)?,
    ];
    assert_eq!(
        expected[0].claims().state_digest,
        expected[1].claims().state_digest
    );
    assert_ne!(
        expected[0].claims().key_bundle_digest,
        expected[1].claims().key_bundle_digest
    );
    assert_eq!(
        report["state_sha256"],
        hex(&expected[0].claims().state_digest)?
    );
    let first = fs::metadata(packages.join(GATEWAY).join("state.msb"))?;
    let second = fs::metadata(packages.join(STORAGE).join("state.msb"))?;
    assert_eq!((first.dev(), first.ino()), (second.dev(), second.ino()));
    assert_eq!(first.nlink(), 2);
    Ok(expected)
}

async fn install_set(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    expected: &[RecoveryStateTransfer; 2],
) -> Result<(), Box<dyn Error>> {
    let packages = directory.join("packages");
    super::recovery_consensus_permission::reject_incomplete(root, directory).await?;
    assert!(
        open(directory)?
            .require_recovery_state_installations(authority, expected)
            .is_err()
    );
    install_and_collect(root, directory, &packages.join(GATEWAY), GATEWAY, "gateway").await?;
    super::recovery_consensus_permission::reject_incomplete(root, directory).await?;
    assert!(
        open(directory)?
            .require_recovery_state_installations(authority, expected)
            .is_err()
    );
    rejects_wrong_identity(root, directory, &packages.join(STORAGE)).await?;
    install_and_collect(root, directory, &packages.join(STORAGE), STORAGE, "storage").await?;
    let repository = open(directory)?;
    repository.require_recovery_state_installations(authority, expected)?;
    assert!(
        repository
            .require_recovery_state_installations(
                authority,
                &[expected[0].clone(), expected[0].clone()]
            )
            .is_err()
    );
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    drop(repository);
    for name in [
        "root-authority.sqlite3",
        "filesystem/filesystem-branch.sqlite3",
        "filesystem/filesystem-content.sqlite3",
    ] {
        assert_eq!(
            fs::read(directory.join("installed-gateway").join(name))?,
            fs::read(directory.join("installed-storage").join(name))?
        );
    }
    verify_runtime_key_projection(directory, expected)?;
    Ok(())
}

fn verify_runtime_key_projection(
    directory: &Path,
    expected: &[RecoveryStateTransfer; 2],
) -> Result<(), Box<dyn Error>> {
    let gateway = LocalWrappingKey::open(&directory.join("wrapping.x25519"))?;
    let storage = LocalWrappingKey::open(&directory.join("storage.x25519"))?;
    for label in ["gateway", "storage"] {
        let database = PartitionDatabase::open_existing(
            &directory.join(format!("installed-{label}/root-authority.sqlite3")),
            OperatingSystemClock.now(),
        )?;
        let repository = AuthoritativeRepository::new(database);
        let mesh = expected[0].claims().authorization.claims().mesh_id;
        assert_eq!(
            repository.latest_online_authority_generation(mesh)?,
            Some(2)
        );
        assert_eq!(repository.latest_storage_permit_generation(mesh)?, Some(2));
        assert_eq!(
            repository
                .online_certificate_authority(mesh)?
                .ok_or("issuer absent")?
                .generation,
            2
        );
        for (transfer, key) in expected
            .iter()
            .zip([gateway.public_key(), storage.public_key()])
        {
            assert_eq!(
                repository
                    .node_wrapping_key(transfer.claims().node_id)?
                    .ok_or("node key absent")?
                    .public_key,
                key
            );
        }
        for context in repository
            .secret_generation_contexts(None, meshspan_metadata::PageLimit::new(128)?)?
            .items
        {
            let secret = repository
                .secret_generation(context)?
                .ok_or("secret absent")?;
            let assigned_storage = secret.recipients.iter().any(|recipient| {
                recipient
                    .recipient_public_key()
                    .is_ok_and(|key| key == storage.public_key())
            });
            assert_eq!(
                assigned_storage,
                context.kind() == meshspan_metadata::STORAGE_PERMIT_KEY_SECRET_KIND
                    && context.generation() == 2
            );
            assert!(secret.recipients.iter().any(|recipient| {
                recipient
                    .recipient_public_key()
                    .is_ok_and(|key| key == gateway.public_key())
            }));
        }
        assert!(matches!(
            repository.load_consensus_state(2),
            Err(ConsensusStoreError::RecoveryAdmissionRequired)
        ));
    }
    // Projection happened only inside the export snapshot, never in the coordinator.
    let repository = open(directory)?;
    let mesh = expected[0].claims().authorization.claims().mesh_id;
    assert_eq!(
        repository.latest_online_authority_generation(mesh)?,
        Some(1)
    );
    assert!(
        repository
            .node_wrapping_key(expected[0].claims().node_id)?
            .is_none()
    );
    Ok(())
}

fn prepare_inputs(
    original: &Path,
    directory: &Path,
) -> Result<[std::net::UdpSocket; 2], Box<dyn Error>> {
    fs::create_dir(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    fs::copy(
        original.join("identity.pk8"),
        directory.join("identity.pk8"),
    )?;
    fs::copy(
        original.join("wrapping.x25519"),
        directory.join("wrapping.x25519"),
    )?;
    fs::copy(original.join("root.der"), directory.join("root.der"))?;
    let identity = LocalNodeIdentity::create(&directory.join("storage.pk8"), "storage.invalid")?;
    let wrapping = LocalWrappingKey::open_or_create(&directory.join("storage.x25519"))?;
    let mut selection: serde_json::Value =
        serde_json::from_slice(&fs::read(original.join("selection.json"))?)?;
    selection["recovery_id"] = "bdbdbdbd-bdbd-8dbd-adbd-bdbdbdbdbdbd".into();
    let reservations = [
        std::net::UdpSocket::bind("127.0.0.1:0")?,
        std::net::UdpSocket::bind("127.0.0.1:0")?,
    ];
    selection["nodes"][0]["private_endpoint"] = reservations[0].local_addr()?.to_string().into();
    selection["nodes"]
        .as_array_mut()
        .ok_or("missing nodes")?
        .push(serde_json::json!({
            "node_id": STORAGE, "host_id": "bebebebe-bebe-bebe-bebe-bebebebebebe",
            "host_name": "Second replacement host", "node_name": "Storage replacement",
            "incarnation": "1", "roles": ["storage"],
            "identity_public_key": hex(identity.public_key_sec1())?,
            "wrapping_public_key": hex(&wrapping.public_key().as_bytes())?,
            "private_endpoint": reservations[1].local_addr()?.to_string()
        }));
    let file = directory.join("selection.json");
    fs::write(&file, serde_json::to_vec(&selection)?)?;
    fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
    Ok(reservations)
}

async fn install_and_collect(
    root: &ProcessFixture,
    directory: &Path,
    package: &Path,
    node: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let mut install = Command::new(&root.daemon_binary);
    let (identity, wrapping) = if node == STORAGE {
        ("storage.pk8", "storage.x25519")
    } else {
        ("identity.pk8", "wrapping.x25519")
    };
    let destination = directory.join(format!("installed-{label}"));
    install
        .arg("install-recovery-state")
        .arg(package)
        .arg(directory.join("root.der"))
        .arg(node)
        .arg(directory.join(identity))
        .arg(directory.join(wrapping))
        .arg(&destination);
    if node == STORAGE {
        install
            .arg("--storage-target")
            .arg(directory.join("live-target-work"))
            .arg(directory.join("live-restored-storage"));
    }
    let report = accepted(install).await?;
    assert_eq!(report["installed"], true);
    assert_eq!(report["node_id"], node);
    let mut collect = Command::new(&root.daemon_binary);
    collect
        .arg("collect-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(package.join("state.auth"))
        .arg(destination.join("installed.json"));
    assert_eq!(accepted(collect).await?["recorded"], true);
    Ok(())
}

async fn rejects_wrong_identity(
    root: &ProcessFixture,
    directory: &Path,
    package: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut install = Command::new(&root.daemon_binary);
    let destination = directory.join("wrong-identity");
    install
        .arg("install-recovery-state")
        .arg(package)
        .arg(directory.join("root.der"))
        .arg(STORAGE)
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(&destination);
    let rejected = super::offline_backup::run_command(install).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!destination.join("installed.json").exists());
    assert!(!destination.join("root-authority.sqlite3").exists());
    Ok(())
}

async fn rejects_mixed_set(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    authority: &RecoveredAuthority,
    expected: &[RecoveryStateTransfer; 2],
) -> Result<(), Box<dyn Error>> {
    let package = directory.join("later-gateway-package");
    let mut export = Command::new(&root.daemon_binary);
    export
        .arg("export-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(GATEWAY)
        .arg(&package);
    accepted(export).await?;
    install_and_collect(root, directory, &package, GATEWAY, "later-gateway").await?;
    let later = transfer(&package, authority)?;
    assert_ne!(
        later.claims().state_digest,
        expected[0].claims().state_digest
    );
    let repository = open(directory)?;
    // Both signatures have been durably collected; only the common candidate is acceptable.
    assert!(
        repository
            .require_recovery_state_installations(authority, &[later, expected[1].clone()])
            .is_err()
    );
    repository.require_recovery_state_installations(authority, expected)?;
    assert_eq!(
        repository.current_revision()?,
        expected[0].claims().authorization.claims().source_revision
    );
    Ok(())
}

fn transfer(
    package: &Path,
    authority: &RecoveredAuthority,
) -> Result<RecoveryStateTransfer, Box<dyn Error>> {
    Ok(RecoveryStateTransfer::decode(
        authority.root_certificate_der(),
        &fs::read(package.join("state.auth"))?,
    )?)
}

fn open(directory: &Path) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    let database = PartitionDatabase::open_existing(
        &directory.join("coordinator/prepared.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    database.check_integrity()?;
    Ok(AuthoritativeRepository::new(database))
}

pub(super) async fn accepted(command: Command) -> Result<serde_json::Value, Box<dyn Error>> {
    let operation = command
        .get_args()
        .next()
        .ok_or("command missing")?
        .to_owned();
    let output = super::offline_backup::run_command(command).await?;
    if !output.status.success() {
        // Returning the failure keeps this harness's private fixture for diagnosis.
        return Err(format!(
            "{}: {}",
            operation.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["service_started"], false);
    assert_eq!(report["admission_ready"], false);
    Ok(report)
}

fn verify_source_media(
    root: &ProcessFixture,
    original: &Path,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let selected: serde_json::Value =
        serde_json::from_slice(&fs::read(original.join("selection.json"))?)?;
    let id = meshspan_domain::TargetId::parse(
        &selected["storage"]["targets"][0]["target_id"]
            .as_str()
            .ok_or("target missing")?
            .replace('-', ""),
    )?;
    let fingerprint = open(original)?
        .recovery_storage_target_marker(id, 1)?
        .ok_or("source marker missing")?;
    let folder = meshspan_storage::RecoveryFolder::open(
        &root.storage_path,
        meshspan_storage::MarkerFingerprint::from_bytes(fingerprint),
    )?;
    let sequences = folder.pack_sequences()?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sequences, [1]);
    let pack = folder.open_pack(1, &directory.join("source-check"), 16 * 1024 * 1024)?;
    let page = pack.inventory_page(0, 2)?;
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    pack.read_exact(record.shard, record.length, record.digest)?;
    pack.finish()?;
    Ok(())
}
