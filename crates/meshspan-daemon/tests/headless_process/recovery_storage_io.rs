// SPDX-License-Identifier: GPL-2.0-only

//! An admitted storage-only daemon serves real, capability-bound shard IO without gateway keys.

use super::{Error, ProcessFixture};
use meshspan_cluster::{ConsensusNetwork, ConsensusNetworkConfig, ConsensusPeerConfig};
use meshspan_contracts::{
    BoundedBytes, ReservationClass, ShardIdentity, ShardReadPermit, ShardWritePermit,
    StoragePermitMacKey, read_permit_mac, write_permit_mac,
};
use meshspan_daemon::{
    LocalWrappingKey, OperatingSystemClock, SecretGenerationAuthority,
    SecretGenerationAuthorityError, StoragePermitAuthority, StoragePermitLoadingService,
};
use meshspan_domain::{Clock as _, MeshId, NodeId, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, LocalTargetRecord, PartitionDatabase, SecretGenerationRecord,
};
use meshspan_protocol::v1::NodeRole;
use meshspan_secret_envelope::SecretContext;
use std::{fs, path::Path};

#[path = "recovery_storage_cleanup.rs"]
mod cleanup;

pub(super) use cleanup::prove_committed_cleanup;

#[derive(Clone, Copy)]
pub(super) enum Scenario {
    RoundTrip,
    RetainedRead,
}

pub(super) async fn prove(
    gateway: &ProcessFixture,
    storage: &ProcessFixture,
    target: &LocalTargetRecord,
    scenario: Scenario,
) -> Result<(), Box<dyn Error>> {
    let directory = gateway.state_path.clone();
    let destination = storage.private_address;
    let target = target.clone();
    let runtime = tokio::runtime::Handle::current();
    let client = tokio::task::spawn_blocking(move || {
        prepare(&directory, destination, &target, &runtime).map_err(|e| e.to_string())
    })
    .await??;
    let outcome = tokio::time::timeout(super::WAIT_LIMIT, client.exercise(scenario)).await;
    let close = client.network.close();
    outcome??;
    close?;
    Ok(())
}

struct StorageIoClient {
    network: ConsensusNetwork,
    destination: NodeId,
    key: StoragePermitMacKey,
    write: ShardWritePermit,
    membership_epoch: u64,
}

impl StorageIoClient {
    async fn exercise(&self, scenario: Scenario) -> Result<(), Box<dyn Error>> {
        let connection = self.network.connect_data_peer(self.destination).await?;
        let limits = self.network.wire_limits();
        // These are opaque shard bytes, not a file-encryption or namespace-recovery assertion.
        let bytes = BoundedBytes::copy_from(&[0x52; 8192], 8192)?;
        let mut write = self.write;
        write.permit_digest = write_permit_mac(&self.key, write);
        if matches!(scenario, Scenario::RoundTrip) {
            let header = self
                .network
                .control_header(write.operation_id, write.expires_at.get())?;
            let receipt =
                meshspan_data_plane::put_shard(&connection, header, write, &bytes, limits).await?;
            assert_eq!(receipt.target_id, write.target_id);
            assert_eq!(receipt.shard, write.shard);
            assert_eq!(receipt.length, 8192);
        }
        let mut read = ShardReadPermit {
            operation_id: OperationId::from_bytes([231; 16])?,
            mesh_id: write.mesh_id,
            target_id: write.target_id,
            target_generation: write.target_generation,
            shard: write.shard,
            authorization_revision: write.authorization_revision,
            expires_at: write.expires_at,
            permit_digest: [0; 32],
        };
        read.permit_digest = read_permit_mac(&self.key, read);
        let header = self
            .network
            .control_header(read.operation_id, read.expires_at.get())?;
        let fetched =
            meshspan_data_plane::get_shard(&connection, header, read, 8192, limits).await?;
        assert_eq!(fetched.as_slice(), &[0x52; 8192]);
        self.reject_uncommitted_cleanup(&connection, read).await?;
        let mut forged = read;
        forged.permit_digest[0] ^= 1;
        let header = self
            .network
            .control_header(forged.operation_id, forged.expires_at.get())?;
        assert!(
            meshspan_data_plane::get_shard(&connection, header, forged, 8192, limits)
                .await
                .is_err()
        );
        connection.close(0_u32.into(), b"proof complete");
        Ok(())
    }

    /// Even a real enrolled gateway holding the MAC key cannot invent a cleanup decision.
    async fn reject_uncommitted_cleanup(
        &self,
        connection: &quinn::Connection,
        read: ShardReadPermit,
    ) -> Result<(), Box<dyn Error>> {
        let mut removal = meshspan_contracts::RemovalPermit {
            operation_id: OperationId::from_bytes([239; 16])?,
            mesh_id: read.mesh_id,
            target_id: read.target_id,
            target_generation: read.target_generation,
            shard: read.shard,
            authority_epoch: self.membership_epoch,
            catalogue_revision: read.authorization_revision,
            expires_at: read.expires_at,
            permit_digest: [0; 32],
        };
        removal.permit_digest = meshspan_contracts::removal_permit_mac(&self.key, removal);
        let header = self
            .network
            .control_header(removal.operation_id, removal.expires_at.get())?;
        let result = meshspan_data_plane::tombstone_shard(
            connection,
            header,
            removal,
            self.network.wire_limits(),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(meshspan_data_plane::DataPlaneError::Remote(
                    meshspan_protocol::v1::ErrorCode::Unauthorised
                ))
            ),
            "unexpected cleanup outcome: {result:?}"
        );
        let header = self
            .network
            .control_header(read.operation_id, read.expires_at.get())?;
        let retained = meshspan_data_plane::get_shard(
            connection,
            header,
            read,
            8192,
            self.network.wire_limits(),
        )
        .await?;
        assert_eq!(
            retained.as_slice(),
            &[0x52; 8192],
            "denied cleanup changed shard bytes"
        );
        Ok(())
    }
}

fn prepare(
    directory: &Path,
    destination: std::net::SocketAddr,
    target: &LocalTargetRecord,
    runtime: &tokio::runtime::Handle,
) -> Result<StorageIoClient, Box<dyn Error>> {
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &directory.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    let gateway = meshspan_metadata::LocalDatabase::open_existing(
        &directory.join("local.sqlite3"),
        OperatingSystemClock.now(),
    )?
    .node_id();
    let mesh = target.intent.mesh_id;
    let revision = repository.current_revision()?;
    let membership_epoch = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("plan missing")?
        .membership_epoch();
    let wrapping = LocalWrappingKey::open(&directory.join("secrets/node-wrapping-key.x25519"))?;
    let key = StoragePermitLoadingService::new(PermitRepository(repository), wrapping)
        .load_latest(mesh)?;
    let write = ShardWritePermit {
        operation_id: OperationId::from_bytes([230; 16])?,
        mesh_id: mesh,
        target_id: target.intent.target_id,
        target_generation: target.intent.generation,
        shard: ShardIdentity {
            manifest_digest: [232; 32],
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        },
        reservation_class: ReservationClass::ForegroundWrite,
        maximum_bytes: 8192,
        authorization_revision: revision,
        expires_at: UnixMicros::new(
            OperatingSystemClock
                .now()
                .get()
                .checked_add(30_000_000)
                .ok_or("clock overflow")?,
        ),
        permit_digest: [0; 32],
    };
    Ok(StorageIoClient {
        network: start_network(
            directory,
            gateway,
            (target.intent.node_id, destination),
            vec![NodeRole::Gateway],
            runtime,
        )?,
        destination: target.intent.node_id,
        key,
        write,
        membership_epoch,
    })
}

/// Uses only this fixture node's installed private key; peers are certificate-bound.
pub(super) fn start_network(
    directory: &Path,
    local: NodeId,
    destination: (NodeId, std::net::SocketAddr),
    roles: Vec<NodeRole>,
    runtime: &tokio::runtime::Handle,
) -> Result<ConsensusNetwork, Box<dyn Error>> {
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &directory.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    let mesh = repository.local_mesh_id()?.ok_or("mesh missing")?;
    let certificate = repository
        .active_node_certificate(local)?
        .ok_or("local certificate missing")?;
    let remote = repository
        .active_node_certificate(destination.0)?
        .ok_or("remote certificate missing")?;
    let issuer = repository
        .online_certificate_authority(mesh)?
        .ok_or("issuer missing")?;
    let root = repository
        .mesh_recovery_authority(mesh)?
        .ok_or("root missing")?;
    let config = ConsensusNetworkConfig {
        local_node_id: local,
        local_incarnation: certificate.incarnation,
        mesh_id: mesh,
        partition_id: repository.partition_id(),
        routing_epoch: 1,
        roles,
        listen_address: "127.0.0.1:0".parse()?,
        client_address: "127.0.0.1:0".parse()?,
        certificate_chain_der: vec![certificate.certificate_der, issuer.certificate_der],
        certificate_generation: certificate.generation,
        certificate_name: name(local),
        private_key_pkcs8: zeroize::Zeroizing::new(fs::read(
            directory.join("secrets/node-identity.pk8"),
        )?),
        trust_anchors: vec![root.root_certificate_der],
        snapshot_staging_path: None,
        peers: vec![ConsensusPeerConfig {
            node_id: destination.0,
            incarnation: remote.incarnation,
            address: destination.1,
            certificate_der: remote.certificate_der,
            certificate_name: name(destination.0),
        }],
    };
    let (sender, _received) = tokio::sync::mpsc::channel(1);
    let _entered = runtime.enter();
    Ok(ConsensusNetwork::start(config, sender)?)
}

fn name(node: NodeId) -> String {
    format!(
        "node-{}.meshspan.internal",
        node.to_string().replace('-', "")
    )
}

struct PermitRepository(AuthoritativeRepository);
impl SecretGenerationAuthority for PermitRepository {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        self.0
            .runtime_secret_generation(context)
            .map_err(|_| SecretGenerationAuthorityError::Failed)
    }
}
impl StoragePermitAuthority for PermitRepository {
    fn latest_generation(
        &self,
        mesh: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.0
            .latest_storage_permit_generation(mesh)
            .map_err(|_| SecretGenerationAuthorityError::Failed)
    }
}
