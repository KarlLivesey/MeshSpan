// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_certificates::NodeIdentityKey;
use meshspan_consensus::{ActiveQuorumPlan, compile_plan, flat_plan};
use meshspan_domain::{HostId, NodeId, QuorumPlanId, Revision, UnixMicros};
use meshspan_recovery_bundle::RecoveryAuthorizationClaims;
use meshspan_secret_envelope::WrappingPrivateKey;

use super::{Fixture, TestResult};
use crate::{
    AuthoritativeRepository, CommitSecretGeneration, ConsensusStoreError, JoinRoles, PageLimit,
    PartitionDatabase, RecordName, RecoveryControlKeys, RecoveryReplacementNode,
    RecoveryReplacementPlan, RecoverySecretInventoryBuilder, RepositoryError,
};

pub(super) struct Candidate {
    pub(super) fixture: Fixture,
    pub(super) plan: RecoveryReplacementPlan,
    pub(super) identity: NodeIdentityKey,
    control: RecoveryControlKeys,
    retained: Vec<CommitSecretGeneration>,
}

#[test]
fn signed_replacement_plan_binds_exact_prepared_keys_and_survives_reopen() -> TestResult {
    let candidate = Candidate::new()?;
    let mut repo = candidate.restore_keys(true)?;
    assert_eq!(
        repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?,
        None
    );
    let digest = repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    assert_eq!(
        digest,
        candidate
            .fixture
            .authorization
            .claims()
            .replacement_manifest_digest
    );
    drop(repo);
    let mut repo = candidate.reopen()?;
    assert_eq!(
        repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?,
        Some(candidate.plan.clone())
    );
    assert_eq!(
        repo.stage_recovery_replacement_plan(
            &candidate.fixture.authority,
            &candidate.plan,
            UnixMicros::new(41)
        )?,
        digest
    );
    assert_eq!(repo.current_revision()?, Revision::new(1));
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    let db = repo.into_database();
    db.check_integrity()?;
    let timestamp: i64 = db.connection().query_row(
        "SELECT staged_at FROM partition_recovery_replacement_plan",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(timestamp, 40);
    assert!(
        db.connection()
            .execute("DELETE FROM partition_recovery_replacement_plan", [])
            .is_err()
    );
    Ok(())
}

#[test]
fn replacement_plan_rejects_unsigned_substitution_and_unsealed_inventory() -> TestResult {
    let candidate = Candidate::new()?;
    let mut repo = candidate.restore_keys(false)?;
    assert!(matches!(
        repo.stage_recovery_replacement_plan(
            &candidate.fixture.authority,
            &candidate.plan,
            UnixMicros::new(40)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    repo.seal_recovery_secret_inventory(&candidate.fixture.authority, UnixMicros::new(41))?;
    let mut changed = candidate.plan.clone();
    changed.nodes.first_mut().ok_or("no node")?.private_endpoint = "127.0.0.1:10001".to_owned();
    assert!(matches!(
        repo.stage_recovery_replacement_plan(
            &candidate.fixture.authority,
            &changed,
            UnixMicros::new(42)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?,
        None
    );
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(43),
    )?;
    Ok(())
}

#[test]
fn signed_replacement_plan_still_rejects_wrong_recipients_or_membership_epoch() -> TestResult {
    for wrong_recipient in [true, false] {
        let mut candidate = Candidate::new()?;
        if wrong_recipient {
            candidate
                .plan
                .nodes
                .first_mut()
                .ok_or("no node")?
                .wrapping_public_key = WrappingPrivateKey::from_bytes([83; 32])?.public_key();
        } else {
            candidate.plan.quorum =
                quorum(candidate.plan.nodes.first().ok_or("no node")?.node_id, 1)?;
        }
        candidate.sign()?;
        let mut repo = candidate.restore_keys(true)?;
        assert!(matches!(
            repo.stage_recovery_replacement_plan(
                &candidate.fixture.authority,
                &candidate.plan,
                UnixMicros::new(40)
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(
            repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?,
            None
        );
    }
    Ok(())
}

#[test]
fn replacement_plan_codec_rejects_ambiguous_nodes_and_noncanonical_framing() -> TestResult {
    let candidate = Candidate::new()?;
    let bytes = candidate.plan.encode()?;
    assert_eq!(&bytes[..7], b"MSRPLN\x01");
    assert_eq!(RecoveryReplacementPlan::decode(&bytes)?, candidate.plan);
    for end in 0..bytes.len() {
        assert!(RecoveryReplacementPlan::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(RecoveryReplacementPlan::decode(&trailing).is_err());
    assert!(RecoveryReplacementPlan::decode(&vec![0; 2 * 1024 * 1024 + 1]).is_err());
    let mut duplicate = candidate.plan.clone();
    duplicate
        .nodes
        .push(duplicate.nodes.first().ok_or("no node")?.clone());
    assert!(duplicate.encode().is_err());
    let mut invalid_key = candidate.plan.clone();
    invalid_key
        .nodes
        .first_mut()
        .ok_or("no node")?
        .identity_public_key = [0; 65];
    assert!(invalid_key.encode().is_err());
    let mut wrong_role = candidate.plan;
    wrong_role.nodes.first_mut().ok_or("no node")?.roles = JoinRoles::new(JoinRoles::GATEWAY)?;
    assert!(wrong_role.encode().is_err());
    Ok(())
}

impl Candidate {
    pub(super) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_fixture(Fixture::new()?)
    }

    pub(super) fn from_fixture(fixture: Fixture) -> Result<Self, Box<dyn std::error::Error>> {
        let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &fixture.directory.path().join("live.sqlite3"),
            UnixMicros::new(30),
        )?);
        let gateway = WrappingPrivateKey::from_bytes([81; 32])?;
        let mut random = crate::test_support::SequentialRandom(121);
        let control = source.prepare_recovery_control_keys(
            &fixture.authority,
            &[gateway.public_key()],
            &[],
            &mut random,
        )?;
        let claims = fixture.authorization.claims();
        let mut inventory = RecoverySecretInventoryBuilder::new(claims.recovery_id, &control)?;
        let mut retained = Vec::new();
        for context in source
            .secret_generation_contexts(None, PageLimit::new(128)?)?
            .items
        {
            let material = source.prepare_recovery_secret(
                &fixture.authority,
                context,
                &[gateway.public_key()],
                &mut random,
            )?;
            inventory.push(&material)?;
            retained.push(material);
        }
        let identity = NodeIdentityKey::generate()?;
        let node = RecoveryReplacementNode {
            node_id: NodeId::from_bytes([41; 16])?,
            host_id: HostId::from_bytes([42; 16])?,
            host_name: RecordName::new("Replacement host")?,
            node_name: RecordName::new("Replacement node")?,
            incarnation: 1,
            roles: JoinRoles::new(7)?,
            identity_public_key: identity.public_key_sec1().try_into()?,
            wrapping_public_key: gateway.public_key(),
            private_endpoint: "127.0.0.1:10000".to_owned(),
        };
        let plan = RecoveryReplacementPlan {
            mesh_id: claims.mesh_id,
            partition_id: claims.partition_id,
            recovery_id: claims.recovery_id,
            recovery_epoch: claims.recovery_epoch,
            secrets: inventory.finish()?,
            quorum: quorum(node.node_id, 2)?,
            nodes: vec![node],
        };
        let mut candidate = Self {
            fixture,
            plan,
            identity,
            control,
            retained,
        };
        candidate.sign()?;
        Ok(candidate)
    }

    pub(super) fn sign(&mut self) -> TestResult {
        self.fixture.authorization =
            self.fixture
                .authority
                .authorize_recovery(RecoveryAuthorizationClaims {
                    replacement_manifest_digest: self.plan.digest()?,
                    ..*self.fixture.authorization.claims()
                })?;
        Ok(())
    }

    pub(super) fn refresh_control_recipients(&mut self) -> TestResult {
        let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &self.fixture.directory.path().join("live.sqlite3"),
            UnixMicros::new(30),
        )?);
        let selected = |role| {
            self.plan
                .nodes
                .iter()
                .filter(|node| node.roles.bits() & role != 0)
                .map(|node| node.wrapping_public_key)
                .collect::<Vec<_>>()
        };
        let gateways = selected(JoinRoles::GATEWAY);
        let storage = selected(JoinRoles::STORAGE);
        let mut random = crate::test_support::SequentialRandom(131);
        self.control = source.prepare_recovery_control_keys(
            &self.fixture.authority,
            &gateways,
            &storage,
            &mut random,
        )?;
        let mut inventory =
            RecoverySecretInventoryBuilder::new(self.plan.recovery_id, &self.control)?;
        for material in &mut self.retained {
            *material = source.prepare_recovery_secret(
                &self.fixture.authority,
                material.secret.context,
                &gateways,
                &mut random,
            )?;
            inventory.push(material)?;
        }
        self.plan.secrets = inventory.finish()?;
        self.sign()
    }

    pub(super) fn restore_keys(
        &self,
        seal: bool,
    ) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
        self.fixture
            .prepare(&self.fixture.authorization, &self.fixture.authority)?;
        let mut repo = self.reopen()?;
        repo.stage_recovery_control_keys(
            &self.fixture.authority,
            &self.control,
            UnixMicros::new(31),
        )?;
        for material in &self.retained {
            repo.stage_recovery_secret(&self.fixture.authority, material, UnixMicros::new(32))?;
        }
        if seal {
            assert_eq!(
                repo.seal_recovery_secret_inventory(&self.fixture.authority, UnixMicros::new(33))?,
                self.plan.secrets
            );
        }
        Ok(repo)
    }

    pub(super) fn reopen(&self) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
        Ok(AuthoritativeRepository::new(
            PartitionDatabase::open_existing(
                &self.fixture.directory.path().join("prepared.sqlite3"),
                UnixMicros::new(30),
            )?,
        ))
    }
}

#[test]
fn replacement_plan_requires_a_new_incarnation_for_an_existing_node() -> TestResult {
    for incarnation in [1, 2] {
        let mut candidate = Candidate::new()?;
        let node = candidate.plan.nodes.first_mut().ok_or("no node")?;
        node.node_id = NodeId::from_bytes([8; 16])?;
        node.host_id = HostId::from_bytes([7; 16])?;
        node.node_name = RecordName::new("Node")?;
        node.host_name = RecordName::new("Host")?;
        node.incarnation = incarnation;
        candidate.plan.quorum = quorum(node.node_id, 2)?;
        candidate.sign()?;
        let mut repo = candidate.restore_keys(true)?;
        let result = repo.stage_recovery_replacement_plan(
            &candidate.fixture.authority,
            &candidate.plan,
            UnixMicros::new(40),
        );
        if incarnation == 1 {
            assert!(matches!(result, Err(RepositoryError::InvalidCommand)));
        } else {
            assert_eq!(result?, candidate.plan.digest()?);
        }
    }
    Ok(())
}

#[test]
fn planned_inventory_rejects_duplicates_without_poisoning_the_remaining_stream() -> TestResult {
    let candidate = Candidate::new()?;
    assert!(
        RecoverySecretInventoryBuilder::new(candidate.plan.recovery_id, &candidate.control)?
            .finish()
            .is_err()
    );
    let mut builder =
        RecoverySecretInventoryBuilder::new(candidate.plan.recovery_id, &candidate.control)?;
    let first = candidate.retained.first().ok_or("no retained secret")?;
    builder.push(first)?;
    assert!(matches!(
        builder.push(first),
        Err(RepositoryError::InvalidCommand)
    ));
    for material in candidate.retained.iter().skip(1) {
        builder.push(material)?;
    }
    assert_eq!(builder.finish()?, candidate.plan.secrets);
    let mut reversed =
        RecoverySecretInventoryBuilder::new(candidate.plan.recovery_id, &candidate.control)?;
    reversed.push(candidate.retained.last().ok_or("no retained secret")?)?;
    assert!(matches!(
        reversed.push(first),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

fn quorum(node: NodeId, epoch: u64) -> Result<ActiveQuorumPlan, Box<dyn std::error::Error>> {
    Ok(ActiveQuorumPlan::Stable(Box::new(compile_plan(
        flat_plan(
            QuorumPlanId::from_bytes([43; 16])?,
            epoch,
            BTreeSet::from([node]),
            BTreeSet::new(),
        )?,
    )?)))
}
