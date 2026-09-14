// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{NodeId, UnixMicros};
use meshspan_secret_envelope::{SecretEnvelopeError, SecretPlaintext, WrappingPrivateKey};
use sha2::{Digest as _, Sha256};
use std::io::Cursor;

use super::{TestResult, plan::Candidate};
use crate::{
    RecoveryKeyBundleError, RecoveryKeyBundleVerification, RecoveryKeyRecipient,
    verify_recovery_key_bundle,
};

#[test]
fn state_delivery_must_match_the_verified_key_recipient_and_plan() -> TestResult {
    let fixture = Transfer::new()?;
    let verified = fixture.verify(&fixture.bytes, &fixture.key)?;
    let authority = &fixture.candidate.fixture.authority;
    let claims = meshspan_recovery_bundle::RecoveryStateTransferClaims {
        authorization: fixture
            .candidate
            .reopen()?
            .recovery_preparation_authorization(authority)?,
        node_id: fixture.recipient.node_id,
        incarnation: fixture
            .candidate
            .plan
            .nodes
            .first()
            .ok_or("missing node")?
            .incarnation,
        state_digest: [21; 32],
        state_length: 4096,
        key_bundle_digest: verified.bundle_digest(),
        key_bundle_length: u64::try_from(fixture.bytes.len())?,
    };
    assert!(verified.matches_state_transfer(&authority.authorize_state_transfer(claims.clone())?));
    let mut other_node = claims.clone();
    other_node.node_id = NodeId::from_bytes([99; 16])?;
    let mut other_incarnation = claims.clone();
    other_incarnation.incarnation += 1;
    let mut other_bundle = claims;
    other_bundle.key_bundle_digest = [22; 32];
    for changed in [other_node, other_incarnation, other_bundle] {
        assert!(!verified.matches_state_transfer(&authority.authorize_state_transfer(changed)?));
    }
    Ok(())
}

#[test]
fn encrypted_recovery_key_export_requires_fence_and_selected_node() -> TestResult {
    let candidate = Candidate::new()?;
    let mut repo = candidate.restore_keys(true)?;
    let node = candidate.plan.nodes.first().ok_or("missing node")?;
    let mut bytes = Vec::new();
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    assert!(matches!(
        repo.export_recovery_key_bundle(&candidate.fixture.authority, node.node_id, &mut bytes),
        Err(RecoveryKeyBundleError::Authority)
    ));
    assert!(bytes.is_empty());
    repo.fence_recovery_credentials(&candidate.fixture.authority, recovery_time(50))?;
    assert!(
        repo.export_recovery_key_bundle(
            &candidate.fixture.authority,
            NodeId::from_bytes([99; 16])?,
            &mut bytes
        )
        .is_err()
    );
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn recovery_key_export_replays_exact_bytes_and_opens_with_only_the_node_key() -> TestResult {
    let fixture = Transfer::new()?;
    let verified = fixture.verify(&fixture.bytes, &fixture.key)?;
    assert_eq!(verified.verified_generations(), 5);
    assert_eq!(verified.node_certificate().generation(), 1);
    assert_eq!(verified.node_certificate().not_before(), 1_800_000_000);
    assert_eq!(
        verified.node_certificate().not_after(),
        1_800_000_000 + 30 * 86_400
    );
    verified
        .node_certificate()
        .validate(&fixture.recipient.identity_public_key)?;
    assert_eq!(
        verified.bundle_digest(),
        <[u8; 32]>::from(Sha256::digest(&fixture.bytes))
    );
    let mut replay = Vec::new();
    fixture.candidate.reopen()?.export_recovery_key_bundle(
        &fixture.candidate.fixture.authority,
        fixture.recipient.node_id,
        &mut replay,
    )?;
    assert_eq!(replay, fixture.bytes);
    Ok(())
}

#[test]
fn recovery_key_transfer_rejects_substituted_certificate_material() -> TestResult {
    let fixture = Transfer::new()?;
    let mut cursor = Cursor::new(fixture.bytes.as_slice());
    cursor.set_position(23);
    for _ in 0..3 {
        crate::recovery_key_bundle::read_frame(&mut cursor, 2 * 1024 * 1024)?;
    }
    let start = usize::try_from(cursor.position())?;
    // Generation, start, end, leaf framing and the signed leaf are all independently checked.
    for offset in [start + 7, start + 15, start + 23, start + 24, start + 30] {
        let mut changed = fixture.bytes.clone();
        *changed.get_mut(offset).ok_or("missing certificate")? ^= 1;
        assert!(fixture.verify(&changed, &fixture.key).is_err());
    }
    for version in [1, 2] {
        let mut legacy = fixture.bytes.clone();
        *legacy.get_mut(6).ok_or("missing version")? = version;
        assert!(fixture.verify(&legacy, &fixture.key).is_err());
    }
    Ok(())
}

#[test]
fn storage_only_recovery_node_installs_certificate_without_decrypting_gateway_keys() -> TestResult {
    let mut candidate = Candidate::new()?;
    let (identity, wrapping, recipient) = add_storage_node(&mut candidate)?;
    candidate.refresh_control_recipients()?;
    let mut repo = candidate.restore_keys(true)?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, recovery_time(50))?;
    let mut bytes = Vec::new();
    repo.export_recovery_key_bundle(&candidate.fixture.authority, recipient.node_id, &mut bytes)?;
    let mut opened = 0;
    let verified = verify_recovery_key_bundle(
        &mut Cursor::new(&bytes),
        candidate.fixture.authority.root_certificate_der(),
        recipient,
        |secret, envelope| -> Result<SecretPlaintext, SecretEnvelopeError> {
            assert_eq!(
                secret.context().kind(),
                crate::STORAGE_PERMIT_KEY_SECRET_KIND
            );
            assert_eq!(secret.context().generation(), 2);
            opened += 1;
            secret.decrypt(&envelope.open(&wrapping)?)
        },
    )?;
    assert_eq!(opened, 1);
    assert_eq!(verified.verified_generations(), 1);
    assert_eq!(verified.node_certificate().generation(), 1);
    verified
        .node_certificate()
        .validate(&recipient.identity_public_key)?;
    let signature = identity.sign_enrolment_transcript(&verified.installation_message())?;
    repo.record_recovery_key_installation(
        &candidate.fixture.authority,
        recipient.node_id,
        &signature,
        recovery_time(60),
    )?;
    assert!(
        repo.recovery_key_installation(&candidate.fixture.authority, recipient.node_id)?
            .is_some()
    );
    assert!(
        repo.recovery_key_installation(
            &candidate.fixture.authority,
            candidate.plan.nodes[0].node_id
        )?
        .is_none()
    );
    Ok(())
}

#[test]
fn recovery_key_selection_rejects_missing_or_excess_role_authority() -> TestResult {
    use crate::JoinRoles;
    for (prepared_roles, selected_roles) in [
        (JoinRoles::GATEWAY, JoinRoles::STORAGE),
        (JoinRoles::STORAGE, JoinRoles::METADATA_ELIGIBLE),
        (JoinRoles::METADATA_ELIGIBLE, JoinRoles::STORAGE),
    ] {
        let mut candidate = Candidate::new()?;
        add_storage_node(&mut candidate)?;
        candidate.plan.nodes.last_mut().ok_or("node missing")?.roles =
            JoinRoles::new(prepared_roles)?;
        candidate.refresh_control_recipients()?;
        candidate.plan.nodes.last_mut().ok_or("node missing")?.roles =
            JoinRoles::new(selected_roles)?;
        candidate.sign()?;
        let mut repo = candidate.restore_keys(true)?;
        assert!(
            repo.stage_recovery_replacement_plan(
                &candidate.fixture.authority,
                &candidate.plan,
                UnixMicros::new(40)
            )
            .is_err()
        );
        assert!(
            repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn metadata_only_recovery_node_receives_no_operational_or_content_keys() -> TestResult {
    let mut candidate = Candidate::new()?;
    let (_, _, recipient) = add_storage_node(&mut candidate)?;
    candidate.plan.nodes.last_mut().ok_or("node missing")?.roles =
        crate::JoinRoles::new(crate::JoinRoles::METADATA_ELIGIBLE)?;
    candidate.sign()?;
    let mut repo = candidate.restore_keys(true)?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, recovery_time(50))?;
    let mut bytes = Vec::new();
    repo.export_recovery_key_bundle(&candidate.fixture.authority, recipient.node_id, &mut bytes)?;
    let verified = verify_recovery_key_bundle(
        &mut Cursor::new(&bytes),
        candidate.fixture.authority.root_certificate_der(),
        recipient,
        |_, _| -> Result<SecretPlaintext, &str> { Err("metadata role has no secret authority") },
    )?;
    assert_eq!(verified.verified_generations(), 0);
    Ok(())
}

fn add_storage_node(
    candidate: &mut Candidate,
) -> Result<
    (
        meshspan_certificates::NodeIdentityKey,
        WrappingPrivateKey,
        RecoveryKeyRecipient,
    ),
    Box<dyn std::error::Error>,
> {
    let identity = meshspan_certificates::NodeIdentityKey::generate()?;
    let wrapping = WrappingPrivateKey::from_bytes([82; 32])?;
    let mut storage = candidate
        .plan
        .nodes
        .first()
        .ok_or("missing gateway")?
        .clone();
    storage.node_id = NodeId::from_bytes([44; 16])?;
    storage.host_id = meshspan_domain::HostId::from_bytes([45; 16])?;
    storage.node_name = crate::RecordName::new("Storage replacement")?;
    storage.host_name = crate::RecordName::new("Storage host")?;
    storage.roles = crate::JoinRoles::new(crate::JoinRoles::STORAGE)?;
    storage.identity_public_key = identity.public_key_sec1().try_into()?;
    storage.wrapping_public_key = wrapping.public_key();
    storage.private_endpoint = "127.0.0.1:10001".to_owned();
    let recipient = RecoveryKeyRecipient {
        node_id: storage.node_id,
        identity_public_key: storage.identity_public_key,
        wrapping_public_key: storage.wrapping_public_key,
    };
    candidate.plan.nodes.push(storage);
    Ok((identity, wrapping, recipient))
}

#[test]
fn recovery_key_recipient_rejects_wrong_key_and_malformed_frames() -> TestResult {
    let fixture = Transfer::new()?;
    let wrong = WrappingPrivateKey::from_bytes([82; 32])?;
    assert!(matches!(
        fixture.verify(&fixture.bytes, &wrong),
        Err(RecoveryKeyBundleError::Decryption)
    ));
    for end in [0, 6, 22, 26, fixture.bytes.len() - 1] {
        assert!(fixture.verify(&fixture.bytes[..end], &fixture.key).is_err());
    }
    let mut changed = fixture.bytes.clone();
    changed.push(0);
    assert!(fixture.verify(&changed, &fixture.key).is_err());
    let mut excessive = fixture.bytes.clone();
    excessive
        .get_mut(23..27)
        .ok_or("header missing")?
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(fixture.verify(&excessive, &fixture.key).is_err());
    Ok(())
}

pub(super) struct Transfer {
    pub(super) candidate: Candidate,
    pub(super) bytes: Vec<u8>,
    pub(super) key: WrappingPrivateKey,
    pub(super) recipient: RecoveryKeyRecipient,
}

impl Transfer {
    pub(super) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let candidate = Candidate::new()?;
        let mut repo = candidate.restore_keys(true)?;
        repo.stage_recovery_replacement_plan(
            &candidate.fixture.authority,
            &candidate.plan,
            UnixMicros::new(40),
        )?;
        repo.fence_recovery_credentials(&candidate.fixture.authority, recovery_time(50))?;
        let node = candidate.plan.nodes.first().ok_or("missing node")?;
        let mut bytes = Vec::new();
        repo.export_recovery_key_bundle(&candidate.fixture.authority, node.node_id, &mut bytes)?;
        let key = WrappingPrivateKey::from_bytes([81; 32])?;
        let recipient = RecoveryKeyRecipient {
            node_id: node.node_id,
            identity_public_key: node.identity_public_key,
            wrapping_public_key: key.public_key(),
        };
        Ok(Self {
            candidate,
            bytes,
            key,
            recipient,
        })
    }

    pub(super) fn verify(
        &self,
        bytes: &[u8],
        key: &WrappingPrivateKey,
    ) -> Result<RecoveryKeyBundleVerification, RecoveryKeyBundleError> {
        verify_recovery_key_bundle(
            &mut Cursor::new(bytes),
            self.candidate.fixture.authority.root_certificate_der(),
            self.recipient,
            |secret, envelope| -> Result<SecretPlaintext, SecretEnvelopeError> {
                secret.decrypt(&envelope.open(key)?)
            },
        )
    }
}

// Keep recovery certificate intervals inside the test CA's validity (1975 onwards).
pub(super) const fn recovery_time(offset: i64) -> UnixMicros {
    UnixMicros::new(1_800_000_000_000_000 + offset)
}
