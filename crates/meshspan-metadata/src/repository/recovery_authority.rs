// SPDX-License-Identifier: GPL-2.0-only

//! Immutable offline recovery identity and explicit save-verification transition.

use meshspan_domain::{MeshId, PrincipalId, Revision, UnixMicros};
use meshspan_secret_envelope::WrappingPublicKey;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    BootstrapRecoveryIdentity, CommandContext, ConfirmRecoveryBundleSaved, PartitionDatabase,
};

const RECIPIENT_KIND_OFFLINE_RECOVERY: u8 = 2;
const RECIPIENT_STATE_CURRENT: u8 = 1;
const RECOVERY_STATE_PENDING: u8 = 1;
const RECOVERY_STATE_VERIFIED: u8 = 2;
const MAXIMUM_ROOT_CERTIFICATE_BYTES: usize = 8 * 1_024;

/// Current verified offline recipient required by recoverable secret provisioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedRecoveryRecipient {
    pub key_fingerprint: [u8; 32],
    pub public_key: WrappingPublicKey,
}

/// Authoritative lifecycle of the encrypted offline bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryBundleState {
    /// The public authority is committed, but durable off-appliance saving is unproved.
    Pending,
    /// An administrator proved possession of the challenge for the exact bundle.
    Verified,
}

/// Current public offline authority and bundle-delivery evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshRecoveryAuthority {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Validated offline public wrapping key.
    pub public_wrapping_key: WrappingPublicKey,
    /// Immutable offline root certificate.
    pub root_certificate_der: Vec<u8>,
    /// Exact encrypted-bundle digest.
    pub bundle_digest: [u8; 32],
    /// Save-verification state.
    pub state: RecoveryBundleState,
    /// Administrator who completed verification, when verified.
    pub verified_by: Option<PrincipalId>,
    /// Authoritative verification instant, when verified.
    pub verified_at: Option<UnixMicros>,
    /// Latest authority revision.
    pub revision: Revision,
}

pub(super) fn insert_bootstrap(
    transaction: &Transaction<'_>,
    context: CommandContext,
    mesh_id: MeshId,
    recovery: &BootstrapRecoveryIdentity,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let public_key = validate_identity(recovery)?;
    transaction.execute(
        "INSERT INTO secret_wrapping_recipients(
            key_fingerprint, recipient_kind, owner_id, generation, public_key, state,
            registered_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, NULL, ?7)",
        params![
            recovery.key_fingerprint.as_slice(),
            RECIPIENT_KIND_OFFLINE_RECOVERY,
            mesh_id.as_bytes().as_slice(),
            public_key.as_bytes().as_slice(),
            RECIPIENT_STATE_CURRENT,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO mesh_recovery_authorities(
            mesh_id, recovery_key_fingerprint, root_certificate_der,
            root_certificate_digest, bundle_digest, save_challenge_commitment, state,
            created_at, verified_by, verified_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9)",
        params![
            mesh_id.as_bytes().as_slice(),
            recovery.key_fingerprint.as_slice(),
            recovery.root_certificate_der,
            recovery.root_certificate_digest.as_slice(),
            recovery.bundle_digest.as_slice(),
            recovery.save_challenge_commitment.as_slice(),
            RECOVERY_STATE_PENDING,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

pub(super) fn confirm_saved(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfirmRecoveryBundleSaved,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let mesh_id = command.mesh_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE mesh_recovery_authorities
         SET state = ?1, verified_by = ?2, verified_at = ?3, revision = ?4
         WHERE mesh_id = ?5 AND bundle_digest = ?6 AND save_challenge_commitment = ?7
           AND state = ?8 AND verified_by IS NULL AND verified_at IS NULL",
        params![
            RECOVERY_STATE_VERIFIED,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            mesh_id.as_slice(),
            command.bundle_digest.as_slice(),
            command.save_challenge_commitment.as_slice(),
            RECOVERY_STATE_PENDING,
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::RecoveryAuthority,
        id: mesh_id,
    })
}

pub(super) fn current(
    database: &PartitionDatabase,
    mesh_id: MeshId,
) -> Result<Option<MeshRecoveryAuthority>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT recipient.public_key, authority.root_certificate_der,
                    authority.root_certificate_digest, authority.bundle_digest,
                    authority.state, authority.verified_by, authority.verified_at,
                    authority.revision
             FROM mesh_recovery_authorities AS authority
             JOIN secret_wrapping_recipients AS recipient
               ON recipient.key_fingerprint = authority.recovery_key_fingerprint
             WHERE authority.mesh_id = ?1",
            [mesh_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    stored.map_or(Ok(None), |stored| {
        decode_authority(mesh_id, stored).map(Some)
    })
}

pub(super) fn require_verified(transaction: &Transaction<'_>) -> Result<(), RepositoryError> {
    verified_recipient(transaction).map(|_| ())
}

pub(super) fn verified_recipient(
    transaction: &Transaction<'_>,
) -> Result<VerifiedRecoveryRecipient, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT authority.recovery_key_fingerprint, recipient.public_key,
                    (SELECT count(*) FROM mesh_recovery_authorities)
             FROM mesh_recovery_authorities AS authority
             JOIN secret_wrapping_recipients AS recipient
               ON recipient.key_fingerprint = authority.recovery_key_fingerprint
              AND recipient.recipient_kind = ?1
              AND recipient.owner_id = authority.mesh_id
              AND recipient.state = ?2
              AND recipient.retired_at IS NULL
             WHERE authority.state = ?3",
            params![
                RECIPIENT_KIND_OFFLINE_RECOVERY,
                RECIPIENT_STATE_CURRENT,
                RECOVERY_STATE_VERIFIED,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((fingerprint, public_key, authority_count)) = row else {
        return Err(RepositoryError::InvalidCommand);
    };
    if authority_count != 1 {
        return Err(RepositoryError::CorruptState);
    }
    let public_key = WrappingPublicKey::from_bytes(exact(public_key)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let key_fingerprint = exact(fingerprint)?;
    if public_key.fingerprint() != key_fingerprint {
        return Err(RepositoryError::CorruptState);
    }
    Ok(VerifiedRecoveryRecipient {
        key_fingerprint,
        public_key,
    })
}

type StoredAuthority = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
);

fn decode_authority(
    mesh_id: MeshId,
    stored: StoredAuthority,
) -> Result<MeshRecoveryAuthority, RepositoryError> {
    let (public_key, certificate, certificate_digest, bundle_digest, state, actor, at, revision) =
        stored;
    if certificate.is_empty()
        || certificate.len() > MAXIMUM_ROOT_CERTIFICATE_BYTES
        || Sha256::digest(&certificate).as_slice() != certificate_digest
    {
        return Err(RepositoryError::CorruptState);
    }
    let public_wrapping_key = WrappingPublicKey::from_bytes(exact(public_key)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let state = match state {
        value if value == i64::from(RECOVERY_STATE_PENDING) && actor.is_none() && at.is_none() => {
            RecoveryBundleState::Pending
        }
        value if value == i64::from(RECOVERY_STATE_VERIFIED) && actor.is_some() && at.is_some() => {
            RecoveryBundleState::Verified
        }
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(MeshRecoveryAuthority {
        mesh_id,
        public_wrapping_key,
        root_certificate_der: certificate,
        bundle_digest: exact(bundle_digest)?,
        state,
        verified_by: decode_optional_principal(actor)?,
        verified_at: at.map(UnixMicros::new),
        revision: Revision::new(
            u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    })
}

fn validate_identity(
    recovery: &BootstrapRecoveryIdentity,
) -> Result<WrappingPublicKey, RepositoryError> {
    let public_key = WrappingPublicKey::from_bytes(recovery.public_wrapping_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let valid_certificate = (1..=MAXIMUM_ROOT_CERTIFICATE_BYTES)
        .contains(&recovery.root_certificate_der.len())
        && Sha256::digest(&recovery.root_certificate_der).as_slice()
            == recovery.root_certificate_digest;
    if public_key.fingerprint() != recovery.key_fingerprint
        || !valid_certificate
        || recovery.bundle_digest == [0; 32]
        || recovery.save_challenge_commitment == [0; 32]
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(public_key)
    }
}

fn exact<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn decode_optional_principal(
    value: Option<Vec<u8>>,
) -> Result<Option<PrincipalId>, RepositoryError> {
    value
        .map(|bytes| {
            PrincipalId::from_bytes(exact(bytes)?).map_err(|_| RepositoryError::CorruptState)
        })
        .transpose()
}
