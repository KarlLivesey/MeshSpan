// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyBundle, EntropyError, MeshId, OperationId, PrincipalId, RandomSource, RecoveryCodeBundle,
    Revision, UnixMicros,
};
use meshspan_metadata::{AUTHENTICATION_ROOT_KEY_SECRET_KIND, SecretGenerationRecord};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};

use crate::{
    AuthenticationRootAuthority, AuthenticationRootLoadingError, AuthenticationRootLoadingService,
    LocalWrappingKey, ProtectedTotpFactorVerifier, ProtectedTotpRegistrationSecretProtector,
    SecretGenerationAuthority, SecretGenerationAuthorityError, TotpFactorVerifier,
    TotpRegistrationError, TotpRegistrationSecretProtector, TotpSecretBinding, TotpSecretCipher,
    TotpSessionError,
};

#[test]
fn exact_gateway_envelope_expands_stable_distinct_operational_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let mesh_id = MeshId::from_bytes([1; 16])?;
    let authority = FakeAuthority::record(generation_record(
        mesh_id,
        &[7; 32],
        &[local.public_key()],
        10,
    )?);
    let keys = AuthenticationRootLoadingService::new(authority.clone(), &local).load_latest()?;
    let (api_key, recovery_key, totp_key) = keys.into_parts();
    let principal_id = PrincipalId::from_bytes([2; 16])?;
    let operation_id = OperationId::from_bytes([3; 16])?;
    let issued = ApiKeyBundle::derive_issued(&api_key, principal_id, operation_id)?;
    let recovery = RecoveryCodeBundle::derive_issued(&recovery_key, principal_id, operation_id, 1)?;
    assert_ne!(issued.secret_digest(), recovery.secret_digest());

    let binding = TotpSecretBinding {
        method_id: meshspan_domain::AuthenticationMethodId::from_bytes([4; 16])?,
        principal_id,
        algorithm: 1,
        digits: 6,
        period_seconds: 30,
        accepted_step_window: 1,
    };
    let cipher = TotpSecretCipher::new(totp_key);
    let secret = b"12345678901234567890";
    let envelope = ProtectedTotpRegistrationSecretProtector::new(authority.clone(), &local)
        .protect_secret(binding, secret, &mut FixedRandom(20))?;
    assert_eq!(cipher.decrypt(binding, &envelope)?.as_slice(), secret);
    let materials = [meshspan_metadata::TotpVerificationMaterial {
        principal_id,
        method_id: binding.method_id,
        credential_generation: 1,
        revision: Revision::new(2),
        secret_ciphertext: envelope,
        algorithm: binding.algorithm,
        digits: binding.digits,
        period_seconds: binding.period_seconds,
        accepted_step_window: binding.accepted_step_window,
    }];
    let protected = ProtectedTotpFactorVerifier::new(authority, &local);
    assert_eq!(
        protected
            .verify_current(principal_id, &materials, "755224", UnixMicros::new(1))?
            .method_id,
        binding.method_id
    );
    Ok(())
}

#[test]
fn absent_wrong_duplicate_and_malformed_authority_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let mesh_id = MeshId::from_bytes([6; 16])?;
    assert_eq!(
        AuthenticationRootLoadingService::new(FakeAuthority::missing(), &local)
            .load_latest()
            .err(),
        Some(AuthenticationRootLoadingError::NotFound)
    );

    let other = WrappingPrivateKey::from_bytes([8; 32])?.public_key();
    let wrong = generation_record(mesh_id, &[9; 32], &[other], 30)?;
    assert_eq!(
        AuthenticationRootLoadingService::new(FakeAuthority::record(wrong), &local)
            .load_latest()
            .err(),
        Some(AuthenticationRootLoadingError::NotRecipient)
    );

    let mut duplicate = generation_record(mesh_id, &[10; 32], &[local.public_key()], 40)?;
    duplicate.recipients.push(duplicate.recipients[0].clone());
    assert_failed(&local, duplicate);
    assert_failed(
        &local,
        generation_record(mesh_id, &[11; 31], &[local.public_key()], 50)?,
    );
    let mut zero_revision = generation_record(mesh_id, &[12; 32], &[local.public_key()], 60)?;
    zero_revision.revision = Revision::ZERO;
    assert_failed(&local, zero_revision);
    assert_eq!(
        AuthenticationRootLoadingService::new(FakeAuthority::unavailable(), &local)
            .load_latest()
            .err(),
        Some(AuthenticationRootLoadingError::Unavailable)
    );
    assert_eq!(
        ProtectedTotpFactorVerifier::new(FakeAuthority::unavailable(), &local).verify_current(
            PrincipalId::from_bytes([13; 16])?,
            &[],
            "000000",
            UnixMicros::new(1),
        ),
        Err(TotpSessionError::Unavailable)
    );
    assert!(matches!(
        ProtectedTotpRegistrationSecretProtector::new(FakeAuthority::unavailable(), &local)
            .protect_secret(
                TotpSecretBinding {
                    method_id: meshspan_domain::AuthenticationMethodId::from_bytes([14; 16])?,
                    principal_id: PrincipalId::from_bytes([15; 16])?,
                    algorithm: 1,
                    digits: 6,
                    period_seconds: 30,
                    accepted_step_window: 1,
                },
                b"12345678901234567890",
                &mut FixedRandom(1),
            ),
        Err(TotpRegistrationError::Unavailable)
    ));
    Ok(())
}

fn assert_failed(local: &LocalWrappingKey, record: SecretGenerationRecord) {
    assert_eq!(
        AuthenticationRootLoadingService::new(FakeAuthority::record(record), local)
            .load_latest()
            .err(),
        Some(AuthenticationRootLoadingError::Failed)
    );
}

fn generation_record(
    mesh_id: MeshId,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random_seed: u8,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(AUTHENTICATION_ROOT_KEY_SECRET_KIND, mesh_id.as_bytes(), 1)?,
        plaintext,
        recipients,
        &mut FixedRandom(random_seed),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

#[derive(Clone)]
enum FakeAuthority {
    Record(SecretGenerationRecord),
    Missing,
    Unavailable,
}

impl FakeAuthority {
    fn record(record: SecretGenerationRecord) -> Self {
        Self::Record(record)
    }

    const fn missing() -> Self {
        Self::Missing
    }

    const fn unavailable() -> Self {
        Self::Unavailable
    }
}

impl AuthenticationRootAuthority for FakeAuthority {
    fn local_mesh_id(&self) -> Result<Option<MeshId>, SecretGenerationAuthorityError> {
        match self {
            Self::Record(record) => MeshId::from_bytes(record.secret.context().id())
                .map(Some)
                .map_err(|_| SecretGenerationAuthorityError::Failed),
            Self::Missing => Ok(None),
            Self::Unavailable => Err(SecretGenerationAuthorityError::Unavailable),
        }
    }

    fn latest_authentication_root_generation(
        &self,
        _mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        match self {
            Self::Record(record) => Ok(Some(record.secret.context().generation())),
            Self::Missing => Ok(None),
            Self::Unavailable => Err(SecretGenerationAuthorityError::Unavailable),
        }
    }
}

impl SecretGenerationAuthority for FakeAuthority {
    fn secret_generation(
        &self,
        _context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        match self {
            Self::Record(record) => Ok(Some(record.clone())),
            Self::Missing => Ok(None),
            Self::Unavailable => Err(SecretGenerationAuthorityError::Unavailable),
        }
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
