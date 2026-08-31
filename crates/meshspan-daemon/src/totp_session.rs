// SPDX-License-Identifier: GPL-2.0-only

//! Encrypted TOTP verification for fresh and exact-replay session factors.

use meshspan_domain::{AuthenticationMethodId, PrincipalId, UnixMicros};
use meshspan_metadata::TotpVerificationMaterial;
use meshspan_otp::{TotpAlgorithm, TotpProfile};

use crate::{
    TotpFactorVerifier, TotpSecretBinding, TotpSecretCipher, TotpSessionError, VerifiedTotpFactor,
};

/// TOTP factor verifier holding one current mesh-wide envelope-key generation.
pub struct TotpSessionVerifier {
    cipher: TotpSecretCipher,
}

impl TotpSessionVerifier {
    /// Composes verification over one current mesh-wide envelope key.
    #[must_use]
    pub const fn new(cipher: TotpSecretCipher) -> Self {
        Self { cipher }
    }
}

impl TotpFactorVerifier for TotpSessionVerifier {
    fn verify_current(
        &self,
        principal_id: PrincipalId,
        materials: &[TotpVerificationMaterial],
        code: &str,
        now: UnixMicros,
    ) -> Result<VerifiedTotpFactor, TotpSessionError> {
        let seconds =
            u64::try_from(now.get()).map_err(|_| TotpSessionError::InvalidTime)? / 1_000_000;
        let mut accepted = None;
        let mut previous = None;
        for material in materials {
            validate_material_order(principal_id, material, &mut previous)?;
            let (profile, secret) = self.open(material)?;
            if let Some(step) = profile
                .verify(&secret, code, seconds)
                .map_err(|_| TotpSessionError::Rejected)?
            {
                accepted.get_or_insert(VerifiedTotpFactor {
                    principal_id,
                    method_id: material.method_id,
                    credential_generation: material.credential_generation,
                    method_revision: material.revision,
                    accepted_step: step.step(),
                });
            }
        }
        accepted.ok_or(TotpSessionError::Rejected)
    }

    fn verify_replay(
        &self,
        principal_id: PrincipalId,
        materials: &[TotpVerificationMaterial],
        method_id: AuthenticationMethodId,
        code: &str,
        accepted_step: u64,
    ) -> Result<(), TotpSessionError> {
        let mut selected = None;
        let mut previous = None;
        for material in materials {
            validate_material_order(principal_id, material, &mut previous)?;
            if material.method_id == method_id {
                selected = Some(material);
            }
        }
        let material = selected.ok_or(TotpSessionError::Rejected)?;
        let (profile, secret) = self.open(material)?;
        if profile
            .verify_step(&secret, code, accepted_step)
            .map_err(|_| TotpSessionError::Rejected)?
        {
            Ok(())
        } else {
            Err(TotpSessionError::Rejected)
        }
    }
}

impl TotpSessionVerifier {
    fn open(
        &self,
        material: &TotpVerificationMaterial,
    ) -> Result<(TotpProfile, zeroize::Zeroizing<Vec<u8>>), TotpSessionError> {
        let profile = TotpProfile::new(
            algorithm(material.algorithm)?,
            material.digits,
            material.period_seconds,
            material.accepted_step_window,
        )
        .map_err(|_| TotpSessionError::InvalidEvidence)?;
        let secret = self
            .cipher
            .decrypt(binding(material), &material.secret_ciphertext)
            .map_err(|_| TotpSessionError::InvalidEvidence)?;
        Ok((profile, secret))
    }
}

fn validate_material_order(
    principal_id: PrincipalId,
    material: &TotpVerificationMaterial,
    previous: &mut Option<AuthenticationMethodId>,
) -> Result<(), TotpSessionError> {
    if material.principal_id != principal_id
        || material.credential_generation == 0
        || material.revision == meshspan_domain::Revision::ZERO
        || previous.is_some_and(|value| value >= material.method_id)
    {
        return Err(TotpSessionError::InvalidEvidence);
    }
    *previous = Some(material.method_id);
    Ok(())
}

const fn binding(material: &TotpVerificationMaterial) -> TotpSecretBinding {
    TotpSecretBinding {
        method_id: material.method_id,
        principal_id: material.principal_id,
        algorithm: material.algorithm,
        digits: material.digits,
        period_seconds: material.period_seconds,
        accepted_step_window: material.accepted_step_window,
    }
}

const fn algorithm(value: u8) -> Result<TotpAlgorithm, TotpSessionError> {
    match value {
        1 => Ok(TotpAlgorithm::Sha1),
        2 => Ok(TotpAlgorithm::Sha256),
        3 => Ok(TotpAlgorithm::Sha512),
        _ => Err(TotpSessionError::InvalidEvidence),
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{AuthenticationMethodId, PrincipalId, Revision, UnixMicros};
    use meshspan_metadata::TotpVerificationMaterial;

    use crate::passkey_test_support::CountingRandom;
    use crate::{
        TotpEnvelopeKey, TotpFactorVerifier, TotpSecretBinding, TotpSecretCipher, TotpSessionError,
        TotpSessionVerifier,
    };

    #[test]
    fn verifier_accepts_current_and_exact_expired_replay_without_exposing_seed()
    -> Result<(), Box<dyn std::error::Error>> {
        let principal_id = PrincipalId::from_bytes([1; 16])?;
        let method_id = AuthenticationMethodId::from_bytes([2; 16])?;
        let cipher = TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([7; 32])?);
        let binding = TotpSecretBinding {
            method_id,
            principal_id,
            algorithm: 1,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        };
        let ciphertext = cipher.encrypt(
            binding,
            b"12345678901234567890",
            &mut CountingRandom::default(),
        )?;
        let verifier = TotpSessionVerifier::new(cipher);
        let materials = [TotpVerificationMaterial {
            principal_id,
            method_id,
            credential_generation: 1,
            revision: Revision::new(2),
            secret_ciphertext: ciphertext,
            algorithm: 1,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        }];
        let accepted =
            verifier.verify_current(principal_id, &materials, "755224", UnixMicros::new(1))?;
        assert_eq!(accepted.accepted_step, 0);
        verifier.verify_replay(principal_id, &materials, method_id, "755224", 0)?;
        assert_eq!(
            verifier.verify_replay(principal_id, &materials, method_id, "287082", 0),
            Err(TotpSessionError::Rejected)
        );
        Ok(())
    }
}
