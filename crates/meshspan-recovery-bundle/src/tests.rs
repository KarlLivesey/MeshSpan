// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{EntropyError, MeshId, RandomSource};

use crate::{
    RecoveryBundle, RecoveryBundleCode, RecoveryBundleError, RecoveryChallenge,
    create_recovery_bundle,
};

#[test]
fn encoded_bundle_round_trips_and_restores_exact_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mesh_id = MeshId::from_bytes([7; 16])?;
    let (bundle, code, identity) = create_recovery_bundle(mesh_id, &mut SequentialRandom::new(11))?;
    let encoded = bundle.encode()?;
    let decoded = RecoveryBundle::decode(&encoded)?;
    let recovered = decoded.open(&code)?;

    assert_eq!(decoded, bundle);
    assert_eq!(decoded.mesh_id(), mesh_id);
    assert_eq!(identity.mesh_id(), mesh_id);
    assert_eq!(identity.bundle_digest(), decoded.digest());
    assert_eq!(
        identity.public_wrapping_key(),
        recovered.public_wrapping_key()
    );
    assert_eq!(
        identity.root_certificate_der(),
        recovered.root_certificate_der()
    );
    Ok(())
}

#[test]
fn code_and_challenge_use_exact_canonical_presentations() -> Result<(), Box<dyn std::error::Error>>
{
    let (bundle, code, _) =
        create_recovery_bundle(MeshId::from_bytes([9; 16])?, &mut SequentialRandom::new(21))?;
    let presented = code.expose_once();
    let parsed = RecoveryBundleCode::parse(&presented)?;
    assert!(bundle.open(&parsed).is_ok());
    assert!(RecoveryBundleCode::parse(&presented.to_uppercase()).is_err());

    let challenge = bundle.challenge(&parsed);
    let challenge_text = challenge.expose_for_verification();
    assert_eq!(RecoveryChallenge::parse(&challenge_text)?, challenge);
    assert_ne!(
        bundle.challenge(&RecoveryBundleCode::parse(
            "meshspan-offline-v1.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )?),
        challenge
    );
    Ok(())
}

#[test]
fn wrong_code_tampering_truncation_and_excess_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let (bundle, _, _) = create_recovery_bundle(
        MeshId::from_bytes([13; 16])?,
        &mut SequentialRandom::new(31),
    )?;
    let wrong = RecoveryBundleCode::parse(
        "meshspan-offline-v1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    assert!(matches!(
        bundle.open(&wrong),
        Err(RecoveryBundleError::Corrupt)
    ));

    let encoded = bundle.encode()?;
    for candidate in [
        encoded[..encoded.len() - 1].to_vec(),
        {
            let mut value = encoded.clone();
            value.push(0);
            value
        },
        {
            let mut value = encoded.clone();
            let index = value.len() / 2;
            value[index] ^= 1;
            value
        },
    ] {
        assert!(RecoveryBundle::decode(&candidate).is_err());
    }
    Ok(())
}

#[test]
fn reserved_entropy_and_oversized_input_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mesh_id = MeshId::from_bytes([17; 16])?;
    assert!(matches!(
        create_recovery_bundle(mesh_id, &mut ZeroRandom),
        Err(RecoveryBundleError::Entropy)
    ));
    assert!(RecoveryBundle::decode(&vec![0; 16 * 1_024 + 1]).is_err());
    Ok(())
}

struct SequentialRandom {
    next: u8,
}

impl SequentialRandom {
    const fn new(next: u8) -> Self {
        Self { next }
    }
}

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
            if self.next == 0 {
                self.next = 1;
            }
        }
        Ok(())
    }
}

struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(0);
        Ok(())
    }
}
