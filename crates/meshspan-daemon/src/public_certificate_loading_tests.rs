// SPDX-License-Identifier: GPL-2.0-only

use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{EntropyError, RandomSource, Revision};
use meshspan_metadata::{
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};

use crate::{
    LocalWrappingKey, PublicCertificateLoadingError, PublicCertificateLoadingService,
    SecretGenerationAuthority, SecretGenerationAuthorityError,
};

#[test]
fn encrypted_gateway_recipient_loads_exact_validated_tls_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let reference = reference(1);
    let (record, digest) = certificate_record(reference, local.public_key(), 17)?;
    let loaded = PublicCertificateLoadingService::new(FakeAuthority::record(record), local)
        .load(reference)?;

    assert_eq!(loaded.generation(), reference);
    assert_eq!(loaded.bundle_digest(), digest);
    assert_eq!(loaded.server_config().alpn_protocols, vec![b"http/1.1"]);
    Ok(())
}

#[test]
fn missing_recipient_malformed_bundle_and_wrong_key_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let reference = reference(2);
    let other = meshspan_secret_envelope::WrappingPrivateKey::from_bytes([9; 32])?.public_key();
    let (wrong_recipient, _) = certificate_record(reference, other, 31)?;
    assert_eq!(
        PublicCertificateLoadingService::new(FakeAuthority::record(wrong_recipient), &local)
            .load(reference)
            .err(),
        Some(PublicCertificateLoadingError::NotRecipient)
    );

    let malformed = encrypted_record(
        reference,
        b"not a certificate bundle",
        local.public_key(),
        41,
    )?;
    assert_eq!(
        PublicCertificateLoadingService::new(FakeAuthority::record(malformed), &local)
            .load(reference)
            .err(),
        Some(PublicCertificateLoadingError::Failed)
    );

    let authority = CertificateAuthority::new()?;
    let certificate = authority.issue_node("files.example.test")?;
    let other_key = authority.issue_node("other.example.test")?;
    let bundle = PublicCertificateBundle::new(
        vec![certificate.certificate_der().to_vec()],
        other_key.private_key().to_vec(),
    )?;
    let wrong_key = encrypted_record(reference, &bundle.encode()?, local.public_key(), 51)?;
    assert_eq!(
        PublicCertificateLoadingService::new(FakeAuthority::record(wrong_key), &local)
            .load(reference)
            .err(),
        Some(PublicCertificateLoadingError::Failed)
    );
    Ok(())
}

fn certificate_record(
    reference: SecretGenerationReference,
    recipient: WrappingPublicKey,
    seed: u8,
) -> Result<(SecretGenerationRecord, [u8; 32]), Box<dyn std::error::Error>> {
    let authority = CertificateAuthority::new()?;
    let issued = authority.issue_node("files.example.test")?;
    let bundle = PublicCertificateBundle::new(
        vec![issued.certificate_der().to_vec()],
        issued.private_key().to_vec(),
    )?;
    let digest = bundle.digest();
    Ok((
        encrypted_record(reference, &bundle.encode()?, recipient, seed)?,
        digest,
    ))
}

fn encrypted_record(
    reference: SecretGenerationReference,
    plaintext: &[u8],
    recipient: WrappingPublicKey,
    seed: u8,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let context = SecretContext::new(
        PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
        reference.secret_id,
        reference.generation,
    )?;
    let (secret, recipients) =
        encrypt_secret(context, plaintext, &[recipient], &mut FixedRandom(seed))?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

const fn reference(seed: u8) -> SecretGenerationReference {
    SecretGenerationReference {
        secret_id: [seed; 16],
        generation: 1,
    }
}

#[derive(Clone)]
struct FakeAuthority(Option<SecretGenerationRecord>);

impl FakeAuthority {
    fn record(record: SecretGenerationRecord) -> Self {
        Self(Some(record))
    }
}

impl SecretGenerationAuthority for FakeAuthority {
    fn secret_generation(
        &self,
        _context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok(self.0.clone())
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
