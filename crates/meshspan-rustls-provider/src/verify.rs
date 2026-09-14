// SPDX-License-Identifier: GPL-2.0-only

use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::der::Decode;
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub(crate) static INTERNAL_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[&P256_SHA256])],
};

pub(crate) static EXTERNAL_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&P256_SHA256, &P384_SHA384],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[&P384_SHA384]),
    ],
};

#[derive(Debug)]
struct P256Sha256Verifier;

static P256_SHA256: P256Sha256Verifier = P256Sha256Verifier;

impl SignatureVerificationAlgorithm for P256Sha256Verifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let signature =
            p256::ecdsa::DerSignature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

#[derive(Debug)]
struct P384Sha384Verifier;

static P384_SHA384: P384Sha384Verifier = P384Sha384Verifier;

impl SignatureVerificationAlgorithm for P384Sha384Verifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key =
            p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let signature =
            p384::ecdsa::DerSignature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}
