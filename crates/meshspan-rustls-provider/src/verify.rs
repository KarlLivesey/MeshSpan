// SPDX-License-Identifier: GPL-2.0-only

use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::der::Decode;
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[&P256_SHA256])],
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
