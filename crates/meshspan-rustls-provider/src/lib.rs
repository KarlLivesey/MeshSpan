// SPDX-License-Identifier: GPL-2.0-only

//! Narrow, portable RustCrypto-backed cryptography for `MeshSpan`'s Rustls profile.
//!
//! The initial profile deliberately supports only TLS 1.3, P-256 ECDHE and
//! ECDSA P-256 identities. It provides AES-128-GCM and ChaCha20-Poly1305 traffic
//! protection, including the QUIC algorithms required by RFC 9001.

use std::sync::Arc;

use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hmac;
mod kx;
mod quic;
mod sign;
mod verify;

/// TLS 1.3 ChaCha20-Poly1305 with SHA-256.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::SHA256),
        aead_alg: &aead::CHACHA20_POLY1305,
        quic: Some(&quic::CHACHA20_POLY1305),
    });

/// TLS 1.3 AES-128-GCM with SHA-256.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::SHA256),
        aead_alg: &aead::AES_128_GCM,
        quic: Some(&quic::AES_128_GCM),
    });

/// Returns the complete, deliberately narrow `MeshSpan` Rustls provider.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256],
        kx_groups: vec![&kx::SECP256R1],
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &PROVIDER,
        key_provider: &PROVIDER,
    }
}

#[derive(Debug)]
struct Provider;

static PROVIDER: Provider = Provider;

impl SecureRandom for Provider {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(output).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::load_private_key(&key)
    }
}

#[cfg(test)]
mod tests {
    use rustls::{CipherSuite, NamedGroup, SignatureScheme};

    use super::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256, provider};

    #[test]
    fn profile_contains_only_the_proven_algorithms() {
        let provider = provider();
        let suites = provider
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect::<Vec<_>>();

        assert_eq!(
            suites,
            [
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
            ]
        );
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::secp256r1);
        assert_eq!(provider.signature_verification_algorithms.all.len(), 1);
        assert_eq!(provider.signature_verification_algorithms.mapping.len(), 1);
        assert_eq!(
            provider.signature_verification_algorithms.mapping[0].0,
            SignatureScheme::ECDSA_NISTP256_SHA256
        );
        assert_eq!(
            provider.signature_verification_algorithms.mapping[0]
                .1
                .len(),
            1
        );
        assert!(TLS13_AES_128_GCM_SHA256.tls13().is_some());
        assert!(TLS13_CHACHA20_POLY1305_SHA256.tls13().is_some());
    }
}
