// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::sync::Arc;

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey as _};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

pub(crate) fn load_private_key(key: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    let PrivateKeyDer::Pkcs8(pkcs8) = key else {
        return Err(Error::General(
            "MeshSpan identities require a PKCS#8 P-256 private key".into(),
        ));
    };
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8.secret_pkcs8_der())
        .map_err(|_| Error::General("invalid P-256 private key".into()))?;
    let public_key = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| Error::General("P-256 public key encoding failed".into()))?
        .as_bytes()
        .to_vec();
    Ok(Arc::new(P256SigningKey {
        key: Arc::new(signing_key),
        public_key,
    }))
}

struct P256SigningKey {
    key: Arc<p256::ecdsa::SigningKey>,
    public_key: Vec<u8>,
}

impl fmt::Debug for P256SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("P256SigningKey([redacted])")
    }
}

impl SigningKey for P256SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(P256Signer {
                    key: self.key.clone(),
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.public_key.as_slice()))
    }
}

#[derive(Debug)]
struct P256Signer {
    key: Arc<p256::ecdsa::SigningKey>,
}

impl Signer for P256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature: p256::ecdsa::DerSignature = self
            .key
            .try_sign(message)
            .map_err(|_| Error::General("P-256 signing failed".into()))?;
        Ok(signature.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}
