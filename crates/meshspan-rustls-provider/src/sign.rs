// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::sync::Arc;

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _};
use p256::pkcs8::DecodePrivateKey;
use rustls::pki_types::PrivateKeyDer;
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
    Ok(Arc::new(P256SigningKey {
        key: Arc::new(signing_key),
    }))
}

struct P256SigningKey {
    key: Arc<p256::ecdsa::SigningKey>,
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
