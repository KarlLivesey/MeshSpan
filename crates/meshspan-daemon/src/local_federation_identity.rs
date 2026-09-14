// SPDX-License-Identifier: GPL-2.0-only

//! One atomic, node-private federation signing/TLS identity retained across restarts.

use crate::{
    OperatingSystemRandom,
    protected_file::{self, ProtectedFileError, PublishMode},
};
use meshspan_certificates::{NodeIdentityKey, PublicCertificateBundle};
use meshspan_cluster::FederationSigningKey;
use meshspan_domain::{RandomSource, UnixMicros};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MSFI";
const HEADER: usize = 52;
const MAXIMUM_BYTES: usize = 64 * 1024;

pub(crate) struct LocalFederationIdentity {
    pub(crate) signing: FederationSigningKey,
    pub(crate) certificate: PublicCertificateBundle,
    pub(crate) valid_from: UnixMicros,
    pub(crate) valid_until: UnixMicros,
}

impl LocalFederationIdentity {
    pub(crate) fn open_or_create(
        destination: &Path,
        now: UnixMicros,
    ) -> Result<Self, LocalFederationIdentityError> {
        match protected_file::read_bounded(destination, HEADER + 1, MAXIMUM_BYTES) {
            Ok(bytes) => Self::decode(&bytes),
            Err(ProtectedFileError::Missing) => Self::create(destination, now),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn certified_key(&self) -> Result<Arc<CertifiedKey>, LocalFederationIdentityError> {
        Ok(Arc::new(
            CertifiedKey::from_der(
                self.certificate
                    .certificate_chain()
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivatePkcs8KeyDer::from(self.certificate.private_key_pkcs8().to_vec()).into(),
                &meshspan_rustls_provider::provider(),
            )
            .map_err(|_| LocalFederationIdentityError::Invalid)?,
        ))
    }

    fn create(destination: &Path, now: UnixMicros) -> Result<Self, LocalFederationIdentityError> {
        if now.get() < 0 {
            return Err(LocalFederationIdentityError::Invalid);
        }
        let valid_until = now
            .get()
            .checked_add(90 * 24 * 60 * 60 * 1_000_000)
            .ok_or(LocalFederationIdentityError::Invalid)?;
        let mut seed = Zeroizing::new([0; 32]);
        OperatingSystemRandom
            .fill_bytes(seed.as_mut())
            .map_err(|_| LocalFederationIdentityError::Entropy)?;
        let key = NodeIdentityKey::generate().map_err(|_| LocalFederationIdentityError::Invalid)?;
        let certificate = key
            .self_signed("meshspan-federation.local")
            .map_err(|_| LocalFederationIdentityError::Invalid)?;
        let bundle =
            PublicCertificateBundle::new(vec![certificate], key.private_key_pkcs8().to_vec())
                .map_err(|_| LocalFederationIdentityError::Invalid)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(seed.as_ref());
        bytes.extend_from_slice(&now.get().to_be_bytes());
        bytes.extend_from_slice(&valid_until.to_be_bytes());
        bytes.extend_from_slice(
            &bundle
                .encode()
                .map_err(|_| LocalFederationIdentityError::Invalid)?,
        );
        let identity = Self::decode(&bytes)?;
        protected_file::publish(destination, &bytes, PublishMode::Create)?;
        Ok(identity)
    }

    fn decode(bytes: &[u8]) -> Result<Self, LocalFederationIdentityError> {
        if bytes.len() <= HEADER || bytes.len() > MAXIMUM_BYTES || bytes.get(..4) != Some(MAGIC) {
            return Err(LocalFederationIdentityError::Invalid);
        }
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[4..36])
                .map_err(|_| LocalFederationIdentityError::Invalid)?,
        );
        let valid_from = i64::from_be_bytes(
            bytes[36..44]
                .try_into()
                .map_err(|_| LocalFederationIdentityError::Invalid)?,
        );
        let valid_until = i64::from_be_bytes(
            bytes[44..52]
                .try_into()
                .map_err(|_| LocalFederationIdentityError::Invalid)?,
        );
        if valid_from < 0 || valid_until <= valid_from {
            return Err(LocalFederationIdentityError::Invalid);
        }
        let identity = Self {
            signing: FederationSigningKey::from_seed(&seed),
            certificate: PublicCertificateBundle::decode(&bytes[HEADER..])
                .map_err(|_| LocalFederationIdentityError::Invalid)?,
            valid_from: UnixMicros::new(valid_from),
            valid_until: UnixMicros::new(valid_until),
        };
        identity.certified_key()?;
        Ok(identity)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalFederationIdentityError {
    #[error("protected federation identity file failed")]
    File(#[from] ProtectedFileError),
    #[error("federation identity entropy unavailable")]
    Entropy,
    #[error("federation identity is invalid")]
    Invalid,
}
