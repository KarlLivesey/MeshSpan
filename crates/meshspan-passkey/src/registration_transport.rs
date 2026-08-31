// SPDX-License-Identifier: GPL-2.0-only

//! Strict base64url transport decoding for one hostile `WebAuthn` registration.

use crate::base64url;
use crate::{
    MAXIMUM_ATTESTATION_OBJECT_BYTES, MAXIMUM_CLIENT_DATA_BYTES, MAXIMUM_CREDENTIAL_ID_BYTES,
    PasskeyError, Registration,
};

/// Owned decoded registration fields, deliberately without `Debug` or `Display`.
pub struct OwnedRegistration {
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
}

impl OwnedRegistration {
    /// Decodes canonical unpadded base64url fields under the verification layer's byte ceilings.
    ///
    /// # Errors
    ///
    /// Rejects empty fields, padding, invalid alphabet/tail bits and decoded excess.
    pub fn decode(
        credential_id: &str,
        client_data_json: &str,
        attestation_object: &str,
    ) -> Result<Self, PasskeyError> {
        Ok(Self {
            credential_id: base64url::decode(credential_id, MAXIMUM_CREDENTIAL_ID_BYTES)?,
            client_data_json: base64url::decode(client_data_json, MAXIMUM_CLIENT_DATA_BYTES)?,
            attestation_object: base64url::decode(
                attestation_object,
                MAXIMUM_ATTESTATION_OBJECT_BYTES,
            )?,
        })
    }

    /// Borrows all decoded fields for complete registration verification.
    #[must_use]
    pub fn as_registration(&self) -> Registration<'_> {
        Registration {
            credential_id: &self.credential_id,
            client_data_json: &self.client_data_json,
            attestation_object: &self.attestation_object,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedRegistration;
    use crate::PasskeyErrorKind;

    #[test]
    fn transport_decodes_every_field_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let registration = OwnedRegistration::decode("Y3JlZA", "e30", "AQID")?;
        let borrowed = registration.as_registration();
        assert_eq!(borrowed.credential_id, b"cred");
        assert_eq!(borrowed.client_data_json, b"{}");
        assert_eq!(borrowed.attestation_object, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn malformed_or_excessive_transport_fails_closed() {
        for result in [
            OwnedRegistration::decode("=", "e30", "AQ"),
            OwnedRegistration::decode("Y3JlZA", "A", "AQ"),
            OwnedRegistration::decode("Y3JlZA", "e30", "AQ=="),
            OwnedRegistration::decode("Y3JlZA", "e30", "+w"),
        ] {
            assert_eq!(
                result.err().map(crate::PasskeyError::kind),
                Some(PasskeyErrorKind::Malformed)
            );
        }
    }
}
