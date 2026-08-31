// SPDX-License-Identifier: GPL-2.0-only

//! Strict base64url transport decoding for one hostile `WebAuthn` assertion.

use crate::base64url;
use crate::{
    Assertion, MAXIMUM_AUTHENTICATOR_DATA_BYTES, MAXIMUM_CLIENT_DATA_BYTES,
    MAXIMUM_CREDENTIAL_ID_BYTES, MAXIMUM_SIGNATURE_BYTES, MAXIMUM_USER_HANDLE_BYTES, PasskeyError,
};

/// Owned decoded assertion fields, deliberately without `Debug` or `Display`.
pub struct OwnedAssertion {
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

impl OwnedAssertion {
    /// Decodes canonical unpadded base64url fields under the verification layer's byte ceilings.
    ///
    /// # Errors
    ///
    /// Rejects empty required fields, padding, invalid alphabet/tail bits and decoded excess.
    pub fn decode(
        credential_id: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
        user_handle: Option<&str>,
    ) -> Result<Self, PasskeyError> {
        Ok(Self {
            credential_id: base64url::decode(credential_id, MAXIMUM_CREDENTIAL_ID_BYTES)?,
            client_data_json: base64url::decode(client_data_json, MAXIMUM_CLIENT_DATA_BYTES)?,
            authenticator_data: base64url::decode(
                authenticator_data,
                MAXIMUM_AUTHENTICATOR_DATA_BYTES,
            )?,
            signature: base64url::decode(signature, MAXIMUM_SIGNATURE_BYTES)?,
            user_handle: user_handle
                .map(|value| base64url::decode(value, MAXIMUM_USER_HANDLE_BYTES))
                .transpose()?,
        })
    }

    /// Borrows the opaque credential identity for authoritative lookup.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Borrows all decoded fields for complete cryptographic verification.
    #[must_use]
    pub fn as_assertion(&self) -> Assertion<'_> {
        Assertion {
            credential_id: &self.credential_id,
            client_data_json: &self.client_data_json,
            authenticator_data: &self.authenticator_data,
            signature: &self.signature,
            user_handle: self.user_handle.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{OwnedAssertion, PasskeyErrorKind};

    #[test]
    fn transport_decodes_every_field_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let assertion = OwnedAssertion::decode("Y3JlZA", "e30", "AQID", "BAU", Some("dXNlcg"))?;
        let borrowed = assertion.as_assertion();
        assert_eq!(borrowed.credential_id, b"cred");
        assert_eq!(borrowed.client_data_json, b"{}");
        assert_eq!(borrowed.authenticator_data, [1, 2, 3]);
        assert_eq!(borrowed.signature, [4, 5]);
        assert_eq!(borrowed.user_handle, Some(b"user".as_slice()));
        Ok(())
    }

    #[test]
    fn malformed_or_excessive_transport_fails_closed() {
        for result in [
            OwnedAssertion::decode("=", "e30", "AQ", "AQ", None),
            OwnedAssertion::decode("Y3JlZA", "A", "AQ", "AQ", None),
            OwnedAssertion::decode("Y3JlZA", "e30", "AQ", "AQ==", None),
            OwnedAssertion::decode("Y3JlZA", "e30", "AQ", "AQ", Some("+w")),
        ] {
            assert_eq!(
                result.err().map(crate::PasskeyError::kind),
                Some(PasskeyErrorKind::Malformed)
            );
        }
    }
}
