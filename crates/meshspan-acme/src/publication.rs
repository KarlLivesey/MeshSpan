// SPDX-License-Identifier: GPL-2.0-only

//! Immutable public challenge material; worker claims and operation deadlines are not its identity.

use meshspan_contracts::{
    BoundedBytes, CertificateChallengeKind, CertificateChallengeRequest, ContractError,
    ContractVersion, RequestContext, VersionedPayload,
};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use serde::{Deserialize, Serialize};

use crate::{AcmeChallengePreference, Dns01Payload, Http01Payload};

/// Exact non-secret material retained before a challenge publisher may perform IO.
///
/// Contains only an HTTP key authorisation or DNS TXT value, never an account private key.
/// The enclosing authoritative checkpoint binds it to its order and current worker claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AcmeChallengePublication(PublicationFields);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationFields {
    kind: AcmeChallengePreference,
    identifier: String,
    payload_version: u32,
    payload: Vec<u8>,
    configuration_revision: u64,
    order_epoch: u64,
    expires_at: i64,
}

impl AcmeChallengePublication {
    /// Captures bounded exact inputs, without claiming that publication or visibility occurred.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, payloads, versions, revisions, epochs and expiry.
    pub fn capture(request: &CertificateChallengeRequest) -> Result<Self, ContractError> {
        crate::http01::validate_cleanup_request(request, request.kind)?;
        validate_payload(request)?;
        Ok(Self(PublicationFields {
            kind: match request.kind {
                CertificateChallengeKind::Http01 => AcmeChallengePreference::Http01,
                CertificateChallengeKind::Dns01 => AcmeChallengePreference::Dns01,
            },
            identifier: std::str::from_utf8(request.identifier.as_slice())
                .map_err(|_| ContractError::InvalidInput)?
                .to_owned(),
            payload_version: request.challenge.format_version,
            payload: request.challenge.bytes.as_slice().to_vec(),
            configuration_revision: request
                .context
                .expected_revision
                .ok_or(ContractError::InvalidInput)?
                .get(),
            order_epoch: request.order_epoch,
            expires_at: request.expires_at.get(),
        }))
    }

    /// Reconstructs original publication inputs under a separately authorised operation context.
    ///
    /// Neither the supplied deadline nor a worker replacement extends the original expiry.
    ///
    /// # Errors
    ///
    /// Rejects a changed provider revision, invalid context or malformed stored material.
    pub fn request(
        &self,
        context: RequestContext,
    ) -> Result<CertificateChallengeRequest, ContractError> {
        if context.expected_revision != Some(Revision::new(self.0.configuration_revision)) {
            return Err(ContractError::Stale);
        }
        let request = CertificateChallengeRequest {
            context,
            kind: match self.0.kind {
                AcmeChallengePreference::Http01 => CertificateChallengeKind::Http01,
                AcmeChallengePreference::Dns01 => CertificateChallengeKind::Dns01,
            },
            identifier: BoundedBytes::copy_from(self.0.identifier.as_bytes(), 253)
                .map_err(|_| ContractError::InvalidInput)?,
            challenge: VersionedPayload {
                format_version: self.0.payload_version,
                bytes: BoundedBytes::copy_from(&self.0.payload, 1_024)
                    .map_err(|_| ContractError::InvalidInput)?,
            },
            expires_at: self.expires_at(),
            order_epoch: self.order_epoch(),
        };
        crate::http01::validate_cleanup_request(&request, request.kind)?;
        validate_payload(&request)?;
        Ok(request)
    }

    /// Returns the original opaque publication epoch, not the current worker's fence.
    #[must_use]
    pub const fn order_epoch(&self) -> u64 {
        self.0.order_epoch
    }

    /// Returns the original exclusive publication expiry, including after it has elapsed.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMicros {
        UnixMicros::new(self.0.expires_at)
    }

    pub(crate) fn matches_challenge(
        &self,
        dns_name: &str,
        wildcard: bool,
        challenge: &crate::AcmeChallengeRecord,
    ) -> bool {
        let identifier = if wildcard {
            format!("*.{dns_name}")
        } else {
            dns_name.to_owned()
        };
        let kind_matches = matches!(
            (self.0.kind, challenge.kind.as_str()),
            (AcmeChallengePreference::Http01, "http-01")
                | (AcmeChallengePreference::Dns01, "dns-01")
        );
        if self.0.identifier != identifier || !kind_matches {
            return false;
        }
        if self.0.kind == AcmeChallengePreference::Http01 {
            let Ok(bytes) = BoundedBytes::copy_from(&self.0.payload, 1_024) else {
                return false;
            };
            return Http01Payload::decode(&VersionedPayload {
                format_version: self.0.payload_version,
                bytes,
            })
            .is_ok_and(|payload| payload.token() == challenge.token);
        }
        true
    }
}

impl<'de> Deserialize<'de> for AcmeChallengePublication {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let publication = Self(PublicationFields::deserialize(deserializer)?);
        // This context is only a local structural check; it never enters IO or authority.
        let operation_id = OperationId::from_bytes([1; 16]).map_err(serde::de::Error::custom)?;
        publication
            .request(RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id,
                deadline: UnixMicros::new(1),
                expected_revision: Some(Revision::new(publication.0.configuration_revision)),
            })
            .map_err(serde::de::Error::custom)?;
        Ok(publication)
    }
}

fn validate_payload(request: &CertificateChallengeRequest) -> Result<(), ContractError> {
    match request.kind {
        CertificateChallengeKind::Http01 => {
            Http01Payload::decode(&request.challenge).map_err(|_| ContractError::InvalidInput)?;
        }
        CertificateChallengeKind::Dns01 => {
            let payload = Dns01Payload::decode(&request.challenge)
                .map_err(|_| ContractError::InvalidInput)?;
            let identifier = std::str::from_utf8(request.identifier.as_slice())
                .map_err(|_| ContractError::InvalidInput)?;
            if payload.record_name()
                != format!(
                    "_acme-challenge.{}",
                    identifier.strip_prefix("*.").unwrap_or(identifier)
                )
            {
                return Err(ContractError::InvalidInput);
            }
        }
    }
    Ok(())
}
