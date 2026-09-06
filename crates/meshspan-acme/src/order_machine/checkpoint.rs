// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    AcmeAuthorization, AcmeChallengePreference, AcmeChallengeRecord, AcmeDirectory,
    AcmeMachineError, AcmeOrder, AcmeOrderMachine, AcmeOrderRequest, AcmeResourceStatus, Phase,
    select_challenge, validate_nonce,
};

const CHECKPOINT_VERSION: u8 = 2;
pub(super) const MAXIMUM_CHECKPOINT_BYTES: usize = 8 * 1_024 * 1_024;

#[derive(Serialize)]
struct CheckpointReference<'a> {
    version: u8,
    machine: &'a AcmeOrderMachine,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    machine: MachineFields,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineFields {
    directory_url: String,
    request: AcmeOrderRequest,
    preference: AcmeChallengePreference,
    order_epoch: u64,
    phase: Phase,
    directory: Option<AcmeDirectory>,
    nonce: Option<String>,
    account_url: Option<String>,
    order_url: Option<String>,
    order: Option<AcmeOrder>,
    authorization_index: usize,
    authorized_names: Vec<String>,
    authorization: Option<AcmeAuthorization>,
    challenge: Option<AcmeChallengeRecord>,
    publication_digest: Option<[u8; 32]>,
    certificate: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "present_poll_deadline")]
    poll_not_before: PollDeadlineField,
}

// Distinguish the absent v1 field from the explicitly nullable v2 field.
#[derive(Default)]
enum PollDeadlineField {
    #[default]
    Absent,
    Present(Option<i64>),
}

fn present_poll_deadline<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<PollDeadlineField, D::Error> {
    Option::<i64>::deserialize(deserializer).map(PollDeadlineField::Present)
}

const DIRECTORY_PRESENT: u16 = 1 << 0;
const NONCE_PRESENT: u16 = 1 << 1;
const ACCOUNT_PRESENT: u16 = 1 << 2;
const ORDER_URL_PRESENT: u16 = 1 << 3;
const ORDER_PRESENT: u16 = 1 << 4;
const AUTHORIZATION_PRESENT: u16 = 1 << 5;
const CHALLENGE_PRESENT: u16 = 1 << 6;
const PUBLICATION_PRESENT: u16 = 1 << 7;
const CERTIFICATE_PRESENT: u16 = 1 << 8;
const ORDERED_STATE: u16 =
    DIRECTORY_PRESENT | NONCE_PRESENT | ACCOUNT_PRESENT | ORDER_URL_PRESENT | ORDER_PRESENT;

impl AcmeOrderMachine {
    pub(super) fn encode_validated_checkpoint(&self) -> Result<Vec<u8>, AcmeMachineError> {
        self.validate_checkpoint()
            .map_err(closed_checkpoint_error)?;
        let encoded = serde_json::to_vec(&CheckpointReference {
            version: CHECKPOINT_VERSION,
            machine: self,
        })
        .map_err(|_| AcmeMachineError::CorruptState)?;
        if encoded.len() > MAXIMUM_CHECKPOINT_BYTES {
            return Err(AcmeMachineError::CorruptState);
        }
        Ok(encoded)
    }

    pub(super) fn decode_validated_checkpoint(bytes: &[u8]) -> Result<Self, AcmeMachineError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CHECKPOINT_BYTES {
            return Err(AcmeMachineError::CorruptState);
        }
        let checkpoint: Checkpoint =
            serde_json::from_slice(bytes).map_err(|_| AcmeMachineError::CorruptState)?;
        if !matches!(
            (checkpoint.version, &checkpoint.machine.poll_not_before),
            (1, PollDeadlineField::Absent) | (CHECKPOINT_VERSION, PollDeadlineField::Present(_))
        ) {
            return Err(AcmeMachineError::CorruptState);
        }
        let machine = checkpoint.machine.into_machine();
        machine
            .validate_checkpoint()
            .map_err(closed_checkpoint_error)?;
        Ok(machine)
    }

    fn validate_checkpoint(&self) -> Result<(), AcmeMachineError> {
        crate::wire::bounded_url(&self.directory_url)?;
        validate_request(&self.request)?;
        if self.order_epoch == 0 || self.authorized_names.len() != self.authorization_index {
            return Err(AcmeMachineError::CorruptState);
        }
        validate_presence(self)?;
        self.validate_optional_resources()?;
        self.validate_progress()?;
        self.validate_poll_schedule()?;
        self.action_for_phase().map(|_| ())
    }

    fn validate_optional_resources(&self) -> Result<(), AcmeMachineError> {
        if let Some(directory) = &self.directory {
            for url in [
                &directory.new_nonce,
                &directory.new_account,
                &directory.new_order,
            ] {
                crate::wire::bounded_url(url)?;
            }
        }
        if let Some(nonce) = &self.nonce {
            validate_nonce(nonce)?;
        }
        for url in [&self.account_url, &self.order_url].into_iter().flatten() {
            crate::wire::bounded_url(url)?;
        }
        if let Some(order) = &self.order {
            self.validate_order(order)?;
            validate_order_urls(order)?;
        }
        if let Some(authorization) = &self.authorization {
            self.validate_current_authorization(authorization)?;
            validate_authorization(authorization)?;
            let expected_status = match self.phase {
                Phase::CleanupChallenge => AcmeResourceStatus::Valid,
                Phase::PublishChallenge | Phase::NotifyChallenge | Phase::PollAuthorization => {
                    AcmeResourceStatus::Pending
                }
                _ => return Err(AcmeMachineError::CorruptState),
            };
            if authorization.status != expected_status {
                return Err(AcmeMachineError::CorruptState);
            }
        }
        if let Some(challenge) = &self.challenge {
            let authorization = self
                .authorization
                .as_ref()
                .ok_or(AcmeMachineError::CorruptState)?;
            if select_challenge(authorization, self.preference)? != *challenge {
                return Err(AcmeMachineError::CorruptState);
            }
        }
        if self.publication_digest == Some([0; 32])
            || self.certificate.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > crate::wire::MAXIMUM_BODY_BYTES
            })
        {
            return Err(AcmeMachineError::CorruptState);
        }
        Ok(())
    }

    fn validate_progress(&self) -> Result<(), AcmeMachineError> {
        let unique = self.authorized_names.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.authorized_names.len()
            || self
                .authorized_names
                .iter()
                .any(|name| !self.request.dns_names().contains(name))
        {
            return Err(AcmeMachineError::CorruptState);
        }
        let Some(order) = &self.order else {
            return (self.authorization_index == 0 && self.authorized_names.is_empty())
                .then_some(())
                .ok_or(AcmeMachineError::CorruptState);
        };
        if self.authorization_index > order.authorizations.len() {
            return Err(AcmeMachineError::CorruptState);
        }
        let valid_status = match self.phase {
            Phase::FetchAuthorization
            | Phase::PublishChallenge
            | Phase::NotifyChallenge
            | Phase::PollAuthorization
            | Phase::CleanupChallenge => order.status == AcmeResourceStatus::Pending,
            Phase::FinalizeOrder => order.status == AcmeResourceStatus::Ready,
            Phase::PollOrder => matches!(
                order.status,
                AcmeResourceStatus::Pending | AcmeResourceStatus::Processing
            ),
            Phase::DownloadCertificate | Phase::Complete => {
                order.status == AcmeResourceStatus::Valid && order.certificate.is_some()
            }
            Phase::DiscoverDirectory
            | Phase::AcquireNonce
            | Phase::CreateAccount
            | Phase::CreateOrder => false,
        };
        if !valid_status
            || matches!(
                self.phase,
                Phase::FetchAuthorization
                    | Phase::PublishChallenge
                    | Phase::NotifyChallenge
                    | Phase::PollAuthorization
                    | Phase::CleanupChallenge
            ) && self.authorization_index >= order.authorizations.len()
        {
            return Err(AcmeMachineError::CorruptState);
        }
        Ok(())
    }
}

impl MachineFields {
    fn into_machine(self) -> AcmeOrderMachine {
        AcmeOrderMachine {
            directory_url: self.directory_url,
            request: self.request,
            preference: self.preference,
            order_epoch: self.order_epoch,
            phase: self.phase,
            directory: self.directory,
            nonce: self.nonce,
            account_url: self.account_url,
            order_url: self.order_url,
            order: self.order,
            authorization_index: self.authorization_index,
            authorized_names: self.authorized_names,
            authorization: self.authorization,
            challenge: self.challenge,
            publication_digest: self.publication_digest,
            certificate: self.certificate,
            poll_not_before: match self.poll_not_before {
                PollDeadlineField::Absent => None,
                PollDeadlineField::Present(value) => value,
            },
        }
    }
}

fn validate_request(request: &AcmeOrderRequest) -> Result<(), AcmeMachineError> {
    AcmeOrderRequest::new(request.dns_names().to_vec())
        .map(|_| ())
        .map_err(AcmeMachineError::from)
}

fn validate_presence(machine: &AcmeOrderMachine) -> Result<(), AcmeMachineError> {
    let actual = presence(machine);
    let expected = match machine.phase {
        Phase::DiscoverDirectory => 0,
        Phase::AcquireNonce => DIRECTORY_PRESENT,
        Phase::CreateAccount => DIRECTORY_PRESENT | NONCE_PRESENT,
        Phase::CreateOrder => DIRECTORY_PRESENT | NONCE_PRESENT | ACCOUNT_PRESENT,
        Phase::FetchAuthorization
        | Phase::FinalizeOrder
        | Phase::PollOrder
        | Phase::DownloadCertificate => ORDERED_STATE,
        Phase::PublishChallenge => ORDERED_STATE | AUTHORIZATION_PRESENT | CHALLENGE_PRESENT,
        Phase::NotifyChallenge | Phase::PollAuthorization | Phase::CleanupChallenge => {
            ORDERED_STATE | AUTHORIZATION_PRESENT | CHALLENGE_PRESENT | PUBLICATION_PRESENT
        }
        Phase::Complete => ORDERED_STATE | CERTIFICATE_PRESENT,
    };
    (actual == expected)
        .then_some(())
        .ok_or(AcmeMachineError::CorruptState)
}

fn presence(machine: &AcmeOrderMachine) -> u16 {
    let fields = [
        (machine.directory.is_some(), DIRECTORY_PRESENT),
        (machine.nonce.is_some(), NONCE_PRESENT),
        (machine.account_url.is_some(), ACCOUNT_PRESENT),
        (machine.order_url.is_some(), ORDER_URL_PRESENT),
        (machine.order.is_some(), ORDER_PRESENT),
        (machine.authorization.is_some(), AUTHORIZATION_PRESENT),
        (machine.challenge.is_some(), CHALLENGE_PRESENT),
        (machine.publication_digest.is_some(), PUBLICATION_PRESENT),
        (machine.certificate.is_some(), CERTIFICATE_PRESENT),
    ];
    fields.into_iter().fold(
        0,
        |bits, (is_present, bit)| if is_present { bits | bit } else { bits },
    )
}

fn validate_order_urls(order: &crate::AcmeOrder) -> Result<(), AcmeMachineError> {
    crate::wire::bounded_url(&order.finalize)?;
    if let Some(certificate) = &order.certificate {
        crate::wire::bounded_url(certificate)?;
    }
    let mut unique = BTreeSet::new();
    for authorization in &order.authorizations {
        crate::wire::bounded_url(authorization)?;
        if !unique.insert(authorization) {
            return Err(AcmeMachineError::CorruptState);
        }
    }
    Ok(())
}

fn validate_authorization(
    authorization: &crate::AcmeAuthorization,
) -> Result<(), AcmeMachineError> {
    if authorization.challenges.is_empty() || authorization.challenges.len() > 16 {
        return Err(AcmeMachineError::CorruptState);
    }
    let mut unique = BTreeSet::new();
    for challenge in &authorization.challenges {
        crate::wire::bounded_url(&challenge.url)?;
        if !matches!(challenge.kind.as_str(), "http-01" | "dns-01")
            || challenge.token.is_empty()
            || challenge.token.len() > 512
            || !challenge
                .token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !matches!(
                challenge.status,
                AcmeResourceStatus::Pending
                    | AcmeResourceStatus::Processing
                    | AcmeResourceStatus::Valid
                    | AcmeResourceStatus::Invalid
            )
            || !unique.insert((&challenge.kind, &challenge.url))
        {
            return Err(AcmeMachineError::CorruptState);
        }
    }
    Ok(())
}

const fn closed_checkpoint_error(_: AcmeMachineError) -> AcmeMachineError {
    AcmeMachineError::CorruptState
}
