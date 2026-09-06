// SPDX-License-Identifier: GPL-2.0-only

use serde_json::Value;

use super::checkpoint::MAXIMUM_CHECKPOINT_BYTES;
use crate::{
    AcmeAuthorization, AcmeChallengePreference, AcmeChallengeRecord, AcmeDirectory,
    AcmeMachineEvent, AcmeOrder, AcmeOrderMachine, AcmeOrderRequest, AcmeResourceStatus,
};

mod polling;

#[test]
fn every_order_phase_round_trips_as_the_same_next_action() -> Result<(), Box<dyn std::error::Error>>
{
    let mut machine = machine()?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        order: order(AcmeResourceStatus::Pending, None),
        replay_nonce: "nonce-3".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending),
        replay_nonce: "nonce-4".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    let mut unprepared_replacement =
        AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?;
    unprepared_replacement.resume_under_fence(18)?;
    assert_eq!(unprepared_replacement.publication_epoch(), None);
    assert!(matches!(
        unprepared_replacement.action()?,
        crate::AcmeMachineAction::PublishChallenge {
            order_epoch: 18,
            ..
        }
    ));
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [7; 32],
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::ChallengeNotified {
        replay_nonce: "nonce-5".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Valid),
        replay_nonce: "nonce-6".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::OrderPolled {
        order: order(AcmeResourceStatus::Ready, None),
        replay_nonce: "nonce-7".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::OrderFinalized {
        order: order(AcmeResourceStatus::Processing, None),
        replay_nonce: "nonce-8".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::OrderPolled {
        order: order(
            AcmeResourceStatus::Valid,
            Some("https://ca.example.test/certificate/1"),
        ),
        replay_nonce: "nonce-9".to_owned(),
    })?;
    assert_round_trip(&machine)?;
    machine.advance(AcmeMachineEvent::CertificateDownloaded(vec![0x30, 1, 2]))?;
    assert_round_trip(&machine)?;
    Ok(())
}

#[test]
fn hostile_checkpoint_version_shape_and_size_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let machine = machine()?;
    let encoded = machine.encode_checkpoint()?;
    let mut value: Value = serde_json::from_slice(&encoded)?;
    value["version"] = Value::from(4);
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());

    let mut value: Value = serde_json::from_slice(&encoded)?;
    value["machine"]["phase"] = Value::from("complete");
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());

    let mut value: Value = serde_json::from_slice(&encoded)?;
    value["unexpected"] = Value::Bool(true);
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());
    assert!(
        AcmeOrderMachine::decode_checkpoint(&vec![b' '; MAXIMUM_CHECKPOINT_BYTES + 1]).is_err()
    );
    Ok(())
}

#[test]
fn replacement_fence_retains_an_unfinished_challenge_phase()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = machine()?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        order: order(AcmeResourceStatus::Pending, None),
        replay_nonce: "nonce-3".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending),
        replay_nonce: "nonce-4".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [7; 32],
    })?;

    machine.resume_under_fence(18)?;
    assert_eq!(machine.order_epoch(), 18);
    assert!(matches!(
        machine.action()?,
        crate::AcmeMachineAction::NotifyChallenge { .. }
    ));
    assert_eq!(machine.publication_epoch(), Some(17));
    let decoded = AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?;
    assert_eq!(decoded, machine);
    Ok(())
}

#[test]
fn replacement_worker_preserves_valid_authorization_cleanup_and_original_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = machine()?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        order: order(AcmeResourceStatus::Pending, None),
        replay_nonce: "nonce-3".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending),
        replay_nonce: "nonce-4".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [7; 32],
    })?;
    machine.advance(AcmeMachineEvent::ChallengeNotified {
        replay_nonce: "nonce-5".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Valid),
        replay_nonce: "nonce-6".to_owned(),
    })?;
    machine.resume_under_fence(18)?;
    assert!(
        matches!(machine.action()?, crate::AcmeMachineAction::CleanupChallenge {
        order_epoch: 17, publication_digest, ..
    } if publication_digest == [7; 32])
    );
    assert_eq!(machine.order_epoch(), 18);
    assert_eq!(
        AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?,
        machine
    );
    Ok(())
}

fn assert_round_trip(machine: &AcmeOrderMachine) -> Result<(), Box<dyn std::error::Error>> {
    let decoded = AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?;
    assert_eq!(decoded, *machine);
    assert_eq!(decoded.action()?, machine.action()?);
    // Every original phase remains readable in v2 (without retained publication material).
    let mut legacy: Value = serde_json::from_slice(&machine.encode_checkpoint()?)?;
    legacy["version"] = Value::from(2);
    legacy["machine"]
        .as_object_mut()
        .ok_or("expected machine object")?
        .remove("publication");
    let decoded = AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&legacy)?)?;
    assert_eq!(decoded.action()?, machine.action()?);
    assert_eq!(decoded.dns_names(), machine.dns_names());
    assert_eq!(decoded.directory_url(), machine.directory_url());
    assert_eq!(decoded.order_epoch(), machine.order_epoch());
    // v1 additionally predates the nullable polling schedule.
    legacy["version"] = Value::from(1);
    legacy["machine"]
        .as_object_mut()
        .ok_or("expected machine object")?
        .remove("poll_not_before");
    let decoded = AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&legacy)?)?;
    assert_eq!(decoded.action()?, machine.action()?);
    let expected_epoch = machine.publication_action()?.map(|_| machine.order_epoch());
    assert_eq!(decoded.publication_epoch(), expected_epoch);
    Ok(())
}

fn machine() -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    Ok(AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        AcmeChallengePreference::Http01,
        17,
    )?)
}

fn directory() -> AcmeDirectory {
    AcmeDirectory {
        new_nonce: "https://ca.example.test/nonce".to_owned(),
        new_account: "https://ca.example.test/account".to_owned(),
        new_order: "https://ca.example.test/order".to_owned(),
    }
}

fn order(status: AcmeResourceStatus, certificate: Option<&str>) -> AcmeOrder {
    AcmeOrder {
        status,
        dns_names: vec!["files.example.test".to_owned()],
        authorizations: vec!["https://ca.example.test/authorization/1".to_owned()],
        finalize: "https://ca.example.test/finalize/1".to_owned(),
        certificate: certificate.map(str::to_owned),
    }
}

fn authorization(status: AcmeResourceStatus) -> AcmeAuthorization {
    AcmeAuthorization {
        dns_name: "files.example.test".to_owned(),
        wildcard: false,
        status,
        challenges: vec![AcmeChallengeRecord {
            kind: "http-01".to_owned(),
            url: "https://ca.example.test/challenge/1".to_owned(),
            token: "token-1".to_owned(),
            status,
        }],
    }
}
