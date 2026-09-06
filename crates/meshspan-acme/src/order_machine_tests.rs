// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    AcmeAuthorization, AcmeChallengePreference, AcmeChallengeRecord, AcmeDirectory,
    AcmeMachineAction, AcmeMachineError, AcmeMachineEvent, AcmeOrder, AcmeOrderMachine,
    AcmeOrderRequest, AcmeResourceStatus,
};

#[test]
fn rejected_authorization_keeps_exact_cleanup_instead_of_aborting_the_machine()
-> Result<(), Box<dyn std::error::Error>> {
    for status in [
        AcmeResourceStatus::Invalid,
        AcmeResourceStatus::Expired,
        AcmeResourceStatus::Deactivated,
        AcmeResourceStatus::Revoked,
    ] {
        let mut machine = machine(AcmeChallengePreference::Http01)?;
        drive_to_challenge(&mut machine)?;
        machine.advance(AcmeMachineEvent::ChallengePublished {
            publication_digest: [9; 32],
        })?;
        machine.advance(AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce_5".to_owned(),
        })?;
        machine.advance(AcmeMachineEvent::AuthorizationPolled {
            authorization: authorization(status, false),
            replay_nonce: "nonce_6".to_owned(),
        })?;
        assert!(
            matches!(machine.action()?, AcmeMachineAction::CleanupChallenge {
            publication_digest, order_epoch: 7, ..
        } if publication_digest == [9; 32])
        );
        let restored = AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?;
        assert_eq!(restored.action()?, machine.action()?);
        machine.resume_under_fence(88)?;
        machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
        assert_eq!(
            machine.action()?,
            AcmeMachineAction::Retired {
                reason: crate::AcmeOrderRetirementReason::AuthorizationRejected,
            }
        );
        assert_eq!(machine.publication_digest(), None);
        assert_eq!(
            AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?,
            machine
        );
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(&machine.encode_checkpoint()?)?;
        assert_eq!(checkpoint["version"], 4);
        assert_eq!(checkpoint["machine"]["authorization_index"], 0);
        checkpoint["version"] = serde_json::json!(3);
        assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&checkpoint)?).is_err());
    }
    Ok(())
}

#[test]
fn invalid_order_is_retired_without_fabricating_a_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = machine(AcmeChallengePreference::Http01)?;
    drive_to_challenge(&mut machine)?;
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [9; 32],
    })?;
    machine.advance(AcmeMachineEvent::ChallengeNotified {
        replay_nonce: "nonce_5".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Valid, false),
        replay_nonce: "nonce_6".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
    machine.advance_with_retry(
        AcmeMachineEvent::OrderPolled {
            order: order(AcmeResourceStatus::Invalid, None),
            replay_nonce: "nonce_7".to_owned(),
        },
        meshspan_domain::UnixMicros::new(1_000_000),
        Some(crate::AcmeRetryAfter::DelayMicros(30_000_000)),
    )?;
    assert_eq!(
        machine.action()?,
        AcmeMachineAction::Retired {
            reason: crate::AcmeOrderRetirementReason::OrderRejected
        }
    );
    assert_eq!(
        machine.poll_not_before(),
        Some(meshspan_domain::UnixMicros::new(31_000_000))
    );
    assert_eq!(machine.publication_action()?, None);
    assert_eq!(
        AcmeOrderMachine::decode_checkpoint(&machine.encode_checkpoint()?)?,
        machine
    );
    Ok(())
}

#[test]
fn polled_challenge_identity_cannot_replace_the_published_token_or_url()
-> Result<(), Box<dyn std::error::Error>> {
    for change_token in [true, false] {
        let mut machine = machine(AcmeChallengePreference::Http01)?;
        drive_to_challenge(&mut machine)?;
        machine.advance(AcmeMachineEvent::ChallengePublished {
            publication_digest: [9; 32],
        })?;
        machine.advance(AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce_5".to_owned(),
        })?;
        let mut changed = authorization(AcmeResourceStatus::Valid, false);
        let challenge = changed.challenges.first_mut().ok_or("missing challenge")?;
        challenge.status = AcmeResourceStatus::Valid;
        if change_token {
            challenge.token = "substituted_token".to_owned();
        } else {
            challenge.url = "https://ca.example.test/substituted".to_owned();
        }
        assert_eq!(
            machine.advance(AcmeMachineEvent::AuthorizationPolled {
                authorization: changed,
                replay_nonce: "nonce_6".to_owned(),
            }),
            Err(AcmeMachineError::InvalidRemoteState)
        );
    }
    Ok(())
}

#[test]
fn order_machine_runs_one_exact_resumable_http01_cycle() -> Result<(), Box<dyn std::error::Error>> {
    let mut machine = machine(AcmeChallengePreference::Http01)?;
    drive_to_challenge(&mut machine)?;
    drive_challenge_to_finalize(&mut machine)?;
    drive_finalize_to_complete(&mut machine)?;
    assert_eq!(
        machine.action()?,
        AcmeMachineAction::Complete {
            certificate: b"certificate-chain".to_vec()
        }
    );
    Ok(())
}

fn drive_to_challenge(machine: &mut AcmeOrderMachine) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::DiscoverDirectory { .. }
    ));
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::AcquireNonce { .. }
    ));
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::CreateAccount { ref nonce, .. } if nonce == "nonce_1"
    ));
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: account_url(),
        replay_nonce: "nonce_2".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::CreateOrder { ref nonce, .. } if nonce == "nonce_2"
    ));
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: order_url(),
        order: order(AcmeResourceStatus::Pending, None),
        replay_nonce: "nonce_3".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::FetchAuthorization { .. }
    ));
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending, false),
        replay_nonce: "nonce_4".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::PublishChallenge {
            ref challenge,
            order_epoch: 7,
            ..
        } if challenge.kind == "http-01"
    ));
    Ok(())
}

fn drive_challenge_to_finalize(
    machine: &mut AcmeOrderMachine,
) -> Result<(), Box<dyn std::error::Error>> {
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [9; 32],
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::NotifyChallenge { .. }
    ));
    machine.advance(AcmeMachineEvent::ChallengeNotified {
        replay_nonce: "nonce_5".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Pending, false),
        replay_nonce: "nonce_6".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::PollAuthorization { .. }
    ));
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Valid, false),
        replay_nonce: "nonce_7".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::CleanupChallenge {
            publication_digest,
            ..
        } if publication_digest == [9; 32]
    ));
    machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::PollOrder { .. }
    ));
    machine.advance(AcmeMachineEvent::OrderPolled {
        order: order(AcmeResourceStatus::Ready, None),
        replay_nonce: "nonce_8".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::FinalizeOrder { .. }
    ));
    Ok(())
}

fn drive_finalize_to_complete(
    machine: &mut AcmeOrderMachine,
) -> Result<(), Box<dyn std::error::Error>> {
    machine.advance(AcmeMachineEvent::OrderFinalized {
        order: order(AcmeResourceStatus::Processing, None),
        replay_nonce: "nonce_9".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::OrderPolled {
        order: order(
            AcmeResourceStatus::Valid,
            Some("https://ca.example.test/certificate/1"),
        ),
        replay_nonce: "nonce_10".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::DownloadCertificate { .. }
    ));
    machine.advance(AcmeMachineEvent::CertificateDownloaded(
        b"certificate-chain".to_vec(),
    ))?;
    Ok(())
}

#[test]
fn checkpoint_clone_resumes_without_repeating_prior_side_effects()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = machine(AcmeChallengePreference::Dns01)?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    let resumed = machine.clone();
    assert_eq!(resumed, machine);
    assert!(matches!(
        resumed.action()?,
        AcmeMachineAction::CreateAccount { .. }
    ));
    assert_eq!(
        machine.advance(AcmeMachineEvent::ChallengeCleaned),
        Err(AcmeMachineError::InvalidTransition)
    );
    Ok(())
}

#[test]
fn machine_rejects_name_changes_and_http_wildcards() -> Result<(), Box<dyn std::error::Error>> {
    let mut mismatch = machine(AcmeChallengePreference::Http01)?;
    mismatch.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    mismatch.advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    mismatch.advance(AcmeMachineEvent::AccountCreated {
        account_url: account_url(),
        replay_nonce: "nonce_2".to_owned(),
    })?;
    let mut changed = order(AcmeResourceStatus::Pending, None);
    changed.dns_names = vec!["other.example.test".to_owned()];
    assert_eq!(
        mismatch.advance(AcmeMachineEvent::OrderCreated {
            order_url: order_url(),
            order: changed,
            replay_nonce: "nonce_3".to_owned(),
        }),
        Err(AcmeMachineError::NameMismatch)
    );

    let mut wildcard = AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["*.example.test".to_owned()])?,
        AcmeChallengePreference::Http01,
        8,
    )?;
    wildcard.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    wildcard.advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    wildcard.advance(AcmeMachineEvent::AccountCreated {
        account_url: account_url(),
        replay_nonce: "nonce_2".to_owned(),
    })?;
    let mut wildcard_order = order(AcmeResourceStatus::Pending, None);
    wildcard_order.dns_names = vec!["*.example.test".to_owned()];
    wildcard.advance(AcmeMachineEvent::OrderCreated {
        order_url: order_url(),
        order: wildcard_order,
        replay_nonce: "nonce_3".to_owned(),
    })?;
    assert_eq!(
        wildcard.advance(AcmeMachineEvent::AuthorizationFetched {
            authorization: authorization(AcmeResourceStatus::Pending, true),
            replay_nonce: "nonce_4".to_owned(),
        }),
        Err(AcmeMachineError::UnsupportedChallenge)
    );
    Ok(())
}

#[test]
fn authorization_resources_are_matched_by_name_not_array_position()
-> Result<(), Box<dyn std::error::Error>> {
    let request = AcmeOrderRequest::new(vec![
        "files.example.test".to_owned(),
        "www.example.test".to_owned(),
    ])?;
    let mut machine = AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        request,
        AcmeChallengePreference::Dns01,
        9,
    )?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: account_url(),
        replay_nonce: "nonce_2".to_owned(),
    })?;
    let mut two_name_order = order(AcmeResourceStatus::Pending, None);
    two_name_order.dns_names.push("www.example.test".to_owned());
    two_name_order
        .authorizations
        .push("https://ca.example.test/authorizations/2".to_owned());
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: order_url(),
        order: two_name_order,
        replay_nonce: "nonce_3".to_owned(),
    })?;
    let mut first = authorization(AcmeResourceStatus::Valid, false);
    first.dns_name = "www.example.test".to_owned();
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: first,
        replay_nonce: "nonce_4".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::FetchAuthorization { ref url, .. }
            if url.ends_with("/authorizations/2")
    ));
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Valid, false),
        replay_nonce: "nonce_5".to_owned(),
    })?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::PollOrder { .. }
    ));
    Ok(())
}

fn machine(
    preference: AcmeChallengePreference,
) -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    Ok(AcmeOrderMachine::new(
        "https://ca.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        preference,
        7,
    )?)
}

fn directory() -> AcmeDirectory {
    AcmeDirectory {
        new_nonce: "https://ca.example.test/new-nonce".to_owned(),
        new_account: "https://ca.example.test/new-account".to_owned(),
        new_order: "https://ca.example.test/new-order".to_owned(),
    }
}

fn account_url() -> String {
    "https://ca.example.test/accounts/1".to_owned()
}

fn order_url() -> String {
    "https://ca.example.test/orders/1".to_owned()
}

fn order(status: AcmeResourceStatus, certificate: Option<&str>) -> AcmeOrder {
    AcmeOrder {
        status,
        dns_names: vec!["files.example.test".to_owned()],
        authorizations: vec!["https://ca.example.test/authorizations/1".to_owned()],
        finalize: "https://ca.example.test/orders/1/finalize".to_owned(),
        certificate: certificate.map(str::to_owned),
    }
}

fn authorization(status: AcmeResourceStatus, wildcard: bool) -> AcmeAuthorization {
    AcmeAuthorization {
        dns_name: if wildcard {
            "example.test".to_owned()
        } else {
            "files.example.test".to_owned()
        },
        wildcard,
        status,
        challenges: vec![challenge("http-01", "http"), challenge("dns-01", "dns")],
    }
}

fn challenge(kind: &str, suffix: &str) -> AcmeChallengeRecord {
    AcmeChallengeRecord {
        kind: kind.to_owned(),
        url: format!("https://ca.example.test/challenges/{suffix}"),
        token: format!("token_{suffix}"),
        status: AcmeResourceStatus::Pending,
    }
}
