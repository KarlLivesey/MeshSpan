// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::UnixMicros;

use super::*;
use crate::{AcmeMachineAction, AcmeRetryAfter};

#[test]
fn notification_and_pending_authorization_keep_delays_but_cleanup_does_not()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = pending_authorization()?;
    machine.advance_with_retry(
        AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce-5".to_owned(),
        },
        UnixMicros::new(10),
        Some(AcmeRetryAfter::DelayMicros(120)),
    )?;
    assert_eq!(machine.poll_not_before(), Some(UnixMicros::new(130)));
    let bytes = machine.encode_checkpoint()?;
    let mut replacement = AcmeOrderMachine::decode_checkpoint(&bytes)?;
    replacement.resume_under_fence(9)?;
    assert_eq!(replacement.poll_not_before(), Some(UnixMicros::new(130)));
    assert_eq!(
        AcmeOrderMachine::decode_checkpoint(&replacement.encode_checkpoint()?)?,
        replacement
    );

    machine.advance_with_retry(
        AcmeMachineEvent::AuthorizationPolled {
            authorization: authorization(AcmeResourceStatus::Pending),
            replay_nonce: "nonce-6".to_owned(),
        },
        UnixMicros::new(130),
        Some(AcmeRetryAfter::At(UnixMicros::new(200))),
    )?;
    assert_eq!(machine.poll_not_before(), Some(UnixMicros::new(200)));
    machine.advance_with_retry(
        AcmeMachineEvent::AuthorizationPolled {
            authorization: authorization(AcmeResourceStatus::Valid),
            replay_nonce: "nonce-7".to_owned(),
        },
        UnixMicros::new(200),
        Some(AcmeRetryAfter::DelayMicros(500)),
    )?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::CleanupChallenge { .. }
    ));
    assert_eq!(machine.poll_not_before(), None);
    Ok(())
}

#[test]
fn finalization_and_pending_order_delay_only_until_certificate_is_ready()
-> Result<(), Box<dyn std::error::Error>> {
    let mut machine = ordered(AcmeResourceStatus::Ready)?;
    machine.advance_with_retry(
        AcmeMachineEvent::OrderFinalized {
            order: order(AcmeResourceStatus::Processing, None),
            replay_nonce: "nonce-4".to_owned(),
        },
        UnixMicros::new(10),
        Some(AcmeRetryAfter::DelayMicros(120)),
    )?;
    assert_eq!(machine.poll_not_before(), Some(UnixMicros::new(130)));
    machine.advance_with_retry(
        AcmeMachineEvent::OrderPolled {
            order: order(AcmeResourceStatus::Processing, None),
            replay_nonce: "nonce-5".to_owned(),
        },
        UnixMicros::new(130),
        Some(AcmeRetryAfter::At(UnixMicros::new(200))),
    )?;
    assert_eq!(machine.poll_not_before(), Some(UnixMicros::new(200)));
    machine.advance_with_retry(
        AcmeMachineEvent::OrderPolled {
            order: order(
                AcmeResourceStatus::Valid,
                Some("https://ca.example.test/certificate/1"),
            ),
            replay_nonce: "nonce-6".to_owned(),
        },
        UnixMicros::new(200),
        Some(AcmeRetryAfter::DelayMicros(500)),
    )?;
    assert!(matches!(
        machine.action()?,
        AcmeMachineAction::DownloadCertificate { .. }
    ));
    assert_eq!(machine.poll_not_before(), None);
    Ok(())
}

#[test]
fn checkpoint_rejects_impossible_deadlines_and_version_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let machine = ordered(AcmeResourceStatus::Processing)?;
    let original: Value = serde_json::from_slice(&machine.encode_checkpoint()?)?;
    for invalid in [
        serde_json::json!(-1),
        serde_json::json!(0),
        serde_json::json!(1.5),
        serde_json::json!("120"),
    ] {
        let mut value = original.clone();
        value["machine"]["poll_not_before"] = invalid;
        assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());
    }
    let mut missing = original.clone();
    missing["machine"]
        .as_object_mut()
        .ok_or("expected machine object")?
        .remove("poll_not_before");
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&missing)?).is_err());
    let mut value = original;
    value["version"] = Value::from(1);
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());
    value["machine"]["poll_not_before"] = Value::from(120);
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&value)?).is_err());
    let mut fresh: Value = serde_json::from_slice(&super::machine()?.encode_checkpoint()?)?;
    fresh["machine"]["poll_not_before"] = Value::from(120);
    assert!(AcmeOrderMachine::decode_checkpoint(&serde_json::to_vec(&fresh)?).is_err());
    Ok(())
}

fn pending_authorization() -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    let mut machine = ordered(AcmeResourceStatus::Pending)?;
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending),
        replay_nonce: "nonce-4".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: [7; 32],
    })?;
    Ok(machine)
}

fn ordered(status: AcmeResourceStatus) -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    let mut machine = machine()?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(directory()))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        order: order(status, None),
        replay_nonce: "nonce-3".to_owned(),
    })?;
    Ok(machine)
}
