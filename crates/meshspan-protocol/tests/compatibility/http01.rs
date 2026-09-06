// SPDX-License-Identifier: GPL-2.0-only

//! Exact public challenge relay frames and hostile request/response contracts.

use super::*;
use meshspan_protocol::v1::{FetchHttp01Challenge, Http01ChallengeResult};

#[test]
fn public_challenge_request_found_and_absent_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    for message in [
        Message::FetchHttp01Challenge(FetchHttp01Challenge {
            token: "token-1".to_owned(),
        }),
        Message::Http01ChallengeResult(proof()),
        Message::Http01ChallengeResult(Http01ChallengeResult {
            token: "token-1".to_owned(),
            key_authorization: None,
            expires_at_unix_micros: None,
        }),
    ] {
        let envelope = ControlEnvelope {
            header: Some(valid_header()),
            message: Some(message),
        };
        let encoded = encode_control_frame(&envelope, limits()?)?;
        assert_eq!(
            decode_control_frame(&encoded, limits()?)?.into_inner(),
            envelope
        );
    }
    Ok(())
}

#[test]
fn public_challenge_rejects_malformed_tokens_and_response_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    for token in [
        String::new(),
        "a".repeat(129),
        "../token".to_owned(),
        "a\nb".to_owned(),
        "é".to_owned(),
    ] {
        rejected(Message::FetchHttp01Challenge(FetchHttp01Challenge {
            token,
        }))?;
    }
    for body in [
        Vec::new(),
        b"other-token.thumbprint".to_vec(),
        b"token-1.".to_vec(),
        b"token-1.a\nb".to_vec(),
        vec![b'a'; 513],
    ] {
        let mut invalid = proof();
        invalid.key_authorization = Some(body);
        rejected(Message::Http01ChallengeResult(invalid))?;
    }
    for expiry in [None, Some(0), Some(-1)] {
        let mut invalid = proof();
        invalid.expires_at_unix_micros = expiry;
        rejected(Message::Http01ChallengeResult(invalid))?;
    }
    let mut missing_body = proof();
    missing_body.key_authorization = None;
    rejected(Message::Http01ChallengeResult(missing_body))?;
    Ok(())
}

fn proof() -> Http01ChallengeResult {
    Http01ChallengeResult {
        token: "token-1".to_owned(),
        key_authorization: Some(b"token-1.account-thumbprint".to_vec()),
        expires_at_unix_micros: Some(1000),
    }
}

fn rejected(message: Message) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ControlEnvelope {
        header: Some(valid_header()),
        message: Some(message),
    };
    assert_eq!(
        encode_control_frame(&envelope, limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}
