// SPDX-License-Identifier: GPL-2.0-only

use std::collections::VecDeque;
use std::sync::Mutex;

use meshspan_contracts::{ContractError, ContractVersion, RequestContext};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    AcmeChallengeExecution, AcmeChallengeRecord, AcmeHttpMethod, AcmeHttpResponse, AcmeJwsSigner,
    AcmeMachineAction, AcmeMachineEvent, AcmeProtocolError, AcmePublicJwk, AcmeResponseHeaders,
    AcmeRetryAfter, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport, AcmeTransportError,
    AcmeTransportRequest, AcmeWorkerError, Dns01Challenge, DnsTxtProvider, DnsTxtReceipt,
    Http01Challenge,
};

#[tokio::test]
async fn executor_maps_unsigned_transport_steps_to_validated_events()
-> Result<(), Box<dyn std::error::Error>> {
    let transport = RecordingTransport::new([
        response(
            200,
            vec![],
            serde_json::to_vec(&json!({
                "newNonce": "https://ca.example.test/new-nonce",
                "newAccount": "https://ca.example.test/new-account",
                "newOrder": "https://ca.example.test/new-order"
            }))?,
        )?,
        response(204, vec![("replay-nonce", "nonce_1")], Vec::new())?,
    ]);
    let mut executor = AcmeStepExecutor::new(
        transport,
        RecordingSigner::default(),
        Http01Challenge::new(),
    );
    assert!(matches!(
        executor
            .execute(
                &AcmeMachineAction::DiscoverDirectory {
                    url: "https://ca.example.test/directory".to_owned()
                },
                execution()?
            )
            .await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::DirectoryDiscovered(_))
    ));
    assert_eq!(
        executor
            .execute(
                &AcmeMachineAction::AcquireNonce {
                    url: "https://ca.example.test/new-nonce".to_owned()
                },
                execution()?
            )
            .await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::NonceAcquired("nonce_1".to_owned()))
    );
    let (transport, _, _) = executor.into_parts();
    assert_eq!(
        transport.methods(),
        [AcmeHttpMethod::Get, AcmeHttpMethod::Head]
    );
    Ok(())
}

#[tokio::test]
async fn executor_publishes_the_exact_http_key_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = RecordingSigner::default();
    let expected = format!("token_http.{}", signer.public_jwk()?.thumbprint());
    let challenge_reader = Http01Challenge::new();
    let mut executor = AcmeStepExecutor::new(
        RecordingTransport::new([]),
        signer,
        challenge_reader.clone(),
    );
    let outcome = executor
        .execute(
            &AcmeMachineAction::PublishChallenge {
                dns_name: "files.example.test".to_owned(),
                wildcard: false,
                challenge: challenge("http-01", "token_http"),
                order_epoch: 7,
            },
            execution()?,
        )
        .await?;
    assert!(matches!(
        outcome,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengePublished {
            publication_digest
        }) if publication_digest != [0; 32]
    ));
    assert_eq!(
        challenge_reader.response("token_http", UnixMicros::new(150))?,
        Some(expected.into_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn executor_cleans_a_retained_http_receipt_after_its_original_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let mut executor = AcmeStepExecutor::new(
        RecordingTransport::new([]),
        RecordingSigner::default(),
        Http01Challenge::new(),
    );
    let published = executor
        .execute(
            &AcmeMachineAction::PublishChallenge {
                dns_name: "files.example.test".to_owned(),
                wildcard: false,
                challenge: challenge("http-01", "token_http"),
                order_epoch: 7,
            },
            execution()?,
        )
        .await?;
    let AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengePublished { publication_digest }) =
        published
    else {
        return Err("HTTP publication did not return its exact receipt".into());
    };
    let (transport, signer, old_publication) = executor.into_parts();
    drop(old_publication);
    let mut recovered = AcmeStepExecutor::new(transport, signer, Http01Challenge::new());
    let mut cleanup = execution()?;
    cleanup.context.deadline = UnixMicros::new(300);
    assert_eq!(
        recovered
            .execute(
                &AcmeMachineAction::CleanupChallenge {
                    dns_name: "files.example.test".to_owned(),
                    wildcard: false,
                    challenge: challenge("http-01", "token_http"),
                    publication_digest,
                    order_epoch: 7,
                },
                cleanup,
            )
            .await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengeCleaned)
    );
    let (transport, _, publication) = recovered.into_parts();
    assert!(transport.requests.is_empty());
    assert_eq!(
        publication.response("token_http", UnixMicros::new(300))?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn executor_retries_one_bad_nonce_with_the_server_nonce()
-> Result<(), Box<dyn std::error::Error>> {
    let bad_nonce = response(
        400,
        vec![("replay-nonce", "nonce_fresh")],
        serde_json::to_vec(&json!({
            "type": "urn:ietf:params:acme:error:badNonce"
        }))?,
    )?;
    let created = response(
        201,
        vec![
            ("location", "https://ca.example.test/accounts/1"),
            ("replay-nonce", "nonce_after"),
        ],
        b"{}".to_vec(),
    )?;
    let mut executor = AcmeStepExecutor::new(
        RecordingTransport::new([bad_nonce, created]),
        RecordingSigner::default(),
        Http01Challenge::new(),
    );
    assert!(matches!(
        executor
            .execute(
                &AcmeMachineAction::CreateAccount {
                    url: "https://ca.example.test/new-account".to_owned(),
                    nonce: "nonce_stale".to_owned()
                },
                execution()?
            )
            .await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::AccountCreated { .. })
    ));
    let (transport, _, _) = executor.into_parts();
    assert_eq!(transport.requests.len(), 2);
    let second: serde_json::Value = serde_json::from_slice(&transport.requests[1].body)?;
    let protected = crate::wire_tests::decode_json_field(&second, "protected")?;
    assert_eq!(protected["nonce"], "nonce_fresh");
    Ok(())
}

#[tokio::test]
async fn executor_publishes_the_exact_dns01_digest() -> Result<(), Box<dyn std::error::Error>> {
    let signer = RecordingSigner::default();
    let key_authorization = format!("token_dns.{}", signer.public_jwk()?.thumbprint());
    let expected = crate::wire::encode_base64url(&Sha256::digest(key_authorization));
    let mut executor = AcmeStepExecutor::new(
        RecordingTransport::new([]),
        signer,
        Dns01Challenge::new(RecordingDns::default()),
    );
    assert!(matches!(
        executor
            .execute(
                &AcmeMachineAction::PublishChallenge {
                    dns_name: "files.example.test".to_owned(),
                    wildcard: false,
                    challenge: challenge("dns-01", "token_dns"),
                    order_epoch: 8,
                },
                execution()?
            )
            .await?,
        AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengePublished { .. })
    ));
    let (_, _, challenge) = executor.into_parts();
    let provider = challenge.into_provider();
    assert_eq!(
        provider.name.as_deref(),
        Some("_acme-challenge.files.example.test")
    );
    assert_eq!(provider.value.as_deref(), Some(expected.as_bytes()));
    Ok(())
}

fn execution() -> Result<AcmeChallengeExecution<'static>, Box<dyn std::error::Error>> {
    Ok(AcmeChallengeExecution {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([7; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(3)),
        },
        challenge_expires_at: UnixMicros::new(200),
        csr_der: b"csr",
    })
}

fn challenge(kind: &str, token: &str) -> AcmeChallengeRecord {
    AcmeChallengeRecord {
        kind: kind.to_owned(),
        url: "https://ca.example.test/challenges/1".to_owned(),
        token: token.to_owned(),
        status: crate::AcmeResourceStatus::Pending,
    }
}

fn response(
    status: u16,
    headers: Vec<(&str, &str)>,
    body: Vec<u8>,
) -> Result<AcmeHttpResponse, AcmeProtocolError> {
    AcmeHttpResponse::new(
        status,
        AcmeResponseHeaders::new(
            headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        )?,
        body,
    )
}

#[tokio::test]
async fn retry_guidance_survives_get_head_and_signed_post_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let url = "https://ca.example.test/resource".to_owned();
    let actions = [
        AcmeMachineAction::DiscoverDirectory { url: url.clone() },
        AcmeMachineAction::AcquireNonce { url: url.clone() },
        AcmeMachineAction::CreateAccount {
            url,
            nonce: "nonce_1".to_owned(),
        },
    ];
    for action in actions {
        let transport =
            RecordingTransport::new([response(429, vec![("retry-after", "3600")], Vec::new())?]);
        let mut executor = AcmeStepExecutor::new(
            transport,
            RecordingSigner::default(),
            Http01Challenge::new(),
        );
        assert_eq!(
            executor.execute(&action, execution()?).await,
            Err(AcmeWorkerError::RemoteRetry {
                retry_after: Some(AcmeRetryAfter::DelayMicros(3_600_000_000))
            })
        );
        assert_eq!(executor.into_parts().0.requests.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn rate_limit_after_bad_nonce_is_not_retried_again() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = RecordingTransport::new([
        response(
            400,
            vec![("replay-nonce", "nonce_fresh")],
            br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#.to_vec(),
        )?,
        response(429, vec![("retry-after", "1200")], Vec::new())?,
    ]);
    let mut executor = AcmeStepExecutor::new(
        transport,
        RecordingSigner::default(),
        Http01Challenge::new(),
    );
    let action = AcmeMachineAction::CreateAccount {
        url: "https://ca.example.test/account".to_owned(),
        nonce: "nonce_stale".to_owned(),
    };
    assert_eq!(
        executor.execute(&action, execution()?).await,
        Err(AcmeWorkerError::RemoteRetry {
            retry_after: Some(AcmeRetryAfter::DelayMicros(1_200_000_000))
        })
    );
    assert_eq!(executor.into_parts().0.requests.len(), 2);
    Ok(())
}

#[tokio::test]
async fn malformed_retry_guidance_does_not_trigger_an_inline_retry()
-> Result<(), Box<dyn std::error::Error>> {
    for headers in [
        vec![("retry-after", "+120")],
        vec![("retry-after", "120"), ("retry-after", "240")],
    ] {
        let mut executor = AcmeStepExecutor::new(
            RecordingTransport::new([response(429, headers, Vec::new())?]),
            RecordingSigner::default(),
            Http01Challenge::new(),
        );
        let action = AcmeMachineAction::DiscoverDirectory {
            url: "https://ca.example.test/directory".to_owned(),
        };
        assert_eq!(
            executor.execute(&action, execution()?).await,
            Err(AcmeWorkerError::Protocol)
        );
        assert_eq!(executor.into_parts().0.requests.len(), 1);
    }
    Ok(())
}

struct RecordingTransport {
    responses: VecDeque<AcmeHttpResponse>,
    requests: Vec<AcmeTransportRequest>,
}

impl RecordingTransport {
    fn new(responses: impl IntoIterator<Item = AcmeHttpResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    fn methods(&self) -> Vec<AcmeHttpMethod> {
        self.requests.iter().map(|request| request.method).collect()
    }
}

impl AcmeTransport for RecordingTransport {
    fn send(
        &mut self,
        request: &AcmeTransportRequest,
    ) -> impl std::future::Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send
    {
        self.requests.push(request.clone());
        std::future::ready(
            self.responses
                .pop_front()
                .ok_or(AcmeTransportError::Unavailable),
        )
    }
}

#[derive(Default)]
struct RecordingSigner {
    input: Mutex<Vec<u8>>,
}

impl AcmeJwsSigner for RecordingSigner {
    fn public_jwk(&self) -> Result<AcmePublicJwk, AcmeProtocolError> {
        AcmePublicJwk::new("A".repeat(43), "Q".repeat(43))
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AcmeProtocolError> {
        *self
            .input
            .lock()
            .map_err(|_| AcmeProtocolError::InvalidSigner)? = signing_input.to_vec();
        Ok(vec![5; 64])
    }
}

#[derive(Default)]
struct RecordingDns {
    name: Option<String>,
    value: Option<Vec<u8>>,
    receipt: Option<DnsTxtReceipt>,
}

impl DnsTxtProvider for RecordingDns {
    fn receipt(&self, name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
        dns_receipt(name, value, order_epoch)
    }

    fn publish_txt(
        &mut self,
        name: &str,
        value: &[u8],
        order_epoch: u64,
    ) -> impl Future<Output = Result<DnsTxtReceipt, ContractError>> + Send {
        let receipt = dns_receipt(name, value, order_epoch);
        self.name = Some(name.to_owned());
        self.value = Some(value.to_vec());
        self.receipt = Some(receipt);
        std::future::ready(Ok(receipt))
    }

    fn is_txt_visible(
        &self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> impl Future<Output = Result<bool, ContractError>> + Send {
        std::future::ready(Ok(self.name.as_deref() == Some(name)
            && self.value.as_deref() == Some(value)
            && self.receipt == Some(receipt)))
    }

    fn remove_txt(
        &mut self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        let visible = self.name.as_deref() == Some(name)
            && self.value.as_deref() == Some(value)
            && self.receipt == Some(receipt);
        if visible {
            self.name = None;
            self.value = None;
            self.receipt = None;
            std::future::ready(Ok(()))
        } else {
            std::future::ready(Err(ContractError::Stale))
        }
    }
}

fn dns_receipt(name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
    let mut digest = Sha256::new();
    digest.update(name.as_bytes());
    digest.update(value);
    digest.update(order_epoch.to_be_bytes());
    DnsTxtReceipt {
        provider_digest: digest.finalize().into(),
    }
}
