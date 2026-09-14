// SPDX-License-Identifier: GPL-2.0-only

//! Signed backup control exchanges on the existing real mutual-TLS QUIC proof.

use ed25519_dalek::SigningKey;
use meshspan_domain::{DurationMicros, UnixMicros};
use meshspan_protocol::v1::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupReadReceipt,
    ExecuteFederatedBackup, FederatedBackupCapability, FederatedBackupOperation,
    FederatedBackupPermit, FederatedBackupReady, FederatedBackupResult, FederatedBackupScope,
    RemoteBackupAction, RequestFederatedBackupCapability, federated_backup_result::Outcome,
    federation_envelope::Message,
};
use meshspan_protocol::{WireLimits, federation_backup_request_digest_payload};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use super::federation_storage::{client_identity, exchange_context};
use super::{AuthorityPageProof, validated_federation, version};
use crate::{
    FederationExchangeContext, FederationPeerRegistry, FederationReplayGuard, TransportError,
    receive_federation, send_federation, signed_federation_backup_message,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const NOW: UnixMicros = UnixMicros::new(1_500_000);

#[path = "federation_backup/relay.rs"]
mod relay;
pub(super) use relay::prove_node_relay;

pub(super) fn prove_requests(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> TestResult<()> {
    let identity = client_identity(certificate, signing_key)?;
    let context = exchange_context(150, 151, 152, 153)?;
    let request = request(context, RemoteBackupAction::Store);
    let outbound = signed_federation_backup_message(
        &identity,
        context,
        Message::RequestBackupCapability(request.clone()),
        limits,
        NOW,
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = replay()?;
    let authenticated =
        registry.authenticate_backup_request(connection, &validated, NOW, &mut replay)?;
    assert_eq!(
        authenticated.remote_mesh_id(),
        identity.binding().local_mesh_id
    );
    assert_eq!(
        authenticated.local_mesh_id(),
        identity.binding().remote_mesh_id
    );
    assert_eq!(
        authenticated.relationship_id(),
        identity.binding().relationship_id
    );
    assert_eq!(authenticated.authority_epoch(), 1);
    assert_eq!(
        authenticated.capability_request_digest()?,
        <[u8; 32]>::from(Sha256::digest(federation_backup_request_digest_payload(
            &request
        )?))
    );
    assert!(
        authenticated
            .response_context(context.replay_nonce)
            .is_err()
    );
    assert_eq!(
        authenticated.response_context([154; 32])?.operation_id,
        context.operation_id
    );
    assert!(matches!(
        registry.authenticate_backup_request(connection, &validated, NOW, &mut replay),
        Err(TransportError::ReplayedFederationMessage)
    ));
    let mut tampered = outbound.envelope().clone();
    let Some(Message::RequestBackupCapability(value)) = tampered.message.as_mut() else {
        return Err("request".into());
    };
    value.scope.as_mut().ok_or("scope")?.allocation_id = vec![99; 16];
    assert!(matches!(
        registry.authenticate_backup_request(
            connection,
            &validated_federation(&tampered, limits)?,
            NOW,
            &mut self::replay()?
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    let execution = signed_federation_backup_message(
        &identity,
        FederationExchangeContext {
            replay_nonce: [155; 32],
            ..context
        },
        Message::ExecuteBackup(ExecuteFederatedBackup {
            permit: Some(permit(&request)),
            signature: Vec::new(),
        }),
        limits,
        NOW,
    )?;
    let execute = validated_federation(execution.envelope(), limits)?;
    assert!(matches!(
        registry
            .authenticate_backup_request(connection, &execute, NOW, &mut replay)?
            .message(),
        Message::ExecuteBackup(_)
    ));
    assert!(matches!(
        registry.authenticate_backup_request(
            connection,
            &execute,
            UnixMicros::new(1_900_000),
            &mut self::replay()?
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

pub(super) async fn prove_responses(proof: &mut AuthorityPageProof<'_>) -> TestResult<()> {
    for (index, action) in [
        RemoteBackupAction::Lookup,
        RemoteBackupAction::Store,
        RemoteBackupAction::Read,
        RemoteBackupAction::Verify,
        RemoteBackupAction::Delete,
    ]
    .into_iter()
    .enumerate()
    {
        let marker = 160 + u8::try_from(index)? * 5;
        prove_operation(
            proof,
            exchange_context(marker, marker + 1, marker + 2, marker + 3)?,
            action,
        )
        .await?;
    }
    Ok(())
}

async fn prove_operation(
    proof: &mut AuthorityPageProof<'_>,
    context: FederationExchangeContext,
    action: RemoteBackupAction,
) -> TestResult<()> {
    let (permit, mut replay) = prove_capability(proof, context, action).await?;
    let expected = prove_ready(proof, context, &permit, &mut replay).await?;
    prove_result(proof, context, &permit, &expected, &mut replay).await
}

async fn prove_capability(
    proof: &mut AuthorityPageProof<'_>,
    context: FederationExchangeContext,
    action: RemoteBackupAction,
) -> TestResult<(FederatedBackupPermit, FederationReplayGuard)> {
    let key = SigningKey::from_bytes(&[42; 32]);
    let client = client_identity(&proof.certificates.client_certificate, &key)?;
    let request = request(context, action);
    let outbound = signed_federation_backup_message(
        &client,
        context,
        Message::RequestBackupCapability(request.clone()),
        proof.limits,
        NOW,
    )?;
    let permit = permit(&request);
    let reply_context = FederationExchangeContext {
        replay_nonce: [180; 32],
        ..context
    };
    let capability = signed_federation_backup_message(
        proof.server_identity,
        reply_context,
        Message::BackupCapability(FederatedBackupCapability {
            request_digest: Sha256::digest(federation_backup_request_digest_payload(&request)?)
                .to_vec(),
            permit: Some(permit.clone()),
            rejection: None,
            signature: Vec::new(),
        }),
        proof.limits,
        NOW,
    )?;
    send_federation(proof.send, capability.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let mut replay = replay()?;
    let authenticated = proof.registry.authenticate_backup_response(
        proof.connection,
        &received,
        &outbound.expectation()?,
        NOW,
        &mut replay,
    )?;
    assert_eq!(
        authenticated.message(),
        capability.envelope().message.as_ref().ok_or("capability")?
    );
    assert!(authenticated.result_expectation().is_err());
    Ok((permit, replay))
}

async fn prove_ready(
    proof: &mut AuthorityPageProof<'_>,
    context: FederationExchangeContext,
    permit: &FederatedBackupPermit,
    replay: &mut FederationReplayGuard,
) -> TestResult<crate::FederationBackupResponseExpectation> {
    let key = SigningKey::from_bytes(&[42; 32]);
    let client = client_identity(&proof.certificates.client_certificate, &key)?;
    let action =
        RemoteBackupAction::try_from(permit.operation.as_ref().ok_or("operation")?.action)?;
    let execute = signed_federation_backup_message(
        &client,
        FederationExchangeContext {
            replay_nonce: [181; 32],
            ..context
        },
        Message::ExecuteBackup(ExecuteFederatedBackup {
            permit: Some(permit.clone()),
            signature: Vec::new(),
        }),
        proof.limits,
        NOW,
    )?;
    let expected = execute.expectation()?;
    let completed = signed_result(
        proof,
        FederationExchangeContext {
            replay_nonce: [183; 32],
            ..context
        },
        permit,
        action,
    )?;
    assert!(matches!(
        proof.registry.authenticate_backup_response(
            proof.connection,
            &validated_federation(completed.envelope(), proof.limits)?,
            &expected,
            NOW,
            replay
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    let ready = signed_federation_backup_message(
        proof.server_identity,
        FederationExchangeContext {
            replay_nonce: [182; 32],
            ..context
        },
        Message::BackupReady(FederatedBackupReady {
            permit_digest: permit.permit_digest.clone(),
            maximum_frame_bytes: 64,
            rejection: None,
            signature: Vec::new(),
        }),
        proof.limits,
        NOW,
    )?;
    send_federation(proof.send, ready.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let ready = proof.registry.authenticate_backup_response(
        proof.connection,
        &received,
        &expected,
        NOW,
        replay,
    )?;
    Ok(ready.result_expectation()?)
}

async fn prove_result(
    proof: &mut AuthorityPageProof<'_>,
    context: FederationExchangeContext,
    permit: &FederatedBackupPermit,
    expected: &crate::FederationBackupResponseExpectation,
    replay: &mut FederationReplayGuard,
) -> TestResult<()> {
    let action =
        RemoteBackupAction::try_from(permit.operation.as_ref().ok_or("operation")?.action)?;
    let completed = signed_result(
        proof,
        FederationExchangeContext {
            replay_nonce: [183; 32],
            ..context
        },
        permit,
        action,
    )?;
    send_federation(proof.send, completed.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let result = proof.registry.authenticate_backup_response(
        proof.connection,
        &received,
        expected,
        NOW,
        replay,
    )?;
    assert_eq!(
        result.message(),
        completed.envelope().message.as_ref().ok_or("result")?
    );
    assert!(result.result_expectation().is_err());
    assert!(matches!(
        proof.registry.authenticate_backup_response(
            proof.connection,
            &received,
            expected,
            NOW,
            replay
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    let mut wrong_permit = permit.clone();
    wrong_permit
        .operation
        .as_mut()
        .ok_or("operation")?
        .object
        .as_mut()
        .ok_or("object")?
        .digest = vec![99; 32];
    let incorrect = signed_result(
        proof,
        FederationExchangeContext {
            replay_nonce: [184; 32],
            ..context
        },
        &wrong_permit,
        action,
    )?;
    assert!(matches!(
        proof.registry.authenticate_backup_response(
            proof.connection,
            &validated_federation(incorrect.envelope(), proof.limits)?,
            expected,
            NOW,
            replay
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

fn signed_result(
    proof: &AuthorityPageProof<'_>,
    context: FederationExchangeContext,
    permit: &FederatedBackupPermit,
    action: RemoteBackupAction,
) -> TestResult<crate::OutboundFederationBackupMessage> {
    let operation = permit.operation.as_ref().ok_or("operation")?;
    let object = operation.object.clone().ok_or("object")?;
    let receipt = BackupObjectReceipt {
        operation_id: context.operation_id.to_vec(),
        object: Some(object.clone()),
        object_reference: "backup.ms".into(),
    };
    let outcome = match action {
        RemoteBackupAction::Lookup => Outcome::LookedUp(receipt),
        RemoteBackupAction::Store => Outcome::Stored(receipt),
        RemoteBackupAction::Verify => Outcome::Verified(receipt),
        RemoteBackupAction::Read => Outcome::Read(BackupReadReceipt {
            operation_id: context.operation_id.to_vec(),
            byte_length: object.byte_length,
            digest: object.digest,
        }),
        RemoteBackupAction::Delete => Outcome::Deleted(BackupDeleteReceipt {
            operation_id: context.operation_id.to_vec(),
            object: Some(object),
            retirement_revision: 9,
        }),
        RemoteBackupAction::Unspecified => return Err("invalid test action".into()),
    };
    Ok(signed_federation_backup_message(
        proof.server_identity,
        context,
        Message::BackupResult(FederatedBackupResult {
            permit_digest: permit.permit_digest.clone(),
            completed_at_unix_micros: NOW.get(),
            outcome: Some(outcome),
            signature: Vec::new(),
        }),
        proof.limits,
        NOW,
    )?)
}

fn request(
    context: FederationExchangeContext,
    action: RemoteBackupAction,
) -> RequestFederatedBackupCapability {
    RequestFederatedBackupCapability {
        scope: Some(FederatedBackupScope {
            relationship_id: vec![1; 16],
            remote_mesh_id: vec![2; 16],
            provider_mesh_id: vec![3; 16],
            allocation_id: vec![8; 16],
            grant_id: vec![9; 16],
            namespace_grant_id: vec![9; 16],
            provider_node_id: vec![10; 16],
            target_id: vec![11; 16],
            target_generation: 1,
            relationship_authority_epoch: 1,
            grant_revision: 9,
            allocation_revision: 10,
        }),
        operation: Some(FederatedBackupOperation {
            contract_version: Some(version(1, 0)),
            operation_id: context.operation_id.to_vec(),
            deadline_unix_micros: context.deadline.get(),
            authority_revision: Some(9),
            object: Some(BackupObjectIdentity {
                backup_id: vec![12; 16],
                destination_id: vec![13; 16],
                provider_generation: 7,
                byte_length: 10,
                digest: vec![14; 32],
            }),
            action: action.into(),
            object_reference: if matches!(
                action,
                RemoteBackupAction::Store | RemoteBackupAction::Lookup
            ) {
                String::new()
            } else {
                "backup.ms".into()
            },
            retirement_revision: (action == RemoteBackupAction::Delete).then_some(9),
        }),
        signature: Vec::new(),
    }
}

fn permit(request: &RequestFederatedBackupCapability) -> FederatedBackupPermit {
    // Transport verifies the swarm signature and correlation, not the provider-private MAC.
    FederatedBackupPermit {
        scope: request.scope.clone(),
        operation: request.operation.clone(),
        issued_at_unix_micros: 1_400_000,
        expires_at_unix_micros: 1_900_000,
        capability_nonce: vec![185; 32],
        permit_digest: vec![186; 32],
    }
}

fn replay() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(32, DurationMicros::new(1_000_000))
}
