// SPDX-License-Identifier: GPL-2.0-only

//! Real owner-node transport with an independently signed external execution.

use super::*;
use crate::{
    AuthenticatedPeer, FederationPeerBinding, StreamKind, accept_stream, open_stream,
    receive_data_control, send_data_control,
};
use meshspan_protocol::{
    ValidatedDataControlEnvelope, decode_data_control_frame, encode_data_control_frame,
    v1::{
        DataControlEnvelope, ForwardFederatedBackupRequest, RequestHeader,
        data_control_envelope::Message as DataMessage,
    },
};

#[path = "owner_response.rs"]
mod owner_response;

pub(in crate::tests) async fn prove_node_relay(
    client: &quinn::Connection,
    server: &quinn::Connection,
    peer: AuthenticatedPeer,
    limits: WireLimits,
) -> TestResult<()> {
    // This federation identity is independent of both certificates on the internal hop.
    let remote = super::super::certificates()?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let identity = client_identity(&remote.client_certificate, &key)?;
    let binding = identity.binding();
    let registry = FederationPeerRegistry::new([FederationPeerBinding {
        relationship_id: binding.relationship_id,
        local_mesh_id: binding.remote_mesh_id,
        remote_mesh_id: binding.local_mesh_id,
        authority_epoch: binding.authority_epoch,
        identity_generation: binding.identity_generation,
        certificate_fingerprint: binding.certificate_fingerprint,
        verifying_key: binding.verifying_key,
        valid_from: binding.valid_from,
        valid_until: binding.valid_until,
    }])?;
    let context = exchange_context(150, 151, 152, 153)?;
    let outbound = signed_federation_backup_message(
        &identity,
        context,
        Message::ExecuteBackup(ExecuteFederatedBackup {
            permit: Some(permit(&request(context, RemoteBackupAction::Store))),
            signature: Vec::new(),
        }),
        limits,
        NOW,
    )?;
    let forwarded = ForwardFederatedBackupRequest {
        header: Some(RequestHeader {
            version: Some(version(1, 0)),
            mesh_id: vec![3; 16],
            partition_id: vec![31; 16],
            routing_epoch: 1,
            sender_node_id: peer.node_id().as_bytes().to_vec(),
            sender_incarnation: peer.incarnation(),
            request_id: context.request_id.to_vec(),
            operation_id: context.operation_id.to_vec(),
            trace_id: context.trace_id.to_vec(),
            deadline_unix_micros: 1_900_000,
        }),
        provider_node_id: vec![10; 16],
        request: meshspan_protocol::encode_federation_frame(outbound.envelope(), limits)?,
        maximum_frame_bytes: 64,
    };
    let envelope = DataControlEnvelope {
        message: Some(DataMessage::ForwardFederatedBackupRequest(
            forwarded.clone(),
        )),
    };
    let (mut send, _receive) = open_stream(client, StreamKind::Data).await?;
    let mut accepted = accept_stream(server).await?;
    send_data_control(&mut send, &envelope, limits).await?;
    send.finish()?;
    let received = receive_data_control(&mut accepted.receive, limits).await?;
    let mut guard = replay()?;
    let authenticated =
        registry.authenticate_forwarded_backup_request(peer, &received, limits, NOW, &mut guard)?;
    assert_eq!(authenticated.peer(), peer);
    assert_eq!(authenticated.forwarded(), &forwarded);
    assert_eq!(
        authenticated.consumer().remote_mesh_id(),
        binding.local_mesh_id
    );
    assert!(matches!(
        registry.authenticate_forwarded_backup_request(peer, &received, limits, NOW, &mut guard),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_relay_rejections(&registry, peer, &forwarded, limits)?;
    owner_response::prove(&forwarded, limits)?;
    Ok(())
}

fn prove_relay_rejections(
    registry: &FederationPeerRegistry,
    peer: AuthenticatedPeer,
    original: &ForwardFederatedBackupRequest,
    limits: WireLimits,
) -> TestResult<()> {
    for field in ["sender", "incarnation", "expiry", "signature", "allocation"] {
        let mut changed = original.clone();
        let header = changed.header.as_mut().ok_or("header")?;
        match field {
            "sender" => header.sender_node_id = vec![99; 16],
            "incarnation" => header.sender_incarnation += 1,
            "expiry" => header.deadline_unix_micros = NOW.get(),
            "signature" | "allocation" => {
                let mut original_request =
                    meshspan_protocol::decode_federation_frame(&changed.request, limits)?
                        .into_inner();
                let Some(Message::ExecuteBackup(execute)) = original_request.message.as_mut()
                else {
                    return Err("execute".into());
                };
                if field == "signature" {
                    execute.signature = vec![88; 64];
                } else {
                    execute
                        .permit
                        .as_mut()
                        .and_then(|value| value.scope.as_mut())
                        .ok_or("scope")?
                        .allocation_id = vec![88; 16];
                }
                changed.request =
                    meshspan_protocol::encode_federation_frame(&original_request, limits)?;
            }
            _ => return Err("unknown vector".into()),
        }
        let mut guard = replay()?;
        let failure = registry.authenticate_forwarded_backup_request(
            peer,
            &validated(changed, limits)?,
            limits,
            NOW,
            &mut guard,
        );
        match field {
            "sender" | "incarnation" => {
                assert!(matches!(failure, Err(TransportError::UntrustedPeer)));
            }
            "expiry" => assert!(matches!(
                failure,
                Err(TransportError::StaleFederationMessage)
            )),
            "signature" | "allocation" => assert!(matches!(
                failure,
                Err(TransportError::UntrustedFederationPeer)
            )),
            _ => return Err("unknown vector".into()),
        }
        // Invalid signatures and wrappers must not consume the original valid request's nonce.
        registry.authenticate_forwarded_backup_request(
            peer,
            &validated(original.clone(), limits)?,
            limits,
            NOW,
            &mut guard,
        )?;
    }
    Ok(())
}

fn validated(
    request: ForwardFederatedBackupRequest,
    limits: WireLimits,
) -> TestResult<ValidatedDataControlEnvelope> {
    Ok(decode_data_control_frame(
        &encode_data_control_frame(
            &DataControlEnvelope {
                message: Some(DataMessage::ForwardFederatedBackupRequest(request)),
            },
            limits,
        )?,
        limits,
    )?)
}
