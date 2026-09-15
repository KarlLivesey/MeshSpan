// SPDX-License-Identifier: GPL-2.0-only

//! Recover the original provider admission before sending resumed repair bytes.

use meshspan_contracts::{
    ReservationClass, ShardPutIntent, ShardReceipt, ShardWritePermit, encode_shard_put_intent_v1,
};
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, RequestHeader, ResumeShardPutRequest, VersionedPayload,
        data_control_envelope::Message, resume_shard_put_result::Outcome,
    },
};
use meshspan_transport::{StreamKind, open_stream, receive_data_control, send_data_control};

use super::{PreparedShardUpload, ShardUploadClient, deadline_at, expired};
use crate::{
    DataPlaneError,
    capability::{decode_put_identity, encode_write_permit},
    client::ReadyShardUpload,
    wire::{receipt, remote_rejection},
};

/// A repair can resume its exact prepared admission or recover already verified bytes.
pub enum RepairShardUpload {
    /// Same original operation/destination, now permitted to send bytes under fresh authority.
    Prepared(PreparedShardUpload),
    /// No byte upload is needed: the provider independently verified the exact original write.
    Verified(ShardReceipt),
}

impl ShardUploadClient<'_> {
    /// Recovers or creates admission for an immutable repair intent, with no shard bytes sent.
    /// Persist the intent before calling; a lost reply is not evidence of cancellation.
    /// # Errors
    /// Rejects expired/contradictory authority, altered original identity and remote failures.
    pub async fn resume_repair_upload(
        &self,
        header: RequestHeader,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
    ) -> Result<RepairShardUpload, DataPlaneError> {
        self.repair_admission(header, intent, authority, false)
            .await
    }

    /// Completes an admission-only exchange, releasing the server before reconstruction reads.
    /// The immutable intent must already be durable; a lost reply remains recoverable by it.
    /// # Errors
    /// Rejects expired/contradictory authority, substituted admission and transport failure.
    pub async fn prepare_repair_put(
        &self,
        header: RequestHeader,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
    ) -> Result<meshspan_contracts::RepairPutAdmission, DataPlaneError> {
        match self
            .repair_admission(header, intent, authority, true)
            .await?
        {
            RepairShardUpload::Prepared(prepared) => Ok(
                meshspan_contracts::RepairPutAdmission::Prepared(prepared.identity()),
            ),
            RepairShardUpload::Verified(receipt) => {
                Ok(meshspan_contracts::RepairPutAdmission::Verified(receipt))
            }
        }
    }

    async fn repair_admission(
        &self,
        header: RequestHeader,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
        admission_only: bool,
    ) -> Result<RepairShardUpload, DataPlaneError> {
        validate_request(&header, intent, authority)?;
        let expires_at = UnixMicros::new(header.deadline_unix_micros);
        let deadline = deadline_at(expires_at, self.clock.now())?;
        let request = ResumeShardPutRequest {
            header: Some(header),
            target_id: intent.target_id.as_bytes().to_vec(),
            target_generation: intent.target_generation,
            intent: Some(VersionedPayload {
                format_version: 1,
                canonical_bytes: encode_shard_put_intent_v1(intent).to_vec(),
            }),
            write_capability: encode_write_permit(authority),
            admission_only,
        };
        let admission = tokio::time::timeout_at(
            deadline,
            admit(self.connection, request, intent, self.limits),
        )
        .await
        .map_err(|_| expired())??;
        match admission {
            Admission::Prepared(transfer) => Ok(RepairShardUpload::Prepared(PreparedShardUpload {
                transfer,
                deadline,
                expires_at,
            })),
            Admission::Verified(receipt) => Ok(RepairShardUpload::Verified(receipt)),
        }
    }
}

enum Admission {
    Prepared(Box<ReadyShardUpload>),
    Verified(ShardReceipt),
}

async fn admit(
    connection: &quinn::Connection,
    request: ResumeShardPutRequest,
    intent: ShardPutIntent,
    limits: WireLimits,
) -> Result<Admission, DataPlaneError> {
    let admission_only = request.admission_only;
    let original_intent = request
        .intent
        .clone()
        .ok_or(DataPlaneError::InvalidMessage)?;
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::ResumeShardPutRequest(request)),
        },
        limits,
    )
    .await?;
    let envelope = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Some(Message::ResumeShardPutResult(result)) = envelope.message else {
        return Err(DataPlaneError::InvalidMessage);
    };
    if result.intent.as_ref() != Some(&original_intent) {
        return Err(DataPlaneError::InvalidMessage);
    }
    if admission_only {
        let mut trailing = [0; 1];
        if receive
            .read(&mut trailing)
            .await
            .map_err(quinn::ReadExactError::from)
            .map_err(meshspan_transport::TransportError::from)?
            .is_some()
        {
            return Err(DataPlaneError::InvalidMessage);
        }
    }
    match result.outcome.ok_or(DataPlaneError::InvalidMessage)? {
        Outcome::Rejection(error) => Err(remote_rejection(&error)?),
        Outcome::Verified(payload) => verified(&payload, intent).map(Admission::Verified),
        Outcome::Ready(ready) => {
            let payload = ready.original.ok_or(DataPlaneError::InvalidMessage)?;
            let identity = decode_put_identity(&payload.canonical_bytes)?;
            if payload.format_version != 1
                || identity.intent() != intent
                || intent
                    .admitted(identity.reservation)
                    .map_err(DataPlaneError::Contract)?
                    != identity
            {
                return Err(DataPlaneError::InvalidMessage);
            }
            Ok(Admission::Prepared(Box::new(ReadyShardUpload {
                identity,
                logical_shard: intent.shard,
                send,
                receive,
                maximum_frame_bytes: ready.maximum_frame_bytes,
                limits,
                connection_id: connection.stable_id(),
            })))
        }
    }
}

fn verified(
    payload: &VersionedPayload,
    intent: ShardPutIntent,
) -> Result<ShardReceipt, DataPlaneError> {
    let receipt = receipt(Some(payload))?;
    if receipt
        != (ShardReceipt {
            operation_id: intent.context.operation_id,
            shard: intent.shard,
            length: intent.expected_length,
            digest: intent.expected_digest,
            target_id: intent.target_id,
            target_generation: intent.target_generation,
        })
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(receipt)
}

fn validate_request(
    header: &RequestHeader,
    intent: ShardPutIntent,
    authority: ShardWritePermit,
) -> Result<(), DataPlaneError> {
    intent.validate().map_err(DataPlaneError::Contract)?;
    if header.mesh_id.as_slice() != authority.mesh_id.as_bytes()
        || header.operation_id.as_slice() != intent.context.operation_id.as_bytes()
        || header.deadline_unix_micros > authority.expires_at.get()
        || authority.operation_id != intent.context.operation_id
        || authority.target_id != intent.target_id
        || authority.target_generation != intent.target_generation
        || authority.shard != intent.shard
        || authority.reservation_class != intent.reservation_class
        || intent.reservation_class == ReservationClass::ForegroundWrite
        || intent.maximum_bytes > authority.maximum_bytes
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(())
}
