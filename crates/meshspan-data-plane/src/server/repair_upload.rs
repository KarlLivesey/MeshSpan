// SPDX-License-Identifier: GPL-2.0-only

//! Native repair upload resumes the retained physical intent with separately refreshed authority.

use meshspan_contracts::{
    ContractError, PutShardRequest, RepairPutAdmission, ReservationClass, ShardPutIntent,
    ShardWritePermit, StorageProvider, decode_shard_put_intent_v1, verify_write_permit_mac,
};
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, ResumeShardPutReady, ResumeShardPutRequest, ResumeShardPutResult,
        VersionedPayload, data_control_envelope::Message, resume_shard_put_result::Outcome,
    },
};
use meshspan_transport::{AcceptedStream, send_data_control};

use super::{RemoteShardService, receive_put_payload, send_put_result};
use crate::{
    DataPlaneError,
    capability::{decode_write_permit, encode_put_identity},
    wire::{receipt_payload, request_context, wire_error},
};

impl<P: StorageProvider> RemoteShardService<P> {
    pub(super) async fn serve_repair_upload(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        request: ResumeShardPutRequest,
    ) -> Result<(), DataPlaneError> {
        let header = request
            .header
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?;
        let time = UploadLifetime::new(observed_at, UnixMicros::new(header.deadline_unix_micros))?;
        let payload = request
            .intent
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?;
        if payload.format_version != 1 {
            return Err(DataPlaneError::InvalidMessage);
        }
        let intent = decode_shard_put_intent_v1(&payload.canonical_bytes)
            .map_err(DataPlaneError::Contract)?;
        let authority = match self.authorise_repair_upload(&request, intent, time.now()?) {
            Ok(authority) => authority,
            Err(error) => {
                return send_admission(
                    stream,
                    limits,
                    payload.clone(),
                    Outcome::Rejection(wire_error(error)),
                )
                .await;
            }
        };
        tokio::time::timeout_at(
            time.deadline,
            self.serve_authorised_repair(stream, limits, intent, authority, time),
        )
        .await
        .map_err(|_| DataPlaneError::Contract(ContractError::DeadlineExceeded))?
    }

    async fn serve_authorised_repair(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
        time: UploadLifetime,
    ) -> Result<(), DataPlaneError> {
        let payload = VersionedPayload {
            format_version: 1,
            canonical_bytes: meshspan_contracts::encode_shard_put_intent_v1(intent).to_vec(),
        };
        let original = match self
            .provider
            .prepare_repair_put(intent, authority, time.now()?)
        {
            Ok(RepairPutAdmission::Prepared(original)) => original,
            Ok(RepairPutAdmission::Verified(receipt)) => {
                time.now()?;
                return send_admission(
                    stream,
                    limits,
                    payload,
                    Outcome::Verified(receipt_payload(receipt)),
                )
                .await;
            }
            Err(error) => {
                return send_admission(
                    stream,
                    limits,
                    payload,
                    Outcome::Rejection(wire_error(error)),
                )
                .await;
            }
        };
        time.now()?;
        send_admission(
            stream,
            limits,
            payload,
            Outcome::Ready(ResumeShardPutReady {
                original: Some(VersionedPayload {
                    format_version: 1,
                    canonical_bytes: encode_put_identity(original),
                }),
                maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
            }),
        )
        .await?;
        let bytes = receive_put_payload(
            &mut stream.receive,
            (intent.expected_length, intent.expected_digest),
            limits,
            self.maximum_shard_bytes,
        )
        .await?;
        let result = self.provider.finish_repair_put(
            PutShardRequest {
                context: original.context,
                reservation: original.reservation,
                shard: original.shard,
                expected_length: original.expected_length,
                expected_digest: original.expected_digest,
                bytes,
            },
            authority,
            time.now()?,
        );
        send_put_result(stream, limits, result).await?;
        Ok(())
    }

    fn authorise_repair_upload(
        &self,
        request: &ResumeShardPutRequest,
        intent: ShardPutIntent,
        now: UnixMicros,
    ) -> Result<ShardWritePermit, ContractError> {
        let authority = decode_write_permit(&request.write_capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = request.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let context = request_context(header, authority.authorization_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let scope_matches = authority.mesh_id == self.mesh_id
            && header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && request.target_id.as_slice() == self.target_id.as_bytes()
            && request.target_generation == self.target_generation
            && intent.target_id == self.target_id
            && intent.target_generation == self.target_generation
            && authority.target_id == intent.target_id
            && authority.target_generation == intent.target_generation;
        let operation_matches = context.operation_id == intent.context.operation_id
            && authority.operation_id == intent.context.operation_id
            && authority.shard == intent.shard
            && authority.reservation_class == intent.reservation_class
            && intent.reservation_class != ReservationClass::ForegroundWrite;
        if !scope_matches
            || !operation_matches
            || !verify_write_permit_mac(&self.write_key, authority)
            || intent.maximum_bytes > authority.maximum_bytes
            || intent.maximum_bytes > self.maximum_shard_bytes as u64
            || context.deadline > authority.expires_at
            || context.deadline <= now
        {
            return Err(ContractError::Unauthorized);
        }
        Ok(authority)
    }
}

async fn send_admission(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    intent: VersionedPayload,
    outcome: Outcome,
) -> Result<(), DataPlaneError> {
    let terminal = !matches!(outcome, Outcome::Ready(_));
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::ResumeShardPutResult(ResumeShardPutResult {
                intent: Some(intent),
                outcome: Some(outcome),
            })),
        },
        limits,
    )
    .await?;
    if terminal {
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
    }
    Ok(())
}

/// The caller's clock sample advances monotonically while bytes arrive; preparation-time
/// authority is never reused as if no time passed at the final provider write boundary.
#[derive(Clone, Copy)]
struct UploadLifetime {
    observed_at: UnixMicros,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

impl UploadLifetime {
    fn new(observed_at: UnixMicros, expires_at: UnixMicros) -> Result<Self, DataPlaneError> {
        let remaining = expires_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|micros| *micros > 0 && observed_at.get() >= 0)
            .and_then(|micros| u64::try_from(micros).ok())
            .ok_or(DataPlaneError::Contract(ContractError::DeadlineExceeded))?;
        let started = tokio::time::Instant::now();
        let deadline = started
            .checked_add(std::time::Duration::from_micros(remaining))
            .ok_or(DataPlaneError::InvalidMessage)?;
        Ok(Self {
            observed_at,
            started,
            deadline,
        })
    }

    fn now(self) -> Result<UnixMicros, DataPlaneError> {
        self.now_at(tokio::time::Instant::now())
    }

    fn now_at(self, now: tokio::time::Instant) -> Result<UnixMicros, DataPlaneError> {
        if now >= self.deadline {
            return Err(DataPlaneError::Contract(ContractError::DeadlineExceeded));
        }
        let elapsed = now
            .checked_duration_since(self.started)
            .ok_or(DataPlaneError::InvalidMessage)?;
        let elapsed =
            i64::try_from(elapsed.as_micros()).map_err(|_| DataPlaneError::InvalidMessage)?;
        self.observed_at
            .get()
            .checked_add(elapsed)
            .map(UnixMicros::new)
            .ok_or(DataPlaneError::InvalidMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_byte_admission_advances_time_and_expires_at_the_exact_fresh_deadline()
    -> Result<(), DataPlaneError> {
        let lifetime =
            UploadLifetime::new(UnixMicros::new(15_000_000), UnixMicros::new(20_000_000))?;
        assert_eq!(
            lifetime.now_at(lifetime.started + std::time::Duration::from_micros(3_000))?,
            UnixMicros::new(15_003_000)
        );
        assert!(matches!(
            lifetime.now_at(lifetime.deadline),
            Err(DataPlaneError::Contract(ContractError::DeadlineExceeded))
        ));
        assert!(
            UploadLifetime::new(UnixMicros::new(20_000_000), UnixMicros::new(20_000_000)).is_err()
        );
        assert!(UploadLifetime::new(UnixMicros::new(-1), UnixMicros::new(20_000_000)).is_err());
        Ok(())
    }
}
