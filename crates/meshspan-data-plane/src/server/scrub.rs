// SPDX-License-Identifier: GPL-2.0-only

//! Exact federated provider scrub result framing.

use meshspan_contracts::{ContractError, ScrubObservation};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{DataControlEnvelope, ScrubShardResult};
use meshspan_transport::{AcceptedStream, send_data_control};

use crate::DataPlaneError;
use crate::wire::{durable_result, rejected_result, scrub_observation_payload};

pub(super) async fn reject_scrub(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), DataPlaneError> {
    send_scrub_result(stream, limits, Err(error)).await
}

pub(super) async fn send_scrub_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<ScrubObservation, ContractError>,
) -> Result<(), DataPlaneError> {
    let (operation, observation) = match result {
        Ok(observation) => (
            durable_result(),
            Some(scrub_observation_payload(observation)?),
        ),
        Err(error) => (rejected_result(error), None),
    };
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::ScrubShardResult(ScrubShardResult {
                result: Some(operation),
                observation,
            })),
        },
        limits,
    )
    .await?;
    stream
        .send
        .finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(())
}
