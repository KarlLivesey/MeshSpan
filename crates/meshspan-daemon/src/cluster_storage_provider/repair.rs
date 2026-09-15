// SPDX-License-Identifier: GPL-2.0-only

//! Repair admission closes before reconstruction; byte transfer owns a separate bounded stream.

use meshspan_contracts::{
    ContractError, PutShardRequest, RepairPutAdmission, ShardPutIntent, ShardReceipt,
    ShardWritePermit,
};
use meshspan_data_plane::{RepairShardUpload, ShardUploadClient};
use meshspan_protocol::{WireLimits, v1::RequestHeader};

use super::{ClusterShardRouter, map_data_plane_error};

struct RepairConnection {
    connection: quinn::Connection,
    header: RequestHeader,
    limits: WireLimits,
}

impl ClusterShardRouter {
    pub(super) fn remote_prepare_repair(
        &mut self,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
    ) -> Result<RepairPutAdmission, ContractError> {
        let route = self.repair_connection(authority)?;
        let client = ShardUploadClient::new(
            &route.connection,
            route.limits,
            &crate::OperatingSystemClock,
        );
        self.runtime
            .block_on(client.prepare_repair_put(route.header, intent, authority))
            .map_err(|error| map_data_plane_error(&error))
    }

    pub(super) fn remote_finish_repair(
        &mut self,
        request: &PutShardRequest,
        authority: ShardWritePermit,
    ) -> Result<ShardReceipt, ContractError> {
        let route = self.repair_connection(authority)?;
        self.runtime
            .block_on(async {
                let client = ShardUploadClient::new(
                    &route.connection,
                    route.limits,
                    &crate::OperatingSystemClock,
                );
                match client
                    .resume_repair_upload(route.header, request.identity().intent(), authority)
                    .await?
                {
                    RepairShardUpload::Verified(receipt) => Ok(receipt),
                    RepairShardUpload::Prepared(prepared) => {
                        if prepared.identity() != request.identity() {
                            return Err(meshspan_data_plane::DataPlaneError::InvalidMessage);
                        }
                        client.finish_upload(prepared, &request.bytes).await
                    }
                }
            })
            .map_err(|error| map_data_plane_error(&error))
    }

    fn repair_connection(
        &self,
        authority: ShardWritePermit,
    ) -> Result<RepairConnection, ContractError> {
        let route = self.writable_route(authority.target_id, authority.target_generation)?;
        let network = self
            .network
            .network()
            .map_err(|()| ContractError::Unavailable)?;
        let header = network
            .control_header(authority.operation_id, authority.expires_at.get())
            .map_err(|_| ContractError::InvalidInput)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(route.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        Ok(RepairConnection {
            connection,
            header,
            limits: network.wire_limits(),
        })
    }
}
