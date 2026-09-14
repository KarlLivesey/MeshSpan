// SPDX-License-Identifier: GPL-2.0-only

//! One-frame forwarding verifies bytes independently without buffering the whole backup.

use super::{Error, Forwarding};
use meshspan_contracts::{BackupObjectIdentity, ContractError};
use meshspan_transport::{TransportError, receive_data_frame, send_data_frame};
use sha2::{Digest, Sha256};

impl Forwarding<'_, '_> {
    pub(super) async fn copy_bytes(
        &self,
        receive: &mut quinn::RecvStream,
        send: &mut quinn::SendStream,
        object: BackupObjectIdentity,
        maximum: usize,
    ) -> Result<(), Error> {
        let limits = meshspan_protocol::WireLimits::new(
            self.context
                .limits
                .maximum_control_bytes()
                .min(self.context.io.limits.maximum_control_bytes()),
            maximum,
            self.context.limits.maximum_items(),
            self.context.limits.maximum_text_bytes(),
        )
        .map_err(TransportError::from)?;
        let mut offset = 0_u64;
        let mut digest = Sha256::new();
        while offset < object.byte_length {
            self.check()?;
            let frame = receive_data_frame(receive, limits).await?.into_inner();
            self.check()?;
            let next = offset
                .checked_add(frame.bytes.len() as u64)
                .ok_or(ContractError::InvalidInput)?;
            if frame.offset != offset || next > object.byte_length {
                return Err(ContractError::InvalidInput.into());
            }
            digest.update(&frame.bytes);
            send_data_frame(send, &frame, limits).await?;
            offset = next;
        }
        if <[u8; 32]>::from(digest.finalize()) != object.digest {
            return Err(ContractError::InvalidInput.into());
        }
        self.check()
    }

    pub(super) async fn clean_end(&self, receive: &mut quinn::RecvStream) -> Result<(), Error> {
        let mut excess = [0_u8; 1];
        if receive
            .read(&mut excess)
            .await
            .map_err(|error| TransportError::from(quinn::ReadExactError::ReadError(error)))?
            .is_some()
        {
            return Err(ContractError::InvalidInput.into());
        }
        self.check()
    }
}
