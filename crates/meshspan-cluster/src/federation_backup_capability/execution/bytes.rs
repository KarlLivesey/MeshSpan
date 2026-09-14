// SPDX-License-Identifier: GPL-2.0-only

//! Exact bounded frames and end-of-input proof for the blocking backup provider adapter.

use super::{Transfer, wait};
use meshspan_protocol::v1::DataFrame;
use meshspan_transport::{TransportError, receive_data_frame, send_data_frame};
use sha2::Digest;
use std::io::{self, Cursor, Read, Write};

impl Read for Transfer<'_, '_> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        self.check().map_err(rejected)?;
        self.ready(None).map_err(rejected)?;
        let read = self.pending.read(destination)?;
        if read > 0 {
            return Ok(read);
        }
        if self.finished {
            return Ok(0);
        }
        if self.offset == self.permit.request.object().byte_length {
            self.verify_measurement().map_err(rejected)?;
            // The signed execute request binds exact length/digest. FIN is the upload commit
            // marker; extra bytes or a reset must fail before the provider can publish the object.
            let mut excess = [0_u8; 1];
            let received = wait(self.context.runtime, self.deadline, async {
                self.stream
                    .receive
                    .read(&mut excess)
                    .await
                    .map_err(|error| TransportError::from(quinn::ReadExactError::ReadError(error)))
            })
            .map_err(rejected)?;
            if received.is_some() {
                return Err(invalid());
            }
            self.check().map_err(rejected)?;
            self.finished = true;
            return Ok(0);
        }
        let frame = wait(
            self.context.runtime,
            self.deadline,
            receive_data_frame(&mut self.stream.receive, self.context.limits),
        )
        .map_err(rejected)?
        .into_inner();
        self.check().map_err(rejected)?;
        let next = self
            .offset
            .checked_add(frame.bytes.len() as u64)
            .ok_or_else(invalid)?;
        if frame.offset != self.offset || next > self.permit.request.object().byte_length {
            return Err(invalid());
        }
        self.offset = next;
        self.digest.update(&frame.bytes);
        self.pending = Cursor::new(frame.bytes);
        self.pending.read(destination)
    }
}

impl Write for Transfer<'_, '_> {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        if source.is_empty() {
            return Ok(0);
        }
        self.check().map_err(rejected)?;
        let length = source
            .len()
            .min(self.context.limits.maximum_data_frame_bytes());
        let next = self.offset.checked_add(length as u64).ok_or_else(invalid)?;
        if next > self.permit.request.object().byte_length {
            return Err(invalid());
        }
        let frame = DataFrame {
            offset: self.offset,
            bytes: source[..length].to_vec(),
        };
        wait(
            self.context.runtime,
            self.deadline,
            send_data_frame(&mut self.stream.send, &frame, self.context.limits),
        )
        .map_err(rejected)?;
        self.offset = next;
        self.digest.update(&frame.bytes);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check().map_err(rejected)
    }
}

fn rejected(_error: impl std::error::Error) -> io::Error {
    io::Error::other("federated backup stream authority or IO rejected")
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "federated backup frame does not match its exact request",
    )
}
