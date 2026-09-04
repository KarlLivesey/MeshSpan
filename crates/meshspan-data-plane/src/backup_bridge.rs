// SPDX-License-Identifier: GPL-2.0-only

//! Bounded adapters between asynchronous frames and synchronous backup providers.

use std::io::{Error, ErrorKind, Read, Result, Write};

/// Blocking reader fed by a bounded asynchronous frame channel.
pub(crate) struct ProviderReader {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    current: std::io::Cursor<Vec<u8>>,
}

impl ProviderReader {
    pub(crate) fn new(receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            receiver,
            current: std::io::Cursor::new(Vec::new()),
        }
    }
}

impl Read for ProviderReader {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        loop {
            let read = self.current.read(destination)?;
            if read != 0 {
                return Ok(read);
            }
            let Some(next) = self.receiver.blocking_recv() else {
                return Ok(0);
            };
            self.current = std::io::Cursor::new(next);
        }
    }
}

/// Blocking writer drained through a bounded asynchronous frame channel.
pub(crate) struct ProviderWriter {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    maximum_chunk_bytes: usize,
}

impl ProviderWriter {
    pub(crate) const fn new(
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
        maximum_chunk_bytes: usize,
    ) -> Self {
        Self {
            sender,
            maximum_chunk_bytes,
        }
    }
}

impl Write for ProviderWriter {
    fn write(&mut self, source: &[u8]) -> Result<usize> {
        if source.is_empty() {
            return Ok(0);
        }
        if self.maximum_chunk_bytes == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "zero chunk bound"));
        }
        let written = source.len().min(self.maximum_chunk_bytes);
        self.sender
            .blocking_send(source[..written].to_vec())
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "backup receiver closed"))?;
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
