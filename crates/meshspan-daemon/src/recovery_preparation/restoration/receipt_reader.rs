// SPDX-License-Identifier: GPL-2.0-only

//! Bounded canonical receipt stream reader with optional private snapshotting during validation.

use super::Error;
use crate::protected_file;
use meshspan_contracts::{ShardReceipt, decode_shard_receipt_v1};
use meshspan_metadata::RecoveryShardRestoration;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

pub(super) struct ReceiptReader<'a> {
    input: BufReader<File>,
    output: Option<File>,
    claim: &'a RecoveryShardRestoration,
    digest: Sha256,
    count: u64,
    bytes: u64,
    state: ReadState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadState {
    Active,
    Complete,
    Failed,
}

impl<'a> ReceiptReader<'a> {
    pub(super) fn open(
        source: &Path,
        claim: &'a RecoveryShardRestoration,
        snapshot: Option<&Path>,
    ) -> Result<Self, Error> {
        let input = protected_file::open_read(source).map_err(|_| Error::Input)?;
        let expected = claim
            .receipt_count
            .checked_mul(128)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or(Error::Input)?;
        if input.metadata().map_err(|_| Error::Input)?.len() != expected {
            return Err(Error::Content);
        }
        let output = snapshot
            .map(|file| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(file)
            })
            .transpose()
            .map_err(|_| Error::Workspace)?;
        let mut result = Self {
            input: BufReader::new(input),
            output,
            claim,
            digest: Sha256::new(),
            count: 0,
            bytes: 0,
            state: ReadState::Active,
        };
        let mut magic = [0; 8];
        result
            .input
            .read_exact(&mut magic)
            .map_err(|_| Error::Content)?;
        if magic != *b"MSRRCPT\x01" {
            return Err(Error::Content);
        }
        result.capture(&magic)?;
        Ok(result)
    }

    pub(super) fn finish(mut self) -> Result<(), Error> {
        if self.state == ReadState::Failed
            || self.count != self.claim.receipt_count
            || self.next().is_some()
        {
            return Err(Error::Content);
        }
        if let Some(output) = self.output {
            output.sync_all().map_err(|_| Error::Workspace)?;
        }
        Ok(())
    }

    fn read(&mut self) -> Result<Option<ShardReceipt>, Error> {
        if self.count == self.claim.receipt_count {
            let mut extra = [0];
            if self.input.read(&mut extra).map_err(|_| Error::Content)? != 0
                || self.bytes != self.claim.encrypted_bytes
                || <[u8; 32]>::from(self.digest.clone().finalize()) != self.claim.receipts_digest
            {
                return Err(Error::Content);
            }
            return Ok(None);
        }
        let mut frame = [0; 128];
        self.input
            .read_exact(&mut frame)
            .map_err(|_| Error::Content)?;
        if frame[..2] != 126_u16.to_be_bytes() {
            return Err(Error::Content);
        }
        let receipt = decode_shard_receipt_v1(&frame[2..]).map_err(|_| Error::Content)?;
        self.capture(&frame)?;
        self.count += 1;
        self.bytes = self
            .bytes
            .checked_add(receipt.length)
            .ok_or(Error::Content)?;
        Ok(Some(receipt))
    }

    fn capture(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.digest.update(bytes);
        if let Some(output) = &mut self.output {
            output.write_all(bytes).map_err(|_| Error::Workspace)?;
        }
        Ok(())
    }
}

impl Iterator for ReceiptReader<'_> {
    type Item = Result<ShardReceipt, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.state != ReadState::Active {
            return None;
        }
        match self.read() {
            Ok(Some(receipt)) => Some(Ok(receipt)),
            Ok(None) => {
                self.state = ReadState::Complete;
                None
            }
            Err(error) => {
                self.state = ReadState::Failed;
                Some(Err(error))
            }
        }
    }
}
