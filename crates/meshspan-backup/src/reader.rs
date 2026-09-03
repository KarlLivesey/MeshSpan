// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed encrypted-backup restoration.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_secret_envelope::WrappingPrivateKey;
use sha2::{Digest, Sha256};

use crate::format::{
    AUTHENTICATION_TAG_BYTES, BackupHeader, FORMAT_VERSION, MAGIC, MAXIMUM_HEADER_BYTES, chunk_aad,
    chunk_count, chunk_nonce, chunk_plaintext_length, hash_file,
};
use crate::{BackupError, BackupFileEvidence};

/// Restores exact plaintext bytes from an authenticated backup into a new path.
///
/// The destination is never overwritten. A failed restore remains an untrusted
/// staged file and must not be opened as an authoritative database.
///
/// # Errors
///
/// Rejects changed container evidence, unexpected source state, unknown formats,
/// wrong recovery keys, authentication failures, trailing bytes and existing destinations.
pub fn restore_backup(
    source: &Path,
    destination: &Path,
    evidence: BackupFileEvidence,
    recipient: &WrappingPrivateKey,
) -> Result<(), BackupError> {
    evidence
        .source
        .validate()
        .map_err(|_| BackupError::Corrupt)?;
    if evidence.byte_length == 0 || evidence.digest == [0; 32] {
        return Err(BackupError::Corrupt);
    }
    if hash_file(source)? != (evidence.byte_length, evidence.digest) {
        return Err(BackupError::Corrupt);
    }
    let mut source_file = File::open(source)?;
    let (header, header_digest) = read_header(&mut source_file)?;
    if header.source != evidence.source {
        return Err(BackupError::Corrupt);
    }
    let content_key = open_content_key(&header, recipient)?;
    let mut destination_file = create_destination(destination)?;
    restore_chunks(
        &mut source_file,
        &mut destination_file,
        &header,
        content_key.expose(),
        header_digest,
    )?;
    destination_file.sync_all()?;
    Ok(())
}

fn read_header(source: &mut File) -> Result<(BackupHeader, [u8; 32]), BackupError> {
    if read_array::<8>(source)? != MAGIC
        || u16::from_be_bytes(read_array(source)?) != FORMAT_VERSION
    {
        return Err(BackupError::Corrupt);
    }
    let length = usize::try_from(u32::from_be_bytes(read_array(source)?))
        .map_err(|_| BackupError::Corrupt)?;
    if length == 0 || length > MAXIMUM_HEADER_BYTES {
        return Err(BackupError::Corrupt);
    }
    let mut bytes = vec![0; length];
    read_exact(source, &mut bytes)?;
    let digest = Sha256::digest(&bytes).into();
    Ok((BackupHeader::decode(&bytes)?, digest))
}

fn open_content_key(
    header: &BackupHeader,
    recipient: &WrappingPrivateKey,
) -> Result<meshspan_secret_envelope::SecretPlaintext, BackupError> {
    let recipient_public = recipient.public_key();
    let envelope = header
        .recipient_envelopes
        .iter()
        .find(|envelope| envelope.recipient_public_key().ok() == Some(recipient_public))
        .ok_or(BackupError::RecipientUnavailable)?;
    let wrapping_key = envelope.open(recipient)?;
    let content_key = header.encrypted_content_key.decrypt(&wrapping_key)?;
    if content_key.expose().len() != 32 {
        return Err(BackupError::Corrupt);
    }
    Ok(content_key)
}

fn create_destination(destination: &Path) -> Result<File, BackupError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                BackupError::DestinationExists
            } else {
                BackupError::Io(error)
            }
        })
}

fn restore_chunks(
    source: &mut File,
    destination: &mut File,
    header: &BackupHeader,
    content_key: &[u8],
    header_digest: [u8; 32],
) -> Result<(), BackupError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(content_key).map_err(|_| BackupError::Corrupt)?;
    let mut digest = Sha256::new();
    for index in 0..chunk_count(header.source.byte_length) {
        let plaintext_length = chunk_plaintext_length(header.source.byte_length, index)?;
        let mut ciphertext = vec![0; plaintext_length + AUTHENTICATION_TAG_BYTES];
        read_exact(source, &mut ciphertext)?;
        let nonce = chunk_nonce(header.nonce_prefix, index);
        let aad = chunk_aad(header_digest, index, plaintext_length);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BackupError::Corrupt)?;
        if plaintext.len() != plaintext_length {
            return Err(BackupError::Corrupt);
        }
        digest.update(&plaintext);
        destination.write_all(&plaintext)?;
    }
    let mut trailing = [0_u8; 1];
    if source.read(&mut trailing)? != 0 || digest.finalize().as_slice() != header.source.digest {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

fn read_array<const LENGTH: usize>(source: &mut File) -> Result<[u8; LENGTH], BackupError> {
    let mut value = [0; LENGTH];
    read_exact(source, &mut value)?;
    Ok(value)
}

fn read_exact(source: &mut File, destination: &mut [u8]) -> Result<(), BackupError> {
    source.read_exact(destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            BackupError::Corrupt
        } else {
            BackupError::Io(error)
        }
    })
}
