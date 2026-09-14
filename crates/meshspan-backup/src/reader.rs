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
use crate::{
    BackupError, BackupFileEvidence, BackupFiles, BackupHistoryEvidence, BackupJournalEvidence,
};

/// Reads the source manifest only after matching an independently retained container digest.
///
/// This does not decrypt the backup or verify its database. Callers must subsequently restore
/// and validate the authenticated contents before reporting recoverability. The digest must
/// come from a trusted export receipt, not be calculated from an untrusted replacement file.
///
/// # Errors
/// Rejects non-regular inputs, changed container bytes and malformed or unknown headers.
pub fn read_backup_evidence(
    source: &Path,
    expected_digest: [u8; 32],
) -> Result<BackupFileEvidence, BackupError> {
    if expected_digest == [0; 32] || !std::fs::symlink_metadata(source)?.is_file() {
        return Err(BackupError::InvalidInput);
    }
    let (byte_length, digest) = hash_file(source)?;
    if digest != expected_digest {
        return Err(BackupError::Corrupt);
    }
    let (header, _) = read_header(&mut File::open(source)?)?;
    Ok(BackupFileEvidence {
        source: header.source,
        byte_length,
        digest,
    })
}

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
    restore_backup_files(
        source,
        BackupFiles {
            metadata: destination,
            history: None,
        },
        evidence,
        recipient,
    )
    .map(|_| ())
}

/// Restores fixed caller-selected members, authenticating every byte even when history is discarded.
/// A requested history pair must exist in the archive. Returned journal evidence describes bytes,
/// not valid SQLite state, complete roots, available shards or authority to start services.
/// # Errors
/// Rejects missing requested members, changed evidence, malformed/authentication failures,
/// existing destinations and IO failures. Partial private outputs may remain on failure.
pub fn restore_backup_files(
    source: &Path,
    destinations: BackupFiles<'_>,
    evidence: BackupFileEvidence,
    recipient: &WrappingPrivateKey,
) -> Result<Option<BackupHistoryEvidence>, BackupError> {
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
    if destinations.history.is_some() && header.history.is_none() {
        return Err(BackupError::InvalidInput);
    }
    let content_key = open_content_key(&header, recipient)?;
    let mut stream = DecryptionStream {
        cipher: XChaCha20Poly1305::new_from_slice(content_key.expose())
            .map_err(|_| BackupError::Corrupt)?,
        nonce_prefix: header.nonce_prefix,
        header_digest,
        next_index: 0,
    };
    let mut destination_file = create_destination(destinations.metadata)?;
    stream.member(
        &mut source_file,
        &mut destination_file,
        BackupJournalEvidence {
            byte_length: header.source.byte_length,
            digest: header.source.digest,
        },
    )?;
    destination_file.sync_all()?;
    if let Some(history) = header.history {
        for (journal, destination) in [
            (
                history.namespace,
                destinations.history.map(|files| files.namespace),
            ),
            (
                history.content,
                destinations.history.map(|files| files.content),
            ),
        ] {
            match destination {
                Some(destination) => {
                    let mut file = create_destination(destination)?;
                    stream.member(&mut source_file, &mut file, journal)?;
                    file.sync_all()?;
                }
                None => stream.member(&mut source_file, &mut std::io::sink(), journal)?,
            }
        }
    }
    let mut trailing = [0_u8; 1];
    if source_file.read(&mut trailing)? != 0 {
        return Err(BackupError::Corrupt);
    }
    Ok(header.history)
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

struct DecryptionStream {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; 16],
    header_digest: [u8; 32],
    next_index: u64,
}

impl DecryptionStream {
    fn member(
        &mut self,
        source: &mut File,
        destination: &mut dyn Write,
        evidence: BackupJournalEvidence,
    ) -> Result<(), BackupError> {
        let mut digest = Sha256::new();
        for member_index in 0..chunk_count(evidence.byte_length) {
            let plaintext_length = chunk_plaintext_length(evidence.byte_length, member_index)?;
            let mut ciphertext = vec![0; plaintext_length + AUTHENTICATION_TAG_BYTES];
            read_exact(source, &mut ciphertext)?;
            let nonce = chunk_nonce(self.nonce_prefix, self.next_index);
            let aad = chunk_aad(self.header_digest, self.next_index, plaintext_length);
            let plaintext = zeroize::Zeroizing::new(
                self.cipher
                    .decrypt(
                        &XNonce::from(nonce),
                        Payload {
                            msg: &ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| BackupError::Corrupt)?,
            );
            if plaintext.len() != plaintext_length {
                return Err(BackupError::Corrupt);
            }
            digest.update(&plaintext);
            destination.write_all(&plaintext)?;
            self.next_index = self.next_index.checked_add(1).ok_or(BackupError::Corrupt)?;
        }
        if digest.finalize().as_slice() != evidence.digest {
            return Err(BackupError::Corrupt);
        }
        Ok(())
    }
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
