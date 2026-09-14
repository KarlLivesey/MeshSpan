// SPDX-License-Identifier: GPL-2.0-only

//! Streaming encrypted-backup creation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::RandomSource;
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::format::{
    BackupHeader, CHUNK_BYTES, CONTENT_KEY_GENERATION, CONTENT_KEY_SECRET_KIND, FORMAT_VERSION,
    MAGIC, chunk_aad, chunk_count, chunk_nonce, hash_file,
};
use crate::{
    BackupError, BackupFileEvidence, BackupFiles, BackupHistoryEvidence, BackupJournalEvidence,
    BackupSourceManifest,
};

/// Encrypts one closed exact-state database backup into a new destination.
///
/// The destination is never overwritten. A failure may leave an unauthenticated
/// staged file at that path; callers must not publish it without returned evidence.
///
/// # Errors
///
/// Rejects changed source bytes, invalid manifests or recipients, existing
/// destinations, unavailable entropy and filesystem or authentication failures.
pub fn encrypt_backup(
    source: &Path,
    destination: &Path,
    manifest: BackupSourceManifest,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<BackupFileEvidence, BackupError> {
    encrypt_backup_files(
        BackupFiles {
            metadata: source,
            history: None,
        },
        destination,
        manifest,
        recipients,
        random,
    )
}

/// Encrypts a closed control snapshot and optional fixed history pair as one authenticated archive.
/// Each member has independent plaintext evidence; all share the authenticated header and a
/// strictly increasing nonce counter. Callers must verify cross-journal/root consistency first.
/// # Errors
/// Rejects changed or invalid source evidence, unsafe inputs, existing output, entropy or IO failures.
/// Partial output is not publishable without the returned complete-container evidence.
pub fn encrypt_backup_files(
    sources: BackupFiles<'_>,
    destination: &Path,
    manifest: BackupSourceManifest,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<BackupFileEvidence, BackupError> {
    manifest.validate()?;
    if recipients.is_empty() {
        return Err(BackupError::InvalidInput);
    }
    let observed = journal_evidence(sources.metadata)?;
    if (observed.byte_length, observed.digest) != (manifest.byte_length, manifest.digest) {
        return Err(BackupError::InvalidInput);
    }
    let history = sources
        .history
        .map(|files| {
            Ok::<_, BackupError>(BackupHistoryEvidence {
                namespace: journal_evidence(files.namespace)?,
                content: journal_evidence(files.content)?,
            })
        })
        .transpose()?;
    let mut destination_file = create_destination(destination)?;
    let (header, content_key) = create_header(manifest, history, recipients, random)?;
    write_container(sources, &mut destination_file, &header, &content_key)?;
    destination_file.sync_all()?;
    drop(destination_file);
    let (byte_length, digest) = hash_file(destination)?;
    Ok(BackupFileEvidence {
        source: manifest,
        byte_length,
        digest,
    })
}

fn journal_evidence(source: &Path) -> Result<BackupJournalEvidence, BackupError> {
    if !std::fs::symlink_metadata(source)?.is_file() {
        return Err(BackupError::InvalidInput);
    }
    let (byte_length, digest) = hash_file(source)?;
    if byte_length == 0 {
        return Err(BackupError::InvalidInput);
    }
    Ok(BackupJournalEvidence {
        byte_length,
        digest,
    })
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

fn create_header(
    source: BackupSourceManifest,
    history: Option<BackupHistoryEvidence>,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<(BackupHeader, Zeroizing<[u8; 32]>), BackupError> {
    let mut content_key = Zeroizing::new([0_u8; 32]);
    random
        .fill_bytes(content_key.as_mut())
        .map_err(|_| BackupError::Cryptography)?;
    let mut nonce_prefix = [0_u8; 16];
    random
        .fill_bytes(&mut nonce_prefix)
        .map_err(|_| BackupError::Cryptography)?;
    if content_key.as_ref() == [0; 32] || nonce_prefix == [0; 16] {
        return Err(BackupError::Cryptography);
    }
    let context = SecretContext::new(
        CONTENT_KEY_SECRET_KIND,
        source.backup_id.as_bytes(),
        CONTENT_KEY_GENERATION,
    )?;
    let (encrypted_content_key, recipient_envelopes) =
        encrypt_secret(context, content_key.as_ref(), recipients, random)?;
    Ok((
        BackupHeader {
            source,
            history,
            nonce_prefix,
            encrypted_content_key,
            recipient_envelopes,
        },
        content_key,
    ))
}

fn write_container(
    sources: BackupFiles<'_>,
    destination: &mut File,
    header: &BackupHeader,
    content_key: &[u8; 32],
) -> Result<(), BackupError> {
    let header_bytes = header.encode()?;
    destination.write_all(&MAGIC)?;
    destination.write_all(&FORMAT_VERSION.to_be_bytes())?;
    destination.write_all(
        &u32::try_from(header_bytes.len())
            .map_err(|_| BackupError::InvalidInput)?
            .to_be_bytes(),
    )?;
    destination.write_all(&header_bytes)?;
    let header_digest: [u8; 32] = Sha256::digest(&header_bytes).into();
    let mut stream = EncryptionStream {
        cipher: XChaCha20Poly1305::new_from_slice(content_key)
            .map_err(|_| BackupError::Cryptography)?,
        nonce_prefix: header.nonce_prefix,
        header_digest,
        next_index: 0,
    };
    stream.member(
        sources.metadata,
        destination,
        BackupJournalEvidence {
            byte_length: header.source.byte_length,
            digest: header.source.digest,
        },
    )?;
    match (sources.history, header.history) {
        (Some(files), Some(history)) => {
            stream.member(files.namespace, destination, history.namespace)?;
            stream.member(files.content, destination, history.content)?;
        }
        (None, None) => {}
        _ => return Err(BackupError::InvalidInput),
    }
    Ok(())
}

struct EncryptionStream {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; 16],
    header_digest: [u8; 32],
    next_index: u64,
}

impl EncryptionStream {
    fn member(
        &mut self,
        source: &Path,
        destination: &mut File,
        evidence: BackupJournalEvidence,
    ) -> Result<(), BackupError> {
        let mut source = File::open(source)?;
        let mut plaintext_digest = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_BYTES]);
        for member_index in 0..chunk_count(evidence.byte_length) {
            let length = crate::format::chunk_plaintext_length(evidence.byte_length, member_index)?;
            source.read_exact(&mut buffer[..length])?;
            plaintext_digest.update(&buffer[..length]);
            let nonce = chunk_nonce(self.nonce_prefix, self.next_index);
            let aad = chunk_aad(self.header_digest, self.next_index, length);
            let ciphertext = self
                .cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &buffer[..length],
                        aad: &aad,
                    },
                )
                .map_err(|_| BackupError::Cryptography)?;
            destination.write_all(&ciphertext)?;
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or(BackupError::InvalidInput)?;
        }
        let mut trailing = [0_u8; 1];
        if source.read(&mut trailing)? != 0
            || plaintext_digest.finalize().as_slice() != evidence.digest
        {
            return Err(BackupError::InvalidInput);
        }
        Ok(())
    }
}
