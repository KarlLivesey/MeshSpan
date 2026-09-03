// SPDX-License-Identifier: GPL-2.0-only

//! Bounded binary container header shared by backup creation and restoration.

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use meshspan_domain::{BackupId, MeshId, PartitionId, UnixMicros};
use meshspan_secret_envelope::{
    EncryptedSecret, EncryptedSecretParts, RecipientEnvelopeParts, RecipientKeyEnvelope,
    SecretContext,
};

use crate::BackupError;

pub(crate) const MAGIC: [u8; 8] = *b"MSBACKUP";
pub(crate) const FORMAT_VERSION: u16 = 1;
pub(crate) const CONTENT_KEY_SECRET_KIND: u16 = 0x100;
pub(crate) const CONTENT_KEY_GENERATION: u64 = 1;
pub(crate) const CHUNK_BYTES: usize = 1_048_576;
pub(crate) const MAXIMUM_HEADER_BYTES: usize = 256 * 1_024;
pub(crate) const AUTHENTICATION_TAG_BYTES: usize = 16;
const MAXIMUM_RECIPIENTS: usize = 1_024;

/// Exact committed database state represented by plaintext backup bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupSourceManifest {
    /// Stable identity of this backup generation.
    pub backup_id: BackupId,
    /// Metadata partition contained in the backup.
    pub partition_id: PartitionId,
    /// Mesh whose recovery authority owns the partition.
    pub mesh_id: MeshId,
    /// Last applied committed consensus log index.
    pub last_log_index: u64,
    /// Term of the last applied committed consensus entry.
    pub last_log_term: u64,
    /// Exact authoritative state revision.
    pub state_revision: u64,
    /// Explicit SQLite-compatible schema version.
    pub schema_version: u32,
    /// Exact plaintext file length.
    pub byte_length: u64,
    /// SHA-256 of the complete closed plaintext backup.
    pub digest: [u8; 32],
    /// Authority-agreed backup creation instant.
    pub created_at: UnixMicros,
}

impl BackupSourceManifest {
    pub(crate) fn validate(self) -> Result<(), BackupError> {
        let valid_position = (self.last_log_index == 0) == (self.last_log_term == 0);
        if !valid_position
            || self.state_revision == 0
            || self.schema_version == 0
            || self.byte_length == 0
            || self.digest == [0; 32]
            || self.created_at.get() < 0
        {
            return Err(BackupError::InvalidInput);
        }
        Ok(())
    }
}

/// Digest and length of one complete encrypted backup container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupFileEvidence {
    /// Exact source state bound into every authenticated chunk.
    pub source: BackupSourceManifest,
    /// Exact encrypted container length.
    pub byte_length: u64,
    /// SHA-256 of the complete encrypted container.
    pub digest: [u8; 32],
}

pub(crate) struct BackupHeader {
    pub(crate) source: BackupSourceManifest,
    pub(crate) nonce_prefix: [u8; 16],
    pub(crate) encrypted_content_key: EncryptedSecret,
    pub(crate) recipient_envelopes: Vec<RecipientKeyEnvelope>,
}

impl BackupHeader {
    pub(crate) fn context(&self) -> Result<SecretContext, BackupError> {
        SecretContext::new(
            CONTENT_KEY_SECRET_KIND,
            self.source.backup_id.as_bytes(),
            CONTENT_KEY_GENERATION,
        )
        .map_err(Into::into)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, BackupError> {
        self.source.validate()?;
        if self.nonce_prefix == [0; 16]
            || self.recipient_envelopes.is_empty()
            || self.recipient_envelopes.len() > MAXIMUM_RECIPIENTS
            || self.encrypted_content_key.context() != self.context()?
        {
            return Err(BackupError::InvalidInput);
        }
        let mut output = Vec::new();
        encode_source(&mut output, self.source);
        output.extend_from_slice(&self.nonce_prefix);
        encode_secret(&mut output, &self.encrypted_content_key.parts())?;
        push_u16(&mut output, self.recipient_envelopes.len())?;
        for envelope in &self.recipient_envelopes {
            if envelope.context() != self.context()? {
                return Err(BackupError::InvalidInput);
            }
            encode_envelope(&mut output, &envelope.parts())?;
        }
        if output.len() > MAXIMUM_HEADER_BYTES {
            return Err(BackupError::InvalidInput);
        }
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BackupError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_HEADER_BYTES {
            return Err(BackupError::Corrupt);
        }
        let mut input = Cursor::new(bytes);
        let source = decode_source(&mut input)?;
        source.validate().map_err(|_| BackupError::Corrupt)?;
        let nonce_prefix = read_array(&mut input)?;
        let context = SecretContext::new(
            CONTENT_KEY_SECRET_KIND,
            source.backup_id.as_bytes(),
            CONTENT_KEY_GENERATION,
        )
        .map_err(|_| BackupError::Corrupt)?;
        let encrypted_content_key = decode_secret(&mut input, context)?;
        let recipient_count = usize::from(read_u16(&mut input)?);
        if recipient_count == 0 || recipient_count > MAXIMUM_RECIPIENTS {
            return Err(BackupError::Corrupt);
        }
        let mut recipient_envelopes = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipient_envelopes.push(decode_envelope(&mut input, context)?);
        }
        if input.position() != bytes.len() as u64 || nonce_prefix == [0; 16] {
            return Err(BackupError::Corrupt);
        }
        Ok(Self {
            source,
            nonce_prefix,
            encrypted_content_key,
            recipient_envelopes,
        })
    }
}

fn encode_source(output: &mut Vec<u8>, source: BackupSourceManifest) {
    output.extend_from_slice(&source.backup_id.as_bytes());
    output.extend_from_slice(&source.partition_id.as_bytes());
    output.extend_from_slice(&source.mesh_id.as_bytes());
    output.extend_from_slice(&source.last_log_index.to_be_bytes());
    output.extend_from_slice(&source.last_log_term.to_be_bytes());
    output.extend_from_slice(&source.state_revision.to_be_bytes());
    output.extend_from_slice(&source.schema_version.to_be_bytes());
    output.extend_from_slice(&source.byte_length.to_be_bytes());
    output.extend_from_slice(&source.digest);
    output.extend_from_slice(&source.created_at.get().to_be_bytes());
}

fn decode_source(input: &mut Cursor<&[u8]>) -> Result<BackupSourceManifest, BackupError> {
    Ok(BackupSourceManifest {
        backup_id: BackupId::from_bytes(read_array(input)?).map_err(|_| BackupError::Corrupt)?,
        partition_id: PartitionId::from_bytes(read_array(input)?)
            .map_err(|_| BackupError::Corrupt)?,
        mesh_id: MeshId::from_bytes(read_array(input)?).map_err(|_| BackupError::Corrupt)?,
        last_log_index: read_u64(input)?,
        last_log_term: read_u64(input)?,
        state_revision: read_u64(input)?,
        schema_version: read_u32(input)?,
        byte_length: read_u64(input)?,
        digest: read_array(input)?,
        created_at: UnixMicros::new(read_i64(input)?),
    })
}

fn encode_secret(output: &mut Vec<u8>, secret: &EncryptedSecretParts) -> Result<(), BackupError> {
    output.push(secret.format_version);
    output.extend_from_slice(&secret.nonce);
    push_bytes(output, &secret.ciphertext)?;
    output.extend_from_slice(&secret.digest);
    Ok(())
}

fn decode_secret(
    input: &mut Cursor<&[u8]>,
    context: SecretContext,
) -> Result<EncryptedSecret, BackupError> {
    EncryptedSecret::from_parts(EncryptedSecretParts {
        format_version: read_u8(input)?,
        context,
        nonce: read_array(input)?,
        ciphertext: read_bytes(input, 128)?,
        digest: read_array(input)?,
    })
    .map_err(|_| BackupError::Corrupt)
}

fn encode_envelope(
    output: &mut Vec<u8>,
    envelope: &RecipientEnvelopeParts,
) -> Result<(), BackupError> {
    output.push(envelope.format_version);
    output.extend_from_slice(&envelope.recipient_public_key);
    output.extend_from_slice(&envelope.ephemeral_public_key);
    output.extend_from_slice(&envelope.salt);
    output.extend_from_slice(&envelope.nonce);
    push_bytes(output, &envelope.ciphertext)?;
    output.extend_from_slice(&envelope.digest);
    Ok(())
}

fn decode_envelope(
    input: &mut Cursor<&[u8]>,
    context: SecretContext,
) -> Result<RecipientKeyEnvelope, BackupError> {
    RecipientKeyEnvelope::from_parts(RecipientEnvelopeParts {
        format_version: read_u8(input)?,
        context,
        recipient_public_key: read_array(input)?,
        ephemeral_public_key: read_array(input)?,
        salt: read_array(input)?,
        nonce: read_array(input)?,
        ciphertext: read_bytes(input, 128)?,
        digest: read_array(input)?,
    })
    .map_err(|_| BackupError::Corrupt)
}

fn push_u16(output: &mut Vec<u8>, value: usize) -> Result<(), BackupError> {
    output.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| BackupError::InvalidInput)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BackupError> {
    push_u16(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn read_u8(input: &mut Cursor<&[u8]>) -> Result<u8, BackupError> {
    Ok(read_array::<1>(input)?[0])
}

fn read_u16(input: &mut Cursor<&[u8]>) -> Result<u16, BackupError> {
    Ok(u16::from_be_bytes(read_array(input)?))
}

fn read_u32(input: &mut Cursor<&[u8]>) -> Result<u32, BackupError> {
    Ok(u32::from_be_bytes(read_array(input)?))
}

fn read_u64(input: &mut Cursor<&[u8]>) -> Result<u64, BackupError> {
    Ok(u64::from_be_bytes(read_array(input)?))
}

fn read_i64(input: &mut Cursor<&[u8]>) -> Result<i64, BackupError> {
    Ok(i64::from_be_bytes(read_array(input)?))
}

fn read_array<const LENGTH: usize>(input: &mut Cursor<&[u8]>) -> Result<[u8; LENGTH], BackupError> {
    let mut value = [0; LENGTH];
    input
        .read_exact(&mut value)
        .map_err(|_| BackupError::Corrupt)?;
    Ok(value)
}

fn read_bytes(input: &mut Cursor<&[u8]>, maximum: usize) -> Result<Vec<u8>, BackupError> {
    let length = usize::from(read_u16(input)?);
    if length == 0 || length > maximum {
        return Err(BackupError::Corrupt);
    }
    let mut value = vec![0; length];
    input
        .read_exact(&mut value)
        .map_err(|_| BackupError::Corrupt)?;
    Ok(value)
}

pub(crate) fn hash_file(file_path: &Path) -> Result<(u64, [u8; 32]), BackupError> {
    use sha2::{Digest, Sha256};

    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1_024];
    let mut byte_length = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_length = byte_length
            .checked_add(u64::try_from(read).map_err(|_| BackupError::Corrupt)?)
            .ok_or(BackupError::Corrupt)?;
        hasher.update(&buffer[..read]);
    }
    Ok((byte_length, hasher.finalize().into()))
}

pub(crate) fn chunk_count(byte_length: u64) -> u64 {
    byte_length.div_ceil(CHUNK_BYTES as u64)
}

pub(crate) fn chunk_plaintext_length(byte_length: u64, index: u64) -> Result<usize, BackupError> {
    let offset = index
        .checked_mul(CHUNK_BYTES as u64)
        .ok_or(BackupError::Corrupt)?;
    let remaining = byte_length
        .checked_sub(offset)
        .ok_or(BackupError::Corrupt)?;
    usize::try_from(remaining.min(CHUNK_BYTES as u64)).map_err(|_| BackupError::Corrupt)
}

pub(crate) fn chunk_nonce(prefix: [u8; 16], index: u64) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&prefix);
    nonce[16..].copy_from_slice(&index.to_be_bytes());
    nonce
}

pub(crate) fn chunk_aad(header_digest: [u8; 32], index: u64, length: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(80);
    aad.extend_from_slice(b"meshspan.metadata-backup.chunk.v1\0");
    aad.extend_from_slice(&header_digest);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&(length as u64).to_be_bytes());
    aad
}
