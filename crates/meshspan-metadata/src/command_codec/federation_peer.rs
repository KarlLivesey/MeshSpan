// SPDX-License-Identifier: GPL-2.0-only

//! Canonical public peer records shared by HTTPS pairing, consensus and retained metadata.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{FederationPairingPeer, RecordName, SignedFederationPairingPeer};
use meshspan_domain::{MeshId, NodeId, UnixMicros};

const MAXIMUM_BYTES: usize = 18 * 1024;

/// Encodes one bounded signed public peer record. Signature authority is checked separately.
///
/// # Errors
/// Rejects excessive names, routes or certificates.
pub fn encode_federation_pairing_peer(
    value: &SignedFederationPairingPeer,
) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let mut encoder = Encoder::new(MAXIMUM_BYTES);
    encoder.fixed(b"MSFP\x01")?;
    let peer = &value.peer;
    encoder.identifier(peer.mesh_id.as_bytes())?;
    encoder.identifier(peer.node_id.as_bytes())?;
    encoder.text(peer.name.display(), 256)?;
    encoder.text(&peer.endpoint, 512)?;
    encoder.bytes(&peer.certificate_der, 16 * 1024)?;
    encoder.fixed(&peer.verifying_key)?;
    encoder.i64(peer.valid_from.get())?;
    encoder.i64(peer.valid_until.get())?;
    encoder.fixed(&value.signature)?;
    Ok(encoder.finish())
}

/// Decodes one complete bounded signed public peer record without granting it authority.
///
/// # Errors
/// Rejects non-canonical names/IDs, bad framing, bounds or trailing bytes.
pub fn decode_federation_pairing_peer(
    bytes: &[u8],
) -> Result<SignedFederationPairingPeer, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<5>()? != *b"MSFP\x01" {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let value = SignedFederationPairingPeer {
        peer: FederationPairingPeer {
            mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
            node_id: NodeId::from_bytes(decoder.identifier()?)?,
            name: RecordName::new(&decoder.text(256)?)
                .map_err(|_| MetadataCommandCodecError::Invalid)?,
            endpoint: decoder.text(512)?,
            certificate_der: decoder.bytes(16 * 1024)?,
            verifying_key: decoder.fixed()?,
            valid_from: UnixMicros::new(decoder.i64()?),
            valid_until: UnixMicros::new(decoder.i64()?),
        },
        signature: decoder.fixed()?,
    };
    decoder.finish()?;
    if encode_federation_pairing_peer(&value)? != bytes {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(value)
}
