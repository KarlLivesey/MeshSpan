// SPDX-License-Identifier: GPL-2.0-only

use std::any::Any;
use std::io;
use std::sync::Arc;

use bytes::BytesMut;
use quinn_proto::crypto::{self, CryptoError, ExportKeyingMaterialError, KeyPair, Keys};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::quic::{
    Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version,
};

use crate::retry;

/// Authentication data made available after the QUIC TLS handshake advances.
pub struct HandshakeData {
    /// Negotiated application protocol, when ALPN is configured.
    pub protocol: Option<Vec<u8>>,
    /// Client-supplied server name on incoming sessions.
    pub server_name: Option<String>,
}

pub(crate) fn client(
    config: Arc<rustls::ClientConfig>,
    initial: Suite,
    version: Version,
    server_name: &str,
    parameters: &TransportParameters,
) -> Result<Box<dyn crypto::Session>, ConnectError> {
    let server_name = ServerName::try_from(server_name)
        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
        .to_owned();
    let inner = rustls::quic::ClientConnection::new(
        config,
        version,
        server_name,
        encode_parameters(parameters),
    )
    .map_err(|_| ConnectError::UnsupportedVersion)?;
    Ok(Box::new(TlsSession::new(
        Connection::Client(inner),
        initial,
        version,
    )))
}

pub(crate) fn server(
    config: Arc<rustls::ServerConfig>,
    initial: Suite,
    version: Version,
    parameters: &TransportParameters,
) -> Box<dyn crypto::Session> {
    match rustls::quic::ServerConnection::new(config, version, encode_parameters(parameters)) {
        Ok(inner) => Box::new(TlsSession::new(Connection::Server(inner), initial, version)),
        Err(_) => rejected(initial, version),
    }
}

pub(crate) fn rejected(initial: Suite, version: Version) -> Box<dyn crypto::Session> {
    Box::new(RejectedSession { initial, version })
}

struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
    initial: Suite,
}

impl TlsSession {
    fn new(inner: Connection, initial: Suite, version: Version) -> Self {
        Self {
            version,
            got_handshake_data: false,
            next_secrets: None,
            inner,
            initial,
        }
    }

    const fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, destination: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *destination, side, &self.initial)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data.then(|| {
            Box::new(HandshakeData {
                protocol: self.inner.alpn_protocol().map(<[u8]>::to_vec),
                server_name: match &self.inner {
                    Connection::Client(_) => None,
                    Connection::Server(server) => server.server_name().map(str::to_owned),
                },
            }) as Box<dyn Any>
        })
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().map(|certificates| {
            Box::new(
                certificates
                    .iter()
                    .map(|certificate| certificate.clone().into_owned())
                    .collect::<Vec<CertificateDer<'static>>>(),
            ) as Box<dyn Any>
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((
            Box::new(RustlsHeaderKey(keys.header)),
            Box::new(RustlsPacketKey(keys.packet)),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match &self.inner {
            Connection::Client(client) => Some(client.is_early_data_accepted()),
            Connection::Server(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, input: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(input).map_err(|error| {
            self.inner.alert().map_or_else(
                || protocol_violation(format!("TLS error: {error}")),
                |alert| TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: error.to_string(),
                },
            )
        })?;
        if self.got_handshake_data {
            return Ok(false);
        }
        let has_server_name = match &self.inner {
            Connection::Client(_) => false,
            Connection::Server(server) => server.server_name().is_some(),
        };
        if self.inner.alpn_protocol().is_some() || has_server_name || !self.is_handshaking() {
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner
            .quic_transport_parameters()
            .map(|encoded| {
                TransportParameters::read(self.side(), &mut io::Cursor::new(encoded))
                    .map_err(Into::into)
            })
            .transpose()
    }

    fn write_handshake(&mut self, output: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(output)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };
        Some(wrap_keys(keys))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let keys = self.next_secrets.as_mut()?.next_packet_keys();
        Some(KeyPair {
            local: Box::new(RustlsPacketKey(keys.local)),
            remote: Box::new(RustlsPacketKey(keys.remote)),
        })
    }

    fn is_valid_retry(
        &self,
        original_destination: &ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        retry::valid(self.version, original_destination, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner
            .export_keying_material(output, label, Some(context))
            .map(|_| ())
            .map_err(|_| ExportKeyingMaterialError)
    }
}

struct RejectedSession {
    initial: Suite,
    version: Version,
}

impl crypto::Session for RejectedSession {
    fn initial_keys(&self, destination: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *destination, side, &self.initial)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        true
    }

    fn read_handshake(&mut self, _input: &[u8]) -> Result<bool, TransportError> {
        Err(rejected_transport())
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Err(rejected_transport())
    }

    fn write_handshake(&mut self, _output: &mut Vec<u8>) -> Option<Keys> {
        None
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        None
    }

    fn is_valid_retry(
        &self,
        _original_destination: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        false
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

fn rejected_transport() -> TransportError {
    protocol_violation("TLS session configuration was rejected")
}

fn protocol_violation(reason: impl Into<String>) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
}

pub(crate) fn initial_keys(
    version: Version,
    destination: ConnectionId,
    side: Side,
    suite: &Suite,
) -> Keys {
    let keys = suite.keys(&destination, rustls_side(side), version);
    wrap_keys(keys)
}

fn wrap_keys(keys: rustls::quic::Keys) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(RustlsHeaderKey(keys.local.header)),
            remote: Box::new(RustlsHeaderKey(keys.remote.header)),
        },
        packet: KeyPair {
            local: Box::new(RustlsPacketKey(keys.local.packet)),
            remote: Box::new(RustlsPacketKey(keys.remote.packet)),
        },
    }
}

const fn rustls_side(side: Side) -> rustls::Side {
    match side {
        Side::Client => rustls::Side::Client,
        Side::Server => rustls::Side::Server,
    }
}

fn encode_parameters(parameters: &TransportParameters) -> Vec<u8> {
    let mut encoded = Vec::new();
    parameters.write(&mut encoded);
    encoded
}

struct RustlsHeaderKey(Box<dyn HeaderProtectionKey>);

impl crypto::HeaderKey for RustlsHeaderKey {
    fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        self.apply(packet_number_offset, packet, false);
    }

    fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        self.apply(packet_number_offset, packet, true);
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}

impl RustlsHeaderKey {
    fn apply(&self, packet_number_offset: usize, packet: &mut [u8], encrypting: bool) {
        let Some(sample_offset) = packet_number_offset.checked_add(4) else {
            packet.fill(0);
            return;
        };
        let Some(required) = sample_offset.checked_add(self.0.sample_len()) else {
            packet.fill(0);
            return;
        };
        if packet_number_offset == 0 || packet.len() < required {
            packet.fill(0);
            return;
        }
        let (header, sample_and_payload) = packet.split_at_mut(sample_offset);
        let sample = &sample_and_payload[..self.0.sample_len()];
        let (first, rest) = header.split_at_mut(1);
        let packet_number_start = packet_number_offset - 1;
        let packet_number_end = rest.len().min(packet_number_offset + 3);
        let packet_number = &mut rest[packet_number_start..packet_number_end];
        let result = if encrypting {
            self.0
                .encrypt_in_place(sample, &mut first[0], packet_number)
        } else {
            self.0
                .decrypt_in_place(sample, &mut first[0], packet_number)
        };
        if result.is_err() {
            packet.fill(0);
        }
    }
}

struct RustlsPacketKey(Box<dyn PacketKey>);

impl crypto::PacketKey for RustlsPacketKey {
    fn encrypt(&self, packet_number: u64, buffer: &mut [u8], header_length: usize) {
        let tag_length = self.0.tag_len();
        let Some(payload_and_tag_length) = buffer.len().checked_sub(header_length) else {
            buffer.fill(0);
            return;
        };
        let Some(payload_length) = payload_and_tag_length.checked_sub(tag_length) else {
            buffer.fill(0);
            return;
        };
        let (header, payload_and_tag) = buffer.split_at_mut(header_length);
        let (payload, tag_storage) = payload_and_tag.split_at_mut(payload_length);
        match self.0.encrypt_in_place(packet_number, header, payload) {
            Ok(tag) => tag_storage.copy_from_slice(tag.as_ref()),
            Err(_) => buffer.fill(0),
        }
    }

    fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plaintext = self
            .0
            .decrypt_in_place(packet_number, header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plaintext_length = plaintext.len();
        payload.truncate(plaintext_length);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}
