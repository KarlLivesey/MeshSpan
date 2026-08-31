// SPDX-License-Identifier: GPL-2.0-only

//! Runtime wire-format conformance and hostile-input tests.

use meshspan_protobuf::{
    DecodeError, DecodeErrorKind, DecodeLimits, DecodeState, Decoder, EncodeError, EncodedLength,
    Encoder, Message, WireType,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Example {
    sequence: u64,
    name: String,
    child: Option<Child>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Child {
    signed: i64,
}

impl Message for Example {
    fn encoded_len(&self, length: &mut EncodedLength) -> Result<(), EncodeError> {
        if self.sequence != 0 {
            length.add(meshspan_protobuf::encode::varint_field_len(
                1,
                self.sequence,
            ))?;
        }
        if !self.name.is_empty() {
            length.add(meshspan_protobuf::encode::bytes_field_len(
                2,
                self.name.len(),
            )?)?;
        }
        if let Some(child) = &self.child {
            length.add(meshspan_protobuf::encode::message_field_len(3, child)?)?;
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        if self.sequence != 0 {
            encoder.varint_field(1, self.sequence);
        }
        if !self.name.is_empty() {
            encoder.bytes_field(2, self.name.as_bytes())?;
        }
        if let Some(child) = &self.child {
            encoder.message_field(3, child)?;
        }
        Ok(())
    }

    fn merge_field(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        decoder: &mut Decoder<'_>,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        match (field_number, wire_type) {
            (1, WireType::Varint) => self.sequence = decoder.varint()?,
            (2, WireType::LengthDelimited) => self.name = decoder.string(state)?,
            (3, WireType::LengthDelimited) => {
                decoder.embedded(&mut self.child, state, depth)?;
            }
            (1..=3, _) => {
                return Err(DecodeError::new(
                    DecodeErrorKind::WrongWireType,
                    decoder.position(),
                ));
            }
            _ => decoder.skip_field(field_number, wire_type, state, depth)?,
        }
        Ok(())
    }
}

impl Message for Child {
    fn encoded_len(&self, length: &mut EncodedLength) -> Result<(), EncodeError> {
        if self.signed != 0 {
            length.add(meshspan_protobuf::encode::varint_field_len(
                1,
                meshspan_protobuf::encode::zig_zag_encode(self.signed),
            ))?;
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        if self.signed != 0 {
            encoder.sint64_field(1, self.signed);
        }
        Ok(())
    }

    fn merge_field(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        decoder: &mut Decoder<'_>,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        if field_number == 1 && wire_type == WireType::Varint {
            self.signed = decoder.sint64()?;
            return Ok(());
        }
        decoder.skip_field(field_number, wire_type, state, depth)
    }
}

#[test]
fn exact_vector_round_trips_nested_values() -> Result<(), Box<dyn std::error::Error>> {
    let message = Example {
        sequence: 150,
        name: "mesh".to_owned(),
        child: Some(Child { signed: -2 }),
    };
    let encoded = message.encode_to_vec()?;
    assert_eq!(
        encoded,
        [
            0x08, 0x96, 0x01, 0x12, 0x04, b'm', b'e', b's', b'h', 0x1a, 0x02, 0x08, 0x03
        ]
    );
    assert_eq!(Example::decode(&encoded)?, message);
    Ok(())
}

#[test]
fn duplicate_embedded_fields_merge() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = [0x1a, 0x02, 0x08, 0x03, 0x1a, 0x00];
    assert_eq!(
        Example::decode(&encoded)?,
        Example {
            child: Some(Child { signed: -2 }),
            ..Example::default()
        }
    );
    Ok(())
}

#[test]
fn unknown_fields_and_groups_are_validated_then_ignored() -> Result<(), Box<dyn std::error::Error>>
{
    let encoded = [0x08, 0x01, 0x4b, 0x50, 0x02, 0x4c, 0x5a, 0x01, 0xff];
    assert_eq!(Example::decode(&encoded)?.sequence, 1);
    Ok(())
}

#[test]
fn malformed_varints_fail_at_their_start() -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = Example::decode(&[0x08, 0x80]) else {
        return Err("truncated varint was accepted".into());
    };
    assert_eq!(error.kind(), DecodeErrorKind::InvalidVarint);
    assert_eq!(error.offset(), 1);
    Ok(())
}

#[test]
fn limits_apply_before_allocation_or_repeated_work() -> Result<(), Box<dyn std::error::Error>> {
    let limits = DecodeLimits {
        maximum_message_bytes: 2,
        ..DecodeLimits::default()
    };
    let Err(error) = Example::decode_with_limits(&[0x12, 0x02, b'o', b'k'], limits) else {
        return Err("oversized message was accepted".into());
    };
    assert_eq!(error.kind(), DecodeErrorKind::MessageTooLarge);
    Ok(())
}

#[test]
fn wrong_known_wire_type_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = Example::decode(&[0x0a, 0x00]) else {
        return Err("known field accepted the wrong wire type".into());
    };
    assert_eq!(error.kind(), DecodeErrorKind::WrongWireType);
    Ok(())
}
