// SPDX-License-Identifier: GPL-2.0-only

//! Encoded-length and field-encoding source generation.

use super::super::line;
use super::{CodegenError, Field, ResolvedType, ScalarType, Schema};

pub(super) fn render_present_length(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    let number = field.number;
    let expression = match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) => {
            format!("::meshspan_protobuf::encode::bytes_field_len({number}, value.len())?")
        }
        ResolvedType::Scalar(ScalarType::Fixed64) => {
            format!("::meshspan_protobuf::encode::fixed64_field_len({number})")
        }
        ResolvedType::Scalar(ScalarType::Sint64) => format!(
            "::meshspan_protobuf::encode::varint_field_len({number}, ::meshspan_protobuf::encode::zig_zag_encode(*value))"
        ),
        ResolvedType::Scalar(ScalarType::Bool | ScalarType::Uint32) => {
            format!("::meshspan_protobuf::encode::varint_field_len({number}, u64::from(*value))")
        }
        ResolvedType::Scalar(ScalarType::Uint64) => {
            format!("::meshspan_protobuf::encode::varint_field_len({number}, *value)")
        }
        ResolvedType::Message(_) => {
            format!("::meshspan_protobuf::encode::message_field_len({number}, value)?")
        }
        ResolvedType::Enumeration(_) => format!(
            "::meshspan_protobuf::encode::varint_field_len({number}, ::meshspan_protobuf::encode::int32_to_varint(*value))"
        ),
    };
    line(output, format!("{indent}length.add({expression})?;"));
    Ok(())
}

pub(super) fn render_present_encode(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    let number = field.number;
    let statement = match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Bytes) => {
            format!("encoder.bytes_field({number}, value)?;")
        }
        ResolvedType::Scalar(ScalarType::String) => {
            format!("encoder.bytes_field({number}, value.as_bytes())?;")
        }
        ResolvedType::Scalar(ScalarType::Fixed64) => {
            format!("encoder.fixed64_field({number}, *value);")
        }
        ResolvedType::Scalar(ScalarType::Sint64) => {
            format!("encoder.sint64_field({number}, *value);")
        }
        ResolvedType::Scalar(ScalarType::Bool | ScalarType::Uint32) => {
            format!("encoder.varint_field({number}, u64::from(*value));")
        }
        ResolvedType::Scalar(ScalarType::Uint64) => {
            format!("encoder.varint_field({number}, *value);")
        }
        ResolvedType::Message(_) => format!("encoder.message_field({number}, value)?;"),
        ResolvedType::Enumeration(_) => format!("encoder.int32_field({number}, *value);"),
    };
    line(output, format!("{indent}{statement}"));
    Ok(())
}

pub(super) fn render_repeated_length(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Uint32) => line(
            output,
            format!(
                "{indent}length.add(::meshspan_protobuf::encode::packed_uint32_field_len({}, values)?)?;",
                field.number
            ),
        ),
        ResolvedType::Enumeration(_) => line(
            output,
            format!(
                "{indent}length.add(::meshspan_protobuf::encode::packed_int32_field_len({}, values)?)?;",
                field.number
            ),
        ),
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) | ResolvedType::Message(_) => {
            line(output, format!("{indent}for value in values {{"));
            render_present_length(output, schema, field, &format!("{indent}    "))?;
            line(output, format!("{indent}}}"));
        }
        ResolvedType::Scalar(_) => return Err(unsupported_repeated(field)),
    }
    Ok(())
}

pub(super) fn render_repeated_encode(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Uint32) => line(
            output,
            format!("{indent}encoder.packed_uint32({}, values)?;", field.number),
        ),
        ResolvedType::Enumeration(_) => line(
            output,
            format!("{indent}encoder.packed_int32({}, values)?;", field.number),
        ),
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) | ResolvedType::Message(_) => {
            line(output, format!("{indent}for value in values {{"));
            render_present_encode(output, schema, field, &format!("{indent}    "))?;
            line(output, format!("{indent}}}"));
        }
        ResolvedType::Scalar(_) => return Err(unsupported_repeated(field)),
    }
    Ok(())
}

fn unsupported_repeated(field: &Field) -> CodegenError {
    CodegenError::new(format!(
        "repeated type {:?} is not implemented by this generator",
        field.schema_type
    ))
}
