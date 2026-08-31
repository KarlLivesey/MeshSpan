// SPDX-License-Identifier: GPL-2.0-only

//! Field-decoding source generation.

use super::super::line;
use super::super::names::{pascal_case, rust_identifier, snake_case};
use super::{CodegenError, Field, FieldLabel, ResolvedType, ScalarType, Schema};

pub(super) fn render_singular(
    output: &mut String,
    schema: &Schema,
    field: &Field,
) -> Result<(), CodegenError> {
    render_wire_guard(output, schema, field, "                ")?;
    let name = rust_identifier(&field.name);
    if matches!(
        schema.resolve(&field.schema_type)?,
        ResolvedType::Message(_)
    ) {
        line(
            output,
            format!("                decoder.embedded(&mut self.{name}, state, depth)?;"),
        );
    } else {
        let decoded = decode_expression(schema, field, "decoder")?;
        if field.label == FieldLabel::Optional {
            line(
                output,
                format!("                self.{name} = Some({decoded});"),
            );
        } else {
            line(output, format!("                self.{name} = {decoded};"));
        }
    }
    Ok(())
}

pub(super) fn render_repeated(
    output: &mut String,
    schema: &Schema,
    field: &Field,
) -> Result<(), CodegenError> {
    let name = rust_identifier(&field.name);
    match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Uint32) | ResolvedType::Enumeration(_) => {
            render_packed(output, schema, field, &name)?;
        }
        ResolvedType::Message(message) => {
            render_wire_guard(output, schema, field, "                ")?;
            repeated_limit(output, &name, "decoder");
            line(output, "                let bytes = decoder.bytes(state)?;");
            line(
                output,
                "                let mut nested = ::meshspan_protobuf::Decoder::new(bytes);",
            );
            line(
                output,
                format!(
                    "                let mut value = {}::default();",
                    message.name
                ),
            );
            line(
                output,
                "                nested.merge_message(&mut value, state, depth + 1)?;",
            );
            line(output, format!("                self.{name}.push(value);"));
        }
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) => {
            render_wire_guard(output, schema, field, "                ")?;
            repeated_limit(output, &name, "decoder");
            let decoded = decode_expression(schema, field, "decoder")?;
            line(
                output,
                format!("                self.{name}.push({decoded});"),
            );
        }
        ResolvedType::Scalar(_) => {
            return Err(CodegenError::new(format!(
                "repeated type {:?} is not implemented by this generator",
                field.schema_type
            )));
        }
    }
    Ok(())
}

pub(super) fn render_oneof(
    output: &mut String,
    schema: &Schema,
    parent_name: &str,
    oneof_name: &str,
    field: &Field,
) -> Result<(), CodegenError> {
    let module = snake_case(parent_name);
    let oneof_type = pascal_case(oneof_name);
    let variant = pascal_case(&field.name);
    let member = rust_identifier(oneof_name);
    line(output, format!("            {} => {{", field.number));
    render_wire_guard(output, schema, field, "                ")?;
    if let ResolvedType::Message(message) = schema.resolve(&field.schema_type)? {
        line(output, "                let bytes = decoder.bytes(state)?;");
        line(
            output,
            "                let mut nested = ::meshspan_protobuf::Decoder::new(bytes);",
        );
        line(
            output,
            format!(
                "                if let Some({module}::{oneof_type}::{variant}(value)) = &mut self.{member} {{"
            ),
        );
        line(
            output,
            "                    nested.merge_message(value, state, depth + 1)?;",
        );
        line(output, "                } else {");
        line(
            output,
            format!(
                "                    let mut value = {}::default();",
                message.name
            ),
        );
        line(
            output,
            "                    nested.merge_message(&mut value, state, depth + 1)?;",
        );
        line(
            output,
            format!(
                "                    self.{member} = Some({module}::{oneof_type}::{variant}(value));"
            ),
        );
        line(output, "                }");
    } else {
        let value = decode_expression(schema, field, "decoder")?;
        line(output, format!("                let value = {value};"));
        line(
            output,
            format!(
                "                self.{member} = Some({module}::{oneof_type}::{variant}(value));"
            ),
        );
    }
    line(output, "            }");
    Ok(())
}

fn render_packed(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    name: &str,
) -> Result<(), CodegenError> {
    let packed_value = decode_expression(schema, field, "packed")?;
    line(
        output,
        "                if wire_type == ::meshspan_protobuf::WireType::LengthDelimited {",
    );
    line(
        output,
        "                    let bytes = decoder.bytes(state)?;",
    );
    line(
        output,
        "                    let mut packed = ::meshspan_protobuf::Decoder::new(bytes);",
    );
    line(output, "                    while !packed.is_empty() {");
    repeated_limit(output, name, "packed");
    line(
        output,
        format!("                        self.{name}.push({packed_value});"),
    );
    line(output, "                    }");
    line(
        output,
        "                } else if wire_type == ::meshspan_protobuf::WireType::Varint {",
    );
    repeated_limit(output, name, "decoder");
    let single_value = decode_expression(schema, field, "decoder")?;
    line(
        output,
        format!("                    self.{name}.push({single_value});"),
    );
    line(output, "                } else {");
    render_wrong_wire(output, "                    ");
    line(output, "                }");
    Ok(())
}

fn repeated_limit(output: &mut String, name: &str, decoder: &str) {
    let indent = if decoder == "packed" {
        "                        "
    } else {
        "                "
    };
    line(
        output,
        format!("{indent}state.repeated_item(self.{name}.len(), {decoder}.position())?;"),
    );
}

fn render_wire_guard(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    let expected = wire_type(schema, field)?;
    line(
        output,
        format!("{indent}if wire_type != ::meshspan_protobuf::WireType::{expected} {{"),
    );
    render_wrong_wire(output, &format!("{indent}    "));
    line(output, format!("{indent}}}"));
    Ok(())
}

fn render_wrong_wire(output: &mut String, indent: &str) {
    line(
        output,
        format!(
            "{indent}return Err(::meshspan_protobuf::DecodeError::new(::meshspan_protobuf::DecodeErrorKind::WrongWireType, decoder.position()));"
        ),
    );
}

fn wire_type(schema: &Schema, field: &Field) -> Result<&'static str, CodegenError> {
    Ok(match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(
            ScalarType::Bool | ScalarType::Sint64 | ScalarType::Uint32 | ScalarType::Uint64,
        )
        | ResolvedType::Enumeration(_) => "Varint",
        ResolvedType::Scalar(ScalarType::Fixed64) => "Fixed64",
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) | ResolvedType::Message(_) => {
            "LengthDelimited"
        }
    })
}

fn decode_expression(
    schema: &Schema,
    field: &Field,
    decoder: &str,
) -> Result<String, CodegenError> {
    Ok(match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Bool) => format!("{decoder}.boolean()?"),
        ResolvedType::Scalar(ScalarType::Bytes) => format!("{decoder}.byte_vector(state)?"),
        ResolvedType::Scalar(ScalarType::Fixed64) => format!("{decoder}.fixed64()?"),
        ResolvedType::Scalar(ScalarType::Sint64) => format!("{decoder}.sint64()?"),
        ResolvedType::Scalar(ScalarType::String) => format!("{decoder}.string(state)?"),
        ResolvedType::Scalar(ScalarType::Uint32) => format!("{decoder}.uint32()?"),
        ResolvedType::Scalar(ScalarType::Uint64) => format!("{decoder}.varint()?"),
        ResolvedType::Enumeration(_) => format!("{decoder}.int32()?"),
        ResolvedType::Message(_) => {
            return Err(CodegenError::new(
                "message field requested a scalar decode expression",
            ));
        }
    })
}
