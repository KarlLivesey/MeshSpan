// SPDX-License-Identifier: GPL-2.0-only

//! Field type source generation and encoding/decoding dispatch.

mod decode;
mod encode;

use super::line;
use super::names::rust_identifier;
use crate::codegen::CodegenError;
use crate::codegen::model::{Field, FieldLabel, ResolvedType, ScalarType, Schema};

pub(super) fn rust_field_type(field: &Field, schema: &Schema) -> Result<String, CodegenError> {
    let base = rust_base_type(field, schema)?;
    Ok(match field.label {
        FieldLabel::Repeated => format!("::std::vec::Vec<{base}>"),
        FieldLabel::Optional | FieldLabel::Oneof => {
            format!("::core::option::Option<{base}>")
        }
        FieldLabel::Singular
            if matches!(
                schema.resolve(&field.schema_type)?,
                ResolvedType::Message(_)
            ) =>
        {
            format!("::core::option::Option<{base}>")
        }
        FieldLabel::Singular => base,
    })
}

pub(super) fn rust_oneof_variant_type(
    field: &Field,
    schema: &Schema,
) -> Result<String, CodegenError> {
    Ok(match schema.resolve(&field.schema_type)? {
        ResolvedType::Message(message) => format!("super::{}", message.name),
        _ => rust_base_type(field, schema)?,
    })
}

pub(super) fn render_regular_length(
    output: &mut String,
    schema: &Schema,
    field: &Field,
) -> Result<(), CodegenError> {
    let name = rust_identifier(&field.name);
    match field.label {
        FieldLabel::Repeated => {
            line(output, format!("        let values = &self.{name};"));
            line(output, "        if !values.is_empty() {");
            encode::render_repeated_length(output, schema, field, "            ")?;
            line(output, "        }");
        }
        FieldLabel::Optional => {
            line(
                output,
                format!("        if let Some(value) = &self.{name} {{"),
            );
            encode::render_present_length(output, schema, field, "            ")?;
            line(output, "        }");
        }
        FieldLabel::Singular => {
            if matches!(
                schema.resolve(&field.schema_type)?,
                ResolvedType::Message(_)
            ) {
                line(
                    output,
                    format!("        if let Some(value) = &self.{name} {{"),
                );
                encode::render_present_length(output, schema, field, "            ")?;
                line(output, "        }");
            } else {
                line(output, format!("        let value = &self.{name};"));
                line(
                    output,
                    format!(
                        "        if {} {{",
                        non_default_expression(schema, field, "value")?
                    ),
                );
                encode::render_present_length(output, schema, field, "            ")?;
                line(output, "        }");
            }
        }
        FieldLabel::Oneof => {
            return Err(CodegenError::new(
                "oneof field reached regular length rendering",
            ));
        }
    }
    Ok(())
}

pub(super) fn render_regular_encode(
    output: &mut String,
    schema: &Schema,
    field: &Field,
) -> Result<(), CodegenError> {
    let name = rust_identifier(&field.name);
    match field.label {
        FieldLabel::Repeated => {
            line(output, format!("        let values = &self.{name};"));
            line(output, "        if !values.is_empty() {");
            encode::render_repeated_encode(output, schema, field, "            ")?;
            line(output, "        }");
        }
        FieldLabel::Optional => {
            line(
                output,
                format!("        if let Some(value) = &self.{name} {{"),
            );
            encode::render_present_encode(output, schema, field, "            ")?;
            line(output, "        }");
        }
        FieldLabel::Singular => {
            if matches!(
                schema.resolve(&field.schema_type)?,
                ResolvedType::Message(_)
            ) {
                line(
                    output,
                    format!("        if let Some(value) = &self.{name} {{"),
                );
                encode::render_present_encode(output, schema, field, "            ")?;
                line(output, "        }");
            } else {
                line(output, format!("        let value = &self.{name};"));
                line(
                    output,
                    format!(
                        "        if {} {{",
                        non_default_expression(schema, field, "value")?
                    ),
                );
                encode::render_present_encode(output, schema, field, "            ")?;
                line(output, "        }");
            }
        }
        FieldLabel::Oneof => {
            return Err(CodegenError::new(
                "oneof field reached regular encode rendering",
            ));
        }
    }
    Ok(())
}

pub(super) fn render_oneof_length(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    encode::render_present_length(output, schema, field, indent)
}

pub(super) fn render_oneof_encode(
    output: &mut String,
    schema: &Schema,
    field: &Field,
    indent: &str,
) -> Result<(), CodegenError> {
    encode::render_present_encode(output, schema, field, indent)
}

pub(super) fn render_decode_field(
    output: &mut String,
    schema: &Schema,
    field: &Field,
) -> Result<(), CodegenError> {
    line(output, format!("            {} => {{", field.number));
    match field.label {
        FieldLabel::Repeated => decode::render_repeated(output, schema, field)?,
        FieldLabel::Optional | FieldLabel::Singular => {
            decode::render_singular(output, schema, field)?;
        }
        FieldLabel::Oneof => {
            return Err(CodegenError::new(
                "oneof field reached regular decode rendering",
            ));
        }
    }
    line(output, "            }");
    Ok(())
}

pub(super) fn render_decode_oneof(
    output: &mut String,
    schema: &Schema,
    parent_name: &str,
    oneof_name: &str,
    field: &Field,
) -> Result<(), CodegenError> {
    decode::render_oneof(output, schema, parent_name, oneof_name, field)
}

fn rust_base_type(field: &Field, schema: &Schema) -> Result<String, CodegenError> {
    Ok(match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Bool) => "bool".to_owned(),
        ResolvedType::Scalar(ScalarType::Bytes) => "::std::vec::Vec<u8>".to_owned(),
        ResolvedType::Scalar(ScalarType::Fixed64 | ScalarType::Uint64) => "u64".to_owned(),
        ResolvedType::Scalar(ScalarType::Sint64) => "i64".to_owned(),
        ResolvedType::Scalar(ScalarType::String) => "::std::string::String".to_owned(),
        ResolvedType::Scalar(ScalarType::Uint32) => "u32".to_owned(),
        ResolvedType::Message(message) => message.name.clone(),
        ResolvedType::Enumeration(_) => "i32".to_owned(),
    })
}

pub(super) fn non_default_expression(
    schema: &Schema,
    field: &Field,
    value: &str,
) -> Result<String, CodegenError> {
    Ok(match schema.resolve(&field.schema_type)? {
        ResolvedType::Scalar(ScalarType::Bool) => format!("*{value}"),
        ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String) => {
            format!("!{value}.is_empty()")
        }
        ResolvedType::Scalar(_) | ResolvedType::Enumeration(_) => {
            format!("*{value} != 0")
        }
        ResolvedType::Message(_) => "true".to_owned(),
    })
}
