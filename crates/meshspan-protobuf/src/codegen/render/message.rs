// SPDX-License-Identifier: GPL-2.0-only

//! Message records, oneofs and runtime trait implementations.

use super::field::{
    render_decode_field, render_decode_oneof, render_oneof_encode, render_oneof_length,
    render_regular_encode, render_regular_length, rust_field_type, rust_oneof_variant_type,
};
use super::line;
use super::names::{pascal_case, rust_identifier, snake_case};
use crate::codegen::CodegenError;
use crate::codegen::model::{Message, Schema};

pub(super) fn render_message(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    render_struct(output, schema, message)?;
    if !message.oneofs.is_empty() {
        render_oneofs(output, schema, message)?;
    }
    render_message_impl(output, schema, message)?;
    line(output, "");
    Ok(())
}

fn render_struct(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    let copy = if schema.message_is_copy(message) {
        "Copy, "
    } else {
        ""
    };
    line(
        output,
        format!("#[derive(Clone, {copy}Debug, Default, PartialEq, Eq, Hash)]"),
    );
    line(output, format!("pub struct {} {{", message.name));
    for field in &message.fields {
        line(
            output,
            format!(
                "    pub {}: {},",
                rust_identifier(&field.name),
                rust_field_type(field, schema)?
            ),
        );
    }
    let module = snake_case(&message.name);
    for oneof in &message.oneofs {
        line(
            output,
            format!(
                "    pub {}: ::core::option::Option<{module}::{}>,",
                rust_identifier(&oneof.name),
                pascal_case(&oneof.name)
            ),
        );
    }
    line(output, "}");
    Ok(())
}

fn render_oneofs(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    line(output, format!("pub mod {} {{", snake_case(&message.name)));
    for oneof in &message.oneofs {
        let copy = if oneof.fields.iter().all(|field| schema.field_is_copy(field)) {
            "Copy, "
        } else {
            ""
        };
        line(
            output,
            format!("    #[derive(Clone, {copy}Debug, PartialEq, Eq, Hash)]"),
        );
        line(
            output,
            format!("    pub enum {} {{", pascal_case(&oneof.name)),
        );
        for field in &oneof.fields {
            line(
                output,
                format!(
                    "        {}({}),",
                    pascal_case(&field.name),
                    rust_oneof_variant_type(field, schema)?
                ),
            );
        }
        line(output, "    }");
    }
    line(output, "}");
    Ok(())
}

fn render_message_impl(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    line(
        output,
        format!("impl ::meshspan_protobuf::Message for {} {{", message.name),
    );
    render_length_method(output, schema, message)?;
    render_encode_method(output, schema, message)?;
    render_merge_method(output, schema, message)?;
    line(output, "}");
    Ok(())
}

fn render_length_method(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    line(
        output,
        "    fn encoded_len(&self, length: &mut ::meshspan_protobuf::EncodedLength) -> ::core::result::Result<(), ::meshspan_protobuf::EncodeError> {",
    );
    for field in &message.fields {
        render_regular_length(output, schema, field)?;
    }
    let module = snake_case(&message.name);
    for oneof in &message.oneofs {
        let oneof_type = pascal_case(&oneof.name);
        let oneof_name = rust_identifier(&oneof.name);
        line(
            output,
            format!("        if let Some(value) = &self.{oneof_name} {{"),
        );
        line(output, "            match value {");
        for field in &oneof.fields {
            line(
                output,
                format!(
                    "                {module}::{oneof_type}::{}(value) => {{",
                    pascal_case(&field.name)
                ),
            );
            render_oneof_length(output, schema, field, "                    ")?;
            line(output, "                }");
        }
        line(output, "            }");
        line(output, "        }");
    }
    line(output, "        Ok(())");
    line(output, "    }");
    Ok(())
}

fn render_encode_method(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    line(
        output,
        "    fn encode_fields(&self, encoder: &mut ::meshspan_protobuf::Encoder<'_>) -> ::core::result::Result<(), ::meshspan_protobuf::EncodeError> {",
    );
    for field in &message.fields {
        render_regular_encode(output, schema, field)?;
    }
    let module = snake_case(&message.name);
    for oneof in &message.oneofs {
        let oneof_type = pascal_case(&oneof.name);
        let oneof_name = rust_identifier(&oneof.name);
        line(
            output,
            format!("        if let Some(value) = &self.{oneof_name} {{"),
        );
        line(output, "            match value {");
        for field in &oneof.fields {
            line(
                output,
                format!(
                    "                {module}::{oneof_type}::{}(value) => {{",
                    pascal_case(&field.name)
                ),
            );
            render_oneof_encode(output, schema, field, "                    ")?;
            line(output, "                }");
        }
        line(output, "            }");
        line(output, "        }");
    }
    line(output, "        Ok(())");
    line(output, "    }");
    Ok(())
}

fn render_merge_method(
    output: &mut String,
    schema: &Schema,
    message: &Message,
) -> Result<(), CodegenError> {
    line(
        output,
        "    fn merge_field(&mut self, field_number: u32, wire_type: ::meshspan_protobuf::WireType, decoder: &mut ::meshspan_protobuf::Decoder<'_>, state: &mut ::meshspan_protobuf::DecodeState, depth: usize) -> ::core::result::Result<(), ::meshspan_protobuf::DecodeError> {",
    );
    line(output, "        match field_number {");
    for field in &message.fields {
        render_decode_field(output, schema, field)?;
    }
    for oneof in &message.oneofs {
        for field in &oneof.fields {
            render_decode_oneof(output, schema, &message.name, &oneof.name, field)?;
        }
    }
    line(
        output,
        "            _ => decoder.skip_field(field_number, wire_type, state, depth)?,",
    );
    line(output, "        }");
    line(output, "        Ok(())");
    line(output, "    }");
    Ok(())
}
