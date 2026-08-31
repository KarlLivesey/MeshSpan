// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic Rust source rendering.

mod enumeration;
mod field;
mod message;
mod names;

use super::CodegenError;
use super::model::Schema;
use enumeration::render_enumeration;
use message::render_message;

pub(super) fn render_schema(schema: &Schema) -> Result<String, CodegenError> {
    let mut output = String::from(
        "// SPDX-License-Identifier: GPL-2.0-only\n\
         // This file is generated. Do not edit it directly.\n\n",
    );
    for enumeration in &schema.enums {
        render_enumeration(&mut output, enumeration);
    }
    for message in &schema.messages {
        render_message(&mut output, schema, message)?;
    }
    Ok(output)
}

pub(super) fn line(output: &mut String, value: impl AsRef<str>) {
    output.push_str(value.as_ref());
    output.push('\n');
}
