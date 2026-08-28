// SPDX-License-Identifier: GPL-2.0-only

//! Shared schema construction for documentation and runtime enforcement.

use schemars::{JsonSchema, Schema, generate::SchemaSettings, transform::RecursiveTransform};

/// Builds the exact draft 2020-12 schema used to deserialize a request.
pub(crate) fn request_schema<T: JsonSchema>() -> Schema {
    schema_settings()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<T>()
}

/// Builds the exact draft 2020-12 schema used to serialize a response.
pub(crate) fn response_schema<T: JsonSchema>() -> Schema {
    schema_settings()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<T>()
}

fn schema_settings() -> SchemaSettings {
    SchemaSettings::draft2020_12().with(|settings| {
        settings.inline_subschemas = true;
        settings.meta_schema = None;
        settings.transforms.push(Box::new(RecursiveTransform(
            remove_safe_integer_wire_format,
        )));
    })
}

fn remove_safe_integer_wire_format(schema: &mut Schema) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    let is_safe_integer = object.get("type").and_then(serde_json::Value::as_str) == Some("integer")
        && object.get("format").and_then(serde_json::Value::as_str) == Some("int64")
        && object
            .get("maximum")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|maximum| maximum <= 9_007_199_254_740_991_i64);

    if is_safe_integer {
        object.remove("format");
    }
}
