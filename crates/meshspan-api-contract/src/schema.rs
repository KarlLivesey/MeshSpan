// SPDX-License-Identifier: GPL-2.0-only

//! Shared schema construction for documentation and runtime enforcement.

use schemars::{JsonSchema, Schema, generate::SchemaSettings};

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
    })
}
