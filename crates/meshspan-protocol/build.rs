// SPDX-License-Identifier: GPL-2.0-only

//! Deterministically compiles the private protocol without an external process.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schemas = [
        "proto/meshspan/private/v1/common.proto",
        "proto/meshspan/private/v1/connection.proto",
        "proto/meshspan/private/v1/consensus.proto",
        "proto/meshspan/private/v1/control.proto",
        "proto/meshspan/private/v1/data.proto",
        "proto/meshspan/private/v1/federation.proto",
    ];
    for schema in schemas {
        println!("cargo:rerun-if-changed={schema}");
    }

    let output_directory =
        std::env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR to build.rs")?;
    let mut codegen = meshspan_protobuf::codegen::Codegen::new().include("proto");
    for schema in schemas {
        codegen = codegen.input(schema);
    }
    codegen
        .output(PathBuf::from(output_directory).join("meshspan.private.v1.rs"))
        .compile()?;
    Ok(())
}
