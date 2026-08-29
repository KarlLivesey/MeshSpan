// SPDX-License-Identifier: GPL-2.0-only

//! Deterministically compiles the private protocol with a vendored `protoc`.

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

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut configuration = prost_build::Config::new();
    configuration.protoc_executable(protoc);
    configuration.compile_protos(&schemas, &["proto"])?;
    Ok(())
}
