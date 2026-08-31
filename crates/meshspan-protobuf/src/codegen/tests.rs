// SPDX-License-Identifier: GPL-2.0-only

//! Parser, validation and deterministic source generation tests.

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Codegen, parse_schema, render_schema};
use crate::codegen::model::Schema;

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const VALID_SCHEMA: &str = r#"
syntax = "proto3";
package example.v1;

enum ResultKind {
  RESULT_KIND_UNSPECIFIED = 0;
  RESULT_KIND_ACCEPTED = 1;
}

message Child {
  sint64 delta = 1;
}

message Envelope {
  uint64 sequence = 1;
  optional bytes token = 2;
  repeated uint32 features = 3;
  ResultKind result = 4;
  oneof body {
    Child child = 10;
    bytes opaque = 11;
  }
}
"#;

#[test]
fn deterministic_generation_has_plain_rust_records() -> Result<(), Box<dyn std::error::Error>> {
    let schema = parse_schema("memory.proto", VALID_SCHEMA)?;
    let schema = Schema::merge(vec![schema])?;
    let first = render_schema(&schema)?;
    let second = render_schema(&schema)?;
    assert_eq!(first, second);
    assert!(first.contains("pub struct Envelope"));
    assert!(first.contains("pub token: ::core::option::Option<::std::vec::Vec<u8>>"));
    assert!(first.contains("pub enum Body"));
    assert!(first.contains("impl ::meshspan_protobuf::Message for Envelope"));
    assert!(!first.contains("prost"));
    Ok(())
}

#[test]
fn imports_resolve_without_an_external_compiler() -> Result<(), Box<dyn std::error::Error>> {
    let directory = unique_test_directory()?;
    let common = directory.join("common.proto");
    let root = directory.join("root.proto");
    let output = directory.join("generated.rs");
    fs::write(
        &common,
        "syntax = \"proto3\"; package example.v1; message Shared { bytes id = 1; }",
    )?;
    fs::write(
        &root,
        "syntax = \"proto3\"; package example.v1; import \"common.proto\"; message Root { Shared shared = 1; }",
    )?;
    Codegen::new()
        .include(&directory)
        .input(&root)
        .output(&output)
        .compile()?;
    let generated = fs::read_to_string(output)?;
    assert!(generated.contains("pub struct Shared"));
    assert!(generated.contains("pub struct Root"));
    fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn unresolved_types_fail_before_source_generation() -> Result<(), Box<dyn std::error::Error>> {
    let schema = parse_schema(
        "invalid.proto",
        "syntax = \"proto3\"; package example.v1; message Broken { Missing value = 1; }",
    )?;
    let Err(error) = Schema::merge(vec![schema]) else {
        return Err("unresolved field type was accepted".into());
    };
    assert!(error.to_string().contains("is not declared"));
    Ok(())
}

#[test]
fn duplicate_field_numbers_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let schema = parse_schema(
        "invalid.proto",
        "syntax = \"proto3\"; package example.v1; message Broken { bytes first = 1; bytes second = 1; }",
    )?;
    let Err(error) = Schema::merge(vec![schema]) else {
        return Err("duplicate field number was accepted".into());
    };
    assert!(error.to_string().contains("duplicate field number"));
    Ok(())
}

fn unique_test_directory() -> Result<std::path::PathBuf, std::io::Error> {
    let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "meshspan-protobuf-codegen-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}
