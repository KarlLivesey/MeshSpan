// SPDX-License-Identifier: GPL-2.0-only

//! Pure-Rust compiler for the supported proto3 schema surface.

mod lexer;
mod model;
mod parser;
mod render;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs;
use std::path::PathBuf;

use model::Schema;
use parser::parse_schema;
use render::render_schema;

/// A schema compilation failure with a safe build-time diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodegenError {
    message: String,
}

impl CodegenError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(super) fn at(source: &str, line: usize, column: usize, message: &str) -> Self {
        Self::new(format!("{source}:{line}:{column}: {message}"))
    }
}

impl fmt::Display for CodegenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CodegenError {}

/// Builder for deterministic Rust generation from proto3 files.
#[derive(Clone, Debug, Default)]
pub struct Codegen {
    includes: Vec<PathBuf>,
    inputs: Vec<PathBuf>,
    output: Option<PathBuf>,
}

impl Codegen {
    /// Creates an empty generator configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            includes: Vec::new(),
            inputs: Vec::new(),
            output: None,
        }
    }

    /// Adds an import search root.
    #[must_use]
    pub fn include(mut self, directory: impl Into<PathBuf>) -> Self {
        self.includes.push(directory.into());
        self
    }

    /// Adds one root schema file.
    #[must_use]
    pub fn input(mut self, file: impl Into<PathBuf>) -> Self {
        self.inputs.push(file.into());
        self
    }

    /// Selects the generated Rust file.
    #[must_use]
    pub fn output(mut self, file: impl Into<PathBuf>) -> Self {
        self.output = Some(file.into());
        self
    }

    /// Parses, validates and deterministically writes generated Rust records.
    ///
    /// # Errors
    ///
    /// Returns an error for missing configuration, inaccessible files, invalid
    /// schemas, unresolved imports or types, or output failure.
    pub fn compile(self) -> Result<(), CodegenError> {
        let output = self
            .output
            .ok_or_else(|| CodegenError::new("no generated Rust output was configured"))?;
        if self.inputs.is_empty() {
            return Err(CodegenError::new("no root schema input was configured"));
        }
        let schemas = load_schemas(&self.inputs, &self.includes)?;
        let merged = Schema::merge(schemas)?;
        let generated = render_schema(&merged)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CodegenError::new(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        fs::write(&output, generated).map_err(|error| {
            CodegenError::new(format!("cannot write {}: {error}", output.display()))
        })
    }
}

fn load_schemas(inputs: &[PathBuf], includes: &[PathBuf]) -> Result<Vec<Schema>, CodegenError> {
    let mut queue = VecDeque::from(inputs.to_vec());
    let mut visited = BTreeSet::new();
    let mut schemas = BTreeMap::new();
    while let Some(file) = queue.pop_front() {
        let canonical = fs::canonicalize(&file).map_err(|error| {
            CodegenError::new(format!("cannot resolve {}: {error}", file.display()))
        })?;
        if !visited.insert(canonical.clone()) {
            continue;
        }
        let source = fs::read_to_string(&canonical).map_err(|error| {
            CodegenError::new(format!("cannot read {}: {error}", canonical.display()))
        })?;
        let source_name = canonical.display().to_string();
        let schema = parse_schema(&source_name, &source)?;
        for import in &schema.imports {
            queue.push_back(resolve_import(import, includes)?);
        }
        schemas.insert(canonical, schema);
    }
    Ok(schemas.into_values().collect())
}

fn resolve_import(import: &str, includes: &[PathBuf]) -> Result<PathBuf, CodegenError> {
    for include in includes {
        let candidate = include.join(import);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CodegenError::new(format!(
        "cannot resolve imported schema {import:?} from configured include roots"
    )))
}

#[cfg(test)]
mod tests;
