// SPDX-License-Identifier: GPL-2.0-only

//! Validated intermediate schema model.

use std::collections::{BTreeMap, BTreeSet};

use super::CodegenError;

pub(super) const MAXIMUM_FIELD_NUMBER: u32 = (1 << 29) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Schema {
    pub package: String,
    pub imports: Vec<String>,
    pub messages: Vec<Message>,
    pub enums: Vec<Enumeration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Message {
    pub name: String,
    pub fields: Vec<Field>,
    pub oneofs: Vec<Oneof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Oneof {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub label: FieldLabel,
    pub schema_type: String,
    pub name: String,
    pub number: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FieldLabel {
    Singular,
    Optional,
    Repeated,
    Oneof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Enumeration {
    pub name: String,
    pub values: Vec<EnumValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EnumValue {
    pub name: String,
    pub number: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResolvedType<'a> {
    Scalar(ScalarType),
    Message(&'a Message),
    Enumeration(&'a Enumeration),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScalarType {
    Bool,
    Bytes,
    Fixed64,
    Sint64,
    String,
    Uint32,
    Uint64,
}

impl Schema {
    pub fn merge(schemas: Vec<Self>) -> Result<Self, CodegenError> {
        let package = schemas
            .first()
            .map(|schema| schema.package.clone())
            .ok_or_else(|| CodegenError::new("no schemas were loaded"))?;
        let mut merged = Self {
            package,
            imports: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
        };
        for mut schema in schemas {
            if schema.package != merged.package {
                return Err(CodegenError::new(format!(
                    "all generated schemas must share package {:?}; found {:?}",
                    merged.package, schema.package
                )));
            }
            merged.messages.append(&mut schema.messages);
            merged.enums.append(&mut schema.enums);
        }
        merged.validate()?;
        Ok(merged)
    }

    pub fn resolve(&self, name: &str) -> Result<ResolvedType<'_>, CodegenError> {
        if let Some(scalar) = ScalarType::parse(name) {
            return Ok(ResolvedType::Scalar(scalar));
        }
        let local_name = name.rsplit('.').next().unwrap_or(name);
        if let Some(message) = self.messages.iter().find(|value| value.name == local_name) {
            return Ok(ResolvedType::Message(message));
        }
        if let Some(enumeration) = self.enums.iter().find(|value| value.name == local_name) {
            return Ok(ResolvedType::Enumeration(enumeration));
        }
        Err(CodegenError::new(format!(
            "field type {name:?} is not declared in package {:?}",
            self.package
        )))
    }

    pub fn message_is_copy(&self, message: &Message) -> bool {
        self.message_is_copy_inner(message, &mut BTreeSet::new())
    }

    pub fn field_is_copy(&self, field: &Field) -> bool {
        self.field_is_copy_inner(field, &mut BTreeSet::new())
    }

    fn message_is_copy_inner(&self, message: &Message, visiting: &mut BTreeSet<String>) -> bool {
        if !visiting.insert(message.name.clone()) {
            return false;
        }
        let copy = message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|oneof| &oneof.fields))
            .all(|field| self.field_is_copy_inner(field, visiting));
        visiting.remove(&message.name);
        copy
    }

    fn field_is_copy_inner(&self, field: &Field, visiting: &mut BTreeSet<String>) -> bool {
        if field.label == FieldLabel::Repeated {
            return false;
        }
        match self.resolve(&field.schema_type) {
            Ok(ResolvedType::Scalar(ScalarType::Bytes | ScalarType::String)) | Err(_) => false,
            Ok(ResolvedType::Scalar(_) | ResolvedType::Enumeration(_)) => true,
            Ok(ResolvedType::Message(message)) => self.message_is_copy_inner(message, visiting),
        }
    }

    fn validate(&self) -> Result<(), CodegenError> {
        if self.package.is_empty() {
            return Err(CodegenError::new("a non-empty proto package is required"));
        }
        let mut types = BTreeSet::new();
        for name in self
            .messages
            .iter()
            .map(|value| &value.name)
            .chain(self.enums.iter().map(|value| &value.name))
        {
            if !types.insert(name) {
                return Err(CodegenError::new(format!(
                    "duplicate package type {name:?}"
                )));
            }
        }
        for enumeration in &self.enums {
            enumeration.validate()?;
        }
        for message in &self.messages {
            message.validate(self)?;
        }
        Ok(())
    }
}

impl Message {
    fn validate(&self, schema: &Schema) -> Result<(), CodegenError> {
        let mut names = BTreeSet::new();
        let mut numbers = BTreeSet::new();
        for field in self
            .fields
            .iter()
            .chain(self.oneofs.iter().flat_map(|oneof| &oneof.fields))
        {
            if !names.insert(&field.name) {
                return Err(CodegenError::new(format!(
                    "message {:?} has duplicate field {:?}",
                    self.name, field.name
                )));
            }
            if !numbers.insert(field.number) {
                return Err(CodegenError::new(format!(
                    "message {:?} has duplicate field number {}",
                    self.name, field.number
                )));
            }
            if field.number == 0
                || field.number > MAXIMUM_FIELD_NUMBER
                || (19_000..=19_999).contains(&field.number)
            {
                return Err(CodegenError::new(format!(
                    "message {:?} has forbidden field number {}",
                    self.name, field.number
                )));
            }
            schema.resolve(&field.schema_type)?;
        }
        let oneof_names = self
            .oneofs
            .iter()
            .map(|oneof| &oneof.name)
            .collect::<BTreeSet<_>>();
        if oneof_names.len() != self.oneofs.len() {
            return Err(CodegenError::new(format!(
                "message {:?} has duplicate oneof names",
                self.name
            )));
        }
        Ok(())
    }
}

impl Enumeration {
    fn validate(&self) -> Result<(), CodegenError> {
        let Some(first) = self.values.first() else {
            return Err(CodegenError::new(format!(
                "enum {:?} has no values",
                self.name
            )));
        };
        if first.number != 0 {
            return Err(CodegenError::new(format!(
                "proto3 enum {:?} must begin with value zero",
                self.name
            )));
        }
        let mut names = BTreeSet::new();
        let mut numbers = BTreeMap::new();
        for value in &self.values {
            if !names.insert(&value.name) {
                return Err(CodegenError::new(format!(
                    "enum {:?} has duplicate value {:?}",
                    self.name, value.name
                )));
            }
            if let Some(previous) = numbers.insert(value.number, &value.name) {
                return Err(CodegenError::new(format!(
                    "enum {:?} aliases {previous:?} and {:?}; allow_alias is not supported",
                    self.name, value.name
                )));
            }
        }
        Ok(())
    }
}

impl ScalarType {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bool" => Some(Self::Bool),
            "bytes" => Some(Self::Bytes),
            "fixed64" => Some(Self::Fixed64),
            "sint64" => Some(Self::Sint64),
            "string" => Some(Self::String),
            "uint32" => Some(Self::Uint32),
            "uint64" => Some(Self::Uint64),
            _ => None,
        }
    }
}
