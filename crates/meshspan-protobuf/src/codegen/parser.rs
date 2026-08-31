// SPDX-License-Identifier: GPL-2.0-only

//! Parser for the deliberately explicit supported proto3 grammar.

use super::CodegenError;
use super::lexer::{Token, TokenKind, lex};
use super::model::{EnumValue, Enumeration, Field, FieldLabel, Message, Oneof, Schema};

pub(super) fn parse_schema(source_name: &str, source: &str) -> Result<Schema, CodegenError> {
    Parser::new(source_name, lex(source_name, source)?).schema()
}

struct Parser<'a> {
    source_name: &'a str,
    tokens: Vec<Token>,
    offset: usize,
}

impl<'a> Parser<'a> {
    fn new(source_name: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            source_name,
            tokens,
            offset: 0,
        }
    }

    fn schema(mut self) -> Result<Schema, CodegenError> {
        let mut syntax_seen = false;
        let mut package = None;
        let mut imports = Vec::new();
        let mut messages = Vec::new();
        let mut enums = Vec::new();
        while let Some(keyword) = self.peek_identifier() {
            match keyword {
                "syntax" => {
                    if syntax_seen {
                        return Err(self.error("syntax was declared more than once"));
                    }
                    self.parse_syntax()?;
                    syntax_seen = true;
                }
                "package" => {
                    if package.is_some() {
                        return Err(self.error("package was declared more than once"));
                    }
                    package = Some(self.parse_package()?);
                }
                "import" => imports.push(self.parse_import()?),
                "message" => messages.push(self.parse_message()?),
                "enum" => enums.push(self.parse_enum()?),
                unsupported => {
                    return Err(
                        self.error(format!("unsupported top-level declaration {unsupported:?}"))
                    );
                }
            }
        }
        if !syntax_seen {
            return Err(self.error("syntax = \"proto3\" is required"));
        }
        let package = package.ok_or_else(|| self.error("a package declaration is required"))?;
        Ok(Schema {
            package,
            imports,
            messages,
            enums,
        })
    }

    fn parse_syntax(&mut self) -> Result<(), CodegenError> {
        self.expect_identifier("syntax")?;
        self.expect_symbol('=')?;
        let syntax = self.quoted()?;
        if syntax != "proto3" {
            return Err(self.error(format!("only proto3 is supported, found {syntax:?}")));
        }
        self.expect_symbol(';')
    }

    fn parse_package(&mut self) -> Result<String, CodegenError> {
        self.expect_identifier("package")?;
        let package = self.qualified_identifier()?;
        self.expect_symbol(';')?;
        Ok(package)
    }

    fn parse_import(&mut self) -> Result<String, CodegenError> {
        self.expect_identifier("import")?;
        if matches!(self.peek_identifier(), Some("public" | "weak")) {
            return Err(self.error("public and weak imports are not supported"));
        }
        let import = self.quoted()?;
        self.expect_symbol(';')?;
        Ok(import)
    }

    fn parse_message(&mut self) -> Result<Message, CodegenError> {
        self.expect_identifier("message")?;
        let name = self.identifier()?;
        self.expect_symbol('{')?;
        let mut fields = Vec::new();
        let mut oneofs = Vec::new();
        while !self.consume_symbol('}') {
            if self.peek_identifier() == Some("oneof") {
                oneofs.push(self.parse_oneof()?);
            } else {
                fields.push(self.parse_field(FieldLabel::Singular)?);
            }
        }
        Ok(Message {
            name,
            fields,
            oneofs,
        })
    }

    fn parse_oneof(&mut self) -> Result<Oneof, CodegenError> {
        self.expect_identifier("oneof")?;
        let name = self.identifier()?;
        self.expect_symbol('{')?;
        let mut fields = Vec::new();
        while !self.consume_symbol('}') {
            fields.push(self.parse_field(FieldLabel::Oneof)?);
        }
        if fields.is_empty() {
            return Err(self.error(format!("oneof {name:?} has no fields")));
        }
        Ok(Oneof { name, fields })
    }

    fn parse_field(&mut self, default_label: FieldLabel) -> Result<Field, CodegenError> {
        let label = match self.peek_identifier() {
            Some("optional") if default_label != FieldLabel::Oneof => {
                self.take();
                FieldLabel::Optional
            }
            Some("repeated") if default_label != FieldLabel::Oneof => {
                self.take();
                FieldLabel::Repeated
            }
            Some("optional" | "repeated") => {
                return Err(self.error("oneof fields cannot have optional or repeated labels"));
            }
            _ => default_label,
        };
        let schema_type = self.qualified_identifier()?;
        let name = self.identifier()?;
        self.expect_symbol('=')?;
        let number = self.positive_u32()?;
        if self.consume_symbol('[') {
            return Err(self.error("field options are not supported"));
        }
        self.expect_symbol(';')?;
        Ok(Field {
            label,
            schema_type,
            name,
            number,
        })
    }

    fn parse_enum(&mut self) -> Result<Enumeration, CodegenError> {
        self.expect_identifier("enum")?;
        let name = self.identifier()?;
        self.expect_symbol('{')?;
        let mut values = Vec::new();
        while !self.consume_symbol('}') {
            let value_name = self.identifier()?;
            self.expect_symbol('=')?;
            let number = self.i32()?;
            if self.consume_symbol('[') {
                return Err(self.error("enum value options are not supported"));
            }
            self.expect_symbol(';')?;
            values.push(EnumValue {
                name: value_name,
                number,
            });
        }
        Ok(Enumeration { name, values })
    }

    fn qualified_identifier(&mut self) -> Result<String, CodegenError> {
        let leading_dot = self.consume_symbol('.');
        let mut value = self.identifier()?;
        while self.consume_symbol('.') {
            value.push('.');
            value.push_str(&self.identifier()?);
        }
        if leading_dot {
            value.insert(0, '.');
        }
        Ok(value)
    }

    fn positive_u32(&mut self) -> Result<u32, CodegenError> {
        let value = self.integer()?;
        u32::try_from(value).map_err(|_| self.error("field number must be a positive u32"))
    }

    fn i32(&mut self) -> Result<i32, CodegenError> {
        let value = self.integer()?;
        i32::try_from(value).map_err(|_| self.error("enum value must fit in i32"))
    }

    fn expect_identifier(&mut self, expected: &str) -> Result<(), CodegenError> {
        let actual = self.identifier()?;
        if actual == expected {
            Ok(())
        } else {
            Err(self.error(format!("expected {expected:?}, found {actual:?}")))
        }
    }

    fn identifier(&mut self) -> Result<String, CodegenError> {
        match self.take().map(|token| token.kind) {
            Some(TokenKind::Identifier(value)) => Ok(value),
            _ => Err(self.error("expected an identifier")),
        }
    }

    fn integer(&mut self) -> Result<i64, CodegenError> {
        match self.take().map(|token| token.kind) {
            Some(TokenKind::Integer(value)) => Ok(value),
            _ => Err(self.error("expected an integer")),
        }
    }

    fn quoted(&mut self) -> Result<String, CodegenError> {
        match self.take().map(|token| token.kind) {
            Some(TokenKind::Quoted(value)) => Ok(value),
            _ => Err(self.error("expected a quoted string")),
        }
    }

    fn expect_symbol(&mut self, expected: char) -> Result<(), CodegenError> {
        if self.consume_symbol(expected) {
            Ok(())
        } else {
            Err(self.error(format!("expected symbol {expected:?}")))
        }
    }

    fn consume_symbol(&mut self, expected: char) -> bool {
        if matches!(
            self.tokens.get(self.offset).map(|token| &token.kind),
            Some(TokenKind::Symbol(actual)) if *actual == expected
        ) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek_identifier(&self) -> Option<&str> {
        match self.tokens.get(self.offset).map(|token| &token.kind) {
            Some(TokenKind::Identifier(value)) => Some(value),
            _ => None,
        }
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.offset)?.clone();
        self.offset += 1;
        Some(token)
    }

    fn error(&self, message: impl AsRef<str>) -> CodegenError {
        let location = self.tokens.get(self.offset).or_else(|| self.tokens.last());
        let (line, column) = location.map_or((1, 1), |token| (token.line, token.column));
        CodegenError::at(self.source_name, line, column, message.as_ref())
    }
}
