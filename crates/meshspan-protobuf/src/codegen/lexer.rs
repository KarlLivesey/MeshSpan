// SPDX-License-Identifier: GPL-2.0-only

//! Small lexer for deterministic build-time schema parsing.

use super::CodegenError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
    Identifier(String),
    Integer(i64),
    Quoted(String),
    Symbol(char),
}

pub(super) fn lex(source_name: &str, source: &str) -> Result<Vec<Token>, CodegenError> {
    Lexer::new(source_name, source).tokens()
}

struct Lexer<'a> {
    source_name: &'a str,
    characters: Vec<char>,
    offset: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(source_name: &'a str, source: &str) -> Self {
        Self {
            source_name,
            characters: source.chars().collect(),
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    fn tokens(mut self) -> Result<Vec<Token>, CodegenError> {
        let mut tokens = Vec::new();
        while self.peek().is_some() {
            self.skip_trivia()?;
            let Some(character) = self.peek() else {
                break;
            };
            let line = self.line;
            let column = self.column;
            let kind = if is_identifier_start(character) {
                TokenKind::Identifier(self.identifier())
            } else if character.is_ascii_digit() || character == '-' {
                TokenKind::Integer(self.integer()?)
            } else if character == '"' {
                TokenKind::Quoted(self.quoted()?)
            } else if "{}[]=;.(),<>".contains(character) {
                self.advance();
                TokenKind::Symbol(character)
            } else {
                return Err(self.error(format!("unexpected character {character:?}")));
            };
            tokens.push(Token { kind, line, column });
        }
        Ok(tokens)
    }

    fn skip_trivia(&mut self) -> Result<(), CodegenError> {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.advance();
            }
            if self.peek() == Some('/') && self.peek_next() == Some('/') {
                while self.peek().is_some_and(|value| value != '\n') {
                    self.advance();
                }
                continue;
            }
            if self.peek() == Some('/') && self.peek_next() == Some('*') {
                self.advance();
                self.advance();
                loop {
                    match (self.peek(), self.peek_next()) {
                        (Some('*'), Some('/')) => {
                            self.advance();
                            self.advance();
                            break;
                        }
                        (Some(_), _) => {
                            self.advance();
                        }
                        (None, _) => {
                            return Err(self.error("unterminated block comment"));
                        }
                    }
                }
                continue;
            }
            return Ok(());
        }
    }

    fn identifier(&mut self) -> String {
        let mut value = String::new();
        while self.peek().is_some_and(is_identifier_continue) {
            if let Some(character) = self.advance() {
                value.push(character);
            }
        }
        value
    }

    fn integer(&mut self) -> Result<i64, CodegenError> {
        let mut value = String::new();
        if self.peek() == Some('-') {
            value.push('-');
            self.advance();
        }
        while self
            .peek()
            .is_some_and(|character| character.is_ascii_digit())
        {
            if let Some(character) = self.advance() {
                value.push(character);
            }
        }
        if value == "-" {
            return Err(self.error("expected digits after '-'"));
        }
        value
            .parse()
            .map_err(|_| self.error("integer is outside the supported 64-bit range"))
    }

    fn quoted(&mut self) -> Result<String, CodegenError> {
        self.advance();
        let mut value = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(value),
                Some('\\') => match self.advance() {
                    Some('"') => value.push('"'),
                    Some('\\') => value.push('\\'),
                    Some('n') => value.push('\n'),
                    Some('r') => value.push('\r'),
                    Some('t') => value.push('\t'),
                    Some(other) => {
                        return Err(self.error(format!("unsupported escape \\{other}")));
                    }
                    None => return Err(self.error("unterminated quoted string")),
                },
                Some(character) => value.push(character),
                None => return Err(self.error("unterminated quoted string")),
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.characters.get(self.offset).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.characters.get(self.offset + 1).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.offset += 1;
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn error(&self, message: impl AsRef<str>) -> CodegenError {
        CodegenError::at(self.source_name, self.line, self.column, message.as_ref())
    }
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character.is_ascii_alphabetic()
}

fn is_identifier_continue(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}
