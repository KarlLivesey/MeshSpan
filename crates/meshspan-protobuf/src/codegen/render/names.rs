// SPDX-License-Identifier: GPL-2.0-only

//! Schema-to-Rust identifier transformations.

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
];

pub(super) fn rust_identifier(value: &str) -> String {
    if RUST_KEYWORDS.contains(&value) {
        format!("r#{value}")
    } else {
        value.to_owned()
    }
}

pub(super) fn snake_case(value: &str) -> String {
    let mut output = String::new();
    let mut previous_lower_or_digit = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            if previous_lower_or_digit {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
            previous_lower_or_digit = false;
        } else {
            output.push(character);
            previous_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
        }
    }
    output
}

pub(super) fn pascal_case(value: &str) -> String {
    let mut output = String::new();
    for part in value.split('_').filter(|part| !part.is_empty()) {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            output.push(first.to_ascii_uppercase());
            for character in characters {
                output.push(character.to_ascii_lowercase());
            }
        }
    }
    output
}

pub(super) fn enum_prefix(type_name: &str) -> String {
    format!("{}_", snake_case(type_name).to_ascii_uppercase())
}
