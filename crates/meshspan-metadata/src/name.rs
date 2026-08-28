// SPDX-License-Identifier: GPL-2.0-only

//! Canonical user-visible names used as relational uniqueness keys.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

const MAXIMUM_NAME_BYTES: usize = 256;

/// Validated display text and its deterministic case-insensitive NFC key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordName {
    display: String,
    canonical: String,
}

impl RecordName {
    /// Normalises one non-path user-visible name and derives its uniqueness key.
    ///
    /// # Errors
    ///
    /// Rejects blank, surrounding-space, control, slash, dot-segment or excessive names.
    pub fn new(value: &str) -> Result<Self, RecordNameError> {
        let display: String = value.nfc().collect();
        let forbidden = display.is_empty()
            || display != display.trim()
            || display.len() > MAXIMUM_NAME_BYTES
            || display
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'))
            || matches!(display.as_str(), "." | "..");
        if forbidden {
            return Err(RecordNameError::Invalid);
        }
        let canonical: String = display
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .nfc()
            .collect();
        if canonical.is_empty() || canonical.len() > MAXIMUM_NAME_BYTES {
            return Err(RecordNameError::Invalid);
        }
        Ok(Self { display, canonical })
    }

    /// Returns the NFC display form.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Returns the deterministic case-insensitive NFC uniqueness key.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

/// Rejection of a name unsafe for a bounded persisted record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecordNameError {
    /// The input is blank, malformed, path-like, ambiguous or excessive.
    #[error("record name is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::{RecordName, RecordNameError};

    #[test]
    fn canonical_name_normalises_case_and_combining_forms() {
        let composed = RecordName::new("Café");
        let decomposed = RecordName::new("CAFE\u{301}");
        assert_eq!(
            composed.as_ref().map(RecordName::canonical),
            decomposed.as_ref().map(RecordName::canonical)
        );
        assert_eq!(composed.map(|value| value.canonical), Ok("café".to_owned()));
    }

    #[test]
    fn record_name_rejects_path_and_ambiguous_values() {
        for value in ["", " name", "name ", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert_eq!(RecordName::new(value), Err(RecordNameError::Invalid));
        }
    }
}
