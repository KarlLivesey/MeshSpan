// SPDX-License-Identifier: GPL-2.0-only

//! Case-preserving, case-insensitive logical names independent of provider filesystems.

use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

const HARD_MAXIMUM_COMPONENT_BYTES: usize = 16 * 1_024;
const HARD_MAXIMUM_DEPTH: usize = 1_024;
const HARD_MAXIMUM_PATH_BYTES: usize = 1024 * 1_024;

/// User-selected interoperability constraints for one volume namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityProfile {
    /// Conservative cross-client names suitable for the initial HTTPS and SMB adapters.
    Portable,
    /// MeshSpan-only structural safety rules with administrator-selected size limits.
    Extended,
}

/// Explicit component, depth and encoded-path bounds for one volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceLimits {
    profile: CompatibilityProfile,
    maximum_component_bytes: usize,
    maximum_depth: usize,
    maximum_path_bytes: usize,
}

impl NamespaceLimits {
    /// Appliance default balancing broad client interoperability with useful paths.
    pub const PORTABLE: Self = Self {
        profile: CompatibilityProfile::Portable,
        maximum_component_bytes: 255,
        maximum_depth: 256,
        maximum_path_bytes: 4_096,
    };

    /// Constructs explicit limits beneath mandatory parser/allocation ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero values, compiled-ceiling excess and paths smaller than one component.
    pub const fn new(
        profile: CompatibilityProfile,
        maximum_component_bytes: usize,
        maximum_depth: usize,
        maximum_path_bytes: usize,
    ) -> Result<Self, NamespaceNameError> {
        let invalid = maximum_component_bytes == 0
            || maximum_component_bytes > HARD_MAXIMUM_COMPONENT_BYTES
            || maximum_depth == 0
            || maximum_depth > HARD_MAXIMUM_DEPTH
            || maximum_path_bytes < maximum_component_bytes
            || maximum_path_bytes > HARD_MAXIMUM_PATH_BYTES;
        if invalid {
            Err(NamespaceNameError::InvalidLimits)
        } else {
            Ok(Self {
                profile,
                maximum_component_bytes,
                maximum_depth,
                maximum_path_bytes,
            })
        }
    }

    /// Selected interoperability behaviour.
    #[must_use]
    pub const fn profile(self) -> CompatibilityProfile {
        self.profile
    }

    /// Maximum UTF-8 bytes in one normalised display or canonical component.
    #[must_use]
    pub const fn maximum_component_bytes(self) -> usize {
        self.maximum_component_bytes
    }

    /// Maximum logical component count below the volume root.
    #[must_use]
    pub const fn maximum_depth(self) -> usize {
        self.maximum_depth
    }

    /// Maximum slash-separated UTF-8 bytes below the volume root.
    #[must_use]
    pub const fn maximum_path_bytes(self) -> usize {
        self.maximum_path_bytes
    }
}

/// One validated display component plus its deterministic Unicode comparison key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceComponent {
    display: String,
    canonical: String,
}

impl NamespaceComponent {
    /// Normalises display text to NFC and derives a full, non-Turkic Unicode case-fold key.
    ///
    /// # Errors
    ///
    /// Rejects path separators, controls, dot segments, configured excess and portable-profile
    /// names known to be ambiguous or unusable across the initial access clients.
    pub fn new(value: &str, limits: NamespaceLimits) -> Result<Self, NamespaceNameError> {
        let display: String = value.nfc().collect();
        if structurally_invalid(&display)
            || display.len() > limits.maximum_component_bytes
            || (limits.profile == CompatibilityProfile::Portable && portable_name_invalid(&display))
        {
            return Err(NamespaceNameError::InvalidComponent);
        }
        let folded: String = display.as_str().case_fold().collect();
        let canonical: String = folded.nfc().collect();
        if canonical.is_empty() || canonical.len() > limits.maximum_component_bytes {
            return Err(NamespaceNameError::InvalidComponent);
        }
        Ok(Self { display, canonical })
    }

    /// Revalidates a stored display/key pair against mandatory structural and allocation bounds.
    pub(crate) fn from_stored(display: &str, canonical: &str) -> Result<Self, NamespaceNameError> {
        let limits = NamespaceLimits {
            profile: CompatibilityProfile::Extended,
            maximum_component_bytes: HARD_MAXIMUM_COMPONENT_BYTES,
            maximum_depth: HARD_MAXIMUM_DEPTH,
            maximum_path_bytes: HARD_MAXIMUM_PATH_BYTES,
        };
        let component = Self::new(display, limits)?;
        if component.canonical == canonical {
            Ok(component)
        } else {
            Err(NamespaceNameError::InvalidComponent)
        }
    }

    /// Case-preserved NFC text returned to users and adapters.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Full case-folded NFC key used only for namespace comparison and uniqueness.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Whether two display spellings resolve to the same logical component.
    #[must_use]
    pub fn collides_with(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

/// One validated root-relative sequence of namespace components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacePath {
    components: Vec<NamespaceComponent>,
    display_bytes: usize,
    canonical_bytes: usize,
}

impl NamespacePath {
    /// Validates already tokenised components without guessing an adapter's path separator rules.
    ///
    /// # Errors
    ///
    /// Rejects empty paths, excessive depth/encoded size and any invalid component.
    pub fn from_components<'a>(
        values: impl IntoIterator<Item = &'a str>,
        limits: NamespaceLimits,
    ) -> Result<Self, NamespaceNameError> {
        let mut components = Vec::new();
        let mut display_bytes = 0_usize;
        let mut canonical_bytes = 0_usize;
        for value in values
            .into_iter()
            .take(limits.maximum_depth.saturating_add(1))
        {
            if components.len() == limits.maximum_depth {
                return Err(NamespaceNameError::PathTooDeep);
            }
            let component = NamespaceComponent::new(value, limits)?;
            display_bytes = append_component_bytes(display_bytes, component.display.len())?;
            canonical_bytes = append_component_bytes(canonical_bytes, component.canonical.len())?;
            if display_bytes > limits.maximum_path_bytes
                || canonical_bytes > limits.maximum_path_bytes
            {
                return Err(NamespaceNameError::PathTooLong);
            }
            components.push(component);
        }
        if components.is_empty() {
            return Err(NamespaceNameError::InvalidComponent);
        }
        Ok(Self {
            components,
            display_bytes,
            canonical_bytes,
        })
    }

    /// Validated components in root-to-leaf order.
    #[must_use]
    pub fn components(&self) -> &[NamespaceComponent] {
        &self.components
    }

    /// Slash-separated display byte count, excluding any volume/root prefix.
    #[must_use]
    pub const fn display_bytes(&self) -> usize {
        self.display_bytes
    }

    /// Slash-separated canonical key byte count.
    #[must_use]
    pub const fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    /// Whether two differently displayed paths resolve to the same logical location.
    #[must_use]
    pub fn collides_with(&self, other: &Self) -> bool {
        self.components.len() == other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(left, right)| left.collides_with(right))
    }
}

/// Stable namespace-name and path rejection categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NamespaceNameError {
    /// Configured bounds are zero, contradictory or exceed compiled safety ceilings.
    #[error("namespace limits are invalid")]
    InvalidLimits,
    /// A component is empty, path-like, ambiguous, excessive or profile-incompatible.
    #[error("namespace component is invalid")]
    InvalidComponent,
    /// A root-relative path exceeds the configured component count.
    #[error("namespace path exceeds its depth limit")]
    PathTooDeep,
    /// Normalised display or canonical path bytes exceed the configured bound.
    #[error("namespace path exceeds its encoded byte limit")]
    PathTooLong,
}

fn structurally_invalid(value: &str) -> bool {
    value.is_empty()
        || matches!(value, "." | "..")
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
}

fn portable_name_invalid(value: &str) -> bool {
    if value != value.trim() || value.ends_with('.') {
        return true;
    }
    if value
        .chars()
        .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return true;
    }
    let stem = value.split('.').next().unwrap_or(value);
    let folded: String = stem.case_fold().collect();
    matches!(
        folded.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    )
}

fn append_component_bytes(current: usize, component: usize) -> Result<usize, NamespaceNameError> {
    current
        .checked_add(usize::from(current != 0))
        .and_then(|value| value.checked_add(component))
        .ok_or(NamespaceNameError::PathTooLong)
}

#[cfg(test)]
mod tests {
    use super::{
        CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError,
        NamespacePath,
    };

    #[test]
    fn full_case_fold_and_nfc_produce_one_stable_key() -> Result<(), NamespaceNameError> {
        let limits = NamespaceLimits::PORTABLE;
        let street = NamespaceComponent::new("Straße", limits)?;
        let capitals = NamespaceComponent::new("STRASSE", limits)?;
        let composed = NamespaceComponent::new("Café", limits)?;
        let decomposed = NamespaceComponent::new("CAFE\u{301}", limits)?;
        assert!(street.collides_with(&capitals));
        assert!(composed.collides_with(&decomposed));
        assert_eq!(street.display(), "Straße");
        assert_eq!(street.canonical(), "strasse");
        Ok(())
    }

    #[test]
    fn portable_profile_rejects_ambiguous_cross_client_names() {
        for value in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            " leading",
            "trailing ",
            "trailing.",
            "CON",
            "nul.txt",
            "has:colon",
        ] {
            assert_eq!(
                NamespaceComponent::new(value, NamespaceLimits::PORTABLE),
                Err(NamespaceNameError::InvalidComponent)
            );
        }
    }

    #[test]
    fn extended_profile_changes_interoperability_not_safety() -> Result<(), NamespaceNameError> {
        let limits = NamespaceLimits::new(CompatibilityProfile::Extended, 512, 8, 4_096)?;
        assert!(NamespaceComponent::new("has:colon", limits).is_ok());
        assert!(NamespaceComponent::new("CON", limits).is_ok());
        assert!(NamespaceComponent::new("a/b", limits).is_err());
        assert!(NamespaceComponent::new("a\0b", limits).is_err());
        Ok(())
    }

    #[test]
    fn paths_enforce_both_display_and_folded_expansion_bounds() -> Result<(), NamespaceNameError> {
        let limits = NamespaceLimits::new(CompatibilityProfile::Extended, 8, 2, 16)?;
        let display = NamespacePath::from_components(["A", "Straße"], limits)?;
        let canonical = NamespacePath::from_components(["a", "STRASSE"], limits)?;
        assert!(display.collides_with(&canonical));
        assert_eq!(display.display_bytes(), 9);
        assert_eq!(display.canonical_bytes(), 9);
        assert_eq!(
            NamespacePath::from_components(["a", "b", "c"], limits),
            Err(NamespaceNameError::PathTooDeep)
        );
        Ok(())
    }
}
