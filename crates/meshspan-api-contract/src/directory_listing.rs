// SPDX-License-Identifier: GPL-2.0-only

//! Public authenticated directory-listing models.

use schemars::generate::SchemaGenerator;
use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

macro_rules! public_uuid {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(
            #[schemars(
                length(equal = 36),
                pattern(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                )
            )]
            String,
        );

        impl $name {
            /// Parses exact canonical versioned UUID text.
            #[must_use]
            pub fn parse(value: &str) -> Option<Self> {
                parse_public_uuid(value).map(Self)
            }

            /// Constructs canonical UUID text from validated versioned UUID bytes.
            #[must_use]
            pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
                let version = value[6] >> 4;
                if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
                    return None;
                }
                Some(Self(crate::model::format_uuid(value)))
            }

            /// Returns the canonical UUID text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

pub(crate) fn parse_public_uuid(value: &str) -> Option<String> {
    if value.len() != 36 {
        return None;
    }
    let bytes = value.as_bytes();
    if [8, 13, 18, 23]
        .into_iter()
        .any(|index| bytes.get(index) != Some(&b'-'))
    {
        return None;
    }
    let mut decoded = [0_u8; 16];
    let mut source = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (![8, 13, 18, 23].contains(&index)).then_some(*byte));
    for destination in &mut decoded {
        let high = source.next().and_then(decode_hex)?;
        let low = source.next().and_then(decode_hex)?;
        *destination = (high << 4) | low;
    }
    let version = decoded[6] >> 4;
    if source.next().is_some() || !(1..=8).contains(&version) || decoded[8] >> 6 != 2 {
        return None;
    }
    Some(value.to_owned())
}

const fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

public_uuid!(VolumeId, "A public logical-volume identifier.");
public_uuid!(
    NamespaceCommitId,
    "The immutable namespace view used for one directory page."
);
public_uuid!(ObjectId, "A stable logical file or directory identifier.");
public_uuid!(
    ObjectRevisionId,
    "An immutable logical-object revision identifier."
);
public_uuid!(
    FileVersionId,
    "An immutable regular-file version identifier."
);

/// A bounded relative logical directory path; omission selects the volume root.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NamespacePath(
    #[schemars(length(min = 1, max = 4096), pattern(r"^[^\x00-\x1f\x7f]+$"))] String,
);

impl NamespacePath {
    /// Constructs one decoded canonical relative path.
    #[must_use]
    pub fn from_decoded(value: String) -> Option<Self> {
        let path = Self(value);
        path.is_canonical().then_some(path)
    }

    /// Returns the untrusted relative path candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_canonical(&self) -> bool {
        (1..=4_096).contains(&self.0.len())
            && !self.0.starts_with('/')
            && !self.0.ends_with('/')
            && self
                .0
                .chars()
                .all(|character| !character.is_control() && character != '\u{7f}')
            && self
                .0
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
    }
}

/// An opaque, bounded, URL-safe continuation token.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DirectoryCursor(
    #[schemars(length(min = 1, max = 1024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl DirectoryCursor {
    /// Constructs a token that has already passed authoritative cursor encoding.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        let valid_length = (1..=1_024).contains(&value.len());
        let valid_alphabet = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte));
        (valid_length && valid_alphabet).then_some(Self(value))
    }

    /// Returns the opaque token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded directory page query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListDirectoryQuery {
    /// Relative directory path; omission selects the volume root.
    pub path: Option<NamespacePath>,
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<DirectoryCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Public logical object kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryEntryKind {
    /// A logical directory.
    Directory,
    /// A regular logical file.
    File,
}

/// Complete immutable metadata for one logical namespace object.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMetadataResponse {
    /// Case-preserved logical-object name.
    #[schemars(length(min = 1, max = 255), pattern(r"^[^\x00-\x1f\x7f\x2f\\]+$"))]
    pub name: String,
    /// Stable logical-object identity.
    pub object_id: ObjectId,
    /// Exact immutable logical-object revision.
    pub object_revision_id: ObjectRevisionId,
    /// Monotonic name-reuse generation within the parent.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub entry_generation: i64,
    /// Directory or regular-file kind.
    pub kind: DirectoryEntryKind,
    /// Current immutable file version, or null for a directory.
    pub file_version_id: Option<FileVersionId>,
    /// Logical file bytes, or null for a directory.
    #[schemars(schema_with = "nullable_safe_integer_schema")]
    pub logical_length: Option<i64>,
}

fn nullable_safe_integer_schema(_generator: &mut SchemaGenerator) -> Schema {
    let mut schema = Map::new();
    schema.insert("type".to_owned(), json!(["integer", "null"]));
    schema.insert("minimum".to_owned(), Value::from(0));
    schema.insert("maximum".to_owned(), Value::from(9_007_199_254_740_991_i64));
    Schema::from(schema)
}

/// One immutable, bounded directory page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListDirectoryResponse {
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Selected relative path, or null for the root.
    pub path: Option<NamespacePath>,
    /// Immutable namespace view shared by every entry.
    pub namespace_commit_id: NamespaceCommitId,
    /// Stable selected-directory identity.
    pub directory_object_id: ObjectId,
    /// Exact immutable selected-directory revision.
    pub directory_object_revision_id: ObjectRevisionId,
    /// Deterministically ordered complete child metadata.
    #[schemars(length(max = 256))]
    pub entries: Vec<ObjectMetadataResponse>,
    /// Ready-to-follow relative URL, or null when this is the terminal page.
    #[schemars(length(min = 1, max = 16384), pattern(r"^/api/latest/"))]
    pub next_page_url: Option<String>,
}
