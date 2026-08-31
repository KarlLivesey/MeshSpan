// SPDX-License-Identifier: GPL-2.0-only

//! Enumeration declarations and stable name conversions.

use super::line;
use super::names::{enum_prefix, pascal_case};
use crate::codegen::model::Enumeration;

pub(super) fn render_enumeration(output: &mut String, enumeration: &Enumeration) {
    line(
        output,
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]",
    );
    line(output, "#[repr(i32)]");
    line(output, format!("pub enum {} {{", enumeration.name));
    for (index, value) in enumeration.values.iter().enumerate() {
        if index == 0 {
            line(output, "    #[default]");
        }
        line(
            output,
            format!(
                "    {} = {},",
                variant_name(enumeration, &value.name),
                value.number
            ),
        );
    }
    line(output, "}");
    render_into_i32(output, enumeration);
    render_try_from(output, enumeration);
    render_names(output, enumeration);
    line(output, "");
}

fn render_into_i32(output: &mut String, enumeration: &Enumeration) {
    line(
        output,
        format!(
            "impl ::core::convert::From<{}> for i32 {{",
            enumeration.name
        ),
    );
    line(
        output,
        format!("    fn from(value: {}) -> Self {{", enumeration.name),
    );
    line(output, "        value as Self");
    line(output, "    }");
    line(output, "}");
}

fn render_try_from(output: &mut String, enumeration: &Enumeration) {
    line(
        output,
        format!(
            "impl ::core::convert::TryFrom<i32> for {} {{",
            enumeration.name
        ),
    );
    line(
        output,
        "    type Error = ::meshspan_protobuf::UnknownEnumValue;",
    );
    line(
        output,
        "    fn try_from(value: i32) -> ::core::result::Result<Self, Self::Error> {",
    );
    line(output, "        match value {");
    for value in &enumeration.values {
        line(
            output,
            format!(
                "            {} => Ok(Self::{}),",
                value.number,
                variant_name(enumeration, &value.name)
            ),
        );
    }
    line(
        output,
        "            unknown => Err(::meshspan_protobuf::UnknownEnumValue(unknown)),",
    );
    line(output, "        }");
    line(output, "    }");
    line(output, "}");
}

fn render_names(output: &mut String, enumeration: &Enumeration) {
    line(output, format!("impl {} {{", enumeration.name));
    line(
        output,
        "    pub const fn as_str_name(self) -> &'static str {",
    );
    line(output, "        match self {");
    for value in &enumeration.values {
        line(
            output,
            format!(
                "            Self::{} => {:?},",
                variant_name(enumeration, &value.name),
                value.name
            ),
        );
    }
    line(output, "        }");
    line(output, "    }");
    line(
        output,
        "    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {",
    );
    line(output, "        match value {");
    for value in &enumeration.values {
        line(
            output,
            format!(
                "            {:?} => Some(Self::{}),",
                value.name,
                variant_name(enumeration, &value.name)
            ),
        );
    }
    line(output, "            _ => None,");
    line(output, "        }");
    line(output, "    }");
    line(output, "}");
}

pub(super) fn variant_name(enumeration: &Enumeration, value_name: &str) -> String {
    let prefix = enum_prefix(&enumeration.name);
    pascal_case(value_name.strip_prefix(&prefix).unwrap_or(value_name))
}
