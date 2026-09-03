// SPDX-License-Identifier: GPL-2.0-only

pub(super) const MAXIMUM_DNS_NAME_BYTES: usize = 253;

pub(super) fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= MAXIMUM_DNS_NAME_BYTES
        && name.is_ascii()
        && name.contains('.')
        && name.split('.').all(valid_dns_label)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
