// SPDX-License-Identifier: GPL-2.0-only

//! Shared strict parsing helpers for native HTTPS query strings.

pub(crate) fn has_valid_percent_encoding(bytes: &[u8]) -> bool {
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || hex_nibble(bytes[index + 1]).is_none()
                || hex_nibble(bytes[index + 2]).is_none()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
