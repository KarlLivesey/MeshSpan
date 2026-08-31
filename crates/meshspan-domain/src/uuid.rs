// SPDX-License-Identifier: GPL-2.0-only

//! UUID framing for opaque identities derived from authenticated content.

/// Marks opaque deterministic bytes as an RFC 9562 `UUIDv8`.
///
/// Version 8 is reserved for application-defined UUID layouts. The operation preserves all
/// non-version and non-variant bits, so callers remain responsible for deriving the input from a
/// domain-separated cryptographic digest.
#[must_use]
pub const fn uuid_v8(mut bytes: [u8; 16]) -> [u8; 16] {
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

#[cfg(test)]
mod tests {
    use super::uuid_v8;

    #[test]
    fn uuid_v8_preserves_payload_outside_required_header_bits() {
        let source = [0xff; 16];
        let versioned = uuid_v8(source);
        assert_eq!(versioned[6] >> 4, 8);
        assert_eq!(versioned[8] >> 6, 2);
        assert_eq!(versioned[0], source[0]);
        assert_eq!(versioned[15], source[15]);
    }
}
