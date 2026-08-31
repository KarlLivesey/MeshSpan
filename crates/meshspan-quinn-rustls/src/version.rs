// SPDX-License-Identifier: GPL-2.0-only

use quinn_proto::crypto::UnsupportedVersion;
use rustls::quic::Version;

pub(crate) fn interpret(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}
