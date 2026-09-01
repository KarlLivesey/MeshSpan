// SPDX-License-Identifier: GPL-2.0-only

import { blake3 } from "@noble/hashes/blake3.js";

/** Returns the exact lowercase BLAKE3-256 digest required by native upload ranges. */
export function blake3Hex(bytes: Uint8Array): string {
  const digest = blake3(bytes);
  let output = "";
  for (const byte of digest) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}
