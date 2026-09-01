// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { blake3Hex } from "../src/features/file-browser/blake3";

describe("browser upload BLAKE3", () => {
  it("matches the official empty and abc BLAKE3-256 vectors", () => {
    expect(blake3Hex(new Uint8Array())).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
    expect(blake3Hex(new TextEncoder().encode("abc"))).toBe(
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    );
  });
});
