// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { instantFromEpochMicroseconds } from "../src/domain/instant";

describe("instantFromEpochMicroseconds", () => {
  it("preserves microsecond precision through Temporal", () => {
    const instant = instantFromEpochMicroseconds(1_800_000_000_000_123);

    expect(instant.epochNanoseconds).toBe(1_800_000_000_000_123_000n);
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY, 1.5])(
    "rejects an invalid API instant: %s",
    (value) => {
      expect(() => instantFromEpochMicroseconds(value)).toThrow(RangeError);
    },
  );
});
