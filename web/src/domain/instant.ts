// SPDX-License-Identifier: GPL-2.0-only

/** Converts one validated API epoch-microsecond value into a Temporal instant. */
export function instantFromEpochMicroseconds(
  epochMicroseconds: number,
): Temporal.Instant {
  if (!Number.isSafeInteger(epochMicroseconds) || epochMicroseconds < 0) {
    throw new RangeError(
      "epoch microseconds must be a non-negative safe integer",
    );
  }

  return Temporal.Instant.fromEpochNanoseconds(
    BigInt(epochMicroseconds) * 1_000n,
  );
}
