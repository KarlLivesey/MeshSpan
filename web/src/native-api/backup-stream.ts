// SPDX-License-Identifier: GPL-2.0-only

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** Validates an encrypted transfer through EOF without buffering the whole backup.
 * Callers must not commit their output file until consumption completes successfully.
 * The caller has already structurally validated the exact length and digest headers.
 */
export function verifyBackupStream(
  body: ReadableStream<Uint8Array>,
  expectedLength: string,
  expectedDigest: string,
): ReadableStream<Uint8Array> {
  const expected = BigInt(expectedLength);
  const hash = sha256.create();
  const reader = body.getReader();
  let received = 0n;
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller): Promise<void> {
        try {
          const next = await reader.read();
          if (next.done) {
            if (
              received !== expected ||
              `sha256:${bytesToHex(hash.digest())}` !== expectedDigest
            ) {
              throw new TypeError(
                "backup export length or digest does not match",
              );
            }
            hash.destroy();
            reader.releaseLock();
            controller.close();
            return;
          }
          received += BigInt(next.value.byteLength);
          if (received > expected)
            throw new TypeError("backup export exceeds its exact length");
          hash.update(next.value);
          controller.enqueue(next.value);
        } catch (error) {
          hash.destroy();
          controller.error(error);
          try {
            await reader.cancel();
          } finally {
            reader.releaseLock();
          }
        }
      },
      async cancel(reason: unknown): Promise<void> {
        hash.destroy();
        try {
          await reader.cancel(reason);
        } finally {
          reader.releaseLock();
        }
      },
    },
    { highWaterMark: 0 },
  );
}
