// SPDX-License-Identifier: GPL-2.0-only

/** Rejects an advertised response size before allocating or consuming its body. */
export function rejectOversizedContentLength(
  value: string | null,
  maximumBytes: number,
): void {
  if (value === null) {
    return;
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError("response has an invalid Content-Length");
  }
  if (length > maximumBytes) {
    throw new RangeError("response exceeds the byte limit");
  }
}

/** Consumes a web response stream while enforcing the operation's byte ceiling. */
export async function readBoundedBytes(
  body: ReadableStream<Uint8Array> | null,
  maximumBytes: number,
): Promise<Uint8Array> {
  if (body === null) {
    throw new TypeError("response has no body");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let totalLength = 0;

  for (;;) {
    const result = await reader.read();
    if (result.done) {
      break;
    }
    totalLength += result.value.byteLength;
    if (totalLength > maximumBytes) {
      await reader.cancel();
      throw new RangeError("response exceeds the byte limit");
    }
    chunks.push(result.value);
  }

  const bytes = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
