// SPDX-License-Identifier: GPL-2.0-only

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";

const DOWNLOAD_RANGE_BYTES = 8 * 1_024 * 1_024;

export type BrowserDownloadClient = Pick<MeshSpanFetchClient, "readFile">;

export type BrowserDownloadRequest = Readonly<{
  client: BrowserDownloadClient;
  expectedVersionId: string;
  length: number;
  onProgress: (read: number, total: number) => void;
  path: string;
  volumeId: string;
}>;

/** Reads one exact immutable version through bounded native API ranges. */
export async function downloadFileBlob(
  request: BrowserDownloadRequest,
): Promise<Blob> {
  validateLength(request.length);
  const parts: BlobPart[] = [];
  for (
    let offset = 0;
    offset < request.length;
    offset += DOWNLOAD_RANGE_BYTES
  ) {
    const expectedLength = Math.min(
      DOWNLOAD_RANGE_BYTES,
      request.length - offset,
    );
    const result = await request.client.readFile({
      length: expectedLength,
      offset,
      path: request.path,
      volumeId: request.volumeId,
    });
    if (
      result.fileVersionId !== request.expectedVersionId ||
      result.offset !== offset ||
      result.bytes.byteLength !== expectedLength
    ) {
      throw new TypeError(
        "download range does not match the selected file version",
      );
    }
    parts.push(result.bytes.slice().buffer);
    request.onProgress(offset + result.bytes.byteLength, request.length);
  }
  return new Blob(parts, { type: "application/octet-stream" });
}

function validateLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("file length is invalid");
  }
}
