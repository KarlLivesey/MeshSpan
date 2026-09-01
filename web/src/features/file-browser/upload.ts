// SPDX-License-Identifier: GPL-2.0-only

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import { blake3Hex } from "./blake3";

const UPLOAD_RANGE_BYTES = 4 * 1_024 * 1_024;

export type BrowserUploadClient = Pick<
  MeshSpanFetchClient,
  "abortUpload" | "beginUpload" | "commitUpload" | "writeUploadRange"
>;

export type BrowserUploadRequest = Readonly<{
  client: BrowserUploadClient;
  csrfToken: string;
  currentVersionId: string | undefined;
  file: File;
  onProgress: (written: number, total: number) => void;
  path: string;
  volumeId: string;
}>;

/** Uploads one browser file through bounded, independently verified durable ranges. */
export async function uploadBrowserFile(
  request: BrowserUploadRequest,
): Promise<void> {
  validateFileSize(request.file.size);
  const upload = await request.client.beginUpload(
    request.volumeId,
    {
      disposition:
        request.currentVersionId === undefined
          ? { mode: "create_new" }
          : {
              mode: "replace_if_version",
              version_id: request.currentVersionId,
            },
      maximum_bytes: request.file.size,
      operation_id: crypto.randomUUID(),
      path: request.path,
    },
    request.csrfToken,
  );
  let status = upload;
  let committing = false;
  try {
    for (
      let offset = 0;
      offset < request.file.size;
      offset += UPLOAD_RANGE_BYTES
    ) {
      const bytes = new Uint8Array(
        await request.file
          .slice(
            offset,
            Math.min(offset + UPLOAD_RANGE_BYTES, request.file.size),
          )
          .arrayBuffer(),
      );
      status = await request.client.writeUploadRange(
        {
          bytes,
          contentBlake3: blake3Hex(bytes),
          offset,
          operationId: crypto.randomUUID(),
          stageFence: status.stage_fence,
          uploadId: status.upload_id,
        },
        request.csrfToken,
      );
      request.onProgress(
        Math.min(offset + bytes.byteLength, request.file.size),
        request.file.size,
      );
    }
    committing = true;
    await request.client.commitUpload(
      status.upload_id,
      {
        expected_blake3: null,
        expected_sequence: status.checkpoint_sequence,
        final_length: request.file.size,
        operation_id: crypto.randomUUID(),
        sparse: false,
        stage_fence: status.stage_fence,
      },
      request.csrfToken,
    );
  } catch (error) {
    if (!committing) {
      await abortQuietly(
        request.client,
        status.upload_id,
        status.stage_fence,
        request.csrfToken,
      );
    }
    throw error;
  }
}

function validateFileSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError("browser file length is invalid");
  }
}

async function abortQuietly(
  client: BrowserUploadClient,
  uploadId: string,
  stageFence: number,
  csrfToken: string,
): Promise<void> {
  try {
    await client.abortUpload(
      uploadId,
      { operation_id: crypto.randomUUID(), stage_fence: stageFence },
      csrfToken,
    );
  } catch {
    // The original failure remains authoritative; reconciliation resolves an unknown abort.
  }
}
