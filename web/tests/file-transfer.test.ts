// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { describe, expect, it, vi } from "vitest";

import { blake3Hex } from "../src/features/file-browser/blake3";
import { downloadFileBlob } from "../src/features/file-browser/download";
import {
  uploadBrowserFile,
  type BrowserUploadClient,
} from "../src/features/file-browser/upload";
import type {
  CommitUploadResponse,
  UploadStatusResponse,
} from "../src/generated/types.gen";

const FILE_VERSION = "05050505-0505-4505-8505-050505050505";
const OBJECT_ID = "02020202-0202-4202-8202-020202020202";
const OBJECT_REVISION_ID = "03030303-0303-4303-8303-030303030303";
const UPLOAD_ID = "06060606-0606-4606-8606-060606060606";
const VOLUME_ID = "01010101-0101-4101-8101-010101010101";
const CSRF_TOKEN = `meshspan-csrf-v1.${"8".repeat(32)}.${"9".repeat(64)}`;

describe("browser native upload", () => {
  it("hashes and writes bounded ranges before committing the exact checkpoint", async () => {
    const bytes = new Uint8Array(4 * 1_024 * 1_024 + 3);
    bytes.fill(23);
    const fixture = uploadFixture();
    const progress: number[] = [];

    await uploadBrowserFile({
      client: fixture.client,
      csrfToken: CSRF_TOKEN,
      currentVersionId: undefined,
      file: new File([bytes], "archive.bin"),
      onProgress: (written) => progress.push(written),
      path: "archive.bin",
      volumeId: VOLUME_ID,
    });

    expect(fixture.writeUploadRange).toHaveBeenCalledTimes(2);
    const first = fixture.writeUploadRange.mock.calls[0]?.[0];
    const second = fixture.writeUploadRange.mock.calls[1]?.[0];
    expect(first?.offset).toBe(0);
    expect(first?.bytes.byteLength).toBe(4 * 1_024 * 1_024);
    expect(first?.contentBlake3).toBe(
      blake3Hex(first?.bytes ?? new Uint8Array()),
    );
    expect(second?.offset).toBe(4 * 1_024 * 1_024);
    expect(second?.bytes).toEqual(Uint8Array.from([23, 23, 23]));
    expect(progress).toEqual([4 * 1_024 * 1_024, bytes.byteLength]);
    expect(fixture.commitUpload).toHaveBeenCalledWith(
      UPLOAD_ID,
      expect.objectContaining({
        expected_sequence: 2,
        final_length: bytes.byteLength,
      }),
      CSRF_TOKEN,
    );
    expect(fixture.abortUpload).not.toHaveBeenCalled();
  });

  it("abandons a failed private stage but never aborts an ambiguous commit", async () => {
    const rangeFailure = uploadFixture({ failRange: true });
    await expect(
      uploadBrowserFile(uploadRequest(rangeFailure.client)),
    ).rejects.toThrow("range failed");
    expect(rangeFailure.abortUpload).toHaveBeenCalledOnce();

    const commitFailure = uploadFixture({ failCommit: true });
    await expect(
      uploadBrowserFile(uploadRequest(commitFailure.client)),
    ).rejects.toThrow("commit outcome unknown");
    expect(commitFailure.abortUpload).not.toHaveBeenCalled();
  });
});

describe("browser native download", () => {
  it("assembles bounded ranges only from one immutable file version", async () => {
    const length = 8 * 1_024 * 1_024 + 2;
    const offsets: number[] = [];
    const progress: number[] = [];
    const blob = await downloadFileBlob({
      client: {
        readFile: async (request) => {
          offsets.push(request.offset ?? 0);
          return {
            bytes: new Uint8Array(request.length ?? 0).fill(17),
            fileVersionId: FILE_VERSION,
            offset: request.offset ?? 0,
          };
        },
      },
      expectedVersionId: FILE_VERSION,
      length,
      onProgress: (read) => progress.push(read),
      path: "archive.bin",
      volumeId: VOLUME_ID,
    });

    expect(offsets).toEqual([0, 8 * 1_024 * 1_024]);
    expect(progress).toEqual([8 * 1_024 * 1_024, length]);
    expect(blob.size).toBe(length);
  });

  it("rejects a range from a different immutable version", async () => {
    await expect(
      downloadFileBlob({
        client: {
          readFile: async () => ({
            bytes: Uint8Array.from([1]),
            fileVersionId: "07070707-0707-4707-8707-070707070707",
            offset: 0,
          }),
        },
        expectedVersionId: FILE_VERSION,
        length: 1,
        onProgress: () => undefined,
        path: "archive.bin",
        volumeId: VOLUME_ID,
      }),
    ).rejects.toThrow("selected file version");
  });
});

type UploadFixtureOptions = Readonly<{
  failCommit?: boolean;
  failRange?: boolean;
}>;

function uploadFixture(options: UploadFixtureOptions = {}) {
  let sequence = 0;
  const abortUpload = vi.fn<BrowserUploadClient["abortUpload"]>(async () =>
    uploadStatus(sequence, "aborted"),
  );
  const beginUpload = vi.fn<BrowserUploadClient["beginUpload"]>(async () =>
    uploadStatus(0),
  );
  const writeUploadRange = vi.fn<BrowserUploadClient["writeUploadRange"]>(
    async () => {
      if (options.failRange === true) throw new Error("range failed");
      sequence += 1;
      return uploadStatus(sequence);
    },
  );
  const commitUpload = vi.fn<BrowserUploadClient["commitUpload"]>(async () => {
    if (options.failCommit === true) throw new Error("commit outcome unknown");
    return commitResponse(sequence);
  });
  return {
    abortUpload,
    beginUpload,
    client: { abortUpload, beginUpload, commitUpload, writeUploadRange },
    commitUpload,
    writeUploadRange,
  };
}

function uploadRequest(client: BrowserUploadClient) {
  return {
    client,
    csrfToken: CSRF_TOKEN,
    currentVersionId: undefined,
    file: new File([Uint8Array.from([1, 2, 3])], "archive.bin"),
    onProgress: () => undefined,
    path: "archive.bin",
    volumeId: VOLUME_ID,
  };
}

function uploadStatus(
  sequence: number,
  state: UploadStatusResponse["state"] = "active",
): UploadStatusResponse {
  return {
    checkpoint_sequence: sequence,
    committed_object_id: state === "committed" ? OBJECT_ID : null,
    committed_version_id: state === "committed" ? FILE_VERSION : null,
    expires_at_epoch_micros: 1_800_000_000_000_000,
    logical_extent: sequence === 0 ? 0 : 3,
    maximum_bytes: 8_388_608,
    path: "archive.bin",
    ranges_url: `/api/latest/uploads/${UPLOAD_ID}/ranges`,
    stage_fence: 1,
    state,
    upload_id: UPLOAD_ID,
    volume_id: VOLUME_ID,
  };
}

function commitResponse(sequence: number): CommitUploadResponse {
  return {
    acknowledgement: {
      achieved_protection_blake3: "2".repeat(64),
      acknowledged_consistency: "eventual",
      configured_consistency: "eventual",
      durability_scope: "node_local",
      eventual_shard_receipts: 0,
      fallback_applied: false,
      pending_debt_blake3: "3".repeat(64),
      pending_eventual_shards: 0,
      policy_committed: true,
      policy_evidence_blake3: "1".repeat(64),
      required_shard_receipts: 1,
    },
    object: {
      namespace_commit_id: "04040404-0404-4404-8404-040404040404",
      object: {
        entry_generation: 1,
        file_version_id: FILE_VERSION,
        kind: "file",
        logical_length: 3,
        name: "archive.bin",
        object_id: OBJECT_ID,
        object_revision_id: OBJECT_REVISION_ID,
      },
      path: "archive.bin",
      volume_id: VOLUME_ID,
    },
    upload: uploadStatus(sequence, "committed"),
  };
}
