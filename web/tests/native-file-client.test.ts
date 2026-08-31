// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const API_KEY = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const FILE_VERSION = "05050505-0505-4505-8505-050505050505";
const VOLUME_ID = "01010101-0101-4101-8101-010101010101";
const UPLOAD_ID = "06060606-0606-4606-8606-060606060606";
const OPERATION_ID = "07070707-0707-4707-8707-070707070707";
const CSRF_TOKEN = `meshspan-csrf-v1.${"8".repeat(32)}.${"9".repeat(64)}`;
const CONTRACT_HEADERS = {
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
type RecordedRequest = Readonly<{
  input: RequestInfo | URL;
  init?: RequestInit;
}>;

describe("generated native file API client", () => {
  it("authenticates headlessly and validates bounded binary responses", async () => {
    const client = createMeshSpanFetchClient({
      apiKey: API_KEY,
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(requestUrl(input)).toBe(
          `https://node.example/api/latest/volumes/${VOLUME_ID}/file-content?path=reports%2Faccounts.csv&offset=2&length=4`,
        );
        expect(new Headers(init?.headers).get("Authorization")).toBe(
          `Bearer ${API_KEY}`,
        );
        expect(init?.credentials).toBe("omit");
        return Promise.resolve(
          fileResponse(Uint8Array.from([1, 2, 3, 4]), {
            "MeshSpan-Read-Offset": "2",
          }),
        );
      },
    });

    await expect(
      client.readFile({
        length: 4,
        offset: 2,
        path: "reports/accounts.csv",
        volumeId: VOLUME_ID,
      }),
    ).resolves.toEqual({
      bytes: Uint8Array.from([1, 2, 3, 4]),
      fileVersionId: FILE_VERSION,
      offset: 2,
    });
  });
});

describe("generated native resumable upload client", () => {
  it("drives the bounded resumable upload lifecycle over the native API", async () => {
    const requests: Readonly<{
      input: RequestInfo | URL;
      init?: RequestInit;
    }>[] = [];
    const responses = [
      jsonResponse(uploadStatus()),
      jsonResponse(uploadStatus({ checkpoint_sequence: 1, logical_extent: 3 })),
      jsonResponse(uploadStatus({ checkpoint_sequence: 1, logical_extent: 3 })),
      jsonResponse({
        checkpoint_sequence: 1,
        next_page_url: null,
        ranges: [{ end: 3, start: 0 }],
        upload_id: UPLOAD_ID,
      }),
      jsonResponse(uploadStatus({ state: "aborted" })),
    ];
    const client = createMeshSpanFetchClient({
      apiKey: API_KEY,
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requests.push({ input, ...(init === undefined ? {} : { init }) });
        return Promise.resolve(responses.shift() ?? jsonResponse({}));
      },
    });

    await client.beginUpload(VOLUME_ID, {
      disposition: { mode: "create_new" },
      maximum_bytes: 1024,
      operation_id: OPERATION_ID,
      path: "reports/accounts.csv",
    });
    await client.writeUploadRange({
      bytes: Uint8Array.from([1, 2, 3]),
      contentBlake3: "a".repeat(64),
      offset: 0,
      operationId: OPERATION_ID,
      stageFence: 1,
      uploadId: UPLOAD_ID,
    });
    await client.getUpload(UPLOAD_ID);
    await client.listUploadRanges({ limit: 64, uploadId: UPLOAD_ID });
    await client.abortUpload(UPLOAD_ID, {
      operation_id: OPERATION_ID,
      stage_fence: 1,
    });

    expect(requests.map(({ input }) => requestUrl(input))).toEqual([
      `https://node.example/api/latest/volumes/${VOLUME_ID}/uploads`,
      `https://node.example/api/latest/uploads/${UPLOAD_ID}/ranges/0`,
      `https://node.example/api/latest/uploads/${UPLOAD_ID}`,
      `https://node.example/api/latest/uploads/${UPLOAD_ID}/ranges?limit=64`,
      `https://node.example/api/latest/uploads/${UPLOAD_ID}/aborts`,
    ]);
    expect(requests.map(({ init }) => init?.method)).toEqual([
      "POST",
      "PUT",
      "GET",
      "GET",
      "POST",
    ]);
    const rangeHeaders = new Headers(requests[1]?.init?.headers);
    expect(rangeHeaders.get("Authorization")).toBe(`Bearer ${API_KEY}`);
    expect(rangeHeaders.get("Content-Type")).toBe("application/octet-stream");
    expect(rangeHeaders.get("MeshSpan-Content-BLAKE3")).toBe("a".repeat(64));
    expect(rangeHeaders.get("MeshSpan-Operation-Id")).toBe(OPERATION_ID);
    expect(rangeHeaders.get("MeshSpan-Stage-Fence")).toBe("1");
    expect(new Uint8Array(requests[1]?.init?.body as ArrayBuffer)).toEqual(
      Uint8Array.from([1, 2, 3]),
    );
  });
});

describe("generated native namespace mutation client", () => {
  it("creates, renames, and logically deletes through the specialised API", async () => {
    const requests: RecordedRequest[] = [];
    const responses = namespaceMutationResponses();
    const client = createMeshSpanFetchClient({
      apiKey: API_KEY,
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requests.push({ input, ...(init === undefined ? {} : { init }) });
        return Promise.resolve(responses.shift() ?? jsonResponse({}));
      },
    });

    await client.createDirectory(
      VOLUME_ID,
      { operation_id: OPERATION_ID, path: "reports" },
      CSRF_TOKEN,
    );
    await client.renameObject(VOLUME_ID, {
      operation_id: OPERATION_ID,
      source_path: "reports",
      target_path: "archive",
    });
    await client.deleteObject(VOLUME_ID, {
      operation_id: OPERATION_ID,
      path: "archive",
    });

    expect(requests).toHaveLength(3);
    expectNamespaceMutationRequests(requests);
  });

  it("rejects unsafe and no-op mutation paths before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(jsonResponse({}));
      },
    });

    await expect(
      client.createDirectory(VOLUME_ID, {
        operation_id: OPERATION_ID,
        path: "reports/../private",
      }),
    ).rejects.toThrow("invalid MeshSpan namespace path");
    await expect(
      client.renameObject(VOLUME_ID, {
        operation_id: OPERATION_ID,
        source_path: "same",
        target_path: "same",
      }),
    ).rejects.toThrow("rename source and target must differ");
    expect(calls).toBe(0);
  });
});

describe("generated native upload browser protection", () => {
  it("adds browser CSRF only to upload mutations", async () => {
    const observedHeaders: Headers[] = [];
    const responses = [
      jsonResponse(uploadStatus()),
      jsonResponse(uploadStatus()),
    ];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (_input, init) => {
        observedHeaders.push(new Headers(init?.headers));
        return Promise.resolve(responses.shift() ?? jsonResponse({}));
      },
    });

    await client.beginUpload(
      VOLUME_ID,
      {
        disposition: { mode: "create_new" },
        maximum_bytes: 1024,
        operation_id: OPERATION_ID,
        path: "reports/accounts.csv",
      },
      CSRF_TOKEN,
    );
    await client.getUpload(UPLOAD_ID);

    expect(observedHeaders[0]?.get("MeshSpan-CSRF-Token")).toBe(CSRF_TOKEN);
    expect(observedHeaders[1]?.has("MeshSpan-CSRF-Token")).toBe(false);
  });
});

describe("generated native upload commit client", () => {
  it("commits only the caller-selected upload checkpoint", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(requestUrl(input)).toBe(
          `https://node.example/api/latest/uploads/${UPLOAD_ID}/commits`,
        );
        expect(init?.method).toBe("POST");
        return Promise.resolve(
          jsonResponse({
            object: objectResponse(),
            upload: uploadStatus({
              checkpoint_sequence: 1,
              committed_object_id: "02020202-0202-4202-8202-020202020202",
              committed_version_id: FILE_VERSION,
              logical_extent: 3,
              state: "committed",
            }),
          }),
        );
      },
    });

    await expect(
      client.commitUpload(UPLOAD_ID, {
        expected_blake3: "a".repeat(64),
        expected_sequence: 1,
        final_length: 3,
        operation_id: OPERATION_ID,
        sparse: false,
        stage_fence: 1,
      }),
    ).resolves.toMatchObject({ upload: { state: "committed" } });
  });
});

describe("generated native file metadata client", () => {
  it("uses strict generated schemas for directory and object metadata", async () => {
    const responses = [
      jsonResponse({
        directory_object_id: "02020202-0202-4202-8202-020202020202",
        directory_object_revision_id: "03030303-0303-4303-8303-030303030303",
        entries: [],
        namespace_commit_id: "04040404-0404-4404-8404-040404040404",
        next_page_url: null,
        path: "reports",
        volume_id: VOLUME_ID,
      }),
      jsonResponse({
        namespace_commit_id: "04040404-0404-4404-8404-040404040404",
        object: {
          entry_generation: 1,
          file_version_id: FILE_VERSION,
          kind: "file",
          logical_length: 4,
          name: "accounts.csv",
          object_id: "02020202-0202-4202-8202-020202020202",
          object_revision_id: "03030303-0303-4303-8303-030303030303",
        },
        path: "reports/accounts.csv",
        volume_id: VOLUME_ID,
      }),
    ];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => Promise.resolve(responses.shift() ?? jsonResponse({})),
    });

    await expect(
      client.listDirectory({ path: "reports", volumeId: VOLUME_ID }),
    ).resolves.toMatchObject({ entries: [], path: "reports" });
    await expect(
      client.getObject({
        path: "reports/accounts.csv",
        volumeId: VOLUME_ID,
      }),
    ).resolves.toMatchObject({ object: { logical_length: 4 } });
  });
});

describe("generated native file client rejection", () => {
  it("rejects traversal before Fetch and rejects hostile binary metadata", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(
          fileResponse(Uint8Array.from([1]), {
            "MeshSpan-File-Version": "not-a-version",
          }),
        );
      },
    });

    await expect(
      client.readFile({ path: "reports/../private", volumeId: VOLUME_ID }),
    ).rejects.toThrow("invalid MeshSpan namespace path");
    expect(calls).toBe(0);
    await expect(
      client.readFile({ length: 1, path: "reports/file", volumeId: VOLUME_ID }),
    ).rejects.toThrow("invalid immutable version");
    expect(calls).toBe(1);
  });

  it("rejects invalid upload paths and ranges before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(jsonResponse({}));
      },
    });

    await expect(
      client.beginUpload(VOLUME_ID, {
        disposition: { mode: "create_new" },
        maximum_bytes: 1,
        operation_id: OPERATION_ID,
        path: "reports/../private",
      }),
    ).rejects.toThrow("invalid MeshSpan namespace path");
    await expect(
      client.writeUploadRange({
        bytes: new Uint8Array(),
        contentBlake3: "a".repeat(64),
        offset: 0,
        operationId: OPERATION_ID,
        stageFence: 1,
        uploadId: UPLOAD_ID,
      }),
    ).rejects.toThrow("upload range must not be empty");
    await expect(
      client.abortUpload(
        UPLOAD_ID,
        { operation_id: OPERATION_ID, stage_fence: 1 },
        "not-a-csrf-token",
      ),
    ).rejects.toThrow("invalid MeshSpan CSRF token");
    expect(calls).toBe(0);
  });
});

function namespaceMutationResponses(): Response[] {
  const identity = {
    head_sequence: 2,
    namespace_commit_id: "04040404-0404-4404-8404-040404040404",
    object_id: "02020202-0202-4202-8202-020202020202",
    object_revision_id: "03030303-0303-4303-8303-030303030303",
    operation_id: OPERATION_ID,
    volume_id: VOLUME_ID,
  };
  return [
    jsonResponse({ ...identity, head_sequence: 1, path: "reports" }),
    jsonResponse({
      ...identity,
      source_path: "reports",
      target_path: "archive",
    }),
    jsonResponse({
      ...identity,
      head_sequence: 3,
      object_kind: "directory",
      path: "archive",
      scope: "branch_deleted",
    }),
  ];
}

function expectNamespaceMutationRequests(requests: RecordedRequest[]): void {
  expect(requests.map(({ input }) => requestUrl(input))).toEqual([
    `https://node.example/api/latest/volumes/${VOLUME_ID}/directories`,
    `https://node.example/api/latest/volumes/${VOLUME_ID}/renames`,
    `https://node.example/api/latest/volumes/${VOLUME_ID}/deletions`,
  ]);
  expect(requests.every(({ init }) => init?.method === "POST")).toBe(true);
  expect(
    new Headers(requests[0]?.init?.headers).get("MeshSpan-CSRF-Token"),
  ).toBe(CSRF_TOKEN);
  expect(
    new Headers(requests[1]?.init?.headers).has("MeshSpan-CSRF-Token"),
  ).toBe(false);
  expect(new Headers(requests[1]?.init?.headers).get("Authorization")).toBe(
    `Bearer ${API_KEY}`,
  );
}

function uploadStatus(
  overrides: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> {
  return {
    checkpoint_sequence: 0,
    committed_object_id: null,
    committed_version_id: null,
    expires_at_epoch_micros: 1_800_000_000_000_000,
    logical_extent: 0,
    maximum_bytes: 1024,
    path: "reports/accounts.csv",
    ranges_url: `/api/latest/uploads/${UPLOAD_ID}/ranges`,
    stage_fence: 1,
    state: "active",
    upload_id: UPLOAD_ID,
    volume_id: VOLUME_ID,
    ...overrides,
  };
}

function objectResponse(): Readonly<Record<string, unknown>> {
  return {
    namespace_commit_id: "04040404-0404-4404-8404-040404040404",
    object: {
      entry_generation: 1,
      file_version_id: FILE_VERSION,
      kind: "file",
      logical_length: 3,
      name: "accounts.csv",
      object_id: "02020202-0202-4202-8202-020202020202",
      object_revision_id: "03030303-0303-4303-8303-030303030303",
    },
    path: "reports/accounts.csv",
    volume_id: VOLUME_ID,
  };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof Request) {
    return input.url;
  }
  return String(input);
}

function fileResponse(
  bytes: Uint8Array,
  additionalHeaders: Readonly<Record<string, string>> = {},
): Response {
  const body = new Uint8Array(bytes.byteLength);
  body.set(bytes);
  return new Response(body.buffer, {
    headers: {
      ...CONTRACT_HEADERS,
      "Content-Type": "application/octet-stream",
      "MeshSpan-File-Version": FILE_VERSION,
      "MeshSpan-Read-Offset": "0",
      ...additionalHeaders,
    },
  });
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { ...CONTRACT_HEADERS, "Content-Type": "application/json" },
  });
}
