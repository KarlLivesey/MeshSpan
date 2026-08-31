// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const API_KEY = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const FILE_VERSION = "05050505-0505-4505-8505-050505050505";
const VOLUME_ID = "01010101-0101-4101-8101-010101010101";
const CONTRACT_HEADERS = {
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

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
});

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
