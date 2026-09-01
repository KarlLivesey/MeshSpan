// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated storage-folder client", () => {
  it("validates registration and follows only its own continuation", async () => {
    const requested: Readonly<{
      body: string | null;
      url: string;
    }>[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requested.push({
          body: typeof init?.body === "string" ? init.body : null,
          url: requestUrl(input),
        });
        return Promise.resolve(jsonResponse(responseBody(requested.length)));
      },
    });

    const first = await client.listStorageFolders({ limit: 1 });
    await client.listNextStorageFolders(first.next_page_url ?? "missing");
    await client.registerStorageFolder({
      operation_id: operationId(),
      path: "/srv/meshspan",
      usage_limit: { kind: "percent", percent: 95 },
    });

    expect(requested.map(({ url }) => url)).toEqual([
      "https://node.example/api/latest/admin/storage-folders?limit=1",
      `https://node.example${first.next_page_url ?? ""}`,
      "https://node.example/api/latest/admin/storage-folders",
    ]);
    expect(JSON.parse(requested[2]?.body ?? "null")).toEqual({
      operation_id: operationId(),
      path: "/srv/meshspan",
      usage_limit: { kind: "percent", percent: 95 },
    });
  });

  it("rejects hostile continuations and unknown response fields", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(
          jsonResponse({
            folders: [{ ...folder(), sibling_file: "secret" }],
            next_page_url: null,
          }),
        );
      },
    });
    await expect(
      client.listNextStorageFolders("https://attacker.example/steal"),
    ).rejects.toThrow();
    expect(calls).toBe(0);
    await expect(client.listStorageFolders()).rejects.toThrow();
  });
});

function folder() {
  return {
    generation: "1",
    node_id: "00000000-0000-4000-8000-000000000002",
    path: "/srv/meshspan",
    state: "active",
    target_id: "00000000-0000-4000-8000-000000000001",
    usage_limit: { kind: "percent", percent: 95 },
  };
}

function operationId(): string {
  return "00000000-0000-4000-8000-000000000003";
}

function responseBody(call: number): unknown {
  if (call === 1) {
    return {
      folders: [folder()],
      next_page_url:
        "/api/latest/admin/storage-folders?cursor=v1.00000000-0000-4000-8000-000000000001&limit=1",
    };
  }
  return call === 2
    ? { folders: [], next_page_url: null }
    : { folder: folder(), operation_id: operationId() };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) return input.href;
  return input instanceof Request ? input.url : input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
