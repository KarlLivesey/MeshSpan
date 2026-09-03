// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const DRAIN_ID = "123e4567-e89b-42d3-a456-426614174000";
const NODE_ID = "223e4567-e89b-42d3-a456-426614174000";
const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated storage-drain client", () => {
  it("validates admission, exact status and server-provided pagination", async () => {
    const urls: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        const url = requestUrl(input);
        urls.push(url);
        return Promise.resolve(jsonResponse(responseFor(url, urls.length)));
      },
    });

    await client.beginStorageDrain({
      allow_temporary_degraded: true,
      cleanup_requested: false,
      operation_id: DRAIN_ID,
      scope: { incarnation: "7", kind: "node", node_id: NODE_ID },
    });
    const page = await client.listStorageDrains({ limit: 1 });
    await client.listNextStorageDrains(page.next_page_url ?? "missing");
    await client.getStorageDrain(DRAIN_ID);

    expect(urls).toEqual([
      "https://node.example/api/latest/admin/storage-drains",
      "https://node.example/api/latest/admin/storage-drains?limit=1",
      "https://node.example/api/latest/admin/storage-drains?cursor=v1.1.2.next&limit=1",
      `https://node.example/api/latest/admin/storage-drains/${DRAIN_ID}`,
    ]);
  });

  it("rejects foreign drain continuations without a request", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(
          jsonResponse({ drains: [], next_page_url: null }),
        );
      },
    });
    await expect(
      client.listNextStorageDrains("https://attacker.example/collect"),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  });
});

function responseFor(url: string, requestCount: number): unknown {
  if (url.includes(`/${DRAIN_ID}`)) return summary();
  if (url.includes("cursor=")) return { drains: [], next_page_url: null };
  if (url.endsWith("/storage-drains") && requestCount === 1) {
    return { drain: summary(), operation_id: DRAIN_ID };
  }
  return {
    drains: [summary()],
    next_page_url:
      "/api/latest/admin/storage-drains?cursor=v1.1.2.next&limit=1",
  };
}

function summary() {
  return {
    allow_temporary_degraded: true,
    cleanup_requested: false,
    drain_id: DRAIN_ID,
    requested_at_epoch_micros: 1,
    revision: 1,
    safe_at_epoch_micros: null,
    scope: { incarnation: "7", kind: "node", node_id: NODE_ID },
    state: "evacuating",
    status_url: `/api/latest/admin/storage-drains/${DRAIN_ID}`,
  };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) return input.href;
  return input instanceof Request ? input.url : input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
