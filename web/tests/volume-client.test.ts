// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated volume inventory client", () => {
  it("validates the initial query and a server-provided continuation", async () => {
    const requestedUrls: string[] = [];
    const nextPageUrl = "/api/latest/volumes?limit=1&cursor=v1.vol.aa.bb";
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        requestedUrls.push(requestUrl(input));
        return Promise.resolve(
          jsonResponse({
            next_page_url: requestedUrls.length === 1 ? nextPageUrl : null,
            volumes: requestedUrls.length === 1 ? [volume()] : [],
          }),
        );
      },
    });

    const first = await client.listVolumes({ limit: 1 });
    await expect(
      client.listNextVolumes(first.next_page_url ?? "missing"),
    ).resolves.toEqual({ next_page_url: null, volumes: [] });
    expect(requestedUrls).toEqual([
      "https://node.example/api/latest/volumes?limit=1",
      `https://node.example${nextPageUrl}`,
    ]);
  });

  it("rejects substituted or ambiguous continuations before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(jsonResponse({}));
      },
    });

    for (const value of [
      "https://attacker.example/api/latest/volumes",
      "/api/latest/admin/users",
      "/api/latest/volumes?limit=1&limit=2",
    ]) {
      await expect(client.listNextVolumes(value)).rejects.toThrow();
    }
    expect(calls).toBe(0);
  });

  it("rejects unknown fields and incoherent effective rights", async () => {
    for (const candidate of [
      { ...volume(), secret: "must-not-pass" },
      { ...volume(), effective_rights: ["traverse", "traverse"] },
      { ...volume(), effective_rights: ["list", "traverse"] },
      { ...volume(), effective_rights: ["traverse", "read_data"] },
    ]) {
      const client = createMeshSpanFetchClient({
        baseUrl: "https://node.example/api/latest/",
        fetch: async () =>
          Promise.resolve(
            jsonResponse({ next_page_url: null, volumes: [candidate] }),
          ),
      });
      await expect(client.listVolumes()).rejects.toThrow();
    }
  });
});

function volume() {
  return {
    created_at_epoch_micros: 10,
    effective_rights: ["traverse", "list", "read_data"],
    name: "Shared files",
    revision: 1,
    state: "active",
    volume_id: "00000000-0000-4000-8000-000000000001",
  };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) {
    return input.href;
  }
  if (input instanceof Request) {
    return input.url;
  }
  return input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
