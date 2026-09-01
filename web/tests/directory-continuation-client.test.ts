// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const VOLUME_ID = "01010101-0101-4101-8101-010101010101";
const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated directory continuation client", () => {
  it("follows a validated ready-to-use directory page", async () => {
    const requestedUrls: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        requestedUrls.push(
          input instanceof Request ? input.url : String(input),
        );
        return Promise.resolve(directoryResponse());
      },
    });
    const next = `/api/latest/volumes/${VOLUME_ID}/directory-entries?path=Reports&limit=25&cursor=v1.dir.aa`;

    await expect(client.listNextDirectory(next)).resolves.toMatchObject({
      entries: [],
      path: "Reports",
    });
    expect(requestedUrls).toEqual([`https://node.example${next}`]);
  });

  it("rejects substituted, ambiguous and traversing URLs before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(directoryResponse());
      },
    });
    const route = `/api/latest/volumes/${VOLUME_ID}/directory-entries`;
    for (const value of [
      `https://attacker.example${route}`,
      `/api/latest/admin/users?cursor=v1.dir.aa`,
      `${route}?limit=1&limit=2`,
      `${route}?path=Reports%2F..%2Fprivate`,
      `${route}?unrecognised=true`,
    ]) {
      await expect(client.listNextDirectory(value)).rejects.toThrow();
    }
    expect(calls).toBe(0);
  });
});

function directoryResponse(): Response {
  return new Response(
    JSON.stringify({
      directory_object_id: "02020202-0202-4202-8202-020202020202",
      directory_object_revision_id: "03030303-0303-4303-8303-030303030303",
      entries: [],
      namespace_commit_id: "04040404-0404-4404-8404-040404040404",
      next_page_url: null,
      path: "Reports",
      volume_id: VOLUME_ID,
    }),
    { headers: RESPONSE_HEADERS },
  );
}
