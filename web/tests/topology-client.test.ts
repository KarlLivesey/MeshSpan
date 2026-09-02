// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
const GROUP_ID = "00000000-0000-4000-8000-000000000003";
const HOST_ID = "00000000-0000-4000-8000-000000000002";

describe("generated topology client", () => {
  it("validates inventory, creation and overlapping membership requests", async () => {
    const requested: Readonly<{ body: string | null; url: string }>[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        const url = requestUrl(input);
        requested.push({
          body: typeof init?.body === "string" ? init.body : null,
          url,
        });
        return Promise.resolve(jsonResponse(responseFor(url, init?.method)));
      },
    });

    const nodes = await client.listTopologyNodes({ limit: 1 });
    await client.listNextTopologyNodes(nodes.next_page_url ?? "missing");
    await client.createFaultGroup({
      class_name: "Power source",
      group_name: "UPS A",
      operation_id: operationId(),
    });
    await client.setFaultGroupMembership({
      groupId: GROUP_ID,
      hostId: HOST_ID,
      request: { operation_id: operationId(), present: true },
    });

    expect(requested.map(({ url }) => url)).toEqual([
      "https://node.example/api/latest/admin/topology/nodes?limit=1",
      "https://node.example/api/latest/admin/topology/nodes?cursor=v1.n.next&limit=1",
      "https://node.example/api/latest/admin/topology/fault-groups",
      `https://node.example/api/latest/admin/topology/fault-groups/${GROUP_ID}/hosts/${HOST_ID}`,
    ]);
    expect(JSON.parse(requested[3]?.body ?? "null")).toEqual({
      operation_id: operationId(),
      present: true,
    });
  });

  it("rejects foreign continuations before making a request", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(
          jsonResponse({ nodes: [], next_page_url: null }),
        );
      },
    });
    await expect(
      client.listNextTopologyNodes("https://attacker.example/collect"),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  });
});

function responseFor(url: string, method: string | undefined): unknown {
  if (url.includes("/topology/nodes?cursor=")) {
    return { next_page_url: null, nodes: [] };
  }
  if (url.includes("/topology/nodes")) {
    return {
      next_page_url:
        "/api/latest/admin/topology/nodes?cursor=v1.n.next&limit=1",
      nodes: [node()],
    };
  }
  if (url.includes("/hosts/") && method === "PUT") {
    return {
      group_id: GROUP_ID,
      host_id: HOST_ID,
      operation_id: operationId(),
      present: true,
      revision: 2,
    };
  }
  return { group: group(), operation_id: operationId() };
}

function node() {
  return {
    display_name: "Shop node",
    host_id: HOST_ID,
    incarnation: "1",
    node_id: "00000000-0000-4000-8000-000000000001",
    private_endpoint: "10.0.0.2:7443",
    revision: 1,
    roles: { gateway: true, metadata_eligible: true, storage: true },
    state: "active",
  };
}

function group() {
  return {
    class_id: "00000000-0000-4000-8000-000000000004",
    class_name: "Power source",
    group_id: GROUP_ID,
    group_name: "UPS A",
    revision: 2,
  };
}

function operationId(): string {
  return "00000000-0000-4000-8000-000000000005";
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) return input.href;
  return input instanceof Request ? input.url : input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
