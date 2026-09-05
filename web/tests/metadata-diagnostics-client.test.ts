// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it, vi } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { MetadataDiagnosticsResponse } from "../src/generated/types.gen";
import { zMetadataDiagnosticsResponse } from "../src/generated/zod.gen";

const ID = "11111111-1111-4111-8111-111111111111";
const EMPTY: MetadataDiagnosticsResponse = {
  mesh_id: ID,
  partition_id: ID,
  node_id: ID,
  daemon_version: "0.1.0",
  collected_at_epoch_micros: 1,
  revision_before: "9007199254740993",
  revision_after: "9007199254740993",
  consensus: null,
  nodes: { items: [], truncated: false },
  targets: { items: [], truncated: false },
  recent_operations: { items: [], truncated: false },
};

function response(body: string, contentLength?: string): Response {
  return new Response(body, {
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
      ...(contentLength === undefined
        ? {}
        : { "Content-Length": contentLength }),
    },
  });
}

describe("generated metadata diagnostic client", () => {
  it("preserves lossless counters and rejects unsafe structure", () => {
    expect(zMetadataDiagnosticsResponse.parse(EMPTY)).toEqual(EMPTY);
    for (const changes of [
      { revision_before: 1 },
      { revision_before: "01" },
      { collected_at_epoch_micros: -1 },
      { consensus: {} },
      { daemon_version: "private/path" },
      { node_id: "not-an-id" },
      { private_key: "never allowed" },
    ]) {
      expect(
        zMetadataDiagnosticsResponse.safeParse({ ...EMPTY, ...changes })
          .success,
      ).toBe(false);
    }
  });

  it("uses the native authenticated endpoint and propagates cancellation", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      response(JSON.stringify(EMPTY)),
    );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch,
    });
    const cancellation = new AbortController();
    expect(await client.readMetadataDiagnostics(cancellation.signal)).toEqual(
      EMPTY,
    );
    expect(fetch).toHaveBeenCalledOnce();
    const call = fetch.mock.calls[0];
    const target = call?.[0];
    expect(target instanceof Request ? target.url : target?.toString()).toBe(
      "https://node.example/api/latest/admin/diagnostics/metadata",
    );
    expect(call?.[1]?.credentials).toBe("same-origin");
    expect(call?.[1]?.signal).toBe(cancellation.signal);
  });

  it("accepts the larger Rust-authored diagnostic budget but rejects excess bytes", async () => {
    const large = largeSnapshot();
    const encoded = JSON.stringify(large, null, 2);
    expect(encoded.length).toBeGreaterThan(65_536);
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(response(encoded))
      .mockResolvedValueOnce(response(JSON.stringify(EMPTY), "262145"))
      .mockResolvedValueOnce(response(" ".repeat(262_145)));
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch,
    });
    expect(await client.readMetadataDiagnostics()).toEqual(large);
    await expect(client.readMetadataDiagnostics()).rejects.toThrow();
    await expect(client.readMetadataDiagnostics()).rejects.toThrow();
  });

  it("enforces section bounds and reports truncation without claiming completeness", () => {
    const large = largeSnapshot();
    expect(zMetadataDiagnosticsResponse.parse(large).nodes.truncated).toBe(
      true,
    );
    large.nodes.items.push(...large.nodes.items);
    expect(zMetadataDiagnosticsResponse.safeParse(large).success).toBe(false);
  });
});

function largeSnapshot(): MetadataDiagnosticsResponse {
  return {
    ...EMPTY,
    nodes: {
      truncated: true,
      items: Array.from({ length: 100 }, () => ({
        node_id: ID,
        host_id: ID,
        configured_state: "active",
        incarnation: "9007199254740993",
        roles: { storage: true, gateway: true, metadata_eligible: true },
      })),
    },
    targets: {
      truncated: true,
      items: Array.from({ length: 100 }, () => ({
        target_id: ID,
        node_id: ID,
        configured_state: "active",
        generation: "9007199254740993",
        usage_limit: { kind: "bytes", bytes: "9007199254740993" },
      })),
    },
    recent_operations: {
      truncated: true,
      items: Array.from({ length: 100 }, () => ({
        operation_id: ID,
        state: "succeeded",
        revision: "9007199254740993",
        started_at_epoch_micros: 1,
        completed_at_epoch_micros: 2,
      })),
    },
  };
}
