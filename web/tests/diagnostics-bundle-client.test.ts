// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it, vi } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { DiagnosticsBundleResponse } from "../src/generated/types.gen";
import { zDiagnosticsBundleResponse } from "../src/generated/zod.gen";

const ID = "11111111-1111-4111-8111-111111111111";
const RUNTIME: NonNullable<DiagnosticsBundleResponse["runtime"]> = {
  uptime_millis: "9007199254740993",
  observation_sequence: "1",
  dropped_updates: "0",
  target_check_evictions: "0",
  event_evictions: "0",
  reconciliation_cycles: "0",
  reconciliation_failures: "0",
  target_probe_passes: "0",
  target_probe_failures: "1",
  storage_reconciliation: null,
  target_checks: [
    {
      target: { target_id: ID, generation: "1" },
      observation: {
        sequence: "1",
        observed_at_epoch_micros: 100,
        age_millis: "1000",
      },
      duration_millis: "8",
      result: "failed",
    },
  ],
  recent_events: [],
};
const BUNDLE: DiagnosticsBundleResponse = {
  metadata: {
    mesh_id: ID,
    partition_id: ID,
    node_id: ID,
    daemon_version: "0.1.0",
    collected_at_epoch_micros: 100,
    revision_before: "1",
    revision_after: "1",
    consensus: null,
    nodes: { items: [], truncated: false },
    targets: { items: [], truncated: false },
    recent_operations: { items: [], truncated: false },
  },
  runtime: RUNTIME,
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

describe("generated appliance diagnostics bundle", () => {
  it("preserves exact counters, missing observations and bounded target evidence", () => {
    expect(zDiagnosticsBundleResponse.parse(BUNDLE)).toEqual(BUNDLE);
    expect(
      zDiagnosticsBundleResponse.parse({ ...BUNDLE, runtime: null }).runtime,
    ).toBeNull();
    for (const changes of [
      { uptime_millis: 1 },
      { dropped_updates: "01" },
      { secret: "not permitted" },
      {
        target_checks: Array.from(
          { length: 101 },
          () => RUNTIME.target_checks[0],
        ),
      },
      { recent_events: [{ code: "raw text", message: "private/path" }] },
    ]) {
      expect(
        zDiagnosticsBundleResponse.safeParse({
          ...BUNDLE,
          runtime: { ...RUNTIME, ...changes },
        }).success,
      ).toBe(false);
    }
  });

  it("uses the native bundle route, cancellation and its Rust-authored byte budget", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response(`${" ".repeat(262_145)}${JSON.stringify(BUNDLE)}`),
      )
      .mockResolvedValueOnce(response(JSON.stringify(BUNDLE), "524289"))
      .mockResolvedValueOnce(response(" ".repeat(524_289)));
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch,
    });
    const cancellation = new AbortController();
    expect(await client.readDiagnosticsBundle(cancellation.signal)).toEqual(
      BUNDLE,
    );
    const call = fetch.mock.calls[0];
    const target = call?.[0];
    expect(target instanceof Request ? target.url : target?.toString()).toBe(
      "https://node.example/api/latest/admin/diagnostics/bundle",
    );
    expect(call?.[1]?.credentials).toBe("same-origin");
    expect(call?.[1]?.signal).toBe(cancellation.signal);
    await expect(client.readDiagnosticsBundle()).rejects.toThrow();
    await expect(client.readDiagnosticsBundle()).rejects.toThrow();
  });

  it("rejects invalid runtime output even when metadata is valid", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      response(
        JSON.stringify({
          ...BUNDLE,
          runtime: {
            ...RUNTIME,
            target_checks: [{ storage_path: "not permitted" }],
          },
        }),
      ),
    );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch,
    });
    await expect(client.readDiagnosticsBundle()).rejects.toThrow();
  });
});
