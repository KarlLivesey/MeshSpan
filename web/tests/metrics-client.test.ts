// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zConfigureMetricsExporterBody,
  zGetMetricsExporterResponse,
} from "../src/generated/zod.gen";
import type { ConfigureMetricsExporterRequest } from "../src/generated";

const ID = "00000000-0000-4000-8000-000000000001";
const CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const request: ConfigureMetricsExporterRequest = {
  operation_id: ID,
  expected_sequence: 0,
  policy: { enabled: true, allowed_principals: [ID] },
};

describe("generated metrics exporter client", () => {
  it("reads default-off configuration and sends a CSRF-bound exact replacement", async () => {
    const sent: RequestInit[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/metrics/exporter",
        );
        sent.push(init ?? {});
        return Promise.resolve(
          response(
            sent.length === 1
              ? { configuration: null }
              : {
                  operation_id: ID,
                  sequence: 1,
                  committed_revision: 7,
                },
          ),
        );
      },
    });
    expect(await client.getMetricsExporter()).toEqual({ configuration: null });
    expect(await client.configureMetricsExporter(request, CSRF)).toEqual({
      operation_id: ID,
      sequence: 1,
      committed_revision: 7,
    });
    expect(sent[1]?.method).toBe("PUT");
    expect(new Headers(sent[1]?.headers).get("MeshSpan-CSRF-Token")).toBe(CSRF);
    const body = sent[1]?.body;
    if (typeof body !== "string")
      throw new TypeError("Expected a JSON request body");
    expect(JSON.parse(body)).toEqual(request);
  });
});

describe("generated metrics validation", () => {
  it("rejects structural ambiguity and bounds in both directions", () => {
    expect(zConfigureMetricsExporterBody.safeParse(request).success).toBe(true);
    for (const invalid of [
      { ...request, extra: true },
      { ...request, operation_id: "bad" },
      { ...request, expected_sequence: Number.MAX_SAFE_INTEGER },
      { ...request, expected_sequence: "0" },
      { ...request, policy: null },
      { ...request, policy: { enabled: "true", allowed_principals: [ID] } },
      {
        ...request,
        policy: {
          enabled: true,
          allowed_principals: Array<string>(65).fill(ID),
        },
      },
    ])
      expect(zConfigureMetricsExporterBody.safeParse(invalid).success).toBe(
        false,
      );
    for (const invalid of [
      {},
      { configuration: undefined },
      { configuration: null, extra: true },
      {
        configuration: {
          sequence: 0,
          committed_revision: 1,
          policy: request.policy,
        },
      },
      {
        configuration: {
          sequence: 1,
          committed_revision: 1,
          policy: { ...request.policy, extra: true },
        },
      },
    ])
      expect(zGetMetricsExporterResponse.safeParse(invalid).success).toBe(
        false,
      );
  });

  it("rejects a malformed receipt rather than reporting a saved configuration", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({ operation_id: ID, sequence: 1, committed_revision: 0 }),
        ),
    });
    await expect(client.configureMetricsExporter(request)).rejects.toThrow();
  });
});

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
      "MeshSpan-API-Version": "latest",
    },
  });
}
