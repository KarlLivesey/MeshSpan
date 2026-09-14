// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { ConfigureFederationStorageGrantRequest } from "../src/generated/types.gen";
import {
  zConfigureFederationStorageGrantBody,
  zGetFederationStorageGrantQuery,
} from "../src/generated/zod.gen";

const GRANT = "01900000-0000-7000-8000-000000000002";
const ISSUE: ConfigureFederationStorageGrantRequest = {
  operation_id: "01900000-0000-7000-8000-000000000001",
  expected_metadata_revision: 3,
  change: {
    kind: "issue",
    grant_id: GRANT,
    relationship_id: "01900000-0000-7000-8000-000000000003",
    policy: {
      maximum_bytes: "1024",
      counts_towards_protection: true,
      serves_reads: false,
      allow_downstream_delegation: false,
    },
  },
};

describe("generated storage offer validation", () => {
  it("preserves omitted, indefinite and explicit permission lifetimes", () => {
    for (const fields of [
      {},
      { valid_for_seconds: null },
      { valid_for_seconds: 60 },
    ]) {
      const request = { ...ISSUE, change: { ...ISSUE.change, ...fields } };
      expect(zConfigureFederationStorageGrantBody.parse(request)).toEqual(
        request,
      );
    }
  });

  it("rejects coercion, unknown input and unsafe revisions", () => {
    for (const request of [
      { ...ISSUE, unexpected: true },
      { ...ISSUE, expected_metadata_revision: 0 },
      { ...ISSUE, expected_metadata_revision: "3" },
      { ...ISSUE, expected_metadata_revision: 9_007_199_254_740_992 },
      { ...ISSUE, change: { ...ISSUE.change, valid_for_seconds: 59 } },
      { ...ISSUE, change: { ...ISSUE.change, valid_for_seconds: "60" } },
      { ...ISSUE, change: { ...ISSUE.change, unexpected: true } },
    ]) {
      expect(
        zConfigureFederationStorageGrantBody.safeParse(request).success,
      ).toBe(false);
    }
    expect(
      zGetFederationStorageGrantQuery.safeParse({
        grant_id: GRANT,
        extra: true,
      }).success,
    ).toBe(false);
    expect(
      zGetFederationStorageGrantQuery.safeParse({ grant_id: "bad" }).success,
    ).toBe(false);
  });
});

describe("generated storage offer Fetch client", () => {
  it("sends conditional provider intent and validates its receipt", async () => {
    const receipt = {
      operation_id: ISSUE.operation_id,
      grant_id: GRANT,
      committed_revision: 4,
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/federation/storage-grants",
        );
        expect(init?.method).toBe("POST");
        if (typeof init?.body !== "string") {
          throw new TypeError("Expected a JSON request body");
        }
        const sent: unknown = JSON.parse(init.body);
        expect(sent).toEqual(ISSUE);
        return Promise.resolve(response(receipt));
      },
    });
    expect(await client.configureFederationStorageGrant(ISSUE)).toEqual(
      receipt,
    );
  });

  it("queries one exact grant without listing the provider's other offers", async () => {
    const result = { metadata_revision: 3, grant: null };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          `https://node.example/api/latest/admin/federation/storage-grants?grant_id=${GRANT}`,
        );
        expect(init?.method).toBe("GET");
        return Promise.resolve(response(result));
      },
    });
    expect(await client.getFederationStorageGrant({ grant_id: GRANT })).toEqual(
      result,
    );
  });

  it("rejects an invalid server receipt independently of request validation", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({
            operation_id: ISSUE.operation_id,
            grant_id: GRANT,
            committed_revision: 0,
          }),
        ),
    });
    await expect(
      client.configureFederationStorageGrant(ISSUE),
    ).rejects.toThrow();
  });
});

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
    },
  });
}
