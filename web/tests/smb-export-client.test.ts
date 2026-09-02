// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
const VOLUME_ID = "00000000-0000-4000-8000-000000000001";
const ROOT_OBJECT_ID = "00000000-0000-4000-8000-000000000002";
const EXPORT_ID = "00000000-0000-4000-8000-000000000003";

describe("generated SMB-export client", () => {
  it("validates publication and withdrawal in both directions", async () => {
    const requests: { body: unknown; url: string }[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requests.push({
          body: JSON.parse(typeof init?.body === "string" ? init.body : "null"),
          url: requestUrl(input),
        });
        return Promise.resolve(
          jsonResponse(
            requests.length === 1
              ? publicationResponse(requests[0]?.body)
              : {
                  export_id: EXPORT_ID,
                  operation_id: operationId(5),
                  revision: 3,
                },
          ),
        );
      },
    });
    const publication = await client.publishSmbExport(VOLUME_ID, {
      encryption_required: true,
      gateways: { kind: "all_eligible" },
      operation_id: operationId(4),
      root_object_id: ROOT_OBJECT_ID,
      share_name: "Accounts",
    });
    await client.withdrawSmbExport(publication.export_id, {
      operation_id: operationId(5),
      reason: "Office closed",
    });

    expect(requests.map(({ url }) => url)).toEqual([
      `https://node.example/api/latest/admin/volumes/${VOLUME_ID}/smb-exports`,
      `https://node.example/api/latest/admin/smb-exports/${EXPORT_ID}/withdrawals`,
    ]);
    expect(requests[0]?.body).toEqual(
      expect.objectContaining({ encryption_required: true, share_name: "Accounts" }),
    );
  });

  it("rejects invalid input before Fetch and hostile output after Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(jsonResponse({ ...publicationResponse({}), secret: true }));
      },
    });
    await expect(
      client.publishSmbExport(VOLUME_ID, {
        encryption_required: true,
        gateways: { kind: "all_eligible" },
        operation_id: operationId(4),
        root_object_id: ROOT_OBJECT_ID,
        share_name: "bad/share",
      }),
    ).rejects.toThrow();
    expect(calls).toBe(0);
    await expect(
      client.publishSmbExport(VOLUME_ID, {
        encryption_required: true,
        gateways: { kind: "all_eligible" },
        operation_id: operationId(4),
        root_object_id: ROOT_OBJECT_ID,
        share_name: "Accounts",
      }),
    ).rejects.toThrow();
  });
});

function publicationResponse(request: unknown): Record<string, unknown> {
  const body = request as Record<string, unknown>;
  return {
    encryption_required: body["encryption_required"] ?? true,
    export_id: EXPORT_ID,
    gateways: body["gateways"] ?? { kind: "all_eligible" },
    operation_id: body["operation_id"] ?? operationId(4),
    revision: 2,
    root_object_id: body["root_object_id"] ?? ROOT_OBJECT_ID,
    share_name: body["share_name"] ?? "Accounts",
    volume_id: VOLUME_ID,
  };
}

function operationId(seed: number): string {
  return `00000000-0000-4000-8000-00000000000${String(seed)}`;
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) return input.href;
  return input instanceof Request ? input.url : input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
