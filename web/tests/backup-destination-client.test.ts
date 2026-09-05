// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { ConfigureBackupDestinationRequest } from "../src/generated/types.gen";
import { zConfigureBackupDestinationBody } from "../src/generated/zod.gen";

const OPERATION_ID = "01900000-0000-7000-8000-000000000001";
const DESTINATION_ID = "01900000-0000-7000-8000-000000000002";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;

describe("generated backup destination controls", () => {
  it("sends exact settings and validates the original receipt", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/backups/destinations",
        );
        expect(init?.method).toBe("PUT");
        expect(new Headers(init?.headers).get("MeshSpan-CSRF-Token")).toBe(
          CSRF_TOKEN,
        );
        expect(typeof init?.body).toBe("string");
        if (typeof init?.body !== "string")
          throw new TypeError("JSON body missing");
        expect(JSON.parse(init.body)).toEqual(request());
        return Promise.resolve(
          response({
            operation_id: OPERATION_ID,
            destination_id: DESTINATION_ID,
            committed_revision: 7,
          }),
        );
      },
    });
    expect(
      await client.configureBackupDestination(request(), CSRF_TOKEN),
    ).toEqual({
      operation_id: OPERATION_ID,
      destination_id: DESTINATION_ID,
      committed_revision: 7,
    });
  });

  it("validates bounded inventory queries without requiring an event client", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/backups/destinations?limit=1&cursor=v1.bkd.token",
        );
        return Promise.resolve(
          response({ destinations: [], next_page_url: null }),
        );
      },
    });
    expect(
      (
        await client.listBackupDestinations({
          limit: 1,
          cursor: "v1.bkd.token",
        })
      ).next_page_url,
    ).toBeNull();
    await expect(client.listBackupDestinations({ limit: 0 })).rejects.toThrow();
  });
});

describe("generated backup destination validation", () => {
  it("follows only exact same-origin backup continuations with validated query fields", async () => {
    const sent: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        sent.push(input instanceof Request ? input.url : input.toString());
        return response({ destinations: [], next_page_url: null });
      },
    });
    const next =
      "/api/latest/admin/backups/destinations?limit=1&cursor=v1.bkd.token";
    await client.listNextBackupDestinations(next);
    expect(sent).toEqual([`https://node.example${next}`]);
    for (const invalid of [
      "https://attacker.example/steal",
      "//attacker.example/steal",
      "/api/latest/admin/backups/schedule",
      `${next}&limit=2`,
      `${next}&secret=yes`,
      `${next}#fragment`,
      "/api/latest/admin/backups/destinations?limit=1e2",
      "/api/latest/admin/backups/destinations?limit=0",
    ])
      await expect(
        client.listNextBackupDestinations(invalid),
      ).rejects.toThrow();
    expect(sent).toHaveLength(1);
  });

  it("rejects unknown, missing, nullable and coerced mutation fields", () => {
    expect(zConfigureBackupDestinationBody.safeParse(request()).success).toBe(
      true,
    );
    for (const changed of [
      { ...request(), enabled: null },
      { ...request(), enabled: "true" },
      { ...request(), target_generation: 0 },
      { ...request(), expected_revision: -1 },
      { ...request(), target_id: "not-a-uuid" },
      { ...request(), extra: true },
      { operation_id: OPERATION_ID },
      { ...request(), name: "bad\nname" },
    ])
      expect(zConfigureBackupDestinationBody.safeParse(changed).success).toBe(
        false,
      );
  });

  it("rejects invalid server receipts and external continuation URLs", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({
            operation_id: OPERATION_ID,
            destination_id: DESTINATION_ID,
            committed_revision: 0,
          }),
        ),
    });
    await expect(
      client.configureBackupDestination(request()),
    ).rejects.toThrow();
    const inventory = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({
            destinations: [],
            next_page_url: "https://attacker.example/",
          }),
        ),
    });
    await expect(inventory.listBackupDestinations()).rejects.toThrow();
  });
});

function request(): ConfigureBackupDestinationRequest {
  return {
    operation_id: OPERATION_ID,
    destination_id: DESTINATION_ID,
    expected_revision: 0,
    name: "Recovery",
    target_id: "01900000-0000-7000-8000-000000000003",
    target_generation: "1",
    enabled: true,
  };
}

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
