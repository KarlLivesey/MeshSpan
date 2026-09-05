// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import { zConfigureBackupScheduleBody } from "../src/generated/zod.gen";

const OPERATION_ID = "01900000-0000-7000-8000-000000000001";

describe("generated backup schedule client", () => {
  it("reads an unconfigured policy and sends the exact replacement intent", async () => {
    const sent: RequestInit[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/backups/schedule",
        );
        sent.push(init ?? {});
        return Promise.resolve(
          response(
            sent.length === 1
              ? { partition_id: OPERATION_ID, schedule: null }
              : {
                  operation_id: OPERATION_ID,
                  sequence: 1,
                  committed_revision: 7,
                },
          ),
        );
      },
    });
    expect((await client.getBackupSchedule()).schedule).toBeNull();
    const result = await client.configureBackupSchedule(request());
    expect(result).toEqual({
      operation_id: OPERATION_ID,
      sequence: 1,
      committed_revision: 7,
    });
    expect(sent[1]?.method).toBe("PUT");
    const body = sent[1]?.body;
    if (typeof body !== "string") {
      throw new TypeError("Expected an encoded JSON request body");
    }
    expect(JSON.parse(body)).toEqual(request());
  });

  it("rejects unknown, missing and coerced request fields", () => {
    expect(zConfigureBackupScheduleBody.safeParse(request()).success).toBe(
      true,
    );
    for (const policy of [
      { ...request().policy, extra: true },
      { ...request().policy, enabled: "true" },
      { ...request().policy, interval_seconds: 0 },
      { ...request().policy, retained_generations: null },
    ]) {
      expect(
        zConfigureBackupScheduleBody.safeParse({ ...request(), policy })
          .success,
      ).toBe(false);
    }
    expect(
      zConfigureBackupScheduleBody.safeParse({ policy: request().policy })
        .success,
    ).toBe(false);
  });

  it("rejects an invalid server receipt", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({
            operation_id: OPERATION_ID,
            sequence: 1,
            committed_revision: 0,
          }),
        ),
    });
    await expect(client.configureBackupSchedule(request())).rejects.toThrow();
  });
});

function request(): {
  operation_id: string;
  expected_sequence: number;
  policy: {
    enabled: boolean;
    interval_seconds: number;
    retained_generations: number;
    minimum_verified_copies: number;
    minimum_independent_copies: number;
  };
} {
  return {
    operation_id: OPERATION_ID,
    expected_sequence: 0,
    policy: {
      enabled: true,
      interval_seconds: 3600,
      retained_generations: 7,
      minimum_verified_copies: 2,
      minimum_independent_copies: 1,
    },
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
