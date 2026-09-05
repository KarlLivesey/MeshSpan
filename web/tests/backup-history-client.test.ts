// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zListBackupRunsQuery,
  zListBackupRunsResponse2,
} from "../src/generated/zod.gen";

describe("generated backup history contract", () => {
  it("rejects null, coercion, excess and unknown query fields", () => {
    expect(zListBackupRunsQuery.safeParse({}).success).toBe(true);
    for (const query of [
      { limit: 0 },
      { limit: 101 },
      { limit: "2" },
      { cursor: null },
      { limit: null },
      { cursor: "x", secret: true },
    ]) {
      expect(zListBackupRunsQuery.safeParse(query).success).toBe(false);
    }
  });

  it("validates responses and preserves sequence strings beyond JavaScript safe integers", () => {
    const run = {
      backup_id: "01900000-0000-7000-8000-000000000001",
      run_sequence: "9007199254740993",
      schedule_sequence: "1",
      scheduled_for_epoch_micros: 1,
      completed_at_epoch_micros: null,
      state: "queued",
      minimum_verified_copies: 1,
      minimum_independent_copies: 0,
    };
    expect(
      zListBackupRunsResponse2.parse({ runs: [run], next_page_url: null })
        .runs[0]?.run_sequence,
    ).toBe("9007199254740993");
    for (const changes of [
      { run_sequence: 1 },
      { state: "safe" },
      { scheduled_for_epoch_micros: "1" },
      { minimum_verified_copies: 0 },
    ]) {
      expect(
        zListBackupRunsResponse2.safeParse({
          runs: [{ ...run, ...changes }],
          next_page_url: null,
        }).success,
      ).toBe(false);
    }
  });

  it("sends credentials only to an exact validated history continuation", async () => {
    const sent: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        sent.push(input instanceof Request ? input.url : input.toString());
        return new Response(JSON.stringify({ runs: [], next_page_url: null }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
            "MeshSpan-API-Version": "latest",
          },
        });
      },
    });
    const next =
      "/api/latest/admin/backups/runs?limit=25&cursor=v1.bkr.example";
    await client.listNextBackupRuns(next);
    expect(sent).toEqual([`https://node.example${next}`]);
    for (const invalid of [
      "https://attacker.example/",
      "//attacker.example/",
      "/api/latest/admin/backups/schedule",
      `${next}&limit=2`,
      `${next}&secret=yes`,
      `${next}#fragment`,
      "/api/latest/admin/backups/runs?limit=1e2&cursor=x",
      "/api/latest/admin/backups/runs?limit=101&cursor=x",
      "/api/latest/admin/backups/runs?limit=1",
    ]) {
      await expect(client.listNextBackupRuns(invalid)).rejects.toThrow();
    }
    expect(sent).toHaveLength(1);
  });
});
