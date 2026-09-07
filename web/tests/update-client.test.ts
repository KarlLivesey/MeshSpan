// SPDX-License-Identifier: GPL-2.0-only

import { expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zManageUpdateBody,
  zGetUpdatesResponse,
} from "../src/generated/zod.gen";
import type { ManageUpdateRequest } from "../src/generated";

const request: ManageUpdateRequest = {
  operation_id: "00000000-0000-4000-8000-000000000001",
  action: {
    kind: "control",
    rollout_id: "00000000-0000-4000-8000-000000000002",
    expected_sequence: 1,
    control: "pause",
  },
};

it("generates strict update boundaries without client installation claims", () => {
  expect(zManageUpdateBody.safeParse(request).success).toBe(true);
  for (const invalid of [
    { ...request, extra: true },
    { ...request, action: { ...request.action, control: "verified" } },
    { ...request, action: { ...request.action, expected_sequence: "1" } },
    { ...request, action: { ...request.action, expected_sequence: 0 } },
    { ...request, action: null },
  ])
    expect(zManageUpdateBody.safeParse(invalid).success).toBe(false);
  const status = { signers: [], rollout: null, installation_available: false };
  expect(zGetUpdatesResponse.safeParse(status).success).toBe(true);
  expect(
    zGetUpdatesResponse.safeParse({ ...status, private_key: "leaked" }).success,
  ).toBe(false);
  expect(
    zGetUpdatesResponse.safeParse({
      ...status,
      installation_available: "false",
    }).success,
  ).toBe(false);
});

it("uses the public endpoint for retained rollout reads and exact manager commands", async () => {
  const sent: RequestInit[] = [];
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async (input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      expect(url).toBe(
        sent.length === 0
          ? "https://node.example/api/latest/admin/updates?rollout_id=00000000-0000-4000-8000-000000000002"
          : "https://node.example/api/latest/admin/updates",
      );
      sent.push(init ?? {});
      return Promise.resolve(
        new Response(
          JSON.stringify(
            sent.length === 1
              ? { signers: [], rollout: null, installation_available: false }
              : {
                  operation_id: request.operation_id,
                  resource_id: "00000000-0000-4000-8000-000000000002",
                  committed_revision: 10,
                },
          ),
          {
            headers: {
              "content-type": "application/json",
              "MeshSpan-API-Version": "latest",
              "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
            },
          },
        ),
      );
    },
  });
  expect(
    (await client.getUpdates("00000000-0000-4000-8000-000000000002")).rollout,
  ).toBeNull();
  expect((await client.manageUpdate(request)).committed_revision).toBe(10);
  expect(sent[1]?.method).toBe("PUT");
  const body = sent[1]?.body;
  if (typeof body !== "string") throw new TypeError("JSON body absent");
  const payload: unknown = JSON.parse(body);
  expect(payload).toEqual(request);
  await expect(client.getUpdates("bad-id&extra=true")).rejects.toThrow();
  expect(sent).toHaveLength(2);
});
