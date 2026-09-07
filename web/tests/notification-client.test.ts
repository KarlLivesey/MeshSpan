// SPDX-License-Identifier: GPL-2.0-only

import { expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zConfigureNotificationBody,
  zGetNotificationsResponse,
} from "../src/generated/zod.gen";
import type { ConfigureNotificationRequest } from "../src/generated";

const request: ConfigureNotificationRequest = {
  operation_id: "00000000-0000-4000-8000-000000000001",
  channel_id: "00000000-0000-4000-8000-000000000002",
  expected_sequence: 0,
  display_name: "Alerts",
  enabled: true,
  event_filter: 4,
  settings: {
    mode: "replace",
    destination: {
      kind: "webhook",
      endpoint: "https://example.test/events",
      bearer_token: "test-token-0123456789",
    },
  },
};

it("generates strict notification boundaries in both directions", () => {
  expect(zConfigureNotificationBody.safeParse(request).success).toBe(true);
  for (const invalid of [
    { ...request, unknown: true },
    { ...request, enabled: "true" },
    { ...request, settings: null },
    { ...request, event_filter: 0 },
    { ...request, settings: { mode: "retain", destination: {} } },
  ]) {
    expect(zConfigureNotificationBody.safeParse(invalid).success).toBe(false);
  }
  expect(
    zGetNotificationsResponse.safeParse({ channels: [], worker: "running" })
      .success,
  ).toBe(true);
  expect(
    zGetNotificationsResponse.safeParse({
      channels: [],
      worker: "running",
      password: "leaked",
    }).success,
  ).toBe(false);
});

it("sends the native configuration contract and validates the response", async () => {
  const sent: RequestInit[] = [];
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async (input, init) => {
      expect(input instanceof Request ? input.url : input.toString()).toBe(
        "https://node.example/api/latest/admin/notifications",
      );
      sent.push(init ?? {});
      return Promise.resolve(
        new Response(
          JSON.stringify(
            sent.length === 1
              ? { channels: [], worker: "running" }
              : {
                  operation_id: request.operation_id,
                  sequence: 1,
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
  expect(await client.getNotifications()).toEqual({
    channels: [],
    worker: "running",
  });
  expect(await client.configureNotification(request)).toEqual({
    operation_id: request.operation_id,
    sequence: 1,
    committed_revision: 10,
  });
  expect(sent[1]?.method).toBe("PUT");
  const body = sent[1]?.body;
  if (typeof body !== "string")
    throw new TypeError("expected JSON request body");
  const payload: unknown = JSON.parse(body);
  expect(payload).toEqual(request);
});
