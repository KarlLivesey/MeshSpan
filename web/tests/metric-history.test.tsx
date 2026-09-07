// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, expect, it, vi } from "vitest";
import { MetricHistory } from "../src/features/metrics-administration/MetricHistory";
import type { MetricHistoryClient } from "../src/features/metrics-administration/history";
import type { MetricHistoryResponse } from "../src/generated";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import { zGetMetricHistoryResponse } from "../src/generated/zod.gen";

const HISTORY_ID = "1".repeat(32);
const NEXT = `/api/latest/admin/metrics/history?resolution=minute&history_id=${HISTORY_ID}&before=60`;
const disposals = new Set<() => void>();
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

it("loads one page only on request, preserves unknown samples and follows the provided continuation", async () => {
  const first = vi.fn<MetricHistoryClient["getMetricHistory"]>(async () =>
    page(),
  );
  const next = vi.fn<MetricHistoryClient["getNextMetricHistory"]>(async () => ({
    ...page(),
    points: [],
    next_page_url: null,
  }));
  mount({ getMetricHistory: first, getNextMetricHistory: next });
  expect(first).not.toHaveBeenCalled();
  button("Load recent history").click();
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain("18446744073709551615");
  });
  expect(first).toHaveBeenCalledExactlyOnceWith({ resolution: "minute" });
  expect(document.body.textContent).toContain("Sample unavailable");
  expect(document.body.textContent).toContain("1970-01-01T00:02:00Z");
  button("Older measurements").click();
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain("No samples yet");
  });
  expect(next).toHaveBeenCalledExactlyOnceWith(NEXT);
  expect(document.body.textContent).not.toContain("18446744073709551615");
});

it("does not retain a previous page after refusal or apply delayed data after navigation", async () => {
  const pending = Promise.withResolvers<MetricHistoryResponse>();
  const next = vi.fn<MetricHistoryClient["getNextMetricHistory"]>(async () => {
    throw new Error("revoked");
  });
  const first = vi
    .fn<MetricHistoryClient["getMetricHistory"]>()
    .mockResolvedValueOnce(page())
    .mockReturnValueOnce(pending.promise);
  const dispose = mount({
    getMetricHistory: first,
    getNextMetricHistory: next,
  });
  button("Load recent history").click();
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain("18446744073709551615");
  });
  button("Older measurements").click();
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain("History could not be read");
  });
  expect(document.body.textContent).not.toContain("18446744073709551615");
  button("Load recent history").click();
  dispose();
  disposals.delete(dispose);
  pending.resolve(page());
  await pending.promise;
  flush();
  expect(document.body.textContent).toBe("");
});

it("validates history and continuation URLs before attaching client credentials", async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(
    async () =>
      new Response(JSON.stringify(page()), {
        headers: {
          "Content-Type": "application/json",
          "MeshSpan-API-Version": "latest",
          "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
        },
      }),
  );
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch,
  });
  expect(await client.getMetricHistory({ resolution: "minute" })).toEqual(
    page(),
  );
  expect(await client.getNextMetricHistory(NEXT)).toEqual(page());
  expect(fetch).toHaveBeenCalledTimes(2);
  for (const invalid of [
    `https://evil.example${NEXT}`,
    `//evil.example${NEXT}`,
    `${NEXT}#fragment`,
    NEXT.replace("/metrics/history", "/backups/runs"),
    `${NEXT}&before=0`,
    NEXT.replace("resolution=minute", "resolution=day"),
    NEXT.replace(`&history_id=${HISTORY_ID}`, ""),
  ])
    await expect(client.getNextMetricHistory(invalid)).rejects.toThrow();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(
    zGetMetricHistoryResponse.safeParse({ ...page(), secret: "no" }).success,
  ).toBe(false);
  const invalid = page();
  const point = invalid.points[0];
  if (point === undefined) throw new Error("missing fixture point");
  point.metrics = [
    {
      name: "meshspan_v1_https_dispatches",
      measurement: { kind: "counter", value: "01" },
    },
  ];
  expect(zGetMetricHistoryResponse.safeParse(invalid).success).toBe(false);
});

it("accepts a complete 30-sample page above the generic JSON limit using the Rust endpoint budget", async () => {
  const full = page();
  full.next_page_url = null;
  full.uptime_seconds = "1800";
  full.points = Array.from({ length: 30 }, (_, index) => ({
    bucket_start_seconds: String(1800 - index * 60),
    sampled_uptime_seconds: String(1800 - index * 60),
    observed_at_epoch_micros: null,
    metrics: Array.from({ length: 55 }, (_, family) => ({
      name: `meshspan_v1_${"a".repeat(family + 1)}`,
      measurement: { kind: "counter" as const, value: "18446744073709551615" },
    })),
  }));
  const body = JSON.stringify(full);
  expect(new TextEncoder().encode(body).byteLength).toBeGreaterThan(65_536);
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async () =>
      new Response(body, {
        headers: {
          "Content-Type": "application/json",
          "MeshSpan-API-Version": "latest",
          "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
        },
      }),
  });
  expect(await client.getMetricHistory()).toEqual(full);
});

function page(): MetricHistoryResponse {
  return {
    history_id: HISTORY_ID,
    resolution: "minute",
    retention_seconds: "21600",
    uptime_seconds: "120",
    older_samples_expired: false,
    next_page_url: NEXT,
    points: [
      {
        bucket_start_seconds: "120",
        sampled_uptime_seconds: "120",
        observed_at_epoch_micros: 120_000_000,
        metrics: [
          {
            name: "meshspan_v1_https_dispatches",
            measurement: { kind: "counter", value: "18446744073709551615" },
          },
        ],
      },
      {
        bucket_start_seconds: "60",
        sampled_uptime_seconds: "60",
        observed_at_epoch_micros: 60_000_000,
        metrics: null,
      },
    ],
  };
}

function mount(client: MetricHistoryClient): () => void {
  const root = document.createElement("div");
  document.body.append(root);
  const dispose = render(() => <MetricHistory client={client} />, root);
  disposals.add(dispose);
  return dispose;
}

function button(label: string): HTMLButtonElement {
  const value = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (value === undefined) throw new Error(`missing button ${label}`);
  return value;
}
