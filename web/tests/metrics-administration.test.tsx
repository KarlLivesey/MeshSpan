// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, expect, it, vi } from "vitest";
import { MetricsAdministration } from "../src/features/metrics-administration/MetricsAdministration";
import type { MetricsClient } from "../src/features/metrics-administration/model";
import type { MetricsExporterResponse } from "../src/generated";
import { MeshSpanApiError } from "../src/generated/fetch.gen";

const FIRST = "00000000-0000-4000-8000-000000000001";
const SECOND = "00000000-0000-4000-8000-000000000002";
const CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const disposals = new Set<() => void>();
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

it("defaults off, loads users only on demand and rejects enabling without consumers", async () => {
  const client = fixture();
  const users = vi.spyOn(client, "listUsers");
  const save = vi.spyOn(client, "configureMetricsExporter");
  mount(client);
  await shows("Current access: Off");
  expect(users).not.toHaveBeenCalled();
  checkbox().click();
  submit();
  await shows("Choose at least one user");
  expect(save).not.toHaveBeenCalled();
});

it("keeps selections across bounded pages and sends the exact enabled policy then disables it", async () => {
  const client = fixture();
  const save = vi.spyOn(client, "configureMetricsExporter");
  const next = vi.spyOn(client, "listNextPrincipals");
  mount(client);
  await shows("Current access: Off");
  await selectFirst();
  button("Next users").click();
  await shows("Allow Bob");
  button("Allow Bob").click();
  checkbox().click();
  submit();
  await shows("Metrics settings saved.");
  await shows("Current access: Enabled");
  expect(next).toHaveBeenCalledWith(
    "/api/latest/admin/users?limit=1&cursor=v1.next",
  );
  const operationId = save.mock.calls[0]?.[0].operation_id;
  expect(operationId).toMatch(/^[\da-f-]{36}$/u);
  expect(save).toHaveBeenCalledWith(
    {
      operation_id: operationId,
      expected_sequence: 0,
      policy: { enabled: true, allowed_principals: [FIRST, SECOND] },
    },
    CSRF,
  );
  expect(
    document.querySelectorAll('[aria-label="Selected metrics users"] li'),
  ).toHaveLength(2);
  checkbox().click();
  submit();
  await shows("Current access: Off");
  expect(save.mock.calls[1]?.[0]).toMatchObject({
    expected_sequence: 1,
    policy: { enabled: false, allowed_principals: [FIRST, SECOND] },
  });
});

it("retains the identical operation after connection loss and admits no competing change", async () => {
  const client = fixture();
  const save = vi
    .spyOn(client, "configureMetricsExporter")
    .mockRejectedValueOnce(new TypeError("connection lost"));
  mount(client);
  await shows("Current access: Off");
  await selectFirst();
  checkbox().click();
  submit();
  submit();
  await shows("The change is not confirmed.");
  expect(save).toHaveBeenCalledOnce();
  expect(button("Refresh metrics settings").disabled).toBe(true);
  expect(checkbox().closest("fieldset")?.disabled).toBe(true);
  button("Retry metrics change").click();
  await shows("Current access: Enabled");
  expect(save).toHaveBeenCalledTimes(2);
  expect(save.mock.calls[1]).toEqual(save.mock.calls[0]);
});

it("does not treat a wrong operation receipt as success", async () => {
  const client = fixture();
  vi.spyOn(client, "configureMetricsExporter").mockResolvedValue({
    operation_id: SECOND,
    sequence: 1,
    committed_revision: 7,
  });
  mount(client);
  await shows("Current access: Off");
  await selectFirst();
  checkbox().click();
  submit();
  await shows("The change is not confirmed.");
  expect(document.body.textContent).not.toContain("Metrics settings saved.");
});

it("refreshes changed policy without retaining stale checkbox or consumer selections", async () => {
  const client = fixture();
  const read = vi.spyOn(client, "getMetricsExporter");
  mount(client);
  await shows("Current access: Off");
  read.mockResolvedValue({
    configuration: {
      sequence: 2,
      committed_revision: 10,
      policy: { enabled: true, allowed_principals: [SECOND] },
    },
  });
  button("Refresh metrics settings").click();
  await shows("Current access: Enabled");
  expect(checkbox().checked).toBe(true);
  expect(
    document.querySelector('[aria-label="Selected metrics users"]')
      ?.textContent,
  ).toContain(SECOND);
  expect(
    document.querySelector('[aria-label="Selected metrics users"]')
      ?.textContent,
  ).not.toContain(FIRST);
});

it("unlocks editing after a definite policy conflict rather than retrying a stale sequence forever", async () => {
  const client = fixture();
  vi.spyOn(client, "configureMetricsExporter").mockRejectedValueOnce(
    new MeshSpanApiError(409, {
      code: "operation_conflict",
      message: "Policy changed",
      request_id: FIRST,
      operation_id: null,
      issues: [],
    }),
  );
  mount(client);
  await shows("Current access: Off");
  submit();
  await shows("The policy changed before this edit could be saved.");
  expect(button("Refresh metrics settings").disabled).toBe(false);
  expect(document.body.textContent).not.toContain("Retry metrics change");
});

it("does not apply a delayed policy after the view is unmounted", async () => {
  const client = fixture();
  const completion = Promise.withResolvers<MetricsExporterResponse>();
  vi.spyOn(client, "getMetricsExporter").mockReturnValue(completion.promise);
  const dispose = mount(client);
  dispose();
  disposals.delete(dispose);
  completion.resolve({ configuration: null });
  await completion.promise;
  flush();
  expect(document.body.textContent).toBe("");
});

function fixture(): MetricsClient {
  let configuration: MetricsExporterResponse = { configuration: null };
  return {
    getMetricsExporter: async () => configuration,
    configureMetricsExporter: async (request) => {
      configuration = {
        configuration: {
          sequence: request.expected_sequence + 1,
          committed_revision: 7,
          policy: request.policy,
        },
      };
      return {
        operation_id: request.operation_id,
        sequence: request.expected_sequence + 1,
        committed_revision: 7,
      };
    },
    listUsers: async () => ({
      kind: "user",
      next_page_url: "/api/latest/admin/users?limit=1&cursor=v1.next",
      principals: [
        {
          principal_id: FIRST,
          kind: "user",
          revision: 1,
          display_name: "Alice",
          state: "active",
          created_at_epoch_micros: 1,
        },
      ],
    }),
    listNextPrincipals: async () => ({
      kind: "user",
      next_page_url: null,
      principals: [
        {
          principal_id: SECOND,
          kind: "user",
          revision: 1,
          display_name: "Bob",
          state: "active",
          created_at_epoch_micros: 1,
        },
      ],
    }),
  };
}

function mount(client: MetricsClient): () => void {
  const root = document.createElement("div");
  document.body.append(root);
  const dispose = render(
    () => <MetricsAdministration client={client} csrfToken={CSRF} />,
    root,
  );
  disposals.add(dispose);
  return dispose;
}
function button(label: string): HTMLButtonElement {
  const value = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (value === undefined) throw new TypeError(`Missing button: ${label}`);
  return value;
}
function checkbox(): HTMLInputElement {
  const value = document.querySelector('input[name="metrics_enabled"]');
  if (!(value instanceof HTMLInputElement))
    throw new TypeError("Missing enabled checkbox");
  return value;
}
function submit(): void {
  flush();
  const form = checkbox().form;
  if (form === null) throw new TypeError("Missing policy form");
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  flush();
}
async function shows(text: string): Promise<void> {
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain(text);
  });
}
async function selectFirst(): Promise<void> {
  button("Choose users").click();
  await shows("Allow Alice");
  button("Allow Alice").click();
  flush();
}
