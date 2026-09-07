// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, expect, it, vi } from "vitest";
import { NotificationAdministration } from "../src/features/notification-administration/NotificationAdministration";
import type { NotificationClient } from "../src/features/notification-administration/model";
import type { NotificationsResponse } from "../src/generated";

const CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const TOKEN = "test-notification-token-0123456789";
const disposals = new Set<() => void>();
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

it("creates a webhook then disables it without receiving or resubmitting credentials", async () => {
  const client = fixture();
  const save = vi.spyOn(client, "configureNotification");
  mount(client);
  await shows("No channels yet");
  button("Add notification channel").click();
  flush();
  input("display_name").value = "Office alerts";
  input("endpoint").value = "https://notifications.example.test/events";
  input("bearer_token").value = TOKEN;
  submit();
  await shows("Notification settings saved.");
  expect(save.mock.calls[0]?.[0]).toMatchObject({
    expected_sequence: 0,
    enabled: true,
    event_filter: 15,
    settings: {
      mode: "replace",
      destination: {
        kind: "webhook",
        endpoint: "https://notifications.example.test/events",
        bearer_token: TOKEN,
      },
    },
  });
  expect(save.mock.calls[0]?.[1]).toBe(CSRF);
  button("Edit Office alerts").click();
  flush();
  expect(document.querySelector('[name="bearer_token"]')).toBeNull();
  input("enabled").click();
  submit();
  await vi.waitFor(() => {
    flush();
    expect(save).toHaveBeenCalledTimes(2);
  });
  expect(save.mock.calls[1]?.[0]).toMatchObject({
    expected_sequence: 1,
    enabled: false,
    settings: { mode: "retain" },
  });
  expect(document.body.textContent).not.toContain(TOKEN);
});

it("configures email with explicit TLS and retries an ambiguous result with exactly the same payload", async () => {
  const client = fixture();
  const save = vi
    .spyOn(client, "configureNotification")
    .mockRejectedValueOnce(new Error("connection lost"));
  mount(client);
  await shows("No channels yet");
  button("Add notification channel").click();
  flush();
  input("display_name").value = "Email alerts";
  const kind = document.querySelector("select");
  if (!(kind instanceof HTMLSelectElement))
    throw new TypeError("delivery method absent");
  kind.value = "email";
  kind.dispatchEvent(new Event("change", { bubbles: true }));
  flush();
  input("host").value = "smtp.example.test";
  input("username").value = "operator";
  input("password").value = "test-relay-password";
  input("sender").value = "mesh@example.test";
  input("recipients").value = "admin@example.test,owner@example.test";
  submit();
  await shows("This change is not confirmed");
  expect(input("password").matches(":disabled")).toBe(true);
  button("Retry notification change").click();
  await shows("Notification settings saved.");
  expect(save.mock.calls[1]).toEqual(save.mock.calls[0]);
  expect(save.mock.calls[1]?.[0].settings).toEqual({
    mode: "replace",
    destination: {
      kind: "email",
      host: "smtp.example.test",
      port: 465,
      tls: "implicit",
      username: "operator",
      password: "test-relay-password",
      sender: "mesh@example.test",
      recipients: ["admin@example.test", "owner@example.test"],
    },
  });
});

function fixture(): NotificationClient {
  let status: NotificationsResponse = { channels: [], worker: "running" };
  return {
    getNotifications: async () => status,
    configureNotification: async (request) => {
      status = {
        worker: "running",
        channels: [
          {
            channel_id: request.channel_id,
            display_name: request.display_name,
            enabled: request.enabled,
            event_filter: request.event_filter,
            deliveries: {
              pending: "0",
              accepted: "0",
              rejected: "0",
              cancelled: "0",
            },
            sequence: request.expected_sequence + 1,
            kind:
              request.settings.mode === "replace"
                ? request.settings.destination.kind
                : "webhook",
          },
        ],
      };
      return {
        operation_id: request.operation_id,
        sequence: request.expected_sequence + 1,
        committed_revision: 10,
      };
    },
  };
}

it("shows retained rejection separately from a running worker", async () => {
  const client = fixture();
  vi.spyOn(client, "getNotifications").mockResolvedValue({
    worker: "running",
    channels: [
      {
        channel_id: "00000000-0000-4000-8000-000000000001",
        sequence: 1,
        display_name: "Office alerts",
        kind: "webhook",
        enabled: true,
        event_filter: 15,
        deliveries: {
          pending: "1",
          accepted: "9007199254740993",
          rejected: "2",
          cancelled: "3",
        },
      },
    ],
  });
  mount(client);
  await shows("Some deliveries were permanently rejected.");
  expect(document.body.textContent).toContain("9007199254740993 accepted");
  expect(document.body.textContent).toContain("2 rejected");
  expect(document.body.textContent).toContain("Local delivery worker: running");
});

function mount(client: NotificationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => <NotificationAdministration client={client} csrfToken={CSRF} />,
      root,
    ),
  );
}

function button(label: string): HTMLButtonElement {
  const button = [...document.querySelectorAll("button")].find(
    (value) => value.textContent.trim() === label,
  );
  if (button === undefined) throw new TypeError(`missing button: ${label}`);
  return button;
}

function input(name: string): HTMLInputElement {
  const input = document.querySelector(`[name="${name}"]`);
  if (!(input instanceof HTMLInputElement))
    throw new TypeError(`missing input: ${name}`);
  return input;
}

function submit(): void {
  const form = document.querySelector("form");
  if (form === null) throw new TypeError("missing notification form");
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  flush();
}

async function shows(text: string): Promise<void> {
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain(text);
  });
}
