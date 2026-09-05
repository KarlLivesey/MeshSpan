// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackupAdministrationPanel } from "../src/features/backup-administration/BackupAdministrationPanel";
import type {
  BackupAdministrationClient,
  BackupDestination,
  BackupTarget,
} from "../src/features/backup-administration/model";
import type { BackupScheduleResponse } from "../src/generated";

const ID = "00000000-0000-4000-8000-000000000001";
const SECOND_ID = "00000000-0000-4000-8000-000000000002";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("backup schedule administration", () => {
  it("loads the actual policy and saves exact custom settings with CSRF", async () => {
    const client = fixture();
    const configure = vi.spyOn(client, "configureBackupSchedule");
    mount(client);
    await ready();
    expect(document.body.textContent).toContain(
      "not proof of a completed or recoverable backup",
    );
    enter("interval_seconds", "3600");
    enter("retained_generations", "7");
    submit("interval_seconds");
    await vi.waitFor(() => {
      expect(configure).toHaveBeenCalledOnce();
    });
    const operationId = configure.mock.calls[0]?.[0].operation_id;
    expect(operationId).toMatch(/^[\da-f-]{36}$/u);
    expect(configure).toHaveBeenCalledWith(
      {
        expected_sequence: 3,
        operation_id: operationId,
        policy: {
          enabled: true,
          interval_seconds: 3600,
          retained_generations: 7,
          minimum_verified_copies: 2,
          minimum_independent_copies: 0,
        },
      },
      CSRF_TOKEN,
    );
    await shows("Backup settings saved.");
  });

  it("rejects inconsistent requirements before a mutation is sent", async () => {
    const client = fixture();
    const configure = vi.spyOn(client, "configureBackupSchedule");
    mount(client);
    await ready();
    enter("minimum_independent_copies", "3");
    submit("interval_seconds");
    await shows("Independent copies must not exceed verified copies.");
    expect(configure).not.toHaveBeenCalled();
  });
});

describe("backup destination changes", () => {
  it("pauses and resumes with exact identity, generation and observed revisions", async () => {
    const client = fixture();
    const configure = vi.spyOn(client, "configureBackupDestination");
    mount(client);
    await ready();
    button("Pause Recovery folder").click();
    await vi.waitFor(() => {
      expect(configure).toHaveBeenCalledOnce();
    });
    const operationId = configure.mock.calls[0]?.[0].operation_id;
    expect(operationId).toMatch(/^[\da-f-]{36}$/u);
    expect(configure).toHaveBeenCalledWith(
      {
        operation_id: operationId,
        destination_id: ID,
        expected_revision: 7,
        target_id: ID,
        target_generation: "1",
        name: "Recovery folder",
        enabled: false,
      },
      CSRF_TOKEN,
    );
    await vi.waitFor(() => {
      flush();
      expect(button("Resume Recovery folder").disabled).toBe(false);
    });
    button("Resume Recovery folder").click();
    await vi.waitFor(() => {
      expect(configure).toHaveBeenCalledTimes(2);
    });
    expect(configure.mock.calls[1]?.[0]).toMatchObject({
      expected_revision: 8,
      enabled: true,
    });
  });

  it("retries the identical request after an unknown result and prevents duplicate saves", async () => {
    const client = fixture();
    const configure = vi
      .spyOn(client, "configureBackupDestination")
      .mockRejectedValueOnce(new TypeError("connection lost"));
    mount(client);
    await ready();
    button("Pause Recovery folder").click();
    await shows("The result is unknown.");
    expect(button("Pause Recovery folder").disabled).toBe(true);
    expect(button("Refresh settings").disabled).toBe(true);
    button("Retry pending change").click();
    await shows("Backup settings saved.");
    expect(configure).toHaveBeenCalledTimes(2);
    expect(configure.mock.calls[1]).toEqual(configure.mock.calls[0]);
  });
});

describe("backup change confirmation", () => {
  it("does not call a mismatched receipt saved", async () => {
    const client = fixture();
    client.configureBackupDestination = async (request) => ({
      operation_id: request.operation_id,
      destination_id: SECOND_ID,
      committed_revision: 8,
    });
    mount(client);
    await ready();
    button("Pause Recovery folder").click();
    await shows("The result is unknown.");
    expect(document.body.textContent).not.toContain("Backup settings saved.");
  });

  it("admits only one send before reactive updates flush", async () => {
    const client = fixture();
    const configure = vi.spyOn(client, "configureBackupDestination");
    mount(client);
    await ready();
    const pause = button("Pause Recovery folder");
    pause.click();
    pause.click();
    await shows("Backup settings saved.");
    expect(configure).toHaveBeenCalledOnce();
  });
});

describe("backup inventory", () => {
  it("pages folders on demand without losing the entered name and binds the selected generation", async () => {
    const client = fixture();
    client.listTopologyTargets = async () => ({
      targets: [target()],
      next_page_url: "/api/latest/admin/topology/targets?cursor=next",
    });
    client.listNextTopologyTargets = vi.fn(async () => ({
      targets: [
        { ...target(), target_id: SECOND_ID, generation: "9007199254740993" },
      ],
      next_page_url: null,
    }));
    const configure = vi.spyOn(client, "configureBackupDestination");
    mount(client);
    await ready();
    enter("name", "Off-machine recovery");
    expect(client.listNextTopologyTargets).not.toHaveBeenCalled();
    button("Show more storage folders").click();
    await vi.waitFor(() => {
      flush();
      expect(
        document.querySelector(`option[value="${SECOND_ID}"]`),
      ).not.toBeNull();
    });
    expect(field("name").value).toBe("Off-machine recovery");
    field("target_id").value = SECOND_ID;
    submit("name");
    await vi.waitFor(() => {
      expect(configure).toHaveBeenCalledOnce();
    });
    expect(configure).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Off-machine recovery",
        target_id: SECOND_ID,
        target_generation: "9007199254740993",
        enabled: true,
        expected_revision: 0,
      }),
      CSRF_TOKEN,
    );
    await shows("Backup settings saved.");
    expect(field("name").value).toBe("");
  });

  it("clears the old private inventory when refreshing loses access", async () => {
    const client = fixture();
    mount(client);
    await ready();
    client.listBackupDestinations = async () => {
      throw new Error("access revoked");
    };
    button("Refresh settings").click();
    await shows("Backup settings could not be read.");
    expect(document.body.textContent).not.toContain("Recovery folder");
    expect(document.body.textContent).not.toContain(
      "No destinations are configured",
    );
  });
});

function fixture(): BackupAdministrationClient {
  let currentSchedule = schedule();
  let destinations = [destination()];
  return {
    getBackupSchedule: async () => currentSchedule,
    listBackupRuns: async () => ({ runs: [], next_page_url: null }),
    listNextBackupRuns: async () => ({ runs: [], next_page_url: null }),
    listBackupDestinations: async () => ({
      destinations,
      next_page_url: null,
    }),
    listNextBackupDestinations: async () => ({
      destinations: [],
      next_page_url: null,
    }),
    listTopologyTargets: async () => ({
      targets: [target()],
      next_page_url: null,
    }),
    listNextTopologyTargets: async () => ({ targets: [], next_page_url: null }),
    configureBackupSchedule: async (request) => {
      currentSchedule = {
        partition_id: ID,
        schedule: {
          policy: request.policy,
          sequence: request.expected_sequence + 1,
          next_due_at_epoch_micros: 1_700_000_000_000_000,
        },
      };
      return {
        operation_id: request.operation_id,
        sequence: request.expected_sequence + 1,
        committed_revision: 8,
      };
    },
    configureBackupDestination: async (request) => {
      destinations = destinations.filter(
        (record) => record.destination_id !== request.destination_id,
      );
      destinations.push({
        destination_id: request.destination_id,
        name: request.name,
        provider: { kind: "registered_target", target_id: request.target_id },
        provider_generation: request.target_generation,
        failure_relationship: "unknown",
        revision: request.expected_revision + 1,
        state: request.enabled ? "active" : "paused",
      });
      return {
        operation_id: request.operation_id,
        destination_id: request.destination_id,
        committed_revision: request.expected_revision + 1,
      };
    },
  };
}

function schedule(): BackupScheduleResponse {
  return {
    partition_id: ID,
    schedule: {
      sequence: 3,
      next_due_at_epoch_micros: 1_700_000_000_000_000,
      policy: {
        enabled: true,
        interval_seconds: 86400,
        retained_generations: 3,
        minimum_verified_copies: 2,
        minimum_independent_copies: 0,
      },
    },
  };
}

function destination(): BackupDestination {
  return {
    destination_id: ID,
    name: "Recovery folder",
    failure_relationship: "unknown",
    provider: { kind: "registered_target", target_id: ID },
    provider_generation: "1",
    revision: 7,
    state: "active",
  };
}

function target(): BackupTarget {
  return {
    display_name: "Disk A",
    generation: "1",
    host_id: ID,
    node_id: ID,
    revision: 1,
    state: "active",
    target_id: ID,
    usage_limit: { kind: "percent", percent: 95 },
  };
}

function mount(client: BackupAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => (
        <BackupAdministrationPanel client={client} csrfToken={CSRF_TOKEN} />
      ),
      root,
    ),
  );
}

async function ready(): Promise<void> {
  await shows("Recovery folder");
}

async function shows(text: string): Promise<void> {
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain(text);
  });
}

function field(name: string): HTMLInputElement | HTMLSelectElement {
  const element = document.querySelector(`[name="${name}"]`);
  if (!(
    element instanceof HTMLInputElement || element instanceof HTMLSelectElement
  ))
    throw new TypeError(`Missing ${name}`);
  return element;
}

function enter(name: string, value: string): void {
  field(name).value = value;
  field(name).dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function submit(name: string): void {
  const form = field(name).closest("form");
  if (form === null) throw new TypeError("Form missing");
  form.dispatchEvent(
    new SubmitEvent("submit", { bubbles: true, cancelable: true }),
  );
  flush();
}

function button(label: string): HTMLButtonElement {
  const element = [...document.querySelectorAll("button")].find(
    (candidate) =>
      (candidate.getAttribute("aria-label") ?? candidate.textContent.trim()) ===
      label,
  );
  if (element === undefined) throw new TypeError(`Missing button ${label}`);
  return element;
}
