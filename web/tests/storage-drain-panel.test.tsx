// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TopologyAdministrationPanel } from "../src/features/topology-administration/TopologyAdministrationPanel";
import type { TopologyAdministrationClient } from "../src/features/topology-administration/model";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const NODE_ID = "00000000-0000-4000-8000-000000000001";
const HOST_ID = "00000000-0000-4000-8000-000000000002";
const TARGET_ID = "00000000-0000-4000-8000-000000000003";
const DRAIN_ID = "00000000-0000-4000-8000-000000000004";
const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("storage-drain administration", () => {
  it("starts an exact target-generation drain with the safe default", async () => {
    const beginStorageDrain = vi.fn<
      TopologyAdministrationClient["beginStorageDrain"]
    >(async (request) => ({
      drain: summary(request.scope),
      operation_id: request.operation_id,
    }));
    mount(client(beginStorageDrain));
    await settle();

    select("What do you want to remove?", `target:${TARGET_ID}:3`);
    click("Start blocking new writes");
    click("Prepare for removal");
    await settle();

    expect(beginStorageDrain).toHaveBeenCalledWith(
      expect.objectContaining({
        allow_temporary_degraded: true,
        cleanup_requested: false,
        scope: { generation: "3", kind: "target", target_id: TARGET_ID },
      }),
      CSRF_TOKEN,
    );
    expect(document.body.textContent).toContain("Evacuating");
  });
});

function client(
  beginStorageDrain: TopologyAdministrationClient["beginStorageDrain"],
): TopologyAdministrationClient {
  return {
    beginStorageDrain,
    createFaultGroup: async () => {
      throw new Error("not exercised");
    },
    listFaultGroupMemberships: async () => ({
      memberships: [],
      next_page_url: null,
    }),
    listFaultGroups: async () => ({ groups: [], next_page_url: null }),
    listNextFaultGroupMemberships: async () => ({
      memberships: [],
      next_page_url: null,
    }),
    listNextFaultGroups: async () => ({ groups: [], next_page_url: null }),
    listNextStorageDrains: async () => ({ drains: [], next_page_url: null }),
    listNextTopologyNodes: async () => ({ nodes: [], next_page_url: null }),
    listNextTopologyTargets: async () => ({ targets: [], next_page_url: null }),
    listStorageDrains: async () => ({ drains: [], next_page_url: null }),
    listTopologyNodes: async () => ({ nodes: [node()], next_page_url: null }),
    listTopologyTargets: async () => ({
      next_page_url: null,
      targets: [target()],
    }),
    setFaultGroupMembership: async () => {
      throw new Error("not exercised");
    },
  };
}

function node() {
  return {
    display_name: "Shop node",
    host_id: HOST_ID,
    incarnation: "1",
    node_id: NODE_ID,
    private_endpoint: "10.0.0.2:7443",
    revision: 1,
    roles: { gateway: true, metadata_eligible: true, storage: true },
    state: "active" as const,
  };
}

function target() {
  return {
    display_name: "Fast folder",
    generation: "3",
    host_id: HOST_ID,
    node_id: NODE_ID,
    revision: 1,
    state: "active" as const,
    target_id: TARGET_ID,
    usage_limit: { kind: "percent" as const, percent: 95 },
  };
}

function summary(
  scope: Parameters<
    TopologyAdministrationClient["beginStorageDrain"]
  >[0]["scope"],
) {
  return {
    allow_temporary_degraded: true,
    cleanup_requested: false,
    drain_id: DRAIN_ID,
    requested_at_epoch_micros: 1,
    revision: 1,
    safe_at_epoch_micros: null,
    scope,
    state: "evacuating" as const,
    status_url: `/api/latest/admin/storage-drains/${DRAIN_ID}`,
  };
}

function mount(client: TopologyAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => (
        <TopologyAdministrationPanel client={client} csrfToken={CSRF_TOKEN} />
      ),
      root,
    ),
  );
}

function select(label: string, value: string): void {
  const input = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent.includes(label))
    ?.querySelector("select");
  if (input === undefined || input === null)
    throw new TypeError(`expected ${label}`);
  input.value = value;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  flush();
}

function click(label: string): void {
  const element = [
    ...document.querySelectorAll<HTMLElement>("button, label"),
  ].find((candidate) => candidate.textContent.trim().includes(label));
  if (element === undefined) throw new TypeError(`expected ${label}`);
  element.click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
