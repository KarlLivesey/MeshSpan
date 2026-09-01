// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { VolumeAdministrationPanel } from "../src/features/volume-administration/VolumeAdministrationPanel";
import type { VolumeAdministrationClient } from "../src/features/volume-administration/model";
import type {
  ListPrincipalsResponse,
  ListVolumesResponse,
} from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const USER_ID = "00000000-0000-4000-8000-000000000001";
const GROUP_ID = "00000000-0000-4000-8000-000000000002";
const VOLUME_ID = "00000000-0000-4000-8000-000000000003";
const ROOT_OBJECT_ID = "00000000-0000-4000-8000-000000000004";
const mountedRoots = new Set<() => void>();

afterEach(() => {
  for (const dispose of mountedRoots) {
    dispose();
  }
  mountedRoots.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("volume administration panel", () => {
  it("creates a multi-owner volume and displays only the committed result", async () => {
    const createVolume = vi.fn<VolumeAdministrationClient["createVolume"]>(
      async (request) => ({
        created_at_epoch_micros: 80_000_000,
        name: request.name,
        operation_id: request.operation_id,
        owner_principal_ids: request.owner_principal_ids,
        revision: 1,
        root_object_id: ROOT_OBJECT_ID,
        volume_id: VOLUME_ID,
      }),
    );
    mountPanel(clientFixture(createVolume));
    await settle();

    enterVolumeName("  Shared work  ");
    selectOwner("Alex");
    selectOwner("Operators");
    clickButton("Create volume");
    await settle();

    expect(createVolume).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Shared work",
        owner_principal_ids: [USER_ID, GROUP_ID],
      }),
      CSRF_TOKEN,
    );
    expect(document.body.textContent).toContain(
      "Shared work is committed and ready to use.",
    );
    expect(document.querySelector("tbody")?.textContent).toContain(
      "Shared work",
    );
    expect(document.querySelector("tbody")?.textContent).toContain("committed");
  });
});

function clientFixture(
  createVolume: VolumeAdministrationClient["createVolume"],
): VolumeAdministrationClient {
  const listGroups = vi.fn<VolumeAdministrationClient["listGroups"]>(async () =>
    principalPage("group", "Operators", GROUP_ID),
  );
  const listUsers = vi.fn<VolumeAdministrationClient["listUsers"]>(async () =>
    principalPage("user", "Alex", USER_ID),
  );
  const listNextPrincipals = vi.fn<
    VolumeAdministrationClient["listNextPrincipals"]
  >(async () => principalPage("user", "Alex", USER_ID));
  const listVolumes = vi.fn<VolumeAdministrationClient["listVolumes"]>(
    async () => volumePage(),
  );
  const listNextVolumes = vi.fn<VolumeAdministrationClient["listNextVolumes"]>(
    async () => volumePage(),
  );
  return {
    createVolume,
    listGroups,
    listNextPrincipals,
    listNextVolumes,
    listUsers,
    listVolumes,
  };
}

function principalPage(
  kind: "group" | "user",
  displayName: string,
  principalId: string,
): ListPrincipalsResponse {
  return {
    kind,
    next_page_url: null,
    principals: [
      {
        created_at_epoch_micros: 70_000_000,
        display_name: displayName,
        kind,
        principal_id: principalId,
        revision: 1,
        state: "active",
      },
    ],
  };
}

function volumePage(): ListVolumesResponse {
  return { next_page_url: null, volumes: [] };
}

function mountPanel(client: VolumeAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  mountedRoots.add(
    render(
      () => (
        <VolumeAdministrationPanel client={client} csrfToken={CSRF_TOKEN} />
      ),
      root,
    ),
  );
}

function enterVolumeName(value: string): void {
  const input = document.querySelector<HTMLInputElement>(
    ".volume-create input",
  );
  if (input === null) {
    throw new TypeError("expected the volume-name input");
  }
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function selectOwner(label: string): void {
  const input = [...document.querySelectorAll<HTMLInputElement>("input")].find(
    (candidate) => candidate.parentElement?.textContent?.includes(label),
  );
  if (input === undefined) {
    throw new TypeError(`expected owner checkbox: ${label}`);
  }
  input.click();
  flush();
}

function clickButton(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (button === undefined) {
    throw new TypeError(`expected button: ${label}`);
  }
  button.click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
