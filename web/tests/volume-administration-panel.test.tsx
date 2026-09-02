// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, expect, it, vi } from "vitest";

import { VolumeAdministrationPanel } from "../src/features/volume-administration/VolumeAdministrationPanel";
import type { VolumeAdministrationClient } from "../src/features/volume-administration/model";
import type {
  CreateVolumePermissionGrantResponse,
  ListPrincipalsResponse,
  ListVolumePermissionGrantsResponse,
  ListVolumesResponse,
} from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const USER_ID = "00000000-0000-4000-8000-000000000001";
const GROUP_ID = "00000000-0000-4000-8000-000000000002";
const VOLUME_ID = "00000000-0000-4000-8000-000000000003";
const ROOT_OBJECT_ID = "00000000-0000-4000-8000-000000000004";
const GRANT_ID = "00000000-0000-4000-8000-000000000005";
const MANAGER_ID = "00000000-0000-4000-8000-000000000006";
const mountedRoots = new Set<() => void>();

afterEach(() => {
  for (const dispose of mountedRoots) {
    dispose();
  }
  mountedRoots.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

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
  expect(document.querySelector("tbody")?.textContent).toContain("Shared work");
  expect(document.querySelector("tbody")?.textContent).toContain("committed");
});

it("commits and revokes reason-activated volume access", async () => {
  const createGrant = vi.fn<
    VolumeAdministrationClient["createVolumePermissionGrant"]
  >(async (_volumeId, request) => grantResponse(request.operation_id));
  const revokeGrant = vi.fn<
    VolumeAdministrationClient["revokePermissionGrant"]
  >(async (_volumeId, grantId, request) => ({
    grant_id: grantId,
    operation_id: request.operation_id,
    revision: 3,
    revoked_at_epoch_micros: 90_000_000,
  }));
  const client = clientFixture(vi.fn(), {
    createVolumePermissionGrant: createGrant,
    listVolumes: async () => volumePage(true),
    revokePermissionGrant: revokeGrant,
  });
  mountPanel(client);
  await settle();

  clickButton("Manage access");
  await settle();
  selectOption("User or group", GROUP_ID);
  selectOption("Access level", "manage");
  clickCheckbox("Require the user to activate access with a reason");
  clickButton("Grant access");
  await settle();

  const grantCall = createGrant.mock.calls.at(0);
  if (grantCall === undefined) {
    throw new TypeError("expected a permission-grant request");
  }
  expect(grantCall[0]).toBe(VOLUME_ID);
  expect(grantCall[1].activation).toEqual({
    maximum_duration_micros: 3_600_000_000,
    minimum_assurance: "single_factor",
    reason_required: true,
  });
  expect(grantCall[1].rights).toEqual(
    expect.arrayContaining(["read_data", "change_permissions"]),
  );
  expect(grantCall[1].subject_principal_id).toBe(GROUP_ID);
  expect(grantCall[2]).toBe(CSRF_TOKEN);
  expect(document.body.textContent).toContain("Operators");
  expect(document.body.textContent).toContain("activation required");

  clickButton("Remove access");
  enterLabelledInput("Reason for removing access", "Contract ended");
  clickButton("Remove access");
  await settle();

  expect(revokeGrant).toHaveBeenCalledWith(
    VOLUME_ID,
    GRANT_ID,
    expect.objectContaining({ reason: "Contract ended" }),
    CSRF_TOKEN,
  );
  expect(document.body.textContent).toContain(
    "No additional access grants yet.",
  );
});

it("publishes and withdraws the selected volume through embedded SMB", async () => {
  const publish = vi.fn<VolumeAdministrationClient["publishSmbExport"]>(
    async (volumeId, request) => ({
      ...request,
      export_id: "00000000-0000-4000-8000-000000000008",
      revision: 2,
      volume_id: volumeId,
    }),
  );
  const withdraw = vi.fn<VolumeAdministrationClient["withdrawSmbExport"]>(
    async (exportId, request) => ({
      export_id: exportId,
      operation_id: request.operation_id,
      revision: 3,
    }),
  );
  mountPanel(
    clientFixture(vi.fn(), {
      listVolumes: async () => volumePage(true),
      publishSmbExport: publish,
      withdrawSmbExport: withdraw,
    }),
  );
  await settle();

  clickButton("Manage access");
  enterLabelledInput("Share name", "Accounts");
  clickButton("Publish SMB share");
  await settle();
  await settle();

  expect(publish).toHaveBeenCalledWith(
    VOLUME_ID,
    expect.objectContaining({
      encryption_required: true,
      gateways: { kind: "all_eligible" },
      root_object_id: ROOT_OBJECT_ID,
      share_name: "Accounts",
    }),
    CSRF_TOKEN,
  );
  expect(document.body.textContent).toContain("Accounts is published");

  enterLabelledInput("Reason for withdrawing access", "Office closed");
  clickButton("Withdraw SMB share");
  await settle();
  await settle();
  expect(withdraw).toHaveBeenCalledWith(
    "00000000-0000-4000-8000-000000000008",
    expect.objectContaining({ reason: "Office closed" }),
    CSRF_TOKEN,
  );
  expect(document.body.textContent).toContain("Publish SMB share");
});

type ClientOverrides = Partial<
  Pick<
    VolumeAdministrationClient,
    | "createVolumePermissionGrant"
    | "listVolumes"
    | "revokePermissionGrant"
    | "publishSmbExport"
    | "withdrawSmbExport"
  >
>;

function clientFixture(
  createVolume: VolumeAdministrationClient["createVolume"],
  overrides: ClientOverrides = {},
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
  const listVolumePermissionGrants = vi.fn<
    VolumeAdministrationClient["listVolumePermissionGrants"]
  >(async (request) => permissionGrantPage(request.volumeId));
  const listNextVolumePermissionGrants = vi.fn<
    VolumeAdministrationClient["listNextVolumePermissionGrants"]
  >(async () => permissionGrantPage(VOLUME_ID));
  return {
    createVolume,
    createVolumePermissionGrant:
      overrides.createVolumePermissionGrant ??
      (async (_volumeId, request) => grantResponse(request.operation_id)),
    listGroups,
    listNextPrincipals,
    listNextVolumePermissionGrants,
    listNextVolumes,
    listUsers,
    listVolumePermissionGrants,
    listVolumes: overrides.listVolumes ?? listVolumes,
    publishSmbExport:
      overrides.publishSmbExport ??
      (async (volumeId, request) => ({
        ...request,
        export_id: "00000000-0000-4000-8000-000000000008",
        revision: 2,
        volume_id: volumeId,
      })),
    revokePermissionGrant:
      overrides.revokePermissionGrant ??
      (async (_volumeId, grantId, request) => ({
        grant_id: grantId,
        operation_id: request.operation_id,
        revision: 3,
        revoked_at_epoch_micros: 90_000_000,
      })),
    withdrawSmbExport:
      overrides.withdrawSmbExport ??
      (async (exportId, request) => ({
        export_id: exportId,
        operation_id: request.operation_id,
        revision: 3,
      })),
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

function volumePage(includeVolume = false): ListVolumesResponse {
  return {
    next_page_url: null,
    volumes: includeVolume
      ? [
          {
            created_at_epoch_micros: 80_000_000,
            effective_rights: ["read_data", "change_permissions"],
            name: "Shared work",
            revision: 1,
            root_object_id: ROOT_OBJECT_ID,
            state: "active",
            volume_id: VOLUME_ID,
          },
        ]
      : [],
  };
}

function permissionGrantPage(
  volumeId: string,
): ListVolumePermissionGrantsResponse {
  return { grants: [], next_page_url: null, volume_id: volumeId };
}

function grantResponse(
  operationId: string,
): CreateVolumePermissionGrantResponse {
  return {
    grant: {
      activation_policy_id: "00000000-0000-4000-8000-000000000007",
      created_at_epoch_micros: 85_000_000,
      created_by: MANAGER_ID,
      grant_id: GRANT_ID,
      inheritance: "object_and_descendants",
      revision: 2,
      rights: ["traverse", "list", "read_data", "change_permissions"],
      subject_principal_id: GROUP_ID,
      valid_from_epoch_micros: null,
      valid_until_epoch_micros: null,
      volume_id: VOLUME_ID,
    },
    operation_id: operationId,
  };
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
    (candidate) => candidate.parentElement?.textContent.includes(label),
  );
  if (input === undefined) {
    throw new TypeError(`expected owner checkbox: ${label}`);
  }
  input.click();
  flush();
}

function selectOption(label: string, value: string): void {
  const select = labelledSelect(label);
  select.value = value;
  select.dispatchEvent(new Event("change", { bubbles: true }));
  flush();
}

function clickCheckbox(label: string): void {
  labelledInput(label, 'input[type="checkbox"]').click();
  flush();
}

function enterLabelledInput(label: string, value: string): void {
  const input = labelledInput(label, "input");
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function labelledInput(label: string, selector: string): HTMLInputElement {
  const element = labelledElement(label)?.querySelector(selector);
  if (!(element instanceof HTMLInputElement)) {
    throw new TypeError(`expected labelled control: ${label}`);
  }
  return element;
}

function labelledSelect(label: string): HTMLSelectElement {
  const element = labelledElement(label)?.querySelector("select");
  if (!(element instanceof HTMLSelectElement)) {
    throw new TypeError(`expected labelled select: ${label}`);
  }
  return element;
}

function labelledElement(label: string): HTMLLabelElement | undefined {
  return [...document.querySelectorAll("label")].find((candidate) =>
    candidate.textContent.includes(label),
  );
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
