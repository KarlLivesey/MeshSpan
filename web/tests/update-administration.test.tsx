// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, expect, it, vi } from "vitest";
import { UpdateAdministration } from "../src/features/update-administration/UpdateAdministration";
import type { UpdateClient } from "../src/features/update-administration/model";
import type { UpdatesResponse } from "../src/generated";

const ROLLOUT = "00000000-0000-4000-8000-000000000002";
const SIGNER = "00000000-0000-4000-8000-000000000001";
const CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const disposals = new Set<() => void>();
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

it("reads bounded public key and signed candidate files with interruption consent off by default", async () => {
  const status: UpdatesResponse = {
    signers: [],
    rollout: null,
    installation_available: false,
  };
  const client: UpdateClient = {
    stageUpdateArtifact: vi.fn<UpdateClient["stageUpdateArtifact"]>(),
    getUpdates: async () => structuredClone(status),
    manageUpdate: vi.fn<UpdateClient["manageUpdate"]>(async (request) => {
      const action = request.action;
      if (action.kind === "configure_signer") {
        status.signers = [
          {
            signer_id: action.signer_id,
            sequence: 1,
            public_key: action.public_key,
            enabled: true,
          },
        ];
      }
      return {
        operation_id: request.operation_id,
        resource_id:
          action.kind === "configure_signer"
            ? action.signer_id
            : action.rollout_id,
        committed_revision: 10,
      };
    }),
  };
  const publicBytes = new Uint8Array(65);
  publicBytes[0] = 4;
  const files = new Map<string, File>([
    ["publisher_key", readableFile(publicBytes)],
    ["manifest", readableFile(new TextEncoder().encode('{"format":1}'))],
    ["signature", readableFile(new Uint8Array([48, 1, 2]))],
  ]);
  vi.spyOn(FormData.prototype, "get").mockImplementation(
    (name) =>
      files.get(name) ??
      (name === "signer_id" ? (status.signers[0]?.signer_id ?? null) : null),
  );
  mount(client);
  await shows("No publisher keys are pinned.");
  submitForm("publisher_key");
  await shows("Disable publisher");
  submitForm("manifest");
  await vi.waitFor(() => {
    flush();
    expect(client.manageUpdate).toHaveBeenCalledTimes(2);
  });
  const saved = vi.mocked(client.manageUpdate).mock.calls[1];
  expect(saved?.[0].action).toMatchObject({
    kind: "select_candidate",
    manifest: btoa('{"format":1}'),
    signature: "MAEC",
    allow_service_interruption: false,
    signer_sequence: 1,
  });
  expect(saved?.[1]).toBe(CSRF);
});

function readableFile(bytes: Uint8Array<ArrayBuffer>): File {
  return Object.assign(new File([bytes], "fixture.bin"), {
    arrayBuffer: async (): Promise<ArrayBuffer> => bytes.slice().buffer,
  });
}

it("retries the identical executable and operation after a lost upload reply without claiming installation", async () => {
  const client = fixture();
  const bytes = new File(["abc"], "meshspan-daemon");
  const upload = vi
    .spyOn(client, "stageUpdateArtifact")
    .mockRejectedValueOnce(new Error("lost upload reply"))
    .mockImplementation(async (rollout, target, operation) => ({
      operation_id: operation,
      rollout_id: rollout,
      target,
      node_id: SIGNER,
      byte_length: "3",
      sha256: "b".repeat(64),
      committed_revision: 12,
    }));
  const fields = new Map<string, FormDataEntryValue>([
    ["update_executable", bytes],
    ["update_platform", "aarch64-apple-darwin"],
  ]);
  vi.spyOn(FormData.prototype, "get").mockImplementation(
    (name) => fields.get(name) ?? null,
  );
  mount(client);
  await shows("Upload candidate executables");
  submitForm("update_executable");
  await shows("Upload outcome is not confirmed");
  button("Retry executable upload").click();
  await shows(
    "Executable verified and stored on this node. Installation is not confirmed.",
  );
  expect(upload.mock.calls).toHaveLength(2);
  expect(upload.mock.calls[0]).toEqual(upload.mock.calls[1]);
  expect(upload.mock.calls[0]?.[3]).toBe(bytes);
  expect(upload.mock.calls[0]?.[4]).toBe(CSRF);
});

function submitForm(field: string): void {
  const form = document.querySelector(`[name="${field}"]`)?.closest("form");
  if (form === null || form === undefined)
    throw new TypeError("update form absent");
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  flush();
}

it("shows actual checkpoints and retains the exact pause request after a lost reply", async () => {
  const client = fixture();
  const manage = vi
    .spyOn(client, "manageUpdate")
    .mockRejectedValueOnce(new Error("lost response"));
  const read = vi.spyOn(client, "getUpdates");
  mount(client);
  await shows("Version 0.1.0 — running");
  expect(document.body.textContent).toContain(
    "Installation is not connected in this build",
  );
  expect(document.body.textContent).toContain(
    "9007199254740993 awaiting staging",
  );
  button("Pause update").click();
  await shows("This change is not confirmed");
  expect(button("Cancel update").disabled).toBe(true);
  button("Retry update change").click();
  await shows("Update command saved. This does not confirm installation.");
  await shows("Version 0.1.0 — paused");
  expect(manage.mock.calls[1]).toEqual(manage.mock.calls[0]);
  expect(manage.mock.calls[0]?.[0]).toMatchObject({
    action: {
      kind: "control",
      rollout_id: ROLLOUT,
      expected_sequence: 3,
      control: "pause",
    },
  });
  expect(manage.mock.calls[0]?.[1]).toBe(CSRF);
  expect(read).toHaveBeenLastCalledWith(ROLLOUT);
  button("Resume update").click();
  await shows("Version 0.1.0 — running");
  button("Cancel update").click();
  await shows("Version 0.1.0 — cancelled");
  expect(manage.mock.calls[3]?.[0]).toMatchObject({
    action: { expected_sequence: 5, control: "cancel" },
  });
});

it("does not offer cancellation while a restart outcome is unresolved", async () => {
  const client = fixture();
  const status = initial();
  if (status.rollout === null) throw new TypeError("fixture rollout absent");
  status.rollout.progress.unresolved_restarts = "1";
  vi.spyOn(client, "getUpdates").mockResolvedValue(status);
  mount(client);
  await shows("A restart outcome is unresolved");
  expect(button("Cancel update").disabled).toBe(true);
  expect(button("Pause update").disabled).toBe(false);
});

it("disables a pinned publisher without creating separate trust material", async () => {
  const client = fixture();
  const manage = vi.spyOn(client, "manageUpdate");
  mount(client);
  await shows("Version 0.1.0 — running");
  button("Disable publisher").click();
  await shows("Update command saved");
  expect(manage.mock.calls[0]?.[0]).toMatchObject({
    action: {
      kind: "configure_signer",
      signer_id: SIGNER,
      expected_sequence: 1,
      public_key: "A".repeat(87) + "=",
      enabled: false,
    },
  });
});

function initial(): UpdatesResponse {
  return {
    installation_available: false,
    signers: [
      {
        signer_id: SIGNER,
        sequence: 1,
        public_key: "A".repeat(87) + "=",
        enabled: true,
      },
    ],
    rollout: {
      rollout_id: ROLLOUT,
      signer_id: SIGNER,
      version: "0.1.0",
      source_commit: "a".repeat(40),
      artifacts: [
        {
          target: "aarch64-apple-darwin",
          byte_length: 3,
          sha256: "b".repeat(64),
        },
      ],
      sequence: 3,
      state: "running",
      allow_service_interruption: false,
      progress: {
        pending: "9007199254740993",
        staged: "2",
        restarting: "0",
        verified: "0",
        failed: "0",
        unresolved_restarts: "0",
      },
    },
  };
}

function fixture(): UpdateClient {
  const status = initial();
  return {
    stageUpdateArtifact: vi.fn<UpdateClient["stageUpdateArtifact"]>(),
    getUpdates: async () => structuredClone(status),
    manageUpdate: async (request) => {
      const action = request.action;
      if (action.kind === "control" && status.rollout !== null) {
        status.rollout.sequence += 1;
        const states = {
          pause: "paused",
          resume: "running",
          cancel: "cancelled",
        } as const;
        status.rollout.state = states[action.control];
      }
      return {
        operation_id: request.operation_id,
        resource_id:
          action.kind === "configure_signer"
            ? action.signer_id
            : action.rollout_id,
        committed_revision: 10,
      };
    },
  };
}

function mount(client: UpdateClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => <UpdateAdministration client={client} csrfToken={CSRF} />,
      root,
    ),
  );
}

function button(label: string): HTMLButtonElement {
  const found = [...document.querySelectorAll("button")].find(
    (item) => item.textContent.trim() === label,
  );
  if (found === undefined) throw new TypeError(`missing button: ${label}`);
  return found;
}

async function shows(text: string): Promise<void> {
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain(text);
  });
}
