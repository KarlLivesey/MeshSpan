// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FirstStartPage } from "../src/features/setup/FirstStartPage";
import type { MeshSpanFetchClient } from "../src/generated/fetch.gen";

const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) {
    dispose();
  }
  disposals.clear();
  document.body.replaceChildren();
});

describe("first-start page", () => {
  it("creates a swarm and keeps one-time recovery material visible until acknowledged", async () => {
    const createMeshSetup = vi.fn<MeshSpanFetchClient["createMeshSetup"]>(
      async (request) => ({
        api_key: "meshspan-key-v1.secret",
        mesh_id: "00000000-0000-4000-8000-000000000001",
        node_id: "00000000-0000-4000-8000-000000000002",
        operation_id: request.operation_id,
        recovery_bundle: "meshspan-recovery-file-v1.encrypted",
        recovery_challenge: "meshspan-check-v1.challenge",
        recovery_code: "meshspan-offline-v1.secret",
      }),
    );
    const complete = vi.fn();
    const joinMeshSetup = vi.fn<MeshSpanFetchClient["joinMeshSetup"]>();
    const root = document.createElement("div");
    document.body.append(root);
    disposals.add(
      render(
        () => (
          <FirstStartPage
            client={{ createMeshSetup, joinMeshSetup }}
            onComplete={complete}
            onJoinAccepted={vi.fn()}
          />
        ),
        root,
      ),
    );

    enter("One-time claim", "meshspan-claim-v1.local-secret");
    enter("Swarm name", "Studio files");
    enter("First administrator", "Alex");
    enter("Machine name", "Office server");
    enter("MeshSpan instance", "Primary");
    click("Create swarm");
    await settle();

    expect(createMeshSetup).toHaveBeenCalledWith(
      expect.objectContaining({
        administrator_name: "Alex",
        claim: "meshspan-claim-v1.local-secret",
        host_name: "Office server",
        mesh_name: "Studio files",
        node_name: "Primary",
      }),
    );
    expect(document.body.textContent).toContain("meshspan-offline-v1.secret");
    expect(button("Continue to sign in").disabled).toBe(true);

    labelled<HTMLInputElement>(
      "I saved the recovery file, recovery code and API key",
      'input[type="checkbox"]',
    ).click();
    flush();
    click("Continue to sign in");

    expect(complete).toHaveBeenCalledOnce();
  });

  it("accepts a join code through the shared first-start page", async () => {
    const joinMeshSetup = vi.fn<MeshSpanFetchClient["joinMeshSetup"]>(
      async (request) => ({
        operation_id: request.operation_id,
        status_url: `/api/latest/operations/${request.operation_id}`,
      }),
    );
    const accepted = vi.fn();
    const root = document.createElement("div");
    document.body.append(root);
    disposals.add(
      render(
        () => (
          <FirstStartPage
            client={{
              createMeshSetup: vi.fn<MeshSpanFetchClient["createMeshSetup"]>(),
              joinMeshSetup,
            }}
            onComplete={vi.fn()}
            onJoinAccepted={accepted}
          />
        ),
        root,
      ),
    );

    click("Join a swarm");
    enter("One-time claim", "meshspan-claim-v1.local-secret");
    enter("Join code", "meshspan-join-v2.secret");
    enter("Machine name", "Shop server");
    enter("MeshSpan instance", "Shop gateway");
    click("Join swarm");
    await settle();

    expect(joinMeshSetup).toHaveBeenCalledWith(
      expect.objectContaining({
        claim: "meshspan-claim-v1.local-secret",
        host_name: "Shop server",
        join_code: "meshspan-join-v2.secret",
        node_name: "Shop gateway",
      }),
    );
    expect(accepted).toHaveBeenCalledOnce();
  });
});

function enter(label: string, value: string): void {
  const input = labelled<HTMLInputElement>(label, "input");
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function labelled<T extends HTMLElement>(label: string, selector: string): T {
  const control = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent?.includes(label))
    ?.querySelector<T>(selector);
  if (control === undefined || control === null) {
    throw new TypeError(`expected labelled control: ${label}`);
  }
  return control;
}

function button(label: string): HTMLButtonElement {
  const control = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (control === undefined) {
    throw new TypeError(`expected button: ${label}`);
  }
  return control;
}

function click(label: string): void {
  button(label).click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
