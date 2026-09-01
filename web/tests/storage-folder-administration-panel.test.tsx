// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StorageFolderAdministrationPanel } from "../src/features/storage-folder-administration/StorageFolderAdministrationPanel";
import type { StorageFolderAdministrationClient } from "../src/features/storage-folder-administration/model";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("storage-folder administration panel", () => {
  it("registers a second existing path with the selected capacity ceiling", async () => {
    const registerStorageFolder = vi.fn<
      StorageFolderAdministrationClient["registerStorageFolder"]
    >(async (request) => ({
      folder: {
        ...folder(),
        path: request.path,
        usage_limit: request.usage_limit,
      },
      operation_id: request.operation_id,
    }));
    mount({
      listNextStorageFolders: async () => ({
        folders: [],
        next_page_url: null,
      }),
      listStorageFolders: async () => ({
        folders: [folder()],
        next_page_url: null,
      }),
      registerStorageFolder,
    });
    await settle();

    enter("Existing absolute path", "/mnt/second-drive");
    click("Fixed capacity");
    enter("Amount", "2");
    select("Unit", "TiB");
    click("Add storage folder");
    await settle();

    expect(registerStorageFolder).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/mnt/second-drive",
        usage_limit: { bytes: (2n * 1024n ** 4n).toString(), kind: "bytes" },
      }),
      CSRF_TOKEN,
    );
    await vi.waitFor(() => {
      expect(document.body.textContent).toContain(
        "The folder is registered and serving storage work.",
      );
    });
    expect(document.body.textContent).toContain("/mnt/second-drive");
  });
});

function mount(client: StorageFolderAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => (
        <StorageFolderAdministrationPanel
          client={client}
          csrfToken={CSRF_TOKEN}
        />
      ),
      root,
    ),
  );
}

function folder() {
  return {
    generation: "1",
    node_id: "00000000-0000-4000-8000-000000000002",
    path: "/srv/meshspan",
    state: "active" as const,
    target_id: "00000000-0000-4000-8000-000000000001",
    usage_limit: { kind: "percent" as const, percent: 95 },
  };
}

function enter(label: string, value: string): void {
  const input = labelledInput(label);
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function select(label: string, value: string): void {
  const input = labelledSelect(label);
  input.value = value;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  flush();
}

function labelledInput(label: string): HTMLInputElement {
  return labelled(label, "input");
}

function labelledSelect(label: string): HTMLSelectElement {
  return labelled(label, "select");
}

function labelled(label: string, selector: "input"): HTMLInputElement;
function labelled(label: string, selector: "select"): HTMLSelectElement;
function labelled(
  label: string,
  selector: "input" | "select",
): HTMLInputElement | HTMLSelectElement {
  const element = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent.includes(label))
    ?.querySelector(selector);
  if (element === undefined || element === null) {
    throw new TypeError(`expected ${label}`);
  }
  return element;
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
