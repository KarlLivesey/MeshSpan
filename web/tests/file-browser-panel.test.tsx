// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FileBrowser } from "../src/features/file-browser/FileBrowser";
import type { BrowserDownloadClient } from "../src/features/file-browser/download";
import type {
  DirectoryEntry,
  FileBrowserClient,
  VolumeSummary,
} from "../src/features/file-browser/model";
import type {
  CreateDirectoryResponse,
  DeleteObjectResponse,
  ListDirectoryResponse,
  RenameObjectResponse,
} from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"8".repeat(32)}.${"9".repeat(64)}`;
const DIRECTORY_ID = "02020202-0202-4202-8202-020202020202";
const DIRECTORY_REVISION_ID = "03030303-0303-4303-8303-030303030303";
const NAMESPACE_COMMIT_ID = "04040404-0404-4404-8404-040404040404";
const VOLUME_ID = "01010101-0101-4101-8101-010101010101";
const mountedRoots = new Set<() => void>();

afterEach(() => {
  for (const dispose of mountedRoots) dispose();
  mountedRoots.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("native file browser panel", () => {
  it("loads available volumes and navigates logical folders", async () => {
    const fixture = browserFixture();
    mountBrowser(fixture.client, () => CSRF_TOKEN);
    await settle();

    expect(document.body.textContent).toContain("Shared files");
    expect(document.body.textContent).toContain("Reports");
    clickButton("Reports");
    await settle();

    expect(fixture.listDirectory).toHaveBeenLastCalledWith({
      path: "Reports",
      volumeId: VOLUME_ID,
    });
    expect(document.body.textContent).toContain("accounts.csv");
    expect(document.querySelector(".current-path")?.textContent).toContain(
      "/ Reports",
    );
  });

  it("creates, renames and deletes only after committed responses", async () => {
    const fixture = browserFixture();
    mountBrowser(fixture.client, () => CSRF_TOKEN);
    await settle();

    enterText("New folder name", "Quarterly");
    clickButton("Create folder");
    await settle();
    expect(fixture.createDirectory).toHaveBeenCalledWith(
      VOLUME_ID,
      expect.objectContaining({ path: "Quarterly" }),
      CSRF_TOKEN,
    );
    expect(rowFor("Quarterly")).toBeDefined();

    clickRowButton("Quarterly", "Rename");
    enterText("New name for Quarterly", "Archive");
    clickRowButton("Quarterly", "Save name");
    await settle();
    expect(rowFor("Archive")).toBeDefined();

    clickRowButton("Archive", "Delete");
    clickRowButton("Archive", "Confirm delete");
    await settle();
    expect(document.querySelector("tbody")?.textContent).not.toContain(
      "Archive",
    );
  });

  it("keeps browsing available when browser mutation capability is absent", async () => {
    const fixture = browserFixture();
    mountBrowser(fixture.client, () => undefined);
    await settle();

    expect(document.body.textContent).toContain("invoice.txt");
    expect(document.body.textContent).toContain(
      "available to browse but not change",
    );
    expect(buttonNamed("Create folder")).toBeUndefined();
    expect(buttonNamed("Rename")).toBeUndefined();
    expect(buttonNamed("Delete")).toBeUndefined();
  });
});

type BrowserClient = FileBrowserClient & BrowserDownloadClient;

function browserFixture() {
  let rootEntries = [
    directoryEntry("Reports", "10"),
    fileEntry("invoice.txt", "11"),
  ];
  const reportsEntries = [fileEntry("accounts.csv", "12")];
  const listDirectory = vi.fn<FileBrowserClient["listDirectory"]>(
    async (request) =>
      directoryPage(
        request.path === "Reports" ? reportsEntries : rootEntries,
        request.path ?? null,
      ),
  );
  const createDirectory = vi.fn<FileBrowserClient["createDirectory"]>(
    async (_volumeId, request) => {
      rootEntries = [...rootEntries, directoryEntry(request.path, "20")];
      return directoryCreation(request.path, request.operation_id);
    },
  );
  const renameObject = vi.fn<FileBrowserClient["renameObject"]>(
    async (_volumeId, request) => {
      const sourceName = leafName(request.source_path);
      rootEntries = rootEntries.map((entry) =>
        entry.name === sourceName
          ? { ...entry, name: leafName(request.target_path) }
          : entry,
      );
      return renameResponse(request);
    },
  );
  const deleteObject = vi.fn<FileBrowserClient["deleteObject"]>(
    async (_volumeId, request) => {
      const removed = rootEntries.find(
        (entry) => entry.name === leafName(request.path),
      );
      rootEntries = rootEntries.filter((entry) => entry !== removed);
      return deleteResponse(request, removed?.kind ?? "file");
    },
  );
  const client: BrowserClient = {
    abortUpload: rejectUnexpected,
    beginUpload: rejectUnexpected,
    commitUpload: rejectUnexpected,
    createDirectory,
    deleteObject,
    listDirectory,
    listNextDirectory: rejectUnexpected,
    listNextVolumes: rejectUnexpected,
    listVolumes: async () => ({ next_page_url: null, volumes: [volume()] }),
    readFile: rejectUnexpected,
    renameObject,
    writeUploadRange: rejectUnexpected,
  };
  return { client, createDirectory, listDirectory };
}

async function rejectUnexpected(): Promise<never> {
  throw new Error("unexpected browser fixture operation");
}

function mountBrowser(
  client: BrowserClient,
  csrfToken: () => string | undefined,
): void {
  const host = document.createElement("div");
  document.body.append(host);
  mountedRoots.add(
    render(() => <FileBrowser client={client} csrfToken={csrfToken} />, host),
  );
}

async function settle(): Promise<void> {
  for (let cycle = 0; cycle < 6; cycle += 1) {
    await Promise.resolve();
    flush();
  }
}

function clickButton(name: string): void {
  const button = buttonNamed(name);
  if (button === undefined) throw new Error(`button ${name} is missing`);
  button.click();
  flush();
}

function clickRowButton(rowName: string, buttonName: string): void {
  const button = [...rowFor(rowName).querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === buttonName,
  );
  if (button === undefined) throw new Error(`button ${buttonName} is missing`);
  button.click();
  flush();
}

function buttonNamed(name: string): HTMLButtonElement | undefined {
  return [...document.querySelectorAll("button")].find(
    (button) => button.textContent.trim() === name,
  );
}

function rowFor(name: string): HTMLTableRowElement {
  const row = [...document.querySelectorAll("tbody tr")].find((candidate) =>
    candidate.querySelector("th")?.textContent.includes(name),
  );
  if (!(row instanceof HTMLTableRowElement)) {
    throw new Error(`row ${name} is missing`);
  }
  return row;
}

function enterText(label: string, value: string): void {
  const input = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent.includes(label))
    ?.querySelector("input");
  if (!(input instanceof HTMLInputElement)) {
    throw new Error(`field ${label} is missing`);
  }
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function volume(): VolumeSummary {
  return {
    created_at_epoch_micros: 10,
    effective_rights: [
      "traverse",
      "list",
      "read_data",
      "create_child",
      "rename",
      "delete",
    ],
    name: "Shared files",
    revision: 1,
    root_object_id: DIRECTORY_ID,
    state: "active",
    volume_id: VOLUME_ID,
  };
}

function directoryPage(
  entries: DirectoryEntry[],
  path: string | null,
): ListDirectoryResponse {
  return {
    directory_object_id: DIRECTORY_ID,
    directory_object_revision_id: DIRECTORY_REVISION_ID,
    entries,
    namespace_commit_id: NAMESPACE_COMMIT_ID,
    next_page_url: null,
    path,
    volume_id: VOLUME_ID,
  };
}

function directoryEntry(name: string, suffix: string): DirectoryEntry {
  return {
    entry_generation: 1,
    file_version_id: null,
    kind: "directory",
    logical_length: null,
    name,
    object_id: `00000000-0000-4000-8000-${suffix.padStart(12, "0")}`,
    object_revision_id: `10000000-0000-4000-8000-${suffix.padStart(12, "0")}`,
  };
}

function fileEntry(name: string, suffix: string): DirectoryEntry {
  return {
    ...directoryEntry(name, suffix),
    file_version_id: `20000000-0000-4000-8000-${suffix.padStart(12, "0")}`,
    kind: "file",
    logical_length: 42,
  };
}

function directoryCreation(
  path: string,
  operationId: string,
): CreateDirectoryResponse {
  return {
    head_sequence: 1,
    namespace_commit_id: NAMESPACE_COMMIT_ID,
    object_id: DIRECTORY_ID,
    object_revision_id: DIRECTORY_REVISION_ID,
    operation_id: operationId,
    path,
    volume_id: VOLUME_ID,
  };
}

function renameResponse(
  request: Readonly<{
    operation_id: string;
    source_path: string;
    target_path: string;
  }>,
): RenameObjectResponse {
  return {
    head_sequence: 2,
    namespace_commit_id: NAMESPACE_COMMIT_ID,
    object_id: DIRECTORY_ID,
    object_revision_id: DIRECTORY_REVISION_ID,
    operation_id: request.operation_id,
    source_path: request.source_path,
    target_path: request.target_path,
    volume_id: VOLUME_ID,
  };
}

function deleteResponse(
  request: Readonly<{ operation_id: string; path: string }>,
  objectKind: DeleteObjectResponse["object_kind"],
): DeleteObjectResponse {
  return {
    head_sequence: 3,
    namespace_commit_id: NAMESPACE_COMMIT_ID,
    object_id: DIRECTORY_ID,
    object_kind: objectKind,
    object_revision_id: DIRECTORY_REVISION_ID,
    operation_id: request.operation_id,
    path: request.path,
    scope: "branch_deleted",
    volume_id: VOLUME_ID,
  };
}

function leafName(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}
