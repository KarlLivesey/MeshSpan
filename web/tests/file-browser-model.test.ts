// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it, vi } from "vitest";

import {
  createFileBrowserModel,
  type DirectoryEntry,
  type FileBrowserClient,
  type VolumeSummary,
} from "../src/features/file-browser/model";
import type {
  CreateDirectoryResponse,
  ListDirectoryResponse,
} from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"8".repeat(32)}.${"9".repeat(64)}`;
const DIRECTORY_ID = "02020202-0202-4202-8202-020202020202";
const DIRECTORY_REVISION_ID = "03030303-0303-4303-8303-030303030303";
const NAMESPACE_COMMIT_ID = "04040404-0404-4404-8404-040404040404";
const VOLUME_ID = "01010101-0101-4101-8101-010101010101";

describe("native file browser model", () => {
  it("pins directory continuations to one immutable namespace view", async () => {
    const first = directoryPage([directoryEntry("Reports", "10")], "/next");
    const next = directoryPage([fileEntry("accounts.csv", "11")]);
    const fixture = browserFixture({
      firstDirectory: first,
      nextDirectory: next,
    });
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );

    await model.loadInitial();
    await model.loadMore();

    expect(model.directory()?.entries.map((entry) => entry.name)).toEqual([
      "Reports",
      "accounts.csv",
    ]);
    expect(fixture.listNextDirectory).toHaveBeenCalledWith("/next");
  });

  it("rejects a continuation that changes the immutable view", async () => {
    const first = directoryPage([directoryEntry("Reports", "10")], "/next");
    const next = {
      ...directoryPage([fileEntry("accounts.csv", "11")]),
      namespace_commit_id: "09090909-0909-4909-8909-090909090909",
    };
    const fixture = browserFixture({
      firstDirectory: first,
      nextDirectory: next,
    });
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );

    await model.loadInitial();
    await model.loadMore();

    expect(model.directory()?.entries).toHaveLength(1);
    expect(model.error()).toBe("MeshSpan could not load more files.");
  });

  it("records only a committed mutation by re-reading the directory", async () => {
    const fixture = browserFixture();
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );
    await model.loadInitial();

    await model.createDirectory(" New folder ");

    expect(fixture.createDirectory).toHaveBeenCalledWith(
      VOLUME_ID,
      expect.objectContaining({ path: "New folder" }),
      CSRF_TOKEN,
    );
    expect(fixture.listDirectory).toHaveBeenCalledTimes(2);
    expect(model.directory()?.entries[0]?.name).toBe("New folder");
  });
});

describe("file mutation outcomes", () => {
  it("keeps a committed create when refreshing the directory fails", async () => {
    const fixture = browserFixture();
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );
    await model.loadInitial();
    fixture.listDirectory.mockRejectedValueOnce(new Error("refresh lost"));

    await expect(model.createDirectory("Saved")).resolves.toBeUndefined();

    expect(model.error()).toContain("Saved");
    expect(model.error()).not.toContain("did not commit");
    expect(fixture.createDirectory).toHaveBeenCalledTimes(1);
  });

  it("does not accept a receipt for another volume", async () => {
    const fixture = browserFixture();
    fixture.createDirectory.mockImplementationOnce(
      async (_volumeId, request) => ({
        ...directoryCreation(request.path, request.operation_id),
        volume_id: "wrong-volume",
      }),
    );
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );
    await model.loadInitial();
    await model.createDirectory("Requested");
    expect(model.mutation().phase).toBe("unknown");
    expect(fixture.listDirectory).toHaveBeenCalledTimes(1);
  });

  it("retains a lost create response and blocks a changed attempt", async () => {
    const fixture = browserFixture();
    fixture.createDirectory.mockRejectedValueOnce(new Error("response lost"));
    const model = createFileBrowserModel(
      () => fixture.client,
      () => CSRF_TOKEN,
    );
    await model.loadInitial();

    await model.createDirectory("Original").catch(() => undefined);
    expect(model.error()).toContain("unknown");
    await model.createDirectory("Changed").catch(() => undefined);
    expect(fixture.createDirectory).toHaveBeenCalledTimes(1);
  });
});

describe("file mutation recovery", () => {
  it("replays one rename identity after a committed response is lost", async () => {
    const fixture = browserFixture();
    const entry = directoryEntry("Original", "20");
    const rename = vi
      .fn<FileBrowserClient["renameObject"]>()
      .mockRejectedValueOnce(new Error("response lost"))
      .mockImplementation(async (_volumeId, request) => ({
        ...directoryCreation(request.target_path, request.operation_id),
        object_id: entry.object_id,
        source_path: request.source_path,
        target_path: request.target_path,
      }));
    const model = createFileBrowserModel(
      () => ({ ...fixture.client, renameObject: rename }),
      () => CSRF_TOKEN,
    );
    await model.loadInitial();
    await model.renameEntry(entry, "Renamed");
    await model.renameEntry(entry, "Changed");
    expect(rename).toHaveBeenCalledTimes(1);
    await model.retryMutation();
    expect(rename).toHaveBeenCalledTimes(2);
    expect(rename.mock.calls[1]).toEqual(rename.mock.calls[0]);
    expect(model.mutation().phase).toBe("committed");
    expect(fixture.listDirectory).toHaveBeenCalledTimes(2);
  });

  it("does not expose mutations without a browser CSRF capability", async () => {
    const fixture = browserFixture();
    const model = createFileBrowserModel(
      () => fixture.client,
      () => undefined,
    );
    await model.loadInitial();

    expect(model.mutationsAvailable()).toBe(false);
    await expect(model.createDirectory("Blocked")).rejects.toThrow(
      "not writable",
    );
    expect(fixture.createDirectory).not.toHaveBeenCalled();
  });
});

type BrowserFixtureOptions = Readonly<{
  firstDirectory?: ListDirectoryResponse;
  nextDirectory?: ListDirectoryResponse;
}>;

function browserFixture(options: BrowserFixtureOptions = {}) {
  let rootEntries = [...(options.firstDirectory?.entries ?? [])];
  const listDirectory = vi.fn<FileBrowserClient["listDirectory"]>(
    async (request) =>
      options.firstDirectory ??
      directoryPage(rootEntries, null, request.path ?? null),
  );
  const listNextDirectory = vi.fn<FileBrowserClient["listNextDirectory"]>(
    async () => options.nextDirectory ?? directoryPage([]),
  );
  const createDirectory = vi.fn<FileBrowserClient["createDirectory"]>(
    async (_volumeId, request) => {
      rootEntries = [directoryEntry(request.path, "20")];
      return directoryCreation(request.path, request.operation_id);
    },
  );
  const client: FileBrowserClient = {
    abortUpload: vi.fn<FileBrowserClient["abortUpload"]>(async () => {
      throw new Error("abortUpload was not expected");
    }),
    beginUpload: vi.fn<FileBrowserClient["beginUpload"]>(async () => {
      throw new Error("beginUpload was not expected");
    }),
    commitUpload: vi.fn<FileBrowserClient["commitUpload"]>(async () => {
      throw new Error("commitUpload was not expected");
    }),
    createDirectory,
    deleteObject: vi.fn<FileBrowserClient["deleteObject"]>(async () => {
      throw new Error("deleteObject was not expected");
    }),
    listDirectory,
    listNextDirectory,
    listNextVolumes: async () => ({ next_page_url: null, volumes: [] }),
    listVolumes: async () => ({ next_page_url: null, volumes: [volume()] }),
    renameObject: vi.fn<FileBrowserClient["renameObject"]>(async () => {
      throw new Error("renameObject was not expected");
    }),
    writeUploadRange: vi.fn<FileBrowserClient["writeUploadRange"]>(async () => {
      throw new Error("writeUploadRange was not expected");
    }),
  };
  return { client, createDirectory, listDirectory, listNextDirectory };
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
  nextPageUrl: string | null = null,
  path: string | null = null,
): ListDirectoryResponse {
  return {
    directory_object_id: DIRECTORY_ID,
    directory_object_revision_id: DIRECTORY_REVISION_ID,
    entries,
    namespace_commit_id: NAMESPACE_COMMIT_ID,
    next_page_url: nextPageUrl,
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
