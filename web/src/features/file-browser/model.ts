// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor, type Setter } from "solid-js";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type {
  ListDirectoryResponse,
  ListVolumesResponse,
} from "../../generated/types.gen";
import { childPath, parentPath } from "./path";
import { uploadBrowserFile } from "./upload";

export type VolumeSummary = ListVolumesResponse["volumes"][number];
export type DirectoryEntry = ListDirectoryResponse["entries"][number];
export type FileBrowserClient = Pick<
  MeshSpanFetchClient,
  | "abortUpload"
  | "beginUpload"
  | "commitUpload"
  | "createDirectory"
  | "deleteObject"
  | "listDirectory"
  | "listNextDirectory"
  | "listNextVolumes"
  | "listVolumes"
  | "renameObject"
  | "writeUploadRange"
>;
export type BrowserPhase =
  "idle" | "loading" | "loading_more" | "mutating" | "transferring";

export type FileBrowserModel = Readonly<{
  createDirectory: (name: string) => Promise<void>;
  deleteEntry: (entry: DirectoryEntry) => Promise<void>;
  directory: Accessor<ListDirectoryResponse | undefined>;
  error: Accessor<string | undefined>;
  loadInitial: () => Promise<void>;
  loadMore: () => Promise<void>;
  loadMoreVolumes: () => Promise<void>;
  mutationsAvailable: Accessor<boolean>;
  openDirectory: (entry: DirectoryEntry) => Promise<void>;
  openParent: () => Promise<void>;
  phase: Accessor<BrowserPhase>;
  progress: Accessor<TransferProgress | undefined>;
  renameEntry: (entry: DirectoryEntry, name: string) => Promise<void>;
  selectVolume: (volumeId: string) => Promise<void>;
  selectedVolume: Accessor<VolumeSummary | undefined>;
  uploadFile: (file: File) => Promise<void>;
  volumeNextPageUrl: Accessor<string | null>;
  volumes: Accessor<readonly VolumeSummary[]>;
}>;

type TransferProgress = Readonly<{ complete: number; total: number }>;

type BrowserState = Readonly<{
  directory: Accessor<ListDirectoryResponse | undefined>;
  error: Accessor<string | undefined>;
  phase: Accessor<BrowserPhase>;
  progress: Accessor<TransferProgress | undefined>;
  selectedVolumeId: Accessor<string | undefined>;
  setDirectory: Setter<ListDirectoryResponse | undefined>;
  setError: Setter<string | undefined>;
  setPhase: Setter<BrowserPhase>;
  setProgress: Setter<TransferProgress | undefined>;
  setSelectedVolumeId: Setter<string | undefined>;
  setVolumeNextPageUrl: Setter<string | null>;
  setVolumes: Setter<readonly VolumeSummary[]>;
  volumeNextPageUrl: Accessor<string | null>;
  volumes: Accessor<readonly VolumeSummary[]>;
}>;

type BrowserContext = Readonly<{
  client: Accessor<FileBrowserClient>;
  csrfToken: Accessor<string | undefined>;
  selectedVolume: Accessor<VolumeSummary | undefined>;
  state: BrowserState;
}>;

/** Owns one current-user view of the specialised native file API. */
export function createFileBrowserModel(
  client: Accessor<FileBrowserClient>,
  csrfToken: Accessor<string | undefined>,
): FileBrowserModel {
  const state = createBrowserState();
  const selectedVolume = () =>
    state
      .volumes()
      .find((volume) => volume.volume_id === state.selectedVolumeId());
  const context = { client, csrfToken, selectedVolume, state };
  const mutationsAvailable = () =>
    selectedVolume()?.state === "active" && csrfToken() !== undefined;
  return {
    createDirectory: async (name) => createDirectory(context, name),
    deleteEntry: async (entry) => deleteEntry(context, entry),
    directory: state.directory,
    error: state.error,
    loadInitial: async () => loadInitial(context),
    loadMore: async () => loadMore(context),
    loadMoreVolumes: async () => loadMoreVolumes(context),
    mutationsAvailable,
    openDirectory: async (entry) => openDirectory(context, entry),
    openParent: async () =>
      loadDirectory(context, parentPath(directoryPath(state.directory()))),
    phase: state.phase,
    progress: state.progress,
    renameEntry: async (entry, name) => renameEntry(context, entry, name),
    selectVolume: async (volumeId) => selectVolume(context, volumeId),
    selectedVolume,
    uploadFile: async (file) => uploadFile(context, file),
    volumeNextPageUrl: state.volumeNextPageUrl,
    volumes: state.volumes,
  };
}

function createBrowserState(): BrowserState {
  const [volumes, setVolumes] = createSignal<readonly VolumeSummary[]>([], {
    ownedWrite: true,
  });
  const [selectedVolumeId, setSelectedVolumeId] = createSignal<
    string | undefined
  >(undefined, { ownedWrite: true });
  const [directory, setDirectory] = createSignal<
    ListDirectoryResponse | undefined
  >(undefined, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<BrowserPhase>("idle", {
    ownedWrite: true,
  });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const [progress, setProgress] = createSignal<TransferProgress | undefined>(
    undefined,
    { ownedWrite: true },
  );
  const [volumeNextPageUrl, setVolumeNextPageUrl] = createSignal<string | null>(
    null,
    { ownedWrite: true },
  );
  return {
    directory,
    error,
    phase,
    progress,
    selectedVolumeId,
    setDirectory,
    setError,
    setPhase,
    setProgress,
    setSelectedVolumeId,
    setVolumeNextPageUrl,
    setVolumes,
    volumeNextPageUrl,
    volumes,
  };
}

async function loadInitial(context: BrowserContext): Promise<void> {
  context.state.setPhase("loading");
  context.state.setError(undefined);
  try {
    const page = await context.client().listVolumes();
    context.state.setVolumes(page.volumes);
    context.state.setVolumeNextPageUrl(page.next_page_url);
    const first = page.volumes[0];
    if (first !== undefined) {
      context.state.setSelectedVolumeId(first.volume_id);
      await loadDirectory(context, "", first);
    }
  } catch {
    context.state.setError(
      "MeshSpan could not load the volumes available to you.",
    );
  } finally {
    context.state.setPhase("idle");
  }
}

async function loadMoreVolumes(context: BrowserContext): Promise<void> {
  const nextPageUrl = context.state.volumeNextPageUrl();
  if (nextPageUrl === null) return;
  context.state.setPhase("loading_more");
  context.state.setError(undefined);
  try {
    const page = await context.client().listNextVolumes(nextPageUrl);
    context.state.setVolumes((current) => mergeVolumes(current, page.volumes));
    context.state.setVolumeNextPageUrl(page.next_page_url);
  } catch {
    context.state.setError("MeshSpan could not load more volumes.");
  } finally {
    context.state.setPhase("idle");
  }
}

async function loadDirectory(
  context: BrowserContext,
  selectedPath: string,
  knownVolume?: VolumeSummary,
): Promise<void> {
  const selected =
    knownVolume ?? requireSelectedVolume(context.selectedVolume());
  context.state.setPhase("loading");
  context.state.setError(undefined);
  try {
    const page = await context.client().listDirectory({
      ...(selectedPath === "" ? {} : { path: selectedPath }),
      volumeId: selected.volume_id,
    });
    verifyDirectoryPage(page, selected.volume_id, selectedPath);
    context.state.setDirectory(page);
  } catch (cause) {
    context.state.setError("MeshSpan could not load this folder.");
    throw cause;
  } finally {
    context.state.setPhase("idle");
  }
}

async function loadMore(context: BrowserContext): Promise<void> {
  const current = context.state.directory();
  if (current?.next_page_url === null || current === undefined) return;
  context.state.setPhase("loading_more");
  context.state.setError(undefined);
  try {
    const page = await context
      .client()
      .listNextDirectory(current.next_page_url);
    context.state.setDirectory(mergeDirectoryPages(current, page));
  } catch {
    context.state.setError("MeshSpan could not load more files.");
  } finally {
    context.state.setPhase("idle");
  }
}

async function selectVolume(
  context: BrowserContext,
  volumeId: string,
): Promise<void> {
  const selected = context.state
    .volumes()
    .find((volume) => volume.volume_id === volumeId);
  if (selected === undefined) {
    throw new TypeError("selected volume is not available");
  }
  context.state.setSelectedVolumeId(volumeId);
  context.state.setDirectory(undefined);
  await loadDirectory(context, "", selected);
}

async function openDirectory(
  context: BrowserContext,
  entry: DirectoryEntry,
): Promise<void> {
  if (entry.kind !== "directory") throw new TypeError("entry is not a folder");
  const selectedPath = childPath(
    directoryPath(context.state.directory()),
    entry.name,
  );
  await loadDirectory(context, selectedPath);
}

async function createDirectory(
  context: BrowserContext,
  name: string,
): Promise<void> {
  const selected = requireWritableVolume(context);
  const selectedPath = childPath(
    directoryPath(context.state.directory()),
    name,
  );
  await commitMutation(context, async () => {
    await context
      .client()
      .createDirectory(
        selected.volume_id,
        { operation_id: crypto.randomUUID(), path: selectedPath },
        requireCsrfToken(context.csrfToken()),
      );
  });
}

async function deleteEntry(
  context: BrowserContext,
  entry: DirectoryEntry,
): Promise<void> {
  const selected = requireWritableVolume(context);
  const selectedPath = childPath(
    directoryPath(context.state.directory()),
    entry.name,
  );
  await commitMutation(context, async () => {
    await context
      .client()
      .deleteObject(
        selected.volume_id,
        { operation_id: crypto.randomUUID(), path: selectedPath },
        requireCsrfToken(context.csrfToken()),
      );
  });
}

async function renameEntry(
  context: BrowserContext,
  entry: DirectoryEntry,
  name: string,
): Promise<void> {
  const selected = requireWritableVolume(context);
  const currentPath = directoryPath(context.state.directory());
  await commitMutation(context, async () => {
    await context.client().renameObject(
      selected.volume_id,
      {
        operation_id: crypto.randomUUID(),
        source_path: childPath(currentPath, entry.name),
        target_path: childPath(currentPath, name),
      },
      requireCsrfToken(context.csrfToken()),
    );
  });
}

async function uploadFile(context: BrowserContext, file: File): Promise<void> {
  const selected = requireWritableVolume(context);
  const currentPath = directoryPath(context.state.directory());
  const existing = context.state
    .directory()
    ?.entries.find((entry) => entry.name === file.name);
  if (existing?.kind === "directory") {
    throw new TypeError("a folder already has that name");
  }
  context.state.setPhase("transferring");
  context.state.setProgress({ complete: 0, total: file.size });
  context.state.setError(undefined);
  try {
    await uploadBrowserFile({
      client: context.client(),
      csrfToken: requireCsrfToken(context.csrfToken()),
      currentVersionId: existing?.file_version_id ?? undefined,
      file,
      onProgress: (complete, total) =>
        context.state.setProgress({ complete, total }),
      path: childPath(currentPath, file.name),
      volumeId: selected.volume_id,
    });
    await reloadDirectory(context);
  } catch (cause) {
    context.state.setError("MeshSpan could not finish that upload.");
    throw cause;
  } finally {
    context.state.setProgress(undefined);
    context.state.setPhase("idle");
  }
}

async function commitMutation(
  context: BrowserContext,
  operation: () => Promise<void>,
): Promise<void> {
  context.state.setPhase("mutating");
  context.state.setError(undefined);
  try {
    await operation();
    await reloadDirectory(context);
  } catch (cause) {
    context.state.setError("MeshSpan did not commit that change.");
    throw cause;
  } finally {
    context.state.setPhase("idle");
  }
}

async function reloadDirectory(context: BrowserContext): Promise<void> {
  await loadDirectory(context, directoryPath(context.state.directory()));
}

function mergeDirectoryPages(
  current: ListDirectoryResponse,
  next: ListDirectoryResponse,
): ListDirectoryResponse {
  verifySameDirectoryView(current, next);
  const identities = new Set(
    current.entries.map((entry) => entry.object_revision_id),
  );
  if (next.entries.some((entry) => identities.has(entry.object_revision_id))) {
    throw new TypeError("directory continuation repeats an object revision");
  }
  return { ...next, entries: [...current.entries, ...next.entries] };
}

function mergeVolumes(
  current: readonly VolumeSummary[],
  next: readonly VolumeSummary[],
): readonly VolumeSummary[] {
  const identities = new Set(current.map((volume) => volume.volume_id));
  if (next.some((volume) => identities.has(volume.volume_id))) {
    throw new TypeError("volume continuation repeats a volume");
  }
  return [...current, ...next];
}

function verifySameDirectoryView(
  first: ListDirectoryResponse,
  second: ListDirectoryResponse,
): void {
  if (
    first.volume_id !== second.volume_id ||
    first.path !== second.path ||
    first.directory_object_id !== second.directory_object_id ||
    first.directory_object_revision_id !==
      second.directory_object_revision_id ||
    first.namespace_commit_id !== second.namespace_commit_id
  ) {
    throw new TypeError("directory continuation changed its immutable view");
  }
}

function verifyDirectoryPage(
  page: ListDirectoryResponse,
  volumeId: string,
  selectedPath: string,
): void {
  const responsePath = selectedPath === "" ? null : selectedPath;
  if (page.volume_id !== volumeId || page.path !== responsePath) {
    throw new TypeError("directory response does not match its request");
  }
}

function directoryPath(page: ListDirectoryResponse | undefined): string {
  return page?.path ?? "";
}

function requireSelectedVolume(
  volume: VolumeSummary | undefined,
): VolumeSummary {
  if (volume === undefined) throw new TypeError("no volume is selected");
  return volume;
}

function requireWritableVolume(context: BrowserContext): VolumeSummary {
  const selected = requireSelectedVolume(context.selectedVolume());
  if (selected.state !== "active" || context.csrfToken() === undefined) {
    throw new TypeError("selected volume is not writable in this session");
  }
  return selected;
}

function requireCsrfToken(value: string | undefined): string {
  if (value === undefined) {
    throw new TypeError("browser session has no CSRF token");
  }
  return value;
}
