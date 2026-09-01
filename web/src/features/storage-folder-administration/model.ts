// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  ListStorageFoldersResponse,
  MeshSpanFetchClient,
  RegisterStorageFolderRequest,
  RegisterStorageFolderResponse,
} from "../../generated";

export type StorageFolderAdministrationClient = Pick<
  MeshSpanFetchClient,
  "listNextStorageFolders" | "listStorageFolders" | "registerStorageFolder"
>;

export type StorageFolder = ListStorageFoldersResponse["folders"][number];

export type StorageFolderDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly StorageFolder[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "loading_more">;
  register: (
    path: string,
    usageLimit: RegisterStorageFolderRequest["usage_limit"],
    csrfToken: string,
  ) => Promise<RegisterStorageFolderResponse>;
}>;

export function createStorageFolderDirectory(
  client: Accessor<StorageFolderAdministrationClient>,
): StorageFolderDirectory {
  const [items, setItems] = createSignal<readonly StorageFolder[]>([], {
    equals: false,
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<"idle" | "loading" | "loading_more">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const apply = (page: ListStorageFoldersResponse, append: boolean): void => {
    setItems((current) => mergeFolders(append ? current : [], page.folders));
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError();
    try {
      apply(await client().listStorageFolders(), false);
    } catch {
      setError("MeshSpan could not read this node's storage folders.");
    } finally {
      setPhase("idle");
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") return;
    setPhase("loading_more");
    setError();
    try {
      apply(await client().listNextStorageFolders(next), true);
    } catch {
      setError("MeshSpan could not read the next storage-folder page.");
    } finally {
      setPhase("idle");
    }
  };

  const register = async (
    path: string,
    usageLimit: RegisterStorageFolderRequest["usage_limit"],
    csrfToken: string,
  ): Promise<RegisterStorageFolderResponse> => {
    const response = await client().registerStorageFolder(
      {
        operation_id: crypto.randomUUID(),
        path,
        usage_limit: usageLimit,
      },
      csrfToken,
    );
    setItems((current) => mergeFolders(current, [response.folder]));
    return response;
  };

  return {
    error,
    items,
    loadInitial,
    loadNext,
    nextPageUrl,
    phase,
    register,
  };
}

function mergeFolders(
  first: readonly StorageFolder[],
  second: readonly StorageFolder[],
): readonly StorageFolder[] {
  const byId = new Map(first.map((folder) => [folder.target_id, folder]));
  for (const folder of second) byId.set(folder.target_id, folder);
  return [...byId.values()].toSorted((left, right) =>
    left.target_id.localeCompare(right.target_id),
  );
}
