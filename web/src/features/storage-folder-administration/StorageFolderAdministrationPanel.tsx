// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { RegisterStorageFolderForm } from "./RegisterStorageFolderForm";
import { StorageFolderList } from "./StorageFolderList";
import {
  createStorageFolderDirectory,
  type StorageFolderAdministrationClient,
} from "./model";

export function StorageFolderAdministrationPanel(
  props: Readonly<{
    client: StorageFolderAdministrationClient;
    csrfToken: string;
  }>,
): JSX.Element {
  const directory = createStorageFolderDirectory(() => props.client);
  void directory.loadInitial();
  const register: Parameters<
    typeof RegisterStorageFolderForm
  >[0]["register"] = async (path, usageLimit) => {
    await directory.register(path, usageLimit, props.csrfToken);
  };

  return (
    <div class="volume-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / This node</p>
        <h1>Storage folders</h1>
        <p>
          Give this daemon one or more existing folders. MeshSpan keeps its raw
          encrypted storage private beneath each path.
        </p>
      </header>
      <nav class="administration-nav" aria-label="Administration sections">
        <a href="/admin/identities">People and groups</a>
        <a href="/admin/volumes">Volumes</a>
        <a aria-current="page" href="/admin/storage-folders">
          Storage folders
        </a>
        <a href="/admin/operations">Operations</a>
      </nav>
      <RegisterStorageFolderForm register={register} />
      <StorageFolderList directory={directory} />
    </div>
  );
}
