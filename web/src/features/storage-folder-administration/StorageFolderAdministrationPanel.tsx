// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";
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
      <AdministrationNavigation current="storage-folders" />
      <RegisterStorageFolderForm register={register} />
      <StorageFolderList directory={directory} />
    </div>
  );
}
