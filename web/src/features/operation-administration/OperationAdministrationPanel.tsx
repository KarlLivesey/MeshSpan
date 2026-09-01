// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import {
  createOperationDirectory,
  type OperationAdministrationClient,
} from "./model";
import { OperationList } from "./OperationList";

export function OperationAdministrationPanel(
  props: Readonly<{ client: OperationAdministrationClient }>,
): JSX.Element {
  const directory = createOperationDirectory(() => props.client);
  void directory.loadInitial();

  return (
    <div class="operation-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / Activity</p>
        <h1>Operations</h1>
        <p>
          Durable work and its authoritative outcome. Progress is advisory;
          success is shown only after MeshSpan commits it.
        </p>
      </header>
      <nav class="administration-nav" aria-label="Administration sections">
        <a href="/admin/identities">People and groups</a>
        <a href="/admin/volumes">Volumes</a>
        <a href="/admin/storage-folders">Storage folders</a>
        <a href="/admin/topology">Mesh topology</a>
        <a aria-current="page" href="/admin/operations">
          Operations
        </a>
      </nav>
      <OperationList directory={directory} />
    </div>
  );
}
