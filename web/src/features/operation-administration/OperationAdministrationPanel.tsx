// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";
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
      <AdministrationNavigation current="operations" />
      <OperationList directory={directory} />
    </div>
  );
}
