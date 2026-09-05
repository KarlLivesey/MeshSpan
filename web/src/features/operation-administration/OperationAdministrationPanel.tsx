// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";
import {
  createOperationDirectory,
  type OperationAdministrationClient,
} from "./model";
import { OperationList } from "./OperationList";
import { DiagnosticsDownload } from "./DiagnosticsDownload";
import { MetricsAdministration } from "../metrics-administration/MetricsAdministration";
import type { MetricsClient } from "../metrics-administration/model";

export function OperationAdministrationPanel(
  props: Readonly<{
    client: OperationAdministrationClient & MetricsClient;
    csrfToken: string;
  }>,
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
      <DiagnosticsDownload client={props.client} />
      <MetricsAdministration
        client={props.client}
        csrfToken={props.csrfToken}
      />
      <OperationList directory={directory} />
    </div>
  );
}
