// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { CreateFaultGroupForm } from "./CreateFaultGroupForm";
import { FaultGroupEditor } from "./FaultGroupEditor";
import { NodeInventory } from "./NodeInventory";
import { StorageDrainPanel } from "./StorageDrainPanel";
import { TargetInventory } from "./TargetInventory";
import {
  createTopologyDirectory,
  type TopologyAdministrationClient,
} from "./model";

export function TopologyAdministrationPanel(
  props: Readonly<{
    client: TopologyAdministrationClient;
    csrfToken: string;
  }>,
): JSX.Element {
  const directory = createTopologyDirectory(() => props.client);
  void directory.load();
  const createGroup = async (
    className: string,
    groupName: string,
  ): Promise<void> => {
    const csrfToken = props.csrfToken;
    await directory.createGroup(className, groupName, csrfToken);
  };

  return (
    <div class="topology-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / Mesh</p>
        <h1>Machines and failure boundaries</h1>
        <p>
          See every daemon and storage target. Group machines by anything they
          can lose together—such as a room, power supply, building or
          hypervisor.
        </p>
      </header>
      <nav class="administration-nav" aria-label="Administration sections">
        <a href="/admin/identities">People and groups</a>
        <a href="/admin/volumes">Volumes</a>
        <a href="/admin/storage-folders">Storage folders</a>
        <a aria-current="page" href="/admin/topology">
          Mesh topology
        </a>
        <a href="/admin/operations">Operations</a>
      </nav>
      <p class="form-error" role="status" aria-live="polite">
        {directory.error()}
      </p>
      <CreateFaultGroupForm
        create={createGroup}
        saving={directory.phase() === "saving"}
      />
      <NodeInventory directory={directory} />
      <FaultGroupEditor directory={directory} csrfToken={props.csrfToken} />
      <TargetInventory directory={directory} />
      <StorageDrainPanel
        client={props.client}
        csrfToken={props.csrfToken}
        topology={directory}
      />
    </div>
  );
}
