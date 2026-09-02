// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { StorageDrainForm } from "./StorageDrainForm";
import { StorageDrainList } from "./StorageDrainList";
import type { TopologyDirectory } from "./model";
import {
  createStorageDrainDirectory,
  type StorageDrainClient,
} from "./storage-drain-model";

export function StorageDrainPanel(
  props: Readonly<{
    client: StorageDrainClient;
    csrfToken: string;
    topology: TopologyDirectory;
  }>,
): JSX.Element {
  const drains = createStorageDrainDirectory(() => props.client);
  void drains.load();

  return (
    <section class="topology-section" aria-labelledby="storage-drains-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Safe removal</p>
          <h2 id="storage-drains-title">Drain storage</h2>
        </div>
        <button
          disabled={drains.phase() !== "idle"}
          type="button"
          onClick={() => void drains.load()}
        >
          Refresh
        </button>
      </div>
      <p>
        MeshSpan stops new placement immediately, evacuates recoverable data,
        and tells you when the selected folder, node, or failure group is safe
        to detach.
      </p>
      <StorageDrainForm
        begin={drains.begin}
        csrfToken={props.csrfToken}
        saving={drains.phase() !== "idle"}
        topology={props.topology}
      />
      <StorageDrainList directory={drains} />
    </section>
  );
}
