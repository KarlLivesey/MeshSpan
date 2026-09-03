// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";

import { createPrincipalDirectory } from "../identity-administration/model";
import { CreateVolumeForm } from "./CreateVolumeForm";
import { createVolumeDirectory } from "./model";
import type { AdminVolume, VolumeAdministrationClient } from "./model";
import { PermissionGrantPanel } from "./PermissionGrantPanel";
import { SmbExportPanel } from "./SmbExportPanel";
import { VolumeList } from "./VolumeList";

type VolumeAdministrationPanelProps = Readonly<{
  client: VolumeAdministrationClient;
  csrfToken: string;
}>;

export function VolumeAdministrationPanel(
  props: VolumeAdministrationPanelProps,
): JSX.Element {
  const volumes = createVolumeDirectory(() => props.client);
  const users = createPrincipalDirectory(() => props.client, "user");
  const groups = createPrincipalDirectory(() => props.client, "group");
  const [selectedVolume, setSelectedVolume] = createSignal<AdminVolume>();

  void Promise.all([
    volumes.loadInitial(),
    users.loadInitial(),
    groups.loadInitial(),
  ]);

  const create = async (
    name: string,
    ownerPrincipalIds: readonly string[],
  ): Promise<void> => {
    const response = await props.client.createVolume(
      {
        name,
        operation_id: crypto.randomUUID(),
        owner_principal_ids: [...ownerPrincipalIds],
      },
      props.csrfToken,
    );
    volumes.recordCommitted(response);
  };

  const owners = () => [...users.items(), ...groups.items()];
  const ownersLoading = () =>
    users.phase() === "loading" || groups.phase() === "loading";
  const ownersHaveMore = () =>
    users.nextPageUrl() !== null || groups.nextPageUrl() !== null;
  const loadMoreOwners = async (): Promise<void> => {
    await Promise.all([
      users.nextPageUrl() === null ? Promise.resolve() : users.loadNext(),
      groups.nextPageUrl() === null ? Promise.resolve() : groups.loadNext(),
    ]);
  };

  return (
    <div class="volume-administration">
      <VolumeAdministrationHeader />
      <CreateVolumeForm
        create={create}
        owners={owners()}
        ownersLoading={ownersLoading()}
      />
      <VolumeList
        directory={volumes}
        onSelect={setSelectedVolume}
        selectedVolumeId={selectedVolume()?.volumeId}
      />
      <Show when={selectedVolume()}>
        {(volume) => (
          <>
            <SmbExportPanel
              client={props.client}
              csrfToken={props.csrfToken}
              volume={volume()}
            />
            <PermissionGrantPanel
              client={props.client}
              csrfToken={props.csrfToken}
              loadMoreOwners={loadMoreOwners}
              owners={owners()}
              ownersHaveMore={ownersHaveMore()}
              volume={volume()}
            />
          </>
        )}
      </Show>
    </div>
  );
}

function VolumeAdministrationHeader(): JSX.Element {
  return (
    <>
      <header class="page-intro">
        <p class="eyebrow">Administration / Storage</p>
        <h1>Volumes</h1>
        <p>
          Create one logical file space, choose its initial owners, and use it
          from any supported gateway.
        </p>
      </header>
      <AdministrationNavigation current="volumes" />
    </>
  );
}
