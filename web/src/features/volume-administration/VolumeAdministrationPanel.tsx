// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { createPrincipalDirectory } from "../identity-administration/model";
import { CreateVolumeForm } from "./CreateVolumeForm";
import { createVolumeDirectory } from "./model";
import type { VolumeAdministrationClient } from "./model";
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

  return (
    <div class="volume-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / Storage</p>
        <h1>Volumes</h1>
        <p>
          Create one logical file space, choose its initial owners, and use it
          from any supported gateway.
        </p>
      </header>
      <nav class="administration-nav" aria-label="Administration sections">
        <a href="/admin/identities">People and groups</a>
        <a aria-current="page" href="/admin/volumes">
          Volumes
        </a>
      </nav>
      <CreateVolumeForm
        create={create}
        owners={owners()}
        ownersLoading={ownersLoading()}
      />
      <VolumeList directory={volumes} />
    </div>
  );
}
