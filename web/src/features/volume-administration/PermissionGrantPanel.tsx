// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createEffect } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { PrincipalSummary } from "../identity-administration/model";
import type { AdminVolume } from "./model";
import { GrantRevocation } from "./GrantRevocation";
import { PermissionGrantForm } from "./PermissionGrantForm";
import { createPermissionGrantDirectory } from "./permission-grant-model";
import type {
  PermissionGrantClient,
  VolumePermissionGrant,
} from "./permission-grant-model";

type PermissionGrantPanelProps = Readonly<{
  client: PermissionGrantClient;
  csrfToken: string;
  loadMoreOwners: () => Promise<void>;
  owners: readonly PrincipalSummary[];
  ownersHaveMore: boolean;
  volume: AdminVolume;
}>;

export function PermissionGrantPanel(
  props: PermissionGrantPanelProps,
): JSX.Element {
  const directory = createPermissionGrantDirectory(() => props.client);

  createEffect(
    () => props.volume.volumeId,
    (volumeId) => void directory.load(volumeId),
  );

  return (
    <section class="permission-administration" aria-labelledby="grant-heading">
      <div class="membership-heading">
        <div>
          <p class="eyebrow">Volume access</p>
          <h2 id="grant-heading">Share {props.volume.name}</h2>
        </div>
        <p>
          Grant view, edit or management access. Optional dates and activation
          requirements are enforced by every gateway.
        </p>
      </div>
      <PermissionGrantForm
        client={props.client}
        csrfToken={props.csrfToken}
        loadMoreOwners={props.loadMoreOwners}
        onCommitted={directory.record}
        owners={props.owners}
        ownersHaveMore={props.ownersHaveMore}
        volumeId={props.volume.volumeId}
      />
      <GrantList
        client={props.client}
        csrfToken={props.csrfToken}
        directory={directory}
        owners={props.owners}
        volumeId={props.volume.volumeId}
      />
    </section>
  );
}

type GrantListProps = Readonly<{
  client: PermissionGrantClient;
  csrfToken: string;
  directory: ReturnType<typeof createPermissionGrantDirectory>;
  owners: readonly PrincipalSummary[];
  volumeId: string;
}>;

function GrantList(props: GrantListProps): JSX.Element {
  return (
    <div class="permission-grant-list">
      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading committed access…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={<p class="empty-state">No additional access grants yet.</p>}
        >
          <For each={props.directory.items()}>
            {(grant) => <GrantCard {...props} grant={grant} />}
          </For>
        </Show>
      </Show>
      <div class="list-footer" aria-live="polite">
        <Show when={props.directory.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={props.directory.nextPageUrl() !== null}>
          <button
            class="quiet-action"
            disabled={props.directory.phase() !== "idle"}
            onClick={() => void props.directory.loadNext()}
            type="button"
          >
            {props.directory.phase() === "loading_more"
              ? "Loading more access…"
              : "Load more access"}
          </button>
        </Show>
      </div>
    </div>
  );
}

type GrantCardProps = GrantListProps &
  Readonly<{ grant: VolumePermissionGrant }>;

function GrantCard(props: GrantCardProps): JSX.Element {
  const principal = () =>
    props.owners.find(
      (owner) => owner.principal_id === props.grant.subject_principal_id,
    );

  return (
    <article class="permission-grant-card">
      <div>
        <h3>{principal()?.display_name ?? "Unknown principal"}</h3>
        <p>
          {accessLevel(props.grant)} · {activationLabel(props.grant)}
        </p>
      </div>
      <dl>
        <div>
          <dt>Valid from</dt>
          <dd>{formatOptionalInstant(props.grant.valid_from_epoch_micros)}</dd>
        </div>
        <div>
          <dt>Valid until</dt>
          <dd>{formatOptionalInstant(props.grant.valid_until_epoch_micros)}</dd>
        </div>
      </dl>
      <GrantRevocation
        client={props.client}
        csrfToken={props.csrfToken}
        grant={props.grant}
        remove={props.directory.remove}
        volumeId={props.volumeId}
      />
    </article>
  );
}

function accessLevel(grant: VolumePermissionGrant): string {
  if (grant.rights.includes("change_permissions")) {
    return "Manage";
  }
  if (grant.rights.includes("write_data")) {
    return "Edit";
  }
  return "View";
}

function activationLabel(grant: VolumePermissionGrant): string {
  return grant.activation_policy_id === null
    ? "always available"
    : "activation required";
}

function formatOptionalInstant(epochMicros: number | null): string {
  if (epochMicros === null) {
    return "No limit";
  }
  return instantFromEpochMicroseconds(epochMicros).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
