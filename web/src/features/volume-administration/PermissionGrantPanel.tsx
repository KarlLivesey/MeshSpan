// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createEffect, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { PrincipalSummary } from "../identity-administration/model";
import type { AdminVolume } from "./model";
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
  const [confirming, setConfirming] = createSignal(false);
  const [reason, setReason] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const principal = () =>
    props.owners.find(
      (owner) => owner.principal_id === props.grant.subject_principal_id,
    );

  const revoke = async (): Promise<void> => {
    const auditReason = reason().trim();
    if (auditReason.length === 0 || pending()) {
      setError("Enter a reason for removing access.");
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      const response = await props.client.revokePermissionGrant(
        props.volumeId,
        props.grant.grant_id,
        { operation_id: crypto.randomUUID(), reason: auditReason },
        props.csrfToken,
      );
      props.directory.remove(response);
    } catch {
      setError("MeshSpan could not remove this access grant.");
    } finally {
      setPending(false);
    }
  };

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
      <Show
        when={confirming()}
        fallback={
          <button
            class="quiet-action danger-action"
            onClick={() => setConfirming(true)}
            type="button"
          >
            Remove access
          </button>
        }
      >
        <div class="grant-revocation">
          <label>
            <span>Reason for removing access</span>
            <input
              disabled={pending()}
              maxlength="512"
              onInput={(event) => setReason(event.currentTarget.value)}
              value={reason()}
            />
          </label>
          <div class="membership-removal-actions">
            <button
              class="primary-action danger-button"
              disabled={pending()}
              onClick={() => void revoke()}
              type="button"
            >
              {pending() ? "Removing access…" : "Remove access"}
            </button>
            <button
              class="quiet-button"
              disabled={pending()}
              onClick={() => setConfirming(false)}
              type="button"
            >
              Keep access
            </button>
          </div>
          <Show when={error()}>
            {(message) => <p class="error">{message()}</p>}
          </Show>
        </div>
      </Show>
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
