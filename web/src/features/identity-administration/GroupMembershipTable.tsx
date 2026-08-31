// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type {
  GroupMembership,
  GroupMembershipDirectory,
} from "./group-membership-model";

type GroupMembershipTableProps = Readonly<{
  directory: GroupMembershipDirectory;
}>;

export function GroupMembershipTable(
  props: GroupMembershipTableProps,
): JSX.Element {
  return (
    <>
      <div class="principal-table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Member</th>
              <th scope="col">Type</th>
              <th scope="col">Availability</th>
              <th scope="col">Membership</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.directory.items()}>
              {(membership) => (
                <MembershipRow
                  directory={props.directory}
                  membership={membership}
                />
              )}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={props.directory.nextPageUrl() !== null}>
        <button
          class="quiet-action"
          disabled={props.directory.phase() !== "idle"}
          onClick={() => void props.directory.loadNext()}
          type="button"
        >
          {props.directory.phase() === "loading_more"
            ? "Loading more members…"
            : "Load more members"}
        </button>
      </Show>
    </>
  );
}

type MembershipRowProps = Readonly<{
  directory: GroupMembershipDirectory;
  membership: GroupMembership;
}>;

function MembershipRow(props: MembershipRowProps): JSX.Element {
  const [editing, setEditing] = createSignal(false);
  const isIdle = () => props.directory.phase() === "idle";

  return (
    <>
      <tr>
        <th data-label="Member" scope="row">
          {props.membership.member.display_name}
        </th>
        <td data-label="Type">{props.membership.member.kind}</td>
        <td data-label="Availability" class="timestamp">
          {formatAvailability(props.membership)}
        </td>
        <td data-label="Membership">
          <button
            class="quiet-action table-action danger-action"
            disabled={!isIdle()}
            onClick={() => setEditing(true)}
            type="button"
          >
            Remove membership
          </button>
        </td>
      </tr>
      <Show when={editing()}>
        <tr class="membership-removal-row">
          <td colspan="4">
            <MembershipRemovalForm
              directory={props.directory}
              memberPrincipalId={props.membership.member.principal_id}
              onCancel={() => setEditing(false)}
            />
          </td>
        </tr>
      </Show>
    </>
  );
}

type MembershipRemovalFormProps = Readonly<{
  directory: GroupMembershipDirectory;
  memberPrincipalId: string;
  onCancel: () => void;
}>;

function MembershipRemovalForm(props: MembershipRemovalFormProps): JSX.Element {
  const [reason, setReason] = createSignal("");
  const [error, setError] = createSignal<string>();
  const isIdle = () => props.directory.phase() === "idle";
  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    const auditReason = reason().trim();
    if (auditReason.length === 0) {
      setError("Enter a reason for removing this membership.");
      return;
    }
    setError(undefined);
    await props.directory.remove(props.memberPrincipalId, auditReason);
  };

  return (
    <form class="membership-removal" onSubmit={(event) => void submit(event)}>
      <label>
        <span>Reason for removing access</span>
        <input
          autocomplete="off"
          maxlength="512"
          onInput={(event) => setReason(event.currentTarget.value)}
          value={reason()}
        />
      </label>
      <div class="membership-removal-actions">
        <button
          class="primary-action danger-button"
          disabled={!isIdle()}
          type="submit"
        >
          {props.directory.phase() === "removing"
            ? "Removing access…"
            : "Remove access"}
        </button>
        <button
          class="quiet-action"
          disabled={!isIdle()}
          onClick={() => {
            props.onCancel();
          }}
          type="button"
        >
          Keep membership
        </button>
      </div>
      <Show when={error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
    </form>
  );
}

function formatAvailability(membership: GroupMembership): string {
  const start = membership.valid_from_epoch_micros;
  const end = membership.valid_until_epoch_micros;
  if (start === null && end === null) {
    return "Always";
  }
  if (start === null) {
    return `Until ${formatInstant(end)}`;
  }
  if (end === null) {
    return `From ${formatInstant(start)}`;
  }
  return `${formatInstant(start)} – ${formatInstant(end)}`;
}

function formatInstant(value: number | null): string {
  if (value === null) {
    throw new TypeError("expected an exact membership instant");
  }
  return instantFromEpochMicroseconds(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
