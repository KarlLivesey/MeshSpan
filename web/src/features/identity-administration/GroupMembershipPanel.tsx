// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { GroupMembershipAddForm } from "./GroupMembershipAddForm";
import type { GroupMembershipDirectory } from "./group-membership-model";
import { GroupMembershipTable } from "./GroupMembershipTable";
import type { PrincipalSummary } from "./model";

type GroupMembershipPanelProps = Readonly<{
  candidates: readonly PrincipalSummary[];
  directory: GroupMembershipDirectory;
  group: PrincipalSummary;
}>;

export function GroupMembershipPanel(
  props: GroupMembershipPanelProps,
): JSX.Element {
  return (
    <section
      class="membership-administration"
      aria-labelledby="membership-heading"
    >
      <div class="membership-heading">
        <div>
          <p class="eyebrow">Direct membership</p>
          <h2 id="membership-heading">{props.group.display_name}</h2>
        </div>
        <p>
          Add people or nested groups. Their access follows this group wherever
          it is granted.
        </p>
      </div>

      <GroupMembershipAddForm
        candidates={props.candidates}
        directory={props.directory}
        group={props.group}
      />

      <Show when={props.directory.error()}>
        {(message) => (
          <p class="error membership-service-error" aria-live="polite">
            {message()}
          </p>
        )}
      </Show>

      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading direct membership…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={
            <p class="empty-state">
              This group has no direct members yet. Add one above.
            </p>
          }
        >
          <GroupMembershipTable directory={props.directory} />
        </Show>
      </Show>
    </section>
  );
}
