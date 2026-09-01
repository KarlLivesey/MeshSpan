// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { CreatePrincipalForm } from "./CreatePrincipalForm";
import { createGroupMembershipDirectory } from "./group-membership-model";
import { GroupMembershipPanel } from "./GroupMembershipPanel";
import { createPrincipalDirectory } from "./model";
import { PrincipalList } from "./PrincipalList";
import type {
  IdentityAdministrationClient,
  PrincipalKind,
  PrincipalSummary,
} from "./model";

type IdentityAdministrationPanelProps = Readonly<{
  client: IdentityAdministrationClient;
  csrfToken: string;
}>;

export function IdentityAdministrationPanel(
  props: IdentityAdministrationPanelProps,
): JSX.Element {
  const users = createPrincipalDirectory(() => props.client, "user");
  const groups = createPrincipalDirectory(() => props.client, "group");
  const memberships = createGroupMembershipDirectory(
    () => props.client,
    () => props.csrfToken,
  );
  const [selectedGroupId, setSelectedGroupId] = createSignal<string>();
  const selectedGroup = () =>
    groups.items().find((group) => group.principal_id === selectedGroupId());

  void Promise.all([users.loadInitial(), groups.loadInitial()]);

  const create = async (
    kind: PrincipalKind,
    displayName: string,
  ): Promise<void> => {
    const request = {
      display_name: displayName,
      operation_id: crypto.randomUUID(),
    };
    const result =
      kind === "user"
        ? await props.client.createUser(request, props.csrfToken)
        : await props.client.createGroup(request, props.csrfToken);
    (kind === "user" ? users : groups).record(result.principal);
  };

  const selectGroup = (group: PrincipalSummary): void => {
    setSelectedGroupId(group.principal_id);
    void memberships.load(group.principal_id);
  };

  return (
    <div class="identity-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / Access</p>
        <h1>People and groups</h1>
        <p>
          Identities are swarm-wide. Create them once, then grant access where
          it belongs.
        </p>
      </header>
      <nav class="administration-nav" aria-label="Administration sections">
        <a aria-current="page" href="/admin/identities">
          People and groups
        </a>
        <a href="/admin/volumes">Volumes</a>
        <a href="/admin/operations">Operations</a>
      </nav>
      <CreatePrincipalForm create={create} />
      <div class="principal-columns">
        <PrincipalList directory={users} kind="user" />
        <PrincipalList
          directory={groups}
          kind="group"
          onSelect={selectGroup}
          selectedPrincipalId={selectedGroupId()}
        />
      </div>
      <Show when={selectedGroup()}>
        {(group) => (
          <GroupMembershipPanel
            candidates={[...users.items(), ...groups.items()]}
            directory={memberships}
            group={group()}
          />
        )}
      </Show>
    </div>
  );
}
