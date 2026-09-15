// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";

import { CreatePrincipalForm } from "./CreatePrincipalForm";
import { createGroupMembershipDirectory } from "./group-membership-model";
import { GroupMembershipPanel } from "./GroupMembershipPanel";
import { createPrincipalDirectory } from "./model";
import { InvitationPanel } from "./InvitationPanel";
import type { InvitationStepUpAction } from "./InvitationStepUp";
import { PrincipalList } from "./PrincipalList";
import type {
  IdentityAdministrationClient,
  PrincipalKind,
  PrincipalSummary,
} from "./model";

type IdentityAdministrationPanelProps = Readonly<{
  client: IdentityAdministrationClient;
  csrfToken: string;
  stepUp: InvitationStepUpAction;
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
  const [selectedUser, setSelectedUser] = createSignal<PrincipalSummary>();
  const [invitationLocked, setInvitationLocked] = createSignal(false);
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
    if (kind === "user" && !invitationLocked())
      setSelectedUser(result.principal);
  };

  const selectGroup = (group: PrincipalSummary): void => {
    setSelectedGroupId(group.principal_id);
    void memberships.load(group.principal_id);
  };

  return (
    <div class="identity-administration">
      <IdentityIntroduction />
      <AdministrationNavigation current="identities" />
      <CreatePrincipalForm create={create} />
      <div class="principal-columns">
        <PrincipalList
          directory={users}
          kind="user"
          onSelect={(principal) => {
            if (!invitationLocked()) setSelectedUser(principal);
          }}
          selectionDisabled={invitationLocked()}
          selectedPrincipalId={selectedUser()?.principal_id}
        />
        <PrincipalList
          directory={groups}
          kind="group"
          onSelect={selectGroup}
          selectedPrincipalId={selectedGroupId()}
        />
      </div>
      <Show when={selectedUser()} keyed>
        {(principal) => (
          <InvitationPanel
            client={props.client}
            csrfToken={props.csrfToken}
            principal={principal}
            onLocked={setInvitationLocked}
            stepUp={props.stepUp}
          />
        )}
      </Show>
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

function IdentityIntroduction(): JSX.Element {
  return (
    <header class="page-intro">
      <p class="eyebrow">Administration / Access</p>
      <h1>People and groups</h1>
      <p>
        Identities are swarm-wide. Create them once, then grant access where it
        belongs.
      </p>
    </header>
  );
}
