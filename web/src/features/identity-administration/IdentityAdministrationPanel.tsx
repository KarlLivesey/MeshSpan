// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";

import { CreatePrincipalForm } from "./CreatePrincipalForm";
import { createPrincipalDirectory } from "./model";
import { PrincipalList } from "./PrincipalList";
import type { IdentityAdministrationClient, PrincipalKind } from "./model";

type IdentityAdministrationPanelProps = Readonly<{
  client: IdentityAdministrationClient;
  csrfToken: string;
}>;

export function IdentityAdministrationPanel(
  props: IdentityAdministrationPanelProps,
): JSX.Element {
  const users = createPrincipalDirectory(() => props.client, "user");
  const groups = createPrincipalDirectory(() => props.client, "group");

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
      <CreatePrincipalForm create={create} />
      <div class="principal-columns">
        <PrincipalList directory={users} kind="user" />
        <PrincipalList directory={groups} kind="group" />
      </div>
    </div>
  );
}
