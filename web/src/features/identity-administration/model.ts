// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";
import type {
  AddGroupMemberRequest,
  AddGroupMemberResponse,
  CreateGroupRequest,
  CreatePrincipalResponse,
  CreateUserRequest,
  ListGroupMembershipsResponse,
  ListPrincipalsResponse,
  RemoveGroupMemberRequest,
  RemoveGroupMemberResponse,
} from "../../generated/types.gen";

export type PrincipalSummary = ListPrincipalsResponse["principals"][number];

export type PrincipalKind = "group" | "user";

export interface IdentityAdministrationClient {
  addGroupMember(
    groupId: string,
    request: AddGroupMemberRequest,
    csrfToken?: string,
  ): Promise<AddGroupMemberResponse>;
  createGroup(
    request: CreateGroupRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  createUser(
    request: CreateUserRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  listGroups(): Promise<ListPrincipalsResponse>;
  listGroupMembers(
    request: Readonly<{ groupId: string }>,
  ): Promise<ListGroupMembershipsResponse>;
  listNextGroupMembers(
    nextPageUrl: string,
  ): Promise<ListGroupMembershipsResponse>;
  listNextPrincipals(nextPageUrl: string): Promise<ListPrincipalsResponse>;
  listUsers(): Promise<ListPrincipalsResponse>;
  removeGroupMember(
    groupId: string,
    memberPrincipalId: string,
    request: RemoveGroupMemberRequest,
    csrfToken?: string,
  ): Promise<RemoveGroupMemberResponse>;
}

export type PrincipalDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly PrincipalSummary[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "loading_more">;
  record: (principal: PrincipalSummary) => void;
}>;

export function createPrincipalDirectory(
  client: Accessor<IdentityAdministrationClient>,
  kind: PrincipalKind,
): PrincipalDirectory {
  const [items, setItems] = createSignal<readonly PrincipalSummary[]>([], {
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<"idle" | "loading" | "loading_more">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const applyPage = (page: ListPrincipalsResponse, append: boolean): void => {
    if (page.kind !== kind) {
      throw new TypeError("principal page returned the wrong identity kind");
    }
    setItems((current) =>
      mergePrincipals(append ? current : [], page.principals),
    );
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError(undefined);
    try {
      const page =
        kind === "user"
          ? await client().listUsers()
          : await client().listGroups();
      applyPage(page, false);
    } catch {
      setError(`MeshSpan could not load the current ${kind} list.`);
    } finally {
      setPhase("idle");
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") {
      return;
    }
    setPhase("loading_more");
    setError(undefined);
    try {
      applyPage(await client().listNextPrincipals(next), true);
    } catch {
      setError(`MeshSpan could not load more ${kind}s.`);
    } finally {
      setPhase("idle");
    }
  };

  const record = (principal: PrincipalSummary): void => {
    if (principal.kind !== kind) {
      throw new TypeError("created principal has the wrong identity kind");
    }
    setItems((current) => mergePrincipals([principal], current));
  };

  return { error, items, loadInitial, loadNext, nextPageUrl, phase, record };
}

function mergePrincipals(
  first: readonly PrincipalSummary[],
  second: readonly PrincipalSummary[],
): readonly PrincipalSummary[] {
  const seen = new Set<string>();
  return [...first, ...second].filter((principal) => {
    if (seen.has(principal.principal_id)) {
      return false;
    }
    seen.add(principal.principal_id);
    return true;
  });
}
