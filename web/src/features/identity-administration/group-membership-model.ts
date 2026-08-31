// SPDX-License-Identifier: GPL-2.0-only

import type { Accessor } from "solid-js";

import {
  addMembership,
  loadMembershipPage,
  loadNextMembershipPage,
  removeMembership,
} from "./group-membership-actions";
import {
  createMembershipState,
  type GroupMembership,
} from "./group-membership-state";
import type { IdentityAdministrationClient } from "./model";

export type { GroupMembership } from "./group-membership-state";

type MembershipPhase =
  "adding" | "idle" | "loading" | "loading_more" | "removing";

export type GroupMembershipDirectory = Readonly<{
  add: (memberPrincipalId: string) => Promise<boolean>;
  error: Accessor<string | undefined>;
  groupId: Accessor<string | undefined>;
  items: Accessor<readonly GroupMembership[]>;
  load: (groupId: string) => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<MembershipPhase>;
  remove: (memberPrincipalId: string, reason: string) => Promise<boolean>;
}>;

export function createGroupMembershipDirectory(
  client: Accessor<IdentityAdministrationClient>,
  csrfToken: Accessor<string>,
): GroupMembershipDirectory {
  const state = createMembershipState();
  return {
    add: async (memberId) =>
      addMembership(state, client(), csrfToken(), memberId),
    error: state.error,
    groupId: state.groupId,
    items: state.items,
    load: async (groupId) => loadMembershipPage(state, client(), groupId),
    loadNext: async () => loadNextMembershipPage(state, client()),
    nextPageUrl: state.nextPageUrl,
    phase: state.phase,
    remove: async (memberId, reason) =>
      removeMembership(state, client(), csrfToken(), memberId, reason),
  };
}
