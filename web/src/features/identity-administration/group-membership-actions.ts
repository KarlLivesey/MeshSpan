// SPDX-License-Identifier: GPL-2.0-only

import type { IdentityAdministrationClient } from "./model";
import type {
  MembershipState,
  MembershipToken,
} from "./group-membership-state";

export async function loadMembershipPage(
  state: MembershipState,
  client: IdentityAdministrationClient,
  groupId: string,
): Promise<void> {
  const token = state.beginLoad(groupId);
  try {
    state.applyPage(token, await client.listGroupMembers({ groupId }), false);
  } catch {
    state.fail(token, "MeshSpan could not load this group's direct members.");
  } finally {
    state.finish(token);
  }
}

export async function loadNextMembershipPage(
  state: MembershipState,
  client: IdentityAdministrationClient,
): Promise<void> {
  const request = state.beginNextPage();
  if (request === undefined) {
    return;
  }
  try {
    state.applyPage(
      request.token,
      await client.listNextGroupMembers(request.nextPageUrl),
      true,
    );
  } catch {
    state.fail(request.token, "MeshSpan could not load more direct members.");
  } finally {
    state.finish(request.token);
  }
}

export async function addMembership(
  state: MembershipState,
  client: IdentityAdministrationClient,
  csrfToken: string,
  memberPrincipalId: string,
): Promise<boolean> {
  const token = state.beginMutation("adding");
  if (token === undefined) {
    return false;
  }
  try {
    const result = await client.addGroupMember(
      token.groupId,
      {
        activation_required: false,
        member_principal_id: memberPrincipalId,
        operation_id: crypto.randomUUID(),
      },
      csrfToken,
    );
    validateAddition(token, memberPrincipalId, result.membership);
    return state.recordAddition(token, result.membership);
  } catch {
    state.fail(token, "MeshSpan could not add that direct member.");
    return false;
  } finally {
    state.finish(token);
  }
}

export async function removeMembership(
  state: MembershipState,
  client: IdentityAdministrationClient,
  csrfToken: string,
  memberPrincipalId: string,
  reason: string,
): Promise<boolean> {
  const auditReason = reason.trim();
  const token = validRemovalReason(auditReason)
    ? state.beginMutation("removing")
    : undefined;
  if (token === undefined) {
    return false;
  }
  try {
    const result = await client.removeGroupMember(
      token.groupId,
      memberPrincipalId,
      { operation_id: crypto.randomUUID(), reason: auditReason },
      csrfToken,
    );
    if (
      result.group_id !== token.groupId ||
      result.member_principal_id !== memberPrincipalId
    ) {
      throw new TypeError("membership removal returned substituted identity");
    }
    return state.recordRemoval(token, memberPrincipalId);
  } catch {
    state.fail(token, "MeshSpan could not remove that direct member.");
    return false;
  } finally {
    state.finish(token);
  }
}

function validateAddition(
  token: MembershipToken,
  memberPrincipalId: string,
  membership: Parameters<MembershipState["recordAddition"]>[1],
): void {
  if (
    membership.group_id !== token.groupId ||
    membership.member.principal_id !== memberPrincipalId
  ) {
    throw new TypeError("membership addition returned substituted identity");
  }
}

function validRemovalReason(value: string): boolean {
  return value.length > 0 && value.length <= 512;
}
