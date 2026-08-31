// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor, type Setter } from "solid-js";
import type { ListGroupMembershipsResponse } from "../../generated/types.gen";

export type GroupMembership =
  ListGroupMembershipsResponse["memberships"][number];
export type MembershipPhase =
  "adding" | "idle" | "loading" | "loading_more" | "removing";
export type MembershipToken = Readonly<{
  generation: number;
  groupId: string;
}>;

export type MembershipState = Readonly<{
  applyPage: (
    token: MembershipToken,
    page: ListGroupMembershipsResponse,
    append: boolean,
  ) => boolean;
  beginLoad: (groupId: string) => MembershipToken;
  beginMutation: (phase: "adding" | "removing") => MembershipToken | undefined;
  beginNextPage: () =>
    Readonly<{ nextPageUrl: string; token: MembershipToken }> | undefined;
  error: Accessor<string | undefined>;
  fail: (token: MembershipToken, message: string) => void;
  finish: (token: MembershipToken) => void;
  groupId: Accessor<string | undefined>;
  items: Accessor<readonly GroupMembership[]>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<MembershipPhase>;
  recordAddition: (
    token: MembershipToken,
    membership: GroupMembership,
  ) => boolean;
  recordRemoval: (token: MembershipToken, memberPrincipalId: string) => boolean;
}>;

export function createMembershipState(): MembershipState {
  return new ReactiveMembershipState();
}

class ReactiveMembershipState implements MembershipState {
  private generation = 0;
  private readonly setError: Setter<string | undefined>;
  private readonly setGroupId: Setter<string | undefined>;
  private readonly setItems: Setter<readonly GroupMembership[]>;
  private readonly setNextPageUrl: Setter<string | null>;
  private readonly setPhase: Setter<MembershipPhase>;

  public readonly error: Accessor<string | undefined>;
  public readonly groupId: Accessor<string | undefined>;
  public readonly items: Accessor<readonly GroupMembership[]>;
  public readonly nextPageUrl: Accessor<string | null>;
  public readonly phase: Accessor<MembershipPhase>;

  public constructor() {
    const [error, setError] = createSignal<string | undefined>();
    const [groupId, setGroupId] = createSignal<string | undefined>();
    const [items, setItems] = createSignal<readonly GroupMembership[]>([]);
    const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null);
    const [phase, setPhase] = createSignal<MembershipPhase>("idle");
    this.error = error;
    this.setError = setError;
    this.groupId = groupId;
    this.setGroupId = setGroupId;
    this.items = items;
    this.setItems = setItems;
    this.nextPageUrl = nextPageUrl;
    this.setNextPageUrl = setNextPageUrl;
    this.phase = phase;
    this.setPhase = setPhase;
  }

  public applyPage(
    token: MembershipToken,
    page: ListGroupMembershipsResponse,
    append: boolean,
  ): boolean {
    validatePage(token.groupId, page);
    if (!this.isCurrent(token)) {
      return false;
    }
    this.setItems((existing) =>
      mergeMemberships(append ? existing : [], page.memberships),
    );
    this.setNextPageUrl(page.next_page_url);
    return true;
  }

  public beginLoad(selectedGroupId: string): MembershipToken {
    this.generation += 1;
    this.setGroupId(selectedGroupId);
    this.setItems([]);
    this.setNextPageUrl(null);
    this.setError(undefined);
    this.setPhase("loading");
    return { generation: this.generation, groupId: selectedGroupId };
  }

  public beginMutation(
    nextPhase: "adding" | "removing",
  ): MembershipToken | undefined {
    const selectedGroupId = this.groupId();
    if (selectedGroupId === undefined || this.phase() !== "idle") {
      return undefined;
    }
    this.setError(undefined);
    this.setPhase(nextPhase);
    return { generation: this.generation, groupId: selectedGroupId };
  }

  public beginNextPage():
    Readonly<{ nextPageUrl: string; token: MembershipToken }> | undefined {
    const selectedGroupId = this.groupId();
    const next = this.nextPageUrl();
    if (
      selectedGroupId === undefined ||
      next === null ||
      this.phase() !== "idle"
    ) {
      return undefined;
    }
    this.setError(undefined);
    this.setPhase("loading_more");
    return {
      nextPageUrl: next,
      token: { generation: this.generation, groupId: selectedGroupId },
    };
  }

  public fail(token: MembershipToken, message: string): void {
    if (this.isCurrent(token)) {
      this.setError(message);
    }
  }

  public finish(token: MembershipToken): void {
    if (this.isCurrent(token)) {
      this.setPhase("idle");
    }
  }

  public recordAddition(
    token: MembershipToken,
    membership: GroupMembership,
  ): boolean {
    if (!this.isCurrent(token)) {
      return false;
    }
    this.setItems((existing) => mergeMemberships(existing, [membership]));
    return true;
  }

  public recordRemoval(
    token: MembershipToken,
    memberPrincipalId: string,
  ): boolean {
    if (!this.isCurrent(token)) {
      return false;
    }
    this.setItems((existing) =>
      existing.filter(
        ({ member }) => member.principal_id !== memberPrincipalId,
      ),
    );
    return true;
  }

  private isCurrent(token: MembershipToken): boolean {
    return (
      token.generation === this.generation && token.groupId === this.groupId()
    );
  }
}

function validatePage(
  expectedGroupId: string,
  page: ListGroupMembershipsResponse,
): void {
  if (
    page.group_id !== expectedGroupId ||
    page.memberships.some(
      (membership) => membership.group_id !== expectedGroupId,
    )
  ) {
    throw new TypeError("membership page returned a substituted group");
  }
}

function mergeMemberships(
  first: readonly GroupMembership[],
  second: readonly GroupMembership[],
): readonly GroupMembership[] {
  const byPrincipal = new Map<string, GroupMembership>();
  for (const membership of [...first, ...second]) {
    byPrincipal.set(membership.member.principal_id, membership);
  }
  return [...byPrincipal.values()].sort((left, right) =>
    left.member.display_name.localeCompare(right.member.display_name),
  );
}
