// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IdentityAdministrationPanel } from "../src/features/identity-administration/IdentityAdministrationPanel";
import type { IdentityAdministrationClient } from "../src/features/identity-administration/model";
import type {
  CreatePrincipalResponse,
  ListGroupMembershipsResponse,
  ListPrincipalsResponse,
} from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const USER_NEXT_PAGE = "/api/latest/admin/users?limit=50&cursor=v1.user";
const mountedRoots = new Set<() => void>();

afterEach(() => {
  for (const dispose of mountedRoots) {
    dispose();
  }
  mountedRoots.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("identity administration panel", () => {
  it("loads both directories and follows a ready-to-use next page", async () => {
    const fixture = clientFixture({
      groups: page("group", [principal("group", "Operators", "group-1")]),
      users: page(
        "user",
        [principal("user", "Alex", "user-1")],
        USER_NEXT_PAGE,
      ),
      userNext: page("user", [principal("user", "Sam", "user-2")]),
    });

    mountPanel(fixture.client);
    await settle();

    expect(document.body.textContent).toContain("Alex");
    expect(document.body.textContent).toContain("Operators");
    clickButton("Load more users");
    await settle();

    expect(fixture.listNextPrincipals).toHaveBeenCalledWith(USER_NEXT_PAGE);
    expect(document.body.textContent).toContain("Sam");
  });

  it("creates one identity and records only the committed result", async () => {
    const created = principal("user", "Taylor", "user-created");
    const fixture = clientFixture({ createdUser: created });

    mountPanel(fixture.client);
    await settle();
    enterDisplayName("  Taylor  ");
    clickButton("Create identity");
    await settle();

    expect(fixture.createUser).toHaveBeenCalledWith(
      expect.objectContaining({ display_name: "Taylor" }),
      CSRF_TOKEN,
    );
    expect(document.body.textContent).toContain(
      "Taylor is ready to receive access.",
    );
    expect(document.body.textContent).toContain("Taylor");
  });

  it("surfaces bounded load and mutation failures without inventing state", async () => {
    const fixture = clientFixture({
      failGroups: true,
      failUserCreation: true,
    });

    mountPanel(fixture.client);
    await settle();
    expect(document.body.textContent).toContain(
      "MeshSpan could not load the current group list.",
    );

    enterDisplayName("Morgan");
    clickButton("Create identity");
    await settle();
    expect(document.body.textContent).toContain(
      "MeshSpan could not create Morgan. Check the name and try again.",
    );
    expect(document.querySelector("tbody")?.textContent ?? "").not.toContain(
      "Morgan",
    );
  });
});

describe("group membership administration panel", () => {
  it("manages direct group membership without leaving the administration page", async () => {
    const alex = principal("user", "Alex", "user-1");
    const operators = principal("group", "Operators", "group-1");
    const fixture = clientFixture({
      groups: page("group", [operators]),
      users: page("user", [alex]),
    });

    mountPanel(fixture.client);
    await settle();
    clickButton("Manage members");
    await settle();

    expect(fixture.listGroupMembers).toHaveBeenCalledWith({
      groupId: operators.principal_id,
    });
    selectOption("Choose an identity", alex.principal_id);
    clickButton("Add to group");
    await settle();
    expect(fixture.addGroupMember).toHaveBeenCalledWith(
      operators.principal_id,
      expect.objectContaining({ member_principal_id: alex.principal_id }),
      CSRF_TOKEN,
    );

    clickButton("Remove membership");
    enterRemovalReason("Moved to another team");
    clickButton("Remove access");
    await settle();
    expect(fixture.removeGroupMember).toHaveBeenCalledWith(
      operators.principal_id,
      alex.principal_id,
      expect.objectContaining({ reason: "Moved to another team" }),
      CSRF_TOKEN,
    );
  });
});

type ClientFixtureOptions = Readonly<{
  createdUser?: Principal;
  failGroups?: boolean;
  failUserCreation?: boolean;
  groups?: ListPrincipalsResponse;
  userNext?: ListPrincipalsResponse;
  users?: ListPrincipalsResponse;
}>;

type Principal = ListPrincipalsResponse["principals"][number];

type ClientFixture = Readonly<{
  addGroupMember: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["addGroupMember"]>
  >;
  client: IdentityAdministrationClient;
  createUser: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["createUser"]>
  >;
  listNextPrincipals: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["listNextPrincipals"]>
  >;
  listGroupMembers: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["listGroupMembers"]>
  >;
  removeGroupMember: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["removeGroupMember"]>
  >;
}>;

function clientFixture(options: ClientFixtureOptions = {}): ClientFixture {
  const users = options.users ?? page("user", []);
  const groups = options.groups ?? page("group", []);
  const createdUser =
    options.createdUser ?? principal("user", "New user", "new-user");

  const createGroup = vi.fn<IdentityAdministrationClient["createGroup"]>(
    async (request) =>
      creation(
        request.operation_id,
        principal("group", request.display_name, "new-group"),
      ),
  );
  const createUser = vi.fn<IdentityAdministrationClient["createUser"]>(
    async (request) => {
      if (options.failUserCreation === true) {
        throw new TypeError("deliberate creation failure");
      }
      return creation(request.operation_id, createdUser);
    },
  );
  const listGroups = vi.fn<IdentityAdministrationClient["listGroups"]>(
    async () => {
      if (options.failGroups === true) {
        throw new TypeError("deliberate group read failure");
      }
      return groups;
    },
  );
  const listNextPrincipals = vi.fn<
    IdentityAdministrationClient["listNextPrincipals"]
  >(async () => options.userNext ?? page("user", []));
  const listUsers = vi.fn<IdentityAdministrationClient["listUsers"]>(
    async () => users,
  );
  const listGroupMembers = vi.fn<
    IdentityAdministrationClient["listGroupMembers"]
  >(async ({ groupId }) => membershipPage(groupId));
  const listNextGroupMembers = vi.fn<
    IdentityAdministrationClient["listNextGroupMembers"]
  >(async () => membershipPage(groups.principals[0]?.principal_id ?? userId()));
  const addGroupMember = vi.fn<IdentityAdministrationClient["addGroupMember"]>(
    async (groupId, request) => ({
      membership: membership(
        groupId,
        [...users.principals, ...groups.principals].find(
          (candidate) => candidate.principal_id === request.member_principal_id,
        ) ?? principal("user", "Unknown", "unknown"),
      ),
      operation_id: request.operation_id,
    }),
  );
  const removeGroupMember = vi.fn<
    IdentityAdministrationClient["removeGroupMember"]
  >(async (groupId, memberPrincipalId, request) => ({
    group_id: groupId,
    member_principal_id: memberPrincipalId,
    operation_id: request.operation_id,
    removed_at_epoch_micros: 80_000_000,
    revision: 2,
  }));

  return {
    addGroupMember,
    client: {
      addGroupMember,
      createGroup,
      createUser,
      listGroups,
      listGroupMembers,
      listNextGroupMembers,
      listNextPrincipals,
      listUsers,
      removeGroupMember,
    },
    createUser,
    listGroupMembers,
    listNextPrincipals,
    removeGroupMember,
  };
}

function creation(
  operationId: string,
  createdPrincipal: Principal,
): CreatePrincipalResponse {
  return { operation_id: operationId, principal: createdPrincipal };
}

function page(
  kind: "group" | "user",
  principals: Principal[],
  nextPageUrl: string | null = null,
): ListPrincipalsResponse {
  return { kind, next_page_url: nextPageUrl, principals };
}

function principal(
  kind: "group" | "user",
  displayName: string,
  principalId: string,
): Principal {
  return {
    created_at_epoch_micros: 70_000_000,
    display_name: displayName,
    kind,
    principal_id: `00000000-0000-4000-8000-${principalId.padEnd(12, "0")}`,
    revision: 1,
    state: "active",
  };
}

function membershipPage(groupId: string): ListGroupMembershipsResponse {
  return { group_id: groupId, memberships: [], next_page_url: null };
}

function membership(
  groupId: string,
  member: Principal,
): ListGroupMembershipsResponse["memberships"][number] {
  return {
    activation_required: false,
    created_at_epoch_micros: 70_000_000,
    created_by: userId(),
    group_id: groupId,
    member,
    revision: 1,
    valid_from_epoch_micros: null,
    valid_until_epoch_micros: null,
  };
}

function userId(): string {
  return "00000000-0000-4000-8000-000000000001";
}

function mountPanel(client: IdentityAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  mountedRoots.add(
    render(
      () => (
        <IdentityAdministrationPanel client={client} csrfToken={CSRF_TOKEN} />
      ),
      root,
    ),
  );
}

function enterDisplayName(value: string): void {
  const input = document.querySelector<HTMLInputElement>("input[name], input");
  if (input === null) {
    throw new TypeError("expected the display-name input");
  }
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function clickButton(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (button === undefined) {
    throw new TypeError(`expected button: ${label}`);
  }
  button.click();
  flush();
}

function selectOption(placeholder: string, value: string): void {
  const select = [...document.querySelectorAll("select")].find((candidate) =>
    candidate.textContent.includes(placeholder),
  );
  if (select === undefined) {
    throw new TypeError(`expected select: ${placeholder}`);
  }
  select.value = value;
  select.dispatchEvent(new Event("change", { bubbles: true }));
  flush();
}

function enterRemovalReason(value: string): void {
  const input = document.querySelector<HTMLInputElement>(
    ".membership-removal input",
  );
  if (input === null) {
    throw new TypeError("expected the membership-removal reason input");
  }
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
