// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IdentityAdministrationPanel } from "../src/features/identity-administration/IdentityAdministrationPanel";
import type { IdentityAdministrationClient } from "../src/features/identity-administration/model";
import type {
  CreatePrincipalResponse,
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
  client: IdentityAdministrationClient;
  createUser: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["createUser"]>
  >;
  listNextPrincipals: ReturnType<
    typeof vi.fn<IdentityAdministrationClient["listNextPrincipals"]>
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

  return {
    client: {
      createGroup,
      createUser,
      listGroups,
      listNextPrincipals,
      listUsers,
    },
    createUser,
    listNextPrincipals,
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
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
