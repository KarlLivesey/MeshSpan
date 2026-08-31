// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
const OPERATION_ID = "00000000-0000-4000-8000-000000000051";
const PRINCIPAL_ID = "00000000-0000-4000-8000-000000000052";
const GROUP_ID = "00000000-0000-4000-8000-000000000053";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;

describe("generated identity-administration pagination", () => {
  it("uses bounded filters and follows the exact next-page URL", async () => {
    const requestedUrls: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        const url = requestUrl(input);
        requestedUrls.push(url);
        const lastPage = url.includes("cursor=");
        return Promise.resolve(
          response({
            kind: "user",
            next_page_url: lastPage
              ? null
              : "/api/latest/admin/users?limit=1&cursor=v1.u.cursor",
            principals: [principal("Alex")],
          }),
        );
      },
    });

    const first = await client.listUsers({ limit: 1 });
    const next = first.next_page_url;
    if (next === null) {
      throw new TypeError("expected a continuation URL");
    }
    await expect(client.listNextPrincipals(next)).resolves.toMatchObject({
      next_page_url: null,
    });
    expect(requestedUrls).toEqual([
      "https://node.example/api/latest/admin/users?limit=1",
      "https://node.example/api/latest/admin/users?limit=1&cursor=v1.u.cursor",
    ]);
  });

  it("rejects substituted, repeated and malformed page URLs before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(response({}));
      },
    });

    for (const url of [
      "https://attacker.example/api/latest/admin/users?limit=1",
      "/api/latest/health?limit=1",
      "/api/latest/admin/users?limit=1&limit=2",
      "/api/latest/admin/users?limit=0",
    ]) {
      await expect(client.listNextPrincipals(url)).rejects.toThrow();
    }
    expect(calls).toBe(0);
  });
});

describe("generated identity-administration creation", () => {
  it("creates a user with browser CSRF and validates the committed result", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(requestUrl(input)).toBe(
          "https://node.example/api/latest/admin/users",
        );
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("MeshSpan-CSRF-Token")).toBe(
          CSRF_TOKEN,
        );
        expect(JSON.parse(stringBody(init?.body))).toEqual({
          display_name: "Alex",
          operation_id: OPERATION_ID,
        });
        return Promise.resolve(
          response(
            {
              operation_id: OPERATION_ID,
              principal: principal("Alex"),
            },
            201,
          ),
        );
      },
    });

    await expect(
      client.createUser(
        { display_name: "Alex", operation_id: OPERATION_ID },
        CSRF_TOKEN,
      ),
    ).resolves.toMatchObject({
      operation_id: OPERATION_ID,
      principal: { display_name: "Alex" },
    });
  });

  it("rejects invalid creation input before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(response({}));
      },
    });

    await expect(
      client.createGroup(
        { display_name: "bad/name", operation_id: OPERATION_ID },
        CSRF_TOKEN,
      ),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  });
});

describe("generated group-membership administration", () => {
  it("validates paths, mutations and ready-to-follow membership pages", async () => {
    const seen: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: membershipFetch(seen),
    });

    const page = await client.listGroupMembers({ groupId: GROUP_ID, limit: 1 });
    if (page.next_page_url === null) {
      throw new TypeError("expected a group-membership continuation");
    }
    await client.listNextGroupMembers(page.next_page_url);
    await client.addGroupMember(
      GROUP_ID,
      {
        activation_required: false,
        member_principal_id: PRINCIPAL_ID,
        operation_id: OPERATION_ID,
      },
      CSRF_TOKEN,
    );
    await client.removeGroupMember(
      GROUP_ID,
      PRINCIPAL_ID,
      { operation_id: OPERATION_ID, reason: "Role changed" },
      CSRF_TOKEN,
    );

    expect(seen).toEqual([
      `GET https://node.example/api/latest/admin/groups/${GROUP_ID}/members?limit=1`,
      `GET https://node.example/api/latest/admin/groups/${GROUP_ID}/members?limit=1&cursor=v1.gm.next`,
      `POST https://node.example/api/latest/admin/groups/${GROUP_ID}/members`,
      `POST https://node.example/api/latest/admin/groups/${GROUP_ID}/members/${PRINCIPAL_ID}/removals`,
    ]);
  });

  it("rejects substituted membership continuations before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(response({}));
      },
    });

    for (const url of [
      `https://attacker.example/api/latest/admin/groups/${GROUP_ID}/members?limit=1`,
      `/api/latest/admin/groups/not-a-uuid/members?limit=1`,
      `/api/latest/admin/groups/${GROUP_ID}/members?limit=1&limit=2`,
    ]) {
      await expect(client.listNextGroupMembers(url)).rejects.toThrow();
    }
    expect(calls).toBe(0);
  });
});

function principal(displayName: string) {
  return {
    created_at_epoch_micros: 70_000_000,
    display_name: displayName,
    kind: "user",
    principal_id: PRINCIPAL_ID,
    revision: 51,
    state: "active",
  } as const;
}

function membership() {
  return {
    activation_required: false,
    created_at_epoch_micros: 70_000_000,
    created_by: PRINCIPAL_ID,
    group_id: GROUP_ID,
    member: principal("Alex"),
    revision: 53,
    valid_from_epoch_micros: null,
    valid_until_epoch_micros: null,
  } as const;
}

function membershipFetch(seen: string[]): typeof globalThis.fetch {
  return async (input, init) => {
    const url = requestUrl(input);
    seen.push(`${init?.method ?? "GET"} ${url}`);
    if (url.endsWith("/removals")) {
      return Promise.resolve(
        response({
          group_id: GROUP_ID,
          member_principal_id: PRINCIPAL_ID,
          operation_id: OPERATION_ID,
          removed_at_epoch_micros: 80_000_000,
          revision: 54,
        }),
      );
    }
    if (init?.method === "POST") {
      return Promise.resolve(
        response(
          { membership: membership(), operation_id: OPERATION_ID },
          201,
        ),
      );
    }
    return Promise.resolve(
      response({
        group_id: GROUP_ID,
        memberships: [membership()],
        next_page_url: url.includes("cursor=")
          ? null
          : `/api/latest/admin/groups/${GROUP_ID}/members?limit=1&cursor=v1.gm.next`,
      }),
    );
  };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) {
    return input.href;
  }
  if (input instanceof Request) {
    return input.url;
  }
  return input;
}

function stringBody(body: BodyInit | null | undefined): string {
  if (typeof body !== "string") {
    throw new TypeError("expected a string request body");
  }
  return body;
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: RESPONSE_HEADERS,
    status,
  });
}
