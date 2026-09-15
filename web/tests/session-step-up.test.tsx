// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import type { JSX } from "@solidjs/web";
import { afterEach, expect, it, vi } from "vitest";
import { SessionProvider, useSession } from "../src/app/session";
import type { MeshSpanFetchClient } from "../src/generated/fetch.gen";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const OPERATION = "00000000-0000-4000-8000-000000000010";
const SESSION = "00000000-0000-4000-8000-000000000020";
const ROTATED = "00000000-0000-4000-8000-000000000030";
const TOKEN = `meshspan-csrf-v1.${"1".repeat(32)}.${"2".repeat(64)}`;
const NEXT_TOKEN = `meshspan-csrf-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const STORAGE_KEY = "meshspan.session.csrf.v1";
let dispose: (() => void) | undefined;
afterEach(() => {
  dispose?.();
  dispose = undefined;
  document.body.replaceChildren();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it("retries the exact step-up and adopts rotated CSRF without changing remembered storage", async () => {
  vi.spyOn(crypto, "randomUUID").mockReturnValue(OPERATION);
  vi.stubGlobal("localStorage", memoryStorage());
  vi.stubGlobal("sessionStorage", memoryStorage());
  window.localStorage.setItem(STORAGE_KEY, TOKEN);
  const { client, requests, sentTokens } = stepUpFixture();
  const observed: { session?: ReturnType<typeof useSession> } = {};
  function Probe(): JSX.Element {
    observed.session = useSession();
    return <p>Session fixture</p>;
  }
  dispose = render(
    () => (
      <SessionProvider client={client}>
        <Probe />
      </SessionProvider>
    ),
    document.body,
  );
  await vi.waitFor(() => {
    flush();
    expect(observed.session?.state().phase).toBe("authenticated");
  });
  const session = observed.session;
  if (session === undefined) throw new Error("missing session provider");
  expect(session).toHaveProperty("stepUp");
  await expect(
    session.stepUp({ method: "totp", code: "123456" }),
  ).rejects.toThrow();
  expect(session.csrfToken()).toBe(TOKEN);
  await expect(
    session.stepUp({ method: "totp", code: "654321" }),
  ).resolves.toBeUndefined();
  expect(requests).toHaveLength(2);
  expect(sentTokens).toEqual([TOKEN, TOKEN]);
  expect(requests[1]).toBe(requests[0]);
  expect(JSON.parse(requests[0] ?? "null")).toEqual({
    operation_id: OPERATION,
    additional_factor: { method: "totp", code: "123456" },
  });
  expect(session.csrfToken()).toBe(NEXT_TOKEN);
  expect(window.localStorage.getItem(STORAGE_KEY)).toBe(NEXT_TOKEN);
  expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
});

it.each(["response", "failure"])(
  "ignores a stale session refresh %s after a new sign-in",
  async (outcome) => {
    vi.spyOn(crypto, "randomUUID").mockReturnValue(OPERATION);
    vi.stubGlobal("localStorage", memoryStorage());
    vi.stubGlobal("sessionStorage", memoryStorage());
    window.sessionStorage.setItem(STORAGE_KEY, TOKEN);
    const fixture = sessionRaceFixture();
    const session = await mountSession(fixture.client);
    const refresh = session.refresh();
    await fixture.refreshStarted.promise;
    await session.signInWithApiKey(
      `meshspan-key-v1.${"a".repeat(32)}.${"b".repeat(64)}`,
      false,
    );
    if (outcome === "failure")
      fixture.staleRefresh.reject(new TypeError("late read failure"));
    else fixture.staleRefresh.resolve(response(currentSession(ROTATED)));
    await refresh;
    const state = session.state();
    expect(state.phase).toBe("authenticated");
    if (state.phase !== "authenticated")
      throw new Error("Expected current signed-in session");
    expect(state.session.principal_id).toBe(BOB);
    expect(state.session.session_id).toBe(BOB_SESSION);
    expect(session.csrfToken()).toBe(BOB_TOKEN);
  },
);

it("rejects an old step-up receipt after observing an external session replacement", async () => {
  vi.spyOn(crypto, "randomUUID").mockReturnValue(OPERATION);
  vi.stubGlobal("localStorage", memoryStorage());
  vi.stubGlobal("sessionStorage", memoryStorage());
  window.sessionStorage.setItem(STORAGE_KEY, TOKEN);
  const fixture = sessionRaceFixture(true);
  const session = await mountSession(fixture.client);
  const confirmation = session.stepUp({ method: "totp", code: "123456" });
  await fixture.stepUpStarted.promise;
  fixture.useBobSession();
  await session.refresh();
  fixture.delayedStepUp.resolve(
    response(
      {
        operation_id: OPERATION,
        session_id: ROTATED,
        assurance: "recent_step_up",
        expires_at_epoch_micros: 1000,
      },
      NEXT_TOKEN,
    ),
  );
  await expect(confirmation).rejects.toThrow("replaced");
  const state = session.state();
  expect(state.phase).toBe("authenticated");
  if (state.phase !== "authenticated") throw new Error("Expected Bob session");
  expect(state.session.principal_id).toBe(BOB);
  expect(session.csrfToken()).toBe(TOKEN);
  expect(window.sessionStorage.getItem(STORAGE_KEY)).toBe(TOKEN);
});

it("does not send a competing sign-in while a cookie-rotating step-up is pending", async () => {
  vi.spyOn(crypto, "randomUUID").mockReturnValue(OPERATION);
  vi.stubGlobal("localStorage", memoryStorage());
  vi.stubGlobal("sessionStorage", memoryStorage());
  window.sessionStorage.setItem(STORAGE_KEY, TOKEN);
  const fixture = sessionRaceFixture(true);
  const session = await mountSession(fixture.client);
  const confirmation = session.stepUp({ method: "totp", code: "123456" });
  await fixture.stepUpStarted.promise;
  const competing = await session
    .signInWithApiKey(
      `meshspan-key-v1.${"a".repeat(32)}.${"b".repeat(64)}`,
      false,
    )
    .then(
      () => "sent",
      () => "blocked",
    );
  fixture.delayedStepUp.resolve(
    response(
      {
        operation_id: OPERATION,
        session_id: ROTATED,
        assurance: "recent_step_up",
        expires_at_epoch_micros: 1000,
      },
      NEXT_TOKEN,
    ),
  );
  const confirmed = await confirmation.then(
    () => "confirmed",
    () => "rejected",
  );
  expect(competing).toBe("blocked");
  expect(confirmed).toBe("confirmed");
});

const BOB = "00000000-0000-4000-8000-000000000050";
const BOB_SESSION = "00000000-0000-4000-8000-000000000060";
const BOB_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;

function sessionRaceFixture(delayStepUp = false) {
  const delayedStepUp = Promise.withResolvers<Response>();
  const stepUpStarted = Promise.withResolvers<boolean>();
  const staleRefresh = Promise.withResolvers<Response>();
  const refreshStarted = Promise.withResolvers<boolean>();
  let reads = 0;
  let bobSignedIn = false;
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/step-ups")) {
        stepUpStarted.resolve(true);
        if (delayStepUp) return delayedStepUp.promise;
        return Promise.resolve(
          response(
            {
              operation_id: OPERATION,
              session_id: ROTATED,
              assurance: "recent_step_up",
              expires_at_epoch_micros: 1000,
            },
            NEXT_TOKEN,
          ),
        );
      }
      if (url.endsWith("/sessions")) {
        bobSignedIn = true;
        return Promise.resolve(
          response(
            {
              operation_id: OPERATION,
              session_id: BOB_SESSION,
              assurance: "single_factor",
              expires_at_epoch_micros: 1000,
            },
            BOB_TOKEN,
          ),
        );
      }
      reads += 1;
      if (reads === 2 && !delayStepUp) {
        refreshStarted.resolve(true);
        return staleRefresh.promise;
      }
      const observedSession = reads === 1 ? SESSION : ROTATED;
      return Promise.resolve(
        response(
          !bobSignedIn
            ? currentSession(observedSession)
            : {
                ...currentSession(BOB_SESSION),
                principal_id: BOB,
                administration_available: false,
              },
        ),
      );
    },
  });
  return {
    client,
    staleRefresh,
    refreshStarted,
    delayedStepUp,
    stepUpStarted,
    useBobSession: () => {
      bobSignedIn = true;
    },
  };
}

function currentSession(sessionId: string) {
  return {
    administration_available: true,
    principal_id: "00000000-0000-4000-8000-000000000040",
    session_id: sessionId,
    expires_at_epoch_micros: 1000,
  };
}

async function mountSession(
  client: MeshSpanFetchClient,
): Promise<ReturnType<typeof useSession>> {
  const observed: { session?: ReturnType<typeof useSession> } = {};
  function Probe(): JSX.Element {
    observed.session = useSession();
    return <p>Session fixture</p>;
  }
  dispose = render(
    () => (
      <SessionProvider client={client}>
        <Probe />
      </SessionProvider>
    ),
    document.body,
  );
  await vi.waitFor(() => {
    flush();
    expect(observed.session?.state().phase).toBe("authenticated");
  });
  const session = observed.session;
  if (session === undefined) throw new Error("Missing session provider");
  return session;
}

function stepUpFixture() {
  const requests: string[] = [];
  const sentTokens: (string | null)[] = [];
  let rotated = false;
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async (input, init) => {
      if (
        (input instanceof Request ? input.url : String(input)).endsWith(
          "/step-ups",
        )
      ) {
        sentTokens.push(new Headers(init?.headers).get("MeshSpan-CSRF-Token"));
        if (typeof init?.body !== "string")
          throw new TypeError("expected JSON");
        requests.push(init.body);
        if (requests.length === 1) throw new Error("response lost");
        rotated = true;
        return Promise.resolve(
          response(
            {
              operation_id: OPERATION,
              session_id: ROTATED,
              assurance: "recent_step_up",
              expires_at_epoch_micros: 1000,
            },
            NEXT_TOKEN,
          ),
        );
      }
      return Promise.resolve(
        response({
          administration_available: true,
          principal_id: "00000000-0000-4000-8000-000000000040",
          session_id: rotated ? ROTATED : SESSION,
          expires_at_epoch_micros: 1000,
        }),
      );
    },
  });
  return { client, requests, sentTokens };
}

function response(body: unknown, csrf?: string): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
      ...(csrf === undefined ? {} : { "MeshSpan-CSRF-Token": csrf }),
    },
  });
}

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear: () => {
      values.clear();
    },
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, value),
  };
}
