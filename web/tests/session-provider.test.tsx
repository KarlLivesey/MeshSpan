// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import type { JSX } from "@solidjs/web";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionProvider, useSession } from "../src/app/session";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const API_KEY = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const OPERATION_ID = "00000000-0000-4000-8000-000000000051";
const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
const mountedRoots = new Set<() => void>();

afterEach(() => {
  for (const dispose of mountedRoots) {
    dispose();
  }
  mountedRoots.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("browser session provider", () => {
  it("keeps an in-memory session usable when browser storage is denied", async () => {
    denyBrowserStorage();
    const requests: string[] = [];
    let currentSessionReads = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        const url = requestUrl(input);
        requests.push(`${init?.method ?? "GET"} ${url}`);
        if (url.endsWith("/sessions/current")) {
          currentSessionReads += 1;
          return currentSessionReads === 1
            ? jsonResponse({}, 401)
            : jsonResponse(currentSession());
        }
        return jsonResponse(createdSession(), 201, {
          "MeshSpan-CSRF-Token": CSRF_TOKEN,
        });
      },
    });

    mountSessionProbe(client);
    await waitForPhase("anonymous");
    clickButton("Sign in fixture");
    await waitForPhase("authenticated");

    expect(requests).toEqual([
      "GET https://node.example/api/latest/sessions/current",
      "POST https://node.example/api/latest/sessions",
      "GET https://node.example/api/latest/sessions/current",
    ]);
  });
});

function SessionProbe(): JSX.Element {
  const session = useSession();
  return (
    <div>
      <output data-phase>{session.state().phase}</output>
      <button
        onClick={() => void session.signInWithApiKey(API_KEY, false)}
        type="button"
      >
        Sign in fixture
      </button>
    </div>
  );
}

function mountSessionProbe(
  client: ReturnType<typeof createMeshSpanFetchClient>,
): void {
  const root = document.createElement("div");
  document.body.append(root);
  mountedRoots.add(
    render(
      () => (
        <SessionProvider client={client}>
          <SessionProbe />
        </SessionProvider>
      ),
      root,
    ),
  );
}

function denyBrowserStorage(): void {
  const denial = (): never => {
    throw new DOMException("storage denied", "SecurityError");
  };
  vi.spyOn(window, "localStorage", "get").mockImplementation(denial);
  vi.spyOn(window, "sessionStorage", "get").mockImplementation(denial);
}

function currentSession() {
  return {
    administration_available: true,
    expires_at_epoch_micros: 60_000_000,
    principal_id: "00000000-0000-4000-8000-000000000008",
    session_id: "00000000-0000-4000-8000-000000000007",
  } as const;
}

function createdSession() {
  return {
    assurance: "single_factor",
    expires_at_epoch_micros: 60_000_000,
    operation_id: OPERATION_ID,
    session_id: "00000000-0000-4000-8000-000000000007",
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

function jsonResponse(
  value: unknown,
  status = 200,
  additionalHeaders: Readonly<Record<string, string>> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: { ...RESPONSE_HEADERS, ...additionalHeaders },
    status,
  });
}

function readPhase(): string | null | undefined {
  return document.querySelector("[data-phase]")?.textContent;
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

async function waitForPhase(expected: string): Promise<void> {
  await vi.waitFor(
    () => {
      flush();
      expect(readPhase()).toBe(expected);
    },
    { interval: 1, timeout: 1_000 },
  );
}
