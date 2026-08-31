// SPDX-License-Identifier: GPL-2.0-only

import {
  createContext,
  createSignal,
  untrack,
  useContext,
  type Accessor,
  type ParentProps,
} from "solid-js";
import type { JSX } from "@solidjs/web";
import type { CurrentSessionResponse } from "../generated/types.gen";
import {
  MeshSpanApiError,
  type MeshSpanFetchClient,
} from "../generated/fetch.gen";

export type SessionState =
  | Readonly<{ phase: "checking" }>
  | Readonly<{ phase: "anonymous" }>
  | Readonly<{ phase: "authenticated"; session: CurrentSessionResponse }>
  | Readonly<{ message: string; phase: "unavailable" }>;

type SessionContextValue = Readonly<{
  client: MeshSpanFetchClient;
  csrfToken: Accessor<string | undefined>;
  refresh: () => Promise<void>;
  signInWithApiKey: (secret: string, remember: boolean) => Promise<void>;
  signOut: () => Promise<void>;
  state: Accessor<SessionState>;
}>;

const SessionContext = createContext<SessionContextValue>();
const CSRF_STORAGE_KEY = "meshspan.session.csrf.v1";
type BrowserStorageName = "localStorage" | "sessionStorage";

export function SessionProvider(
  props: ParentProps<Readonly<{ client: MeshSpanFetchClient }>>,
): JSX.Element {
  const [state, setState] = createSignal<SessionState>({ phase: "checking" });
  const [csrfToken, setCsrfToken] = createSignal<string | undefined>(
    readStoredCsrfToken(),
  );

  const refresh = async (): Promise<void> => {
    try {
      const session = await props.client.getCurrentSession();
      setState({ phase: "authenticated", session });
    } catch (error) {
      if (error instanceof MeshSpanApiError && error.statusCode === 401) {
        clearStoredCsrfToken();
        setCsrfToken(undefined);
        setState({ phase: "anonymous" });
        return;
      }
      setState({
        message: "The local MeshSpan service could not confirm this session.",
        phase: "unavailable",
      });
    }
  };

  const signInWithApiKey = async (
    secret: string,
    remember: boolean,
  ): Promise<void> => {
    const result = await props.client.createSession({
      authentication: { method: "api_key", secret },
      operation_id: crypto.randomUUID(),
      remember,
    });
    setCsrfToken(result.csrfToken);
    storeCsrfToken(result.csrfToken, remember);
    await refresh();
  };

  const signOut = async (): Promise<void> => {
    const token = csrfToken();
    if (token === undefined) {
      setState({ phase: "anonymous" });
      return;
    }
    await props.client.revokeCurrentSession(
      { operation_id: crypto.randomUUID() },
      token,
    );
    clearStoredCsrfToken();
    setCsrfToken(undefined);
    setState({ phase: "anonymous" });
  };

  untrack(() => void refresh());

  const context: SessionContextValue = {
    get client() {
      return props.client;
    },
    csrfToken,
    refresh,
    signInWithApiKey,
    signOut,
    state,
  };

  return <SessionContext value={context}>{props.children}</SessionContext>;
}

function readStoredCsrfToken(): string | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  const value = readStorage("sessionStorage") ?? readStorage("localStorage");
  if (value === null || value.length > 256) {
    clearStoredCsrfToken();
    return undefined;
  }
  return value;
}

function storeCsrfToken(value: string, persistent: boolean): void {
  clearStoredCsrfToken();
  writeStorage(persistent ? "localStorage" : "sessionStorage", value);
}

function clearStoredCsrfToken(): void {
  if (typeof window === "undefined") {
    return;
  }
  removeFromStorage("sessionStorage");
  removeFromStorage("localStorage");
}

function readStorage(storageName: BrowserStorageName): string | null {
  try {
    return window[storageName].getItem(CSRF_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStorage(storageName: BrowserStorageName, value: string): void {
  try {
    window[storageName].setItem(CSRF_STORAGE_KEY, value);
  } catch {
    // A valid in-memory session remains usable when browser storage is denied.
  }
}

function removeFromStorage(storageName: BrowserStorageName): void {
  try {
    window[storageName].removeItem(CSRF_STORAGE_KEY);
  } catch {
    // Storage denial must not prevent local session state from being cleared.
  }
}

export function useSession(): SessionContextValue {
  return useContext(SessionContext);
}
