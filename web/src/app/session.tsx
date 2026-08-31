// SPDX-License-Identifier: GPL-2.0-only

import {
  createContext,
  createSignal,
  untrack,
  useContext,
  type Accessor,
  type ParentProps,
  type Setter,
} from "solid-js";
import type { JSX } from "@solidjs/web";

import {
  MeshSpanApiError,
  type CreateSessionResult,
  type MeshSpanFetchClient,
} from "../generated/fetch.gen";
import type {
  CreateSessionRequestWritable,
  CurrentSessionResponse,
} from "../generated/types.gen";
import {
  browserCredentials,
  requestPasskeyAssertion,
} from "../features/authentication/webauthn";

export type SessionAdditionalFactor = NonNullable<
  CreateSessionRequestWritable["additional_factor"]
>;

export type SessionState =
  | Readonly<{ phase: "checking" }>
  | Readonly<{ phase: "anonymous" }>
  | Readonly<{ phase: "authenticated"; session: CurrentSessionResponse }>
  | Readonly<{ message: string; phase: "unavailable" }>;

type SessionContextValue = Readonly<{
  client: MeshSpanFetchClient;
  csrfToken: Accessor<string | undefined>;
  refresh: () => Promise<void>;
  signInWithApiKey: (
    secret: string,
    remember: boolean,
    additionalFactor?: SessionAdditionalFactor,
  ) => Promise<void>;
  signInWithPasskey: (
    remember: boolean,
    additionalFactor?: SessionAdditionalFactor,
  ) => Promise<void>;
  signOut: () => Promise<void>;
  state: Accessor<SessionState>;
}>;

type SessionStore = Readonly<{
  accept: (result: CreateSessionResult, persistent: boolean) => void;
  clear: () => void;
  csrfToken: Accessor<string | undefined>;
  refresh: () => Promise<void>;
  setState: Setter<SessionState>;
  state: Accessor<SessionState>;
}>;

const SessionContext = createContext<SessionContextValue>();
const CSRF_STORAGE_KEY = "meshspan.session.csrf.v1";
type BrowserStorageName = "localStorage" | "sessionStorage";

export function SessionProvider(
  props: ParentProps<Readonly<{ client: MeshSpanFetchClient }>>,
): JSX.Element {
  const client = untrack(() => props.client);
  const store = createSessionStore(client);
  const actions = createSessionActions(client, store);
  untrack(() => void store.refresh());
  const context: SessionContextValue = {
    get client() {
      return props.client;
    },
    csrfToken: store.csrfToken,
    refresh: store.refresh,
    signInWithApiKey: actions.signInWithApiKey,
    signInWithPasskey: actions.signInWithPasskey,
    signOut: actions.signOut,
    state: store.state,
  };
  return <SessionContext value={context}>{props.children}</SessionContext>;
}

function createSessionStore(client: MeshSpanFetchClient): SessionStore {
  const [state, setState] = createSignal<SessionState>({ phase: "checking" });
  const [csrfToken, setCsrfToken] = createSignal<string | undefined>(
    readStoredCsrfToken(),
  );
  const clear = (): void => {
    clearStoredCsrfToken();
    setCsrfToken(undefined);
    setState({ phase: "anonymous" });
  };
  const refresh = async (): Promise<void> => {
    try {
      setState({
        phase: "authenticated",
        session: await client.getCurrentSession(),
      });
    } catch (error) {
      if (error instanceof MeshSpanApiError && error.statusCode === 401) {
        clear();
        return;
      }
      setState({
        message: "The local MeshSpan service could not confirm this session.",
        phase: "unavailable",
      });
    }
  };
  const accept = (result: CreateSessionResult, persistent: boolean): void => {
    setCsrfToken(result.csrfToken);
    storeCsrfToken(result.csrfToken, persistent);
  };
  return { accept, clear, csrfToken, refresh, setState, state };
}

function createSessionActions(
  client: MeshSpanFetchClient,
  store: SessionStore,
) {
  const complete = async (
    result: Promise<CreateSessionResult>,
    persistent: boolean,
  ): Promise<void> => {
    store.accept(await result, persistent);
    await store.refresh();
  };
  const signInWithApiKey = async (
    secret: string,
    remember: boolean,
    additionalFactor?: SessionAdditionalFactor,
  ): Promise<void> => {
    await complete(
      client.createSession({
        ...factorField(additionalFactor),
        authentication: { method: "api_key", secret },
        operation_id: crypto.randomUUID(),
        remember,
      }),
      remember,
    );
  };
  const signInWithPasskey = async (
    remember: boolean,
    additionalFactor?: SessionAdditionalFactor,
  ): Promise<void> => {
    const challenge = await client.createPasskeyChallenge({
      operation_id: crypto.randomUUID(),
    });
    const authentication = await requestPasskeyAssertion(
      challenge,
      browserCredentials(),
    );
    await complete(
      client.createSession({
        ...factorField(additionalFactor),
        authentication,
        operation_id: crypto.randomUUID(),
        remember,
      }),
      remember,
    );
  };
  const signOut = async (): Promise<void> => {
    const token = store.csrfToken();
    if (token === undefined) {
      store.setState({ phase: "anonymous" });
      return;
    }
    await client.revokeCurrentSession(
      { operation_id: crypto.randomUUID() },
      token,
    );
    store.clear();
  };
  return { signInWithApiKey, signInWithPasskey, signOut };
}

function factorField(additionalFactor?: SessionAdditionalFactor): Readonly<{
  additional_factor?: SessionAdditionalFactor;
}> {
  return additionalFactor === undefined
    ? {}
    : { additional_factor: additionalFactor };
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
