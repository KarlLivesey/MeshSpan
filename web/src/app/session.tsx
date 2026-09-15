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
  StepUpCurrentSessionRequestWritable,
} from "../generated/types.gen";
import { createExactMutation } from "../native-api/mutation-outcome";
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
  | Readonly<{ message: string; phase: "unavailable" | "revocation_unknown" }>;

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
  stepUp: (factor: SessionAdditionalFactor) => Promise<void>;
  signOut: () => Promise<void>;
  state: Accessor<SessionState>;
}>;

type SessionStore = Readonly<{
  accept: (result: CreateSessionResult, persistent: boolean) => void;
  clear: () => void;
  rotate: (result: CreateSessionResult) => void;
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
    stepUp: actions.stepUp,
    state: store.state,
  };
  return <SessionContext value={context}>{props.children}</SessionContext>;
}

function createSessionStore(client: MeshSpanFetchClient): SessionStore {
  const [state, setState] = createSignal<SessionState>({ phase: "checking" });
  const initialToken = readStoredCsrfToken();
  const [csrfToken, setCsrfToken] = createSignal<string | undefined>(
    initialToken,
  );
  let persistent =
    initialToken !== undefined && readStorage("localStorage") === initialToken;
  let generation = Symbol();
  const clear = (): void => {
    generation = Symbol();
    clearStoredCsrfToken();
    setCsrfToken(undefined);
    setState({ phase: "anonymous" });
  };
  const refresh = async (): Promise<void> => {
    const owner = generation;
    try {
      const session = await client.getCurrentSession();
      // A late read cannot restore a principal or clear credentials after session replacement.
      if (owner !== generation) return;
      setState({ phase: "authenticated", session });
    } catch (error) {
      if (owner !== generation) return;
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
  const accept = (result: CreateSessionResult, remember: boolean): void => {
    generation = Symbol();
    persistent = remember;
    setCsrfToken(result.csrfToken);
    storeCsrfToken(result.csrfToken, persistent);
  };
  const rotate = (result: CreateSessionResult): void => {
    accept(result, persistent);
  };
  return { accept, clear, csrfToken, refresh, rotate, setState, state };
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
  const signOut = createSignOut(client, store);
  const stepUp = createStepUp(client, store);
  const run = createSessionActionGuard();
  return {
    signInWithApiKey: async (...args: Parameters<typeof signInWithApiKey>) =>
      run(async () => signInWithApiKey(...args)),
    signInWithPasskey: async (...args: Parameters<typeof signInWithPasskey>) =>
      run(async () => signInWithPasskey(...args)),
    signOut: async () => run(signOut),
    stepUp: async (factor: SessionAdditionalFactor) =>
      run(async () => stepUp(factor)),
  };
}

function createSessionActionGuard(): (
  action: () => Promise<void>,
) => Promise<void> {
  let pending = false;
  return async (action) => {
    // Cookie replacement happens in HTTP before JavaScript can reject a stale receipt.
    if (pending)
      throw new Error(
        "Another session change is pending. Wait for it before continuing.",
      );
    pending = true;
    try {
      await action();
    } finally {
      pending = false;
    }
  };
}

function createStepUp(
  client: MeshSpanFetchClient,
  store: SessionStore,
): (factor: SessionAdditionalFactor) => Promise<void> {
  let sessionId: string | undefined;
  let token: string | undefined;
  let submit: ((factor: SessionAdditionalFactor) => Promise<void>) | undefined;
  return async (factor) => {
    const current = store.state();
    const currentToken = store.csrfToken();
    if (current.phase !== "authenticated" || currentToken === undefined)
      throw new Error("Sign in again before confirming this session.");
    if (
      submit === undefined ||
      current.session.session_id !== sessionId ||
      currentToken !== token
    ) {
      sessionId = current.session.session_id;
      token = currentToken;
      submit = createSessionStepUp(client, store, { sessionId, token });
    }
    await submit(factor);
  };
}

function createSessionStepUp(
  client: MeshSpanFetchClient,
  store: SessionStore,
  owner: Readonly<{ sessionId: string; token: string }>,
): (factor: SessionAdditionalFactor) => Promise<void> {
  const mutation = createExactMutation(
    async (request: StepUpCurrentSessionRequestWritable) =>
      client.stepUpCurrentSession(request, owner.token),
    (receipt, request) => {
      if (
        receipt.session.operation_id !== request.operation_id ||
        receipt.session.assurance !== "recent_step_up"
      )
        throw new Error(
          "Session confirmation receipt does not match the request.",
        );
    },
    async () => Promise.resolve(),
  );
  return async (factor) => {
    if (mutation.state().phase === "unknown") await mutation.retry();
    else
      await mutation.submit({
        operation_id: crypto.randomUUID(),
        additional_factor: factor,
      });
    const outcome = mutation.state();
    if (outcome.phase !== "committed")
      throw new Error(
        "Session confirmation is unknown. Retry the same confirmation.",
      );
    const current = store.state();
    if (
      current.phase !== "authenticated" ||
      current.session.session_id !== owner.sessionId ||
      store.csrfToken() !== owner.token
    )
      throw new Error(
        "The confirmed session has been replaced. Check the current sign-in.",
      );
    store.rotate(outcome.receipt);
    await store.refresh();
  };
}

function createSignOut(
  client: MeshSpanFetchClient,
  store: SessionStore,
): () => Promise<void> {
  let sessionId: string | undefined;
  let signOut = createSessionSignOut(client, store, sessionId);
  return async () => {
    const current = store.state();
    if (
      current.phase === "authenticated" &&
      current.session.session_id !== sessionId
    ) {
      sessionId = current.session.session_id;
      signOut = createSessionSignOut(client, store, sessionId);
    }
    await signOut();
  };
}

function createSessionSignOut(
  client: MeshSpanFetchClient,
  store: SessionStore,
  sessionId: string | undefined,
): () => Promise<void> {
  const ownerToken = untrack(store.csrfToken);
  const mutation = createExactMutation(
    async (request: {
      operation_id: string;
      session_id: string;
      token: string;
    }) =>
      client.revokeCurrentSession(
        { operation_id: request.operation_id },
        request.token,
      ),
    (receipt, request) => {
      if (
        receipt.operation_id !== request.operation_id ||
        receipt.session_id !== request.session_id
      ) {
        throw new TypeError(
          "Session revocation receipt does not match the request.",
        );
      }
    },
    async () => {
      const current = store.state();
      // A late receipt only revokes its own session, never a replacement login.
      if (
        store.csrfToken() === ownerToken &&
        (current.phase !== "authenticated" ||
          current.session.session_id === sessionId)
      ) {
        store.clear();
      }
      return Promise.resolve();
    },
  );
  return async () => {
    const token = store.csrfToken();
    const current = store.state();
    if (mutation.locked()) await mutation.retry();
    else if (token !== undefined && current.phase === "authenticated") {
      await mutation.submit({
        operation_id: crypto.randomUUID(),
        session_id: current.session.session_id,
        token,
      });
    }
    const latest = store.state();
    if (
      store.csrfToken() !== ownerToken ||
      (latest.phase === "authenticated" &&
        latest.session.session_id !== sessionId)
    )
      return;
    if (mutation.state().phase !== "committed") {
      store.setState({
        phase: "revocation_unknown",
        message:
          token === undefined
            ? "Sign-out is not confirmed: this browser is missing its session security token. Check the session again; the server cookie may still be valid."
            : "Sign-out is not confirmed. Retry the same revocation or check whether the session is still active.",
      });
    }
  };
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
