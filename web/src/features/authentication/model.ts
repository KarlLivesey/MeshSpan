// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreatePasskeyRegistrationChallengeRequest,
  CreatePasskeyRegistrationChallengeResponse,
  CreatePasskeyRegistrationRequestWritable,
  CreatePasskeyRegistrationResponse,
  CreateRecoveryCodesRequest,
  CreateRecoveryCodesResponse,
  CreateTotpRegistrationChallengeRequest,
  CreateTotpRegistrationChallengeResponse,
  CreateTotpRegistrationRequestWritable,
  CreateTotpRegistrationResponse,
  ListAuthenticationMethodsResponse,
  RevokeAuthenticationMethodRequest,
  RevokeAuthenticationMethodResponse,
} from "../../generated/types.gen";

export type AuthenticationMethodSummary =
  ListAuthenticationMethodsResponse["methods"][number];

export interface AuthenticationSecurityClient {
  createCurrentUserApiKey(
    request: CreateApiKeyRequest,
    csrfToken: string,
  ): Promise<CreateApiKeyResponse>;
  createCurrentUserPasskey(
    request: CreatePasskeyRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationResponse>;
  createCurrentUserPasskeyRegistrationChallenge(
    request: CreatePasskeyRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationChallengeResponse>;
  createCurrentUserRecoveryCodes(
    request: CreateRecoveryCodesRequest,
    csrfToken: string,
  ): Promise<CreateRecoveryCodesResponse>;
  createCurrentUserTotp(
    request: CreateTotpRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationResponse>;
  createCurrentUserTotpRegistrationChallenge(
    request: CreateTotpRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationChallengeResponse>;
  listCurrentUserAuthenticationMethods(): Promise<ListAuthenticationMethodsResponse>;
  listNextCurrentUserAuthenticationMethods(
    nextPageUrl: string,
  ): Promise<ListAuthenticationMethodsResponse>;
  revokeCurrentUserAuthenticationMethod(
    methodId: string,
    request: RevokeAuthenticationMethodRequest,
    csrfToken: string,
  ): Promise<RevokeAuthenticationMethodResponse>;
}

export type AuthenticationMethodDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly AuthenticationMethodSummary[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "loading_more">;
}>;

export function createAuthenticationMethodDirectory(
  client: Accessor<AuthenticationSecurityClient>,
): AuthenticationMethodDirectory {
  const [items, setItems] = createSignal<
    readonly AuthenticationMethodSummary[]
  >([], { ownedWrite: true });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<"idle" | "loading" | "loading_more">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const applyPage = (
    page: ListAuthenticationMethodsResponse,
    append: boolean,
  ): void => {
    setItems((current) => mergeMethods(append ? current : [], page.methods));
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError(undefined);
    try {
      applyPage(await client().listCurrentUserAuthenticationMethods(), false);
    } catch {
      setError("MeshSpan could not load your current sign-in methods.");
    } finally {
      setPhase("idle");
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") {
      return;
    }
    setPhase("loading_more");
    setError(undefined);
    try {
      applyPage(
        await client().listNextCurrentUserAuthenticationMethods(next),
        true,
      );
    } catch {
      setError("MeshSpan could not load more sign-in methods.");
    } finally {
      setPhase("idle");
    }
  };

  return { error, items, loadInitial, loadNext, nextPageUrl, phase };
}

function mergeMethods(
  first: readonly AuthenticationMethodSummary[],
  second: readonly AuthenticationMethodSummary[],
): readonly AuthenticationMethodSummary[] {
  const byId = new Map<string, AuthenticationMethodSummary>();
  for (const method of [...first, ...second]) {
    const current = byId.get(method.method_id);
    if (current === undefined || method.revision > current.revision) {
      byId.set(method.method_id, method);
    }
  }
  return [...byId.values()];
}
