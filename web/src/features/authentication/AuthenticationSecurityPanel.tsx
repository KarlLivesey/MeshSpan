// SPDX-License-Identifier: GPL-2.0-only

import { untrack } from "solid-js";
import type { JSX } from "@solidjs/web";

import { ApiKeyIssuance } from "./ApiKeyIssuance";
import { AuthenticationMethodList } from "./AuthenticationMethodList";
import { PasskeyRegistration } from "./PasskeyRegistration";
import { RecoveryCodeReplacement } from "./RecoveryCodeReplacement";
import { TotpRegistration } from "./TotpRegistration";
import {
  createAuthenticationMethodDirectory,
  type AuthenticationSecurityClient,
} from "./model";

type AuthenticationSecurityPanelProps = Readonly<{
  client: AuthenticationSecurityClient;
  csrfToken: string;
}>;

export function AuthenticationSecurityPanel(
  props: AuthenticationSecurityPanelProps,
): JSX.Element {
  const methods = createAuthenticationMethodDirectory(() => props.client);
  const refresh = async (): Promise<void> => {
    await methods.loadInitial();
  };
  const revoke = async (methodId: string, reason: string): Promise<void> => {
    await props.client.revokeCurrentUserAuthenticationMethod(
      methodId,
      { operation_id: crypto.randomUUID(), reason },
      props.csrfToken,
    );
    await refresh();
  };

  untrack(() => void refresh());

  return (
    <div class="authentication-security">
      <header class="page-intro">
        <p class="eyebrow">Your account</p>
        <h1>Sign-in security</h1>
        <p>
          Add, review and revoke the credentials accepted by every gateway in
          this swarm. Secret values are presented only when created.
        </p>
      </header>
      <AuthenticationMethodList
        error={methods.error()}
        items={methods.items()}
        loading={methods.phase() === "loading"}
        loadingMore={methods.phase() === "loading_more"}
        nextPageAvailable={methods.nextPageUrl() !== null}
        onLoadMore={methods.loadNext}
        onRevoke={revoke}
      />
      <section
        class="security-actions"
        aria-labelledby="security-actions-title"
      >
        <div class="section-heading security-actions-heading">
          <p class="eyebrow">Add or replace</p>
          <h2 id="security-actions-title">Security methods</h2>
          <p>
            Sensible defaults keep ordinary setup short; every method remains
            independently revocable.
          </p>
        </div>
        <div class="security-action-grid">
          <PasskeyRegistration
            client={props.client}
            csrfToken={props.csrfToken}
            onChanged={refresh}
          />
          <TotpRegistration
            client={props.client}
            csrfToken={props.csrfToken}
            onChanged={refresh}
          />
          <RecoveryCodeReplacement
            client={props.client}
            csrfToken={props.csrfToken}
            onChanged={refresh}
          />
          <ApiKeyIssuance
            client={props.client}
            csrfToken={props.csrfToken}
            onChanged={refresh}
          />
        </div>
      </section>
    </div>
  );
}
