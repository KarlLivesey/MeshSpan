// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show, type Accessor, type Setter } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { CreateApiKeyRequest } from "../../generated/types.gen";
import type { AuthenticationSecurityClient } from "./model";

type ApiKeyIssuanceProps = Readonly<{
  client: AuthenticationSecurityClient;
  csrfToken: string;
  onChanged: () => Promise<void>;
}>;

type ApiKeyScope = CreateApiKeyRequest["scopes"][number];

export function ApiKeyIssuance(props: ApiKeyIssuanceProps): JSX.Element {
  const [label, setLabel] = createSignal("Automation");
  const [expiresAt, setExpiresAt] = createSignal("");
  const [httpsSignIn, setHttpsSignIn] = createSignal(false);
  const [nativeApi, setNativeApi] = createSignal(true);
  const [smbSignIn, setSmbSignIn] = createSignal(false);
  const [secret, setSecret] = createSignal<string>();
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();

  const issue = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    setPending(true);
    setSecret(undefined);
    setError(undefined);
    try {
      const result = await props.client.createCurrentUserApiKey(
        {
          expires_at_epoch_micros: expiryEpochMicroseconds(expiresAt()),
          label: label().trim(),
          operation_id: crypto.randomUUID(),
          scopes: selectedScopes(httpsSignIn(), nativeApi(), smbSignIn()),
        },
        props.csrfToken,
      );
      setSecret(result.secret);
      await props.onChanged();
    } catch {
      setError("MeshSpan could not issue that API key. Nothing was changed.");
    } finally {
      setPending(false);
    }
  };

  return (
    <form class="security-action-card" onSubmit={(event) => void issue(event)}>
      <div>
        <p class="eyebrow">Scoped access</p>
        <h3>Create an API key</h3>
        <p>Choose only the entry points this credential needs.</p>
      </div>
      <ApiKeyFields
        expiresAt={expiresAt}
        httpsSignIn={httpsSignIn}
        label={label}
        nativeApi={nativeApi}
        pending={pending}
        setExpiresAt={setExpiresAt}
        setHttpsSignIn={setHttpsSignIn}
        setLabel={setLabel}
        setNativeApi={setNativeApi}
        setSmbSignIn={setSmbSignIn}
        smbSignIn={smbSignIn}
      />
      <button class="quiet-button" disabled={pending()} type="submit">
        {pending() ? "Creating…" : "Create API key"}
      </button>
      <Show when={secret()}>
        {(value) => (
          <div class="one-time-secret">
            <p class="sensitive-note">
              Copy this key now. Ordinary reads never return its secret.
            </p>
            <output class="secret-output">{value()}</output>
          </div>
        )}
      </Show>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>{(value) => <p class="error">{value()}</p>}</Show>
      </div>
    </form>
  );
}

type ApiKeyFieldsProps = Readonly<{
  expiresAt: Accessor<string>;
  httpsSignIn: Accessor<boolean>;
  label: Accessor<string>;
  nativeApi: Accessor<boolean>;
  pending: Accessor<boolean>;
  setExpiresAt: Setter<string>;
  setHttpsSignIn: Setter<boolean>;
  setLabel: Setter<string>;
  setNativeApi: Setter<boolean>;
  setSmbSignIn: Setter<boolean>;
  smbSignIn: Accessor<boolean>;
}>;

function ApiKeyFields(props: ApiKeyFieldsProps): JSX.Element {
  return (
    <>
      <label>
        <span>Name</span>
        <input
          disabled={props.pending()}
          maxlength={80}
          onInput={(event) => props.setLabel(event.currentTarget.value)}
          required
          value={props.label()}
        />
      </label>
      <fieldset class="scope-fields" disabled={props.pending()}>
        <legend>Allowed entry points</legend>
        <ScopeCheckbox
          checked={props.nativeApi}
          label="Native API"
          setChecked={props.setNativeApi}
        />
        <ScopeCheckbox
          checked={props.httpsSignIn}
          label="Web sign-in"
          setChecked={props.setHttpsSignIn}
        />
        <ScopeCheckbox
          checked={props.smbSignIn}
          label="SMB sign-in"
          setChecked={props.setSmbSignIn}
        />
      </fieldset>
      <label>
        <span>Expires</span>
        <input
          disabled={props.pending()}
          onInput={(event) => props.setExpiresAt(event.currentTarget.value)}
          type="datetime-local"
          value={props.expiresAt()}
        />
      </label>
      <p class="field-note-reset">Leave blank for no automatic expiry.</p>
    </>
  );
}

function ScopeCheckbox(
  props: Readonly<{
    checked: Accessor<boolean>;
    label: string;
    setChecked: Setter<boolean>;
  }>,
): JSX.Element {
  return (
    <label class="check-field">
      <input
        checked={props.checked()}
        onChange={(event) => props.setChecked(event.currentTarget.checked)}
        type="checkbox"
      />
      <span>{props.label}</span>
    </label>
  );
}

function selectedScopes(
  httpsSignIn: boolean,
  nativeApi: boolean,
  smbSignIn: boolean,
): ApiKeyScope[] {
  const scopes: ApiKeyScope[] = [];
  if (httpsSignIn) {
    scopes.push("https_session");
  }
  if (nativeApi) {
    scopes.push("headless_api");
  }
  if (smbSignIn) {
    scopes.push("smb_session");
  }
  return scopes;
}

function expiryEpochMicroseconds(value: string): number | null {
  if (value === "") {
    return null;
  }
  const local = Temporal.PlainDateTime.from(value);
  const instant = local.toZonedDateTime(Temporal.Now.timeZoneId()).toInstant();
  const microseconds = instant.epochNanoseconds / 1_000n;
  if (microseconds < 0n || microseconds > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("API-key expiry is outside the supported range");
  }
  return Number(microseconds);
}
