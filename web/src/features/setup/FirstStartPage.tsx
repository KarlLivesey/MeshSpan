// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type { CreateMeshSetupResponse } from "../../generated/types.gen";

type FirstStartPageProps = Readonly<{
  client: Pick<MeshSpanFetchClient, "createMeshSetup" | "joinMeshSetup">;
  onComplete: () => void;
  onJoinAccepted: () => void;
}>;

type SetupMode = "create" | "join";

type SetupField = Readonly<{
  autocomplete: string;
  label: string;
  name: "administrator" | "host" | "mesh" | "node";
  placeholder: string;
}>;

const SETUP_FIELDS: readonly SetupField[] = [
  {
    autocomplete: "organization",
    label: "Swarm name",
    name: "mesh",
    placeholder: "Studio files",
  },
  {
    autocomplete: "name",
    label: "First administrator",
    name: "administrator",
    placeholder: "Alex",
  },
  {
    autocomplete: "off",
    label: "Machine name",
    name: "host",
    placeholder: "Office server",
  },
  {
    autocomplete: "off",
    label: "MeshSpan instance",
    name: "node",
    placeholder: "Primary",
  },
];
const EMPTY_SETUP_VALUES: Record<SetupField["name"], string> = {
  administrator: "",
  host: "",
  mesh: "",
  node: "",
};

export function FirstStartPage(props: FirstStartPageProps): JSX.Element {
  const [mode, setMode] = createSignal<SetupMode>("create");
  const [claim, setClaim] = createSignal("");
  const [joinCode, setJoinCode] = createSignal("");
  const [values, setValues] = createSignal(EMPTY_SETUP_VALUES);
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [result, setResult] = createSignal<CreateMeshSetupResponse>();
  const [saved, setSaved] = createSignal(false);
  const operationId = crypto.randomUUID();

  const create = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    const submitted = values();
    setPending(true);
    setError(undefined);
    const outcome = await settleSubmission(
      props.client.createMeshSetup(
        createSetupRequest(submitted, claim(), operationId),
      ),
      setPending,
      setError,
      "MeshSpan could not create this swarm. Check the claim and names, then retry.",
    );
    if (outcome.ok) {
      setResult(outcome.value);
      setClaim("");
    }
  };

  const join = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    const submitted = values();
    setPending(true);
    setError(undefined);
    const outcome = await settleSubmission(
      props.client.joinMeshSetup(
        joinSetupRequest(submitted, claim(), joinCode(), operationId),
      ),
      setPending,
      setError,
      "MeshSpan could not join that swarm. Check the claim, join code and names, then retry.",
    );
    if (outcome.ok) {
      setClaim("");
      setJoinCode("");
      props.onJoinAccepted();
    }
  };

  return (
    <FirstStartView
      claim={claim()}
      complete={props.onComplete}
      error={error()}
      joinCode={joinCode()}
      mode={mode()}
      onClaim={setClaim}
      onJoinCode={setJoinCode}
      onMode={(nextMode) => {
        setMode(nextMode);
        setError(undefined);
      }}
      onSubmit={mode() === "create" ? create : join}
      onValue={(name, value) => {
        setValues((current) => ({ ...current, [name]: value }));
      }}
      pending={pending()}
      result={result()}
      saved={saved()}
      setSaved={setSaved}
      values={values()}
    />
  );
}

function createSetupRequest(
  values: Record<SetupField["name"], string>,
  claim: string,
  operationId: string,
) {
  return {
    administrator_name: values.administrator.trim(),
    claim: claim.trim(),
    host_name: values.host.trim(),
    mesh_name: values.mesh.trim(),
    node_name: values.node.trim(),
    operation_id: operationId,
  };
}

function joinSetupRequest(
  values: Record<SetupField["name"], string>,
  claim: string,
  joinCode: string,
  operationId: string,
) {
  return {
    claim: claim.trim(),
    host_name: values.host.trim(),
    join_code: joinCode.trim(),
    node_name: values.node.trim(),
    operation_id: operationId,
  };
}

type SubmissionOutcome<T> =
  Readonly<{ ok: true; value: T }> | Readonly<{ ok: false }>;

async function settleSubmission<T>(
  operation: Promise<T>,
  setPending: (value: boolean) => void,
  setError: (value: string | undefined) => void,
  errorMessage: string,
): Promise<SubmissionOutcome<T>> {
  try {
    return { ok: true, value: await operation };
  } catch {
    setError(errorMessage);
    return { ok: false };
  } finally {
    setPending(false);
  }
}

type SetupFormProps = Readonly<{
  claim: string;
  error: string | undefined;
  joinCode: string;
  mode: SetupMode;
  onClaim: (value: string) => void;
  onJoinCode: (value: string) => void;
  onMode: (mode: SetupMode) => void;
  onSubmit: (event: SubmitEvent) => Promise<void>;
  onValue: (name: SetupField["name"], value: string) => void;
  pending: boolean;
  values: Record<SetupField["name"], string>;
}>;

type FirstStartViewProps = SetupFormProps &
  Readonly<{
    complete: () => void;
    result: CreateMeshSetupResponse | undefined;
    saved: boolean;
    setSaved: (value: boolean) => void;
  }>;

function FirstStartView(props: FirstStartViewProps): JSX.Element {
  return (
    <main class="first-start-page">
      <Show when={props.result} fallback={<SetupForm {...props} />}>
        {(created) => (
          <RecoveryMaterial
            complete={props.complete}
            result={created()}
            saved={props.saved}
            setSaved={props.setSaved}
          />
        )}
      </Show>
    </main>
  );
}

function SetupForm(props: SetupFormProps): JSX.Element {
  return (
    <section class="first-start-card">
      <div>
        <p class="eyebrow">New appliance</p>
        <h1>
          {props.mode === "create" ? "Create your swarm" : "Join a swarm"}
        </h1>
        <p>
          Enter the one-time claim printed by this daemon. MeshSpan chooses the
          internal roles automatically.
        </p>
      </div>
      <SetupModePicker {...props} />
      <form onSubmit={(event) => void props.onSubmit(event)}>
        <SetupCredentials {...props} />
        <SetupNameFields {...props} />
        <button class="primary-action" disabled={props.pending} type="submit">
          {submitLabel(props.mode, props.pending)}
        </button>
        <div aria-live="polite">
          <Show when={props.error}>
            {(message) => <p class="error">{message()}</p>}
          </Show>
        </div>
      </form>
    </section>
  );
}

function SetupModePicker(props: SetupFormProps): JSX.Element {
  return (
    <div class="setup-mode" aria-label="First-start action" role="group">
      <button
        aria-pressed={props.mode === "create" ? "true" : "false"}
        disabled={props.pending}
        onClick={() => {
          props.onMode("create");
        }}
        type="button"
      >
        Create a swarm
      </button>
      <button
        aria-pressed={props.mode === "join" ? "true" : "false"}
        disabled={props.pending}
        onClick={() => {
          props.onMode("join");
        }}
        type="button"
      >
        Join a swarm
      </button>
    </div>
  );
}

function SetupCredentials(props: SetupFormProps): JSX.Element {
  return (
    <>
      <label class="claim-field">
        <span>One-time claim</span>
        <input
          autocomplete="off"
          disabled={props.pending}
          onInput={(event) => {
            props.onClaim(event.currentTarget.value);
          }}
          required
          spellcheck={false}
          type="password"
          value={props.claim}
        />
      </label>
      <Show when={props.mode === "join"}>
        <label class="claim-field">
          <span>Join code</span>
          <input
            autocomplete="off"
            disabled={props.pending}
            onInput={(event) => {
              props.onJoinCode(event.currentTarget.value);
            }}
            required
            spellcheck={false}
            type="password"
            value={props.joinCode}
          />
        </label>
      </Show>
    </>
  );
}

function SetupNameFields(props: SetupFormProps): JSX.Element {
  return (
    <div class="setup-name-grid">
      <For each={setupFieldsFor(props.mode)}>
        {(field) => (
          <label>
            <span>{field.label}</span>
            <input
              autocomplete={field.autocomplete}
              disabled={props.pending}
              maxlength="128"
              onInput={(event) => {
                props.onValue(field.name, event.currentTarget.value);
              }}
              placeholder={field.placeholder}
              required
              value={props.values[field.name]}
            />
          </label>
        )}
      </For>
    </div>
  );
}

function setupFieldsFor(mode: SetupMode): readonly SetupField[] {
  return mode === "create"
    ? SETUP_FIELDS
    : SETUP_FIELDS.filter(({ name }) => name === "host" || name === "node");
}

function submitLabel(mode: SetupMode, pending: boolean): string {
  if (mode === "create") {
    return pending ? "Creating swarm…" : "Create swarm";
  }
  return pending ? "Joining swarm…" : "Join swarm";
}

function RecoveryMaterial(
  props: Readonly<{
    complete: () => void;
    result: CreateMeshSetupResponse;
    saved: boolean;
    setSaved: (value: boolean) => void;
  }>,
): JSX.Element {
  return (
    <section class="first-start-card recovery-material">
      <div>
        <p class="eyebrow">Swarm created</p>
        <h1>Save the recovery material</h1>
        <p>
          These values are shown once. Store the recovery file and recovery code
          separately. The API key signs in as the first administrator.
        </p>
      </div>
      <button
        class="primary-action"
        onClick={() => {
          downloadRecoveryBundle(props.result);
        }}
        type="button"
      >
        Download encrypted recovery file
      </button>
      <SecretValue label="Recovery code" value={props.result.recovery_code} />
      <SecretValue label="Administrator API key" value={props.result.api_key} />
      <label class="check-field">
        <input
          checked={props.saved}
          onChange={(event) => {
            props.setSaved(event.currentTarget.checked);
          }}
          type="checkbox"
        />
        <span>I saved the recovery file, recovery code and API key</span>
      </label>
      <button
        class="quiet-button"
        disabled={!props.saved}
        onClick={() => {
          props.complete();
        }}
        type="button"
      >
        Continue to sign in
      </button>
    </section>
  );
}

function SecretValue(
  props: Readonly<{ label: string; value: string }>,
): JSX.Element {
  return (
    <div class="setup-secret">
      <strong>{props.label}</strong>
      <code>{props.value}</code>
    </div>
  );
}

function downloadRecoveryBundle(result: CreateMeshSetupResponse): void {
  const blob = new Blob([`${result.recovery_bundle}\n`], {
    type: "text/plain;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.download = `meshspan-recovery-${result.mesh_id}.txt`;
  anchor.href = url;
  anchor.click();
  URL.revokeObjectURL(url);
}
