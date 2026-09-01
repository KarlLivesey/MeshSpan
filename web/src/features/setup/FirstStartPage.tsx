// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type { CreateMeshSetupResponse } from "../../generated/types.gen";

type FirstStartPageProps = Readonly<{
  client: Pick<MeshSpanFetchClient, "createMeshSetup">;
  onComplete: () => void;
}>;

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

export function FirstStartPage(props: FirstStartPageProps): JSX.Element {
  const [claim, setClaim] = createSignal("");
  const [values, setValues] = createSignal<Record<SetupField["name"], string>>({
    administrator: "",
    host: "",
    mesh: "",
    node: "",
  });
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
    const current = values();
    setPending(true);
    setError(undefined);
    try {
      setResult(
        await props.client.createMeshSetup({
          administrator_name: current.administrator.trim(),
          claim: claim().trim(),
          host_name: current.host.trim(),
          mesh_name: current.mesh.trim(),
          node_name: current.node.trim(),
          operation_id: operationId,
        }),
      );
      setClaim("");
    } catch {
      setError(
        "MeshSpan could not create this swarm. Check the claim and names, then retry.",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <main class="first-start-page">
      <Show
        when={result()}
        fallback={
          <SetupForm
            claim={claim()}
            error={error()}
            onClaim={setClaim}
            onSubmit={create}
            onValue={(name, value) =>
              setValues((current) => ({ ...current, [name]: value }))
            }
            pending={pending()}
            values={values()}
          />
        }
      >
        {(created) => (
          <RecoveryMaterial
            complete={props.onComplete}
            result={created()}
            saved={saved()}
            setSaved={setSaved}
          />
        )}
      </Show>
    </main>
  );
}

type SetupFormProps = Readonly<{
  claim: string;
  error: string | undefined;
  onClaim: (value: string) => void;
  onSubmit: (event: SubmitEvent) => Promise<void>;
  onValue: (name: SetupField["name"], value: string) => void;
  pending: boolean;
  values: Record<SetupField["name"], string>;
}>;

function SetupForm(props: SetupFormProps): JSX.Element {
  return (
    <section class="first-start-card">
      <div>
        <p class="eyebrow">New appliance</p>
        <h1>Create your swarm</h1>
        <p>
          Enter the one-time claim printed by this daemon. MeshSpan will create
          the first administrator and choose the internal roles automatically.
        </p>
      </div>
      <form onSubmit={(event) => void props.onSubmit(event)}>
        <label class="claim-field">
          <span>One-time claim</span>
          <input
            autocomplete="off"
            disabled={props.pending}
            onInput={(event) => props.onClaim(event.currentTarget.value)}
            required
            spellcheck={false}
            type="password"
            value={props.claim}
          />
        </label>
        <div class="setup-name-grid">
          <For each={SETUP_FIELDS}>
            {(field) => (
              <label>
                <span>{field.label}</span>
                <input
                  autocomplete={field.autocomplete}
                  disabled={props.pending}
                  maxlength="128"
                  onInput={(event) =>
                    props.onValue(field.name, event.currentTarget.value)
                  }
                  placeholder={field.placeholder}
                  required
                  value={props.values[field.name]}
                />
              </label>
            )}
          </For>
        </div>
        <button class="primary-action" disabled={props.pending} type="submit">
          {props.pending ? "Creating swarm…" : "Create swarm"}
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
        onClick={() => downloadRecoveryBundle(props.result)}
        type="button"
      >
        Download encrypted recovery file
      </button>
      <SecretValue label="Recovery code" value={props.result.recovery_code} />
      <SecretValue label="Administrator API key" value={props.result.api_key} />
      <label class="check-field">
        <input
          checked={props.saved}
          onChange={(event) => props.setSaved(event.currentTarget.checked)}
          type="checkbox"
        />
        <span>I saved the recovery file, recovery code and API key</span>
      </label>
      <button
        class="quiet-button"
        disabled={!props.saved}
        onClick={props.complete}
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
