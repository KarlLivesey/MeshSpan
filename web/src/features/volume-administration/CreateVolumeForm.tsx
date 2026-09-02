// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { PrincipalSummary } from "../identity-administration/model";

type CreateVolumeFormProps = Readonly<{
  create: (name: string, ownerPrincipalIds: readonly string[]) => Promise<void>;
  owners: readonly PrincipalSummary[];
  ownersLoading: boolean;
}>;

export function CreateVolumeForm(props: CreateVolumeFormProps): JSX.Element {
  const model = createVolumeFormModel(props);
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void model.submit();
  };
  return (
    <form class="volume-create" onSubmit={submit}>
      <div class="section-heading">
        <p class="eyebrow">New volume</p>
        <h2>Create shared storage</h2>
      </div>
      <label class="volume-name-field">
        <span>Name</span>
        <input
          autocomplete="off"
          disabled={model.pending()}
          maxlength="256"
          onInput={(event) => {
            model.setName(event.currentTarget.value);
          }}
          value={model.name()}
        />
      </label>
      <OwnerFields
        loading={props.ownersLoading}
        owners={props.owners}
        pending={model.pending()}
        selectedOwnerIds={model.selectedOwnerIds()}
        toggle={model.toggleOwner}
      />
      <button
        class="primary-action"
        disabled={
          model.pending() || props.ownersLoading || props.owners.length === 0
        }
        type="submit"
      >
        {model.pending() ? "Committing volume…" : "Create volume"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={model.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={model.success()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
      </div>
    </form>
  );
}

function createVolumeFormModel(props: CreateVolumeFormProps) {
  const [name, setName] = createSignal("");
  const [selectedOwnerIds, setSelectedOwnerIds] = createSignal<
    readonly string[]
  >([], { ownedWrite: true });
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();

  const submit = async (): Promise<void> => {
    if (pending()) {
      return;
    }
    const volumeName = name().trim();
    if (volumeName.length === 0) {
      setError("Enter a volume name.");
      return;
    }
    if (selectedOwnerIds().length === 0) {
      setError("Choose at least one owner.");
      return;
    }
    setPending(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      await props.create(volumeName, selectedOwnerIds());
      setName("");
      setSelectedOwnerIds([]);
      setSuccess(`${volumeName} is committed and ready to use.`);
    } catch {
      setError(
        `MeshSpan could not create ${volumeName}. Check the details and try again.`,
      );
    } finally {
      setPending(false);
    }
  };

  const toggleOwner = (principalId: string, selected: boolean): void => {
    setSelectedOwnerIds((current) =>
      selected
        ? [...new Set([...current, principalId])]
        : current.filter((candidate) => candidate !== principalId),
    );
  };

  return {
    error,
    name,
    pending,
    selectedOwnerIds,
    setName,
    submit,
    success,
    toggleOwner,
  };
}

function OwnerFields(
  props: Readonly<{
    loading: boolean;
    owners: readonly PrincipalSummary[];
    pending: boolean;
    selectedOwnerIds: readonly string[];
    toggle: (principalId: string, selected: boolean) => void;
  }>,
): JSX.Element {
  return (
    <fieldset class="owner-fields" disabled={props.pending}>
      <legend>Initial owners</legend>
      <Show
        when={!props.loading}
        fallback={<p>Reading committed users and groups…</p>}
      >
        <Show
          when={props.owners.length > 0}
          fallback={
            <p>Create a user or group before creating the first volume.</p>
          }
        >
          <For each={props.owners}>
            {(owner) => (
              <label class="check-field">
                <input
                  checked={props.selectedOwnerIds.includes(owner.principal_id)}
                  onChange={(event) => {
                    props.toggle(
                      owner.principal_id,
                      event.currentTarget.checked,
                    );
                  }}
                  type="checkbox"
                  value={owner.principal_id}
                />
                <span>
                  {owner.display_name} <small>{owner.kind}</small>
                </span>
              </label>
            )}
          </For>
        </Show>
      </Show>
    </fieldset>
  );
}
