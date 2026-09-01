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
  const [name, setName] = createSignal("");
  const [selectedOwnerIds, setSelectedOwnerIds] = createSignal<
    readonly string[]
  >([], { ownedWrite: true });
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
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

  return (
    <form class="volume-create" onSubmit={(event) => void submit(event)}>
      <div class="section-heading">
        <p class="eyebrow">New volume</p>
        <h2>Create shared storage</h2>
      </div>
      <label class="volume-name-field">
        <span>Name</span>
        <input
          autocomplete="off"
          disabled={pending()}
          maxlength="256"
          onInput={(event) => setName(event.currentTarget.value)}
          value={name()}
        />
      </label>
      <fieldset class="owner-fields" disabled={pending()}>
        <legend>Initial owners</legend>
        <Show
          when={!props.ownersLoading}
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
                    checked={selectedOwnerIds().includes(owner.principal_id)}
                    onChange={(event) =>
                      toggleOwner(
                        owner.principal_id,
                        event.currentTarget.checked,
                      )
                    }
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
      <button
        class="primary-action"
        disabled={pending() || props.ownersLoading || props.owners.length === 0}
        type="submit"
      >
        {pending() ? "Committing volume…" : "Create volume"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={success()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
      </div>
    </form>
  );
}
