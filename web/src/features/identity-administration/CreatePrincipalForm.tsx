// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { PrincipalKind } from "./model";

type CreatePrincipalFormProps = Readonly<{
  create: (kind: PrincipalKind, displayName: string) => Promise<void>;
}>;

export function CreatePrincipalForm(
  props: CreatePrincipalFormProps,
): JSX.Element {
  const [kind, setKind] = createSignal<PrincipalKind>("user");
  const [displayName, setDisplayName] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    const name = displayName().trim();
    if (name.length === 0) {
      setError("Enter a display name.");
      return;
    }
    setPending(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      await props.create(kind(), name);
      setDisplayName("");
      setSuccess(`${name} is ready to receive access.`);
    } catch {
      setError(
        `MeshSpan could not create ${name}. Check the name and try again.`,
      );
    } finally {
      setPending(false);
    }
  };

  const updateKind: JSX.EventHandlerUnion<HTMLSelectElement, Event> = (event) =>
    setKind(event.currentTarget.value === "group" ? "group" : "user");

  return (
    <form class="principal-create" onSubmit={(event) => void submit(event)}>
      <div class="section-heading">
        <p class="eyebrow">New identity</p>
        <h2>Create access holder</h2>
      </div>
      <div class="principal-create-fields">
        <label>
          <span>Type</span>
          <select value={kind()} onChange={updateKind} disabled={pending()}>
            <option value="user">User</option>
            <option value="group">Group</option>
          </select>
        </label>
        <label class="name-field">
          <span>Display name</span>
          <input
            autocomplete="off"
            disabled={pending()}
            maxlength="128"
            onInput={(event) => setDisplayName(event.currentTarget.value)}
            value={displayName()}
          />
        </label>
        <button class="primary-action" disabled={pending()} type="submit">
          {pending() ? "Creating identity…" : "Create identity"}
        </button>
      </div>
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
