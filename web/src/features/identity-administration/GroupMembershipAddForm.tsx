// SPDX-License-Identifier: GPL-2.0-only

import { createMemo, createSignal, For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { GroupMembershipDirectory } from "./group-membership-model";
import type { PrincipalSummary } from "./model";

type GroupMembershipAddFormProps = Readonly<{
  candidates: readonly PrincipalSummary[];
  directory: GroupMembershipDirectory;
  group: PrincipalSummary;
}>;

export function GroupMembershipAddForm(
  props: GroupMembershipAddFormProps,
): JSX.Element {
  const [selectedMemberId, setSelectedMemberId] = createSignal("");
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();
  const availableCandidates = createMemo(() => {
    const current = new Set(
      props.directory.items().map(({ member }) => member.principal_id),
    );
    return props.candidates.filter(
      (candidate) =>
        candidate.state === "active" &&
        candidate.principal_id !== props.group.principal_id &&
        !current.has(candidate.principal_id),
    );
  });
  const isIdle = () => props.directory.phase() === "idle";

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    const initialMemberId = selectedMemberId();
    if (initialMemberId === "") {
      setError("Choose a user or group to add.");
      return;
    }
    setError(undefined);
    setSuccess(undefined);
    if (await props.directory.add(initialMemberId)) {
      const member = props.candidates.find(
        (candidate) => candidate.principal_id === initialMemberId,
      );
      setSelectedMemberId("");
      setSuccess(
        `${member?.display_name ?? "Member"} now belongs to this group.`,
      );
    }
  };

  return (
    <>
      <form class="membership-add" onSubmit={(event) => void submit(event)}>
        <label>
          <span>User or group</span>
          <select
            disabled={!isIdle() || availableCandidates().length === 0}
            onChange={(event) => setSelectedMemberId(event.currentTarget.value)}
            value={selectedMemberId()}
          >
            <option value="">Choose an identity</option>
            <For each={availableCandidates()}>
              {(candidate) => (
                <option value={candidate.principal_id}>
                  {candidate.display_name} — {candidate.kind}
                </option>
              )}
            </For>
          </select>
        </label>
        <button
          class="primary-action"
          disabled={!isIdle() || availableCandidates().length === 0}
          type="submit"
        >
          {props.directory.phase() === "adding"
            ? "Adding member…"
            : "Add to group"}
        </button>
      </form>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={success()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
      </div>
    </>
  );
}
