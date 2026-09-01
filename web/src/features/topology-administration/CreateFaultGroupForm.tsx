// SPDX-License-Identifier: GPL-2.0-only

import { createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

export function CreateFaultGroupForm(
  props: Readonly<{
    create: (className: string, groupName: string) => Promise<void>;
    saving: boolean;
  }>,
): JSX.Element {
  const [className, setClassName] = createSignal("");
  const [groupName, setGroupName] = createSignal("");

  const submit: JSX.EventHandler<HTMLFormElement, SubmitEvent> = (event) => {
    event.preventDefault();
    void submitValues();
  };

  const submitValues = async (): Promise<void> => {
    const boundaryClass = className().trim();
    const boundaryName = groupName().trim();
    if (boundaryClass === "" || boundaryName === "") return;
    await props.create(boundaryClass, boundaryName);
    setGroupName("");
  };

  return (
    <form class="fault-group-create" onSubmit={submit}>
      <div>
        <p class="eyebrow">Shared failure</p>
        <h2>Add a failure boundary</h2>
        <p>
          A machine can be in several groups at once. Reuse the same class name
          to create another room, building, power source or custom boundary.
        </p>
      </div>
      <label>
        Boundary type
        <input
          autocomplete="off"
          maxlength="128"
          onInput={(event) => setClassName(event.currentTarget.value)}
          placeholder="Power source"
          required
          value={className()}
        />
      </label>
      <label>
        Boundary name
        <input
          autocomplete="off"
          maxlength="256"
          onInput={(event) => setGroupName(event.currentTarget.value)}
          placeholder="UPS A"
          required
          value={groupName()}
        />
      </label>
      <button class="primary-action" disabled={props.saving} type="submit">
        {props.saving ? "Adding…" : "Add boundary"}
      </button>
    </form>
  );
}
