// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, For } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { BeginStorageDrainRequest } from "../../generated";
import type { TopologyDirectory } from "./model";
import type { StorageDrainDirectory } from "./storage-drain-model";

type Scope = BeginStorageDrainRequest["scope"];

export function StorageDrainForm(
  props: Readonly<{
    begin: StorageDrainDirectory["begin"];
    csrfToken: string;
    saving: boolean;
    topology: TopologyDirectory;
  }>,
): JSX.Element {
  const [selection, setSelection] = createSignal("");
  const [allowDegraded, setAllowDegraded] = createSignal(true);
  const [cleanup, setCleanup] = createSignal(false);
  const [confirmed, setConfirmed] = createSignal(false);
  const submit: JSX.EventHandler<HTMLFormElement, SubmitEvent> = (event) => {
    event.preventDefault();
    const scope = selectedScope(selection(), props.topology);
    if (scope === undefined || !confirmed()) return;
    void props
      .begin(scope, allowDegraded(), cleanup(), props.csrfToken)
      .then(() => setConfirmed(false))
      .catch(() => undefined);
  };

  return (
    <form class="stacked-form" onSubmit={submit}>
      <label>
        What do you want to remove?
        <select
          required
          value={selection()}
          onChange={(event) => setSelection(event.currentTarget.value)}
        >
          <option value="">Choose a storage scope</option>
          <For each={props.topology.targets()}>
            {(target) => (
              <option value={`target:${target.target_id}:${target.generation}`}>
                Folder: {target.display_name}
              </option>
            )}
          </For>
          <For each={props.topology.nodes()}>
            {(node) => (
              <option value={`node:${node.node_id}:${node.incarnation}`}>
                Node: {node.display_name}
              </option>
            )}
          </For>
          <For each={props.topology.groups()}>
            {(group) => (
              <option value={`fault_group:${group.group_id}`}>
                Failure group: {group.class_name} / {group.group_name}
              </option>
            )}
          </For>
        </select>
      </label>
      <DrainPolicyOptions
        allowDegraded={allowDegraded()}
        cleanup={cleanup()}
        confirmed={confirmed()}
        setAllowDegraded={setAllowDegraded}
        setCleanup={setCleanup}
        setConfirmed={setConfirmed}
      />
      <button
        disabled={selection() === "" || !confirmed() || props.saving}
        type="submit"
      >
        Prepare for removal
      </button>
    </form>
  );
}

function DrainPolicyOptions(
  props: Readonly<{
    allowDegraded: boolean;
    cleanup: boolean;
    confirmed: boolean;
    setAllowDegraded: (value: boolean) => void;
    setCleanup: (value: boolean) => void;
    setConfirmed: (value: boolean) => void;
  }>,
): JSX.Element {
  return (
    <>
      <label class="check-row">
        <input
          checked={props.allowDegraded}
          type="checkbox"
          onChange={(event) => {
            props.setAllowDegraded(event.currentTarget.checked);
          }}
        />
        Allow removal when data is recoverable but preferred redundancy is
        temporarily lower
      </label>
      <label class="check-row">
        <input
          checked={props.cleanup}
          type="checkbox"
          onChange={(event) => {
            props.setCleanup(event.currentTarget.checked);
          }}
        />
        Reclaim evacuated shard bytes after safety is proved
      </label>
      <label class="check-row">
        <input
          checked={props.confirmed}
          type="checkbox"
          onChange={(event) => {
            props.setConfirmed(event.currentTarget.checked);
          }}
        />
        Start blocking new writes to this storage scope now
      </label>
    </>
  );
}

function selectedScope(
  value: string,
  topology: TopologyDirectory,
): Scope | undefined {
  const [kind, identifier, generation] = value.split(":");
  if (kind === "target") {
    const target = topology
      .targets()
      .find(
        (candidate) =>
          candidate.target_id === identifier &&
          candidate.generation === generation,
      );
    return target === undefined
      ? undefined
      : { generation: target.generation, kind, target_id: target.target_id };
  }
  if (kind === "node") {
    const node = topology
      .nodes()
      .find(
        (candidate) =>
          candidate.node_id === identifier &&
          candidate.incarnation === generation,
      );
    return node === undefined
      ? undefined
      : { incarnation: node.incarnation, kind, node_id: node.node_id };
  }
  if (kind === "fault_group") {
    const group = topology
      .groups()
      .find((candidate) => candidate.group_id === identifier);
    return group === undefined
      ? undefined
      : { fault_group_id: group.group_id, kind };
  }
  return undefined;
}
