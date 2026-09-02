// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { FaultGroup, TopologyDirectory, TopologyNode } from "./model";

export function FaultGroupEditor(
  props: Readonly<{
    csrfToken: string;
    directory: TopologyDirectory;
  }>,
): JSX.Element {
  const machines = () => uniqueMachines(props.directory.nodes());
  return (
    <section class="topology-section" aria-labelledby="fault-groups-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Things that fail together</p>
          <h2 id="fault-groups-title">Failure boundaries</h2>
        </div>
        <span>{props.directory.groups().length} shown</span>
      </div>
      <Show
        when={props.directory.groups().length > 0}
        fallback={<p>Add a boundary above, then select every machine in it.</p>}
      >
        <div class="fault-group-list">
          <For each={props.directory.groups()}>
            {(group) => (
              <FaultGroupCard
                csrfToken={props.csrfToken}
                directory={props.directory}
                group={group}
                machines={machines()}
              />
            )}
          </For>
        </div>
      </Show>
      <MoreActions directory={props.directory} />
    </section>
  );
}

function FaultGroupCard(
  props: Readonly<{
    csrfToken: string;
    directory: TopologyDirectory;
    group: FaultGroup;
    machines: readonly Machine[];
  }>,
): JSX.Element {
  const isMember = (hostId: string): boolean =>
    props.directory
      .memberships()
      .some(
        (item) =>
          item.group_id === props.group.group_id && item.host_id === hostId,
      );
  return (
    <fieldset class="fault-group-card">
      <legend>
        <span>{props.group.class_name}</span>
        {props.group.group_name}
      </legend>
      <Show
        when={props.machines.length > 0}
        fallback={<p>No machines are available to assign.</p>}
      >
        <div class="machine-membership-grid">
          <For each={props.machines}>
            {(machine) => (
              <MachineMembership
                checked={isMember(machine.hostId)}
                disabled={props.directory.phase() !== "idle"}
                machine={machine}
                set={(present) => {
                  const csrfToken = props.csrfToken;
                  void props.directory
                    .setMembership(
                      props.group.group_id,
                      machine.hostId,
                      present,
                      csrfToken,
                    )
                    .catch(() => undefined);
                }}
              />
            )}
          </For>
        </div>
      </Show>
    </fieldset>
  );
}

function MachineMembership(
  props: Readonly<{
    checked: boolean;
    disabled: boolean;
    machine: Machine;
    set: (present: boolean) => void;
  }>,
): JSX.Element {
  return (
    <label>
      <input
        checked={props.checked}
        disabled={props.disabled}
        onChange={(event) => {
          props.set(event.currentTarget.checked);
        }}
        type="checkbox"
      />
      <span>
        {props.machine.name}
        <small>{props.machine.detail}</small>
      </span>
    </label>
  );
}

function MoreActions(
  props: Readonly<{ directory: TopologyDirectory }>,
): JSX.Element {
  return (
    <div class="topology-more-actions">
      <Show when={props.directory.nextGroups()}>
        <button
          type="button"
          onClick={() => {
            void props.directory.loadMoreGroups();
          }}
        >
          Show more boundaries
        </button>
      </Show>
      <Show when={props.directory.nextMemberships()}>
        <button
          type="button"
          onClick={() => {
            void props.directory.loadMoreMemberships();
          }}
        >
          Load more assignments
        </button>
      </Show>
    </div>
  );
}

type Machine = Readonly<{ detail: string; hostId: string; name: string }>;

function uniqueMachines(nodes: readonly TopologyNode[]): readonly Machine[] {
  const byHost = new Map<string, TopologyNode[]>();
  for (const node of nodes) {
    byHost.set(node.host_id, [...(byHost.get(node.host_id) ?? []), node]);
  }
  return [...byHost.entries()].map(([hostId, members]) => ({
    detail:
      members.length === 1
        ? `Machine ${hostId.slice(0, 8)}…`
        : `${String(members.length)} daemons on this machine`,
    hostId,
    name: members[0]?.display_name ?? hostId,
  }));
}
