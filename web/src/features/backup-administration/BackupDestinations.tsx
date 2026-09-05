// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { ListBackupDestinationsResponse } from "../../generated";
import type { BackupAdministration, BackupDestination } from "./model";
import { toggleDestination } from "./requests";

export function BackupDestinations(
  props: Readonly<{
    model: BackupAdministration;
    destinations: ListBackupDestinationsResponse;
  }>,
): JSX.Element {
  return (
    <section
      class="topology-section"
      aria-labelledby="backup-destinations-heading"
    >
      <h2 id="backup-destinations-heading">Destinations</h2>
      <p>
        Pausing stops new placement here. It does not delete existing backups. A
        manual choice is not overridden by automatic selection.
      </p>
      <Show
        when={props.destinations.destinations.length > 0}
        fallback={
          <p>
            No destinations are configured yet. Register storage or add a
            destination below.
          </p>
        }
      >
        <ul class="backup-destinations">
          <For each={props.destinations.destinations}>
            {(destination) => (
              <li>
                <div>
                  <h3>{destination.name}</h3>
                  <p>{relationshipLabel(destination.failure_relationship)}</p>
                  <small>
                    {providerLabel(destination.provider)} · generation{" "}
                    {destination.provider_generation}
                  </small>
                </div>
                <span class="state-pill">{destination.state}</span>
                <Show
                  when={
                    destination.provider.kind === "registered_target" &&
                    destination.state !== "retired"
                  }
                >
                  <button
                    type="button"
                    class="quiet-action"
                    disabled={props.model.locked()}
                    aria-label={`${destination.state === "active" ? "Pause" : "Resume"} ${destination.name}`}
                    onClick={() =>
                      void props.model.save({
                        kind: "destination",
                        request: toggleDestination(destination),
                      })
                    }
                  >
                    {destination.state === "active" ? "Pause" : "Resume"}
                  </button>
                </Show>
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={props.destinations.next_page_url !== null}>
        <button
          type="button"
          disabled={props.model.locked()}
          onClick={() => void props.model.loadMore("destinations")}
        >
          Show more destinations
        </button>
      </Show>
    </section>
  );
}

function relationshipLabel(
  value: BackupDestination["failure_relationship"],
): string {
  if (value === "independent") return "Assessed as independent";
  if (value === "overlapping") return "Shares a failure boundary";
  return "Failure independence has not been established";
}

function providerLabel(value: BackupDestination["provider"]): string {
  if (value.kind === "registered_target")
    return `Storage folder ${value.target_id}`;
  if (value.kind === "federated_mesh")
    return `Partner swarm ${value.remote_mesh_id}`;
  return `Backup provider ${value.instance_id}`;
}
