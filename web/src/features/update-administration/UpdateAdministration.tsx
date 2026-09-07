// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { UpdatesResponse } from "../../generated";
import {
  createUpdateModel,
  type UpdateClient,
  type UpdateModel,
} from "./model";
import { CandidateForm, PublisherForm } from "./UpdateForms";
import { ArtifactUpload } from "./ArtifactUpload";

export function UpdateAdministration(
  props: Readonly<{ client: UpdateClient; csrfToken: string }>,
): JSX.Element {
  const model = createUpdateModel(
    () => props.client,
    () => props.csrfToken,
  );
  const locked = (): boolean => model.busy() || model.pending();
  void model.load();
  return (
    <section class="topology-section" aria-labelledby="updates-heading">
      <h2 id="updates-heading">Software updates</h2>
      <button
        type="button"
        class="quiet-action"
        disabled={locked()}
        onClick={() => void model.load()}
      >
        Refresh updates
      </button>
      <Show
        when={model.status()}
        fallback={<p>Update status has not been loaded.</p>}
      >
        {(status) => (
          <UpdateStatus
            status={status()}
            model={model}
            client={props.client}
            csrfToken={props.csrfToken}
          />
        )}
      </Show>
      <Show when={model.pending()}>
        <button
          type="button"
          class="quiet-action"
          disabled={model.busy()}
          onClick={() => void model.retry()}
        >
          Retry update change
        </button>
      </Show>
      <div aria-live="polite">
        <Show when={model.busy()}>
          <p>Checking update state…</p>
        </Show>
        <Show when={model.message()}>{(message) => <p>{message()}</p>}</Show>
      </div>
      <Show when={model.error()}>
        {(error) => (
          <p class="error" role="alert">
            {error()}
          </p>
        )}
      </Show>
    </section>
  );
}

function UpdateStatus(
  props: Readonly<{
    status: UpdatesResponse;
    model: UpdateModel;
    client: UpdateClient;
    csrfToken: string;
  }>,
): JSX.Element {
  return (
    <>
      <Show when={!props.status.installation_available}>
        <p>
          Installation is not connected in this build. You can configure
          publisher trust, select a candidate and upload its executables; no
          running software will be replaced.
        </p>
      </Show>
      <Show
        when={props.status.rollout}
        fallback={
          <p>
            No active candidate. Choose a signed candidate after pinning its
            publisher.
          </p>
        }
      >
        {(rollout) => (
          <SelectedUpdate
            rollout={rollout()}
            model={props.model}
            client={props.client}
            csrfToken={props.csrfToken}
          />
        )}
      </Show>
      <CandidateForm model={props.model} signers={props.status.signers} />
      <PublisherTrust model={props.model} signers={props.status.signers} />
    </>
  );
}

function SelectedUpdate(
  props: Readonly<{
    rollout: NonNullable<UpdatesResponse["rollout"]>;
    model: UpdateModel;
    client: UpdateClient;
    csrfToken: string;
  }>,
): JSX.Element {
  return (
    <div aria-label="Selected update">
      <h3>
        Version {props.rollout.version} — {props.rollout.state}
      </h3>
      <p>
        Candidate <code>{props.rollout.rollout_id}</code>
      </p>
      <p>
        {props.rollout.progress.pending} awaiting staging ·{" "}
        {props.rollout.progress.staged} staged ·{" "}
        {props.rollout.progress.restarting} restarting ·{" "}
        {props.rollout.progress.verified} verified ·{" "}
        {props.rollout.progress.failed} failed
      </p>
      <Show when={props.rollout.progress.unresolved_restarts !== "0"}>
        <p>
          A restart outcome is unresolved. No further restart or cancellation is
          safe until it is checked.
        </p>
      </Show>
      <RolloutControls rollout={props.rollout} model={props.model} />
      <Show
        when={
          props.rollout.state === "running" || props.rollout.state === "paused"
        }
      >
        <ArtifactUpload
          rollout={props.rollout}
          client={props.client}
          csrfToken={props.csrfToken}
        />
      </Show>
    </div>
  );
}

function PublisherTrust(
  props: Readonly<{ model: UpdateModel; signers: UpdatesResponse["signers"] }>,
): JSX.Element {
  const locked = (): boolean => props.model.busy() || props.model.pending();
  return (
    <details>
      <summary>Trusted publishers</summary>
      <p>
        Obtain the public verification key independently of the update package.
        Never upload a private signing key.
      </p>
      <ul aria-label="Trusted publishers">
        <For
          each={props.signers}
          fallback={<li>No publisher keys are pinned.</li>}
        >
          {(signer) => (
            <li>
              <code>{signer.signer_id}</code> —{" "}
              {signer.enabled ? "trusted" : "disabled"}
              <details>
                <summary>Public verification key</summary>
                <code>{signer.public_key}</code>
              </details>
              <button
                type="button"
                class="quiet-action"
                disabled={locked()}
                onClick={() =>
                  void props.model.save({
                    operation_id: crypto.randomUUID(),
                    action: {
                      kind: "configure_signer",
                      signer_id: signer.signer_id,
                      expected_sequence: signer.sequence,
                      public_key: signer.public_key,
                      enabled: !signer.enabled,
                    },
                  })
                }
              >
                {signer.enabled ? "Disable publisher" : "Enable publisher"}
              </button>
            </li>
          )}
        </For>
      </ul>
      <Show when={props.signers.length < 64}>
        <PublisherForm model={props.model} />
      </Show>
    </details>
  );
}

function RolloutControls(
  props: Readonly<{
    rollout: NonNullable<UpdatesResponse["rollout"]>;
    model: UpdateModel;
  }>,
): JSX.Element {
  const locked = (): boolean => props.model.busy() || props.model.pending();
  const control = (action: "pause" | "resume" | "cancel"): void => {
    void props.model.save({
      operation_id: crypto.randomUUID(),
      action: {
        kind: "control",
        rollout_id: props.rollout.rollout_id,
        expected_sequence: props.rollout.sequence,
        control: action,
      },
    });
  };
  return (
    <>
      <Show when={props.rollout.state === "running"}>
        <button
          type="button"
          class="quiet-action"
          disabled={locked()}
          onClick={() => {
            control("pause");
          }}
        >
          Pause update
        </button>
      </Show>
      <Show when={props.rollout.state === "paused"}>
        <button
          type="button"
          class="quiet-action"
          disabled={locked()}
          onClick={() => {
            control("resume");
          }}
        >
          Resume update
        </button>
      </Show>
      <Show
        when={
          props.rollout.state === "running" || props.rollout.state === "paused"
        }
      >
        <p>
          Cancelling stops this rollout; it does not roll back nodes already
          updated.
        </p>
        <button
          type="button"
          class="quiet-action"
          disabled={
            locked() || props.rollout.progress.unresolved_restarts !== "0"
          }
          onClick={() => {
            control("cancel");
          }}
        >
          Cancel update
        </button>
      </Show>
    </>
  );
}
