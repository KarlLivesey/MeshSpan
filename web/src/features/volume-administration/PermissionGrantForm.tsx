// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { CreateVolumePermissionGrantResponse } from "../../generated/types.gen";
import type { PrincipalSummary } from "../identity-administration/model";
import {
  createPermissionGrantFormModel,
  type PermissionGrantFormModel,
} from "./permission-grant-form-model";
import type { PermissionGrantClient } from "./permission-grant-model";

type PermissionGrantFormProps = Readonly<{
  client: PermissionGrantClient;
  csrfToken: string;
  onCommitted: (response: CreateVolumePermissionGrantResponse) => void;
  owners: readonly PrincipalSummary[];
  ownersHaveMore: boolean;
  loadMoreOwners: () => Promise<void>;
  volumeId: string;
}>;

export function PermissionGrantForm(
  props: PermissionGrantFormProps,
): JSX.Element {
  const model = createPermissionGrantFormModel(props);
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void model.submit();
  };
  return (
    <form class="permission-grant-form" onSubmit={submit}>
      <PermissionFields model={model} owners={props.owners} />
      <ActivationFields model={model} />
      <FormActions
        loadMoreOwners={props.loadMoreOwners}
        model={model}
        ownersAvailable={props.owners.length > 0}
        ownersHaveMore={props.ownersHaveMore}
      />
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

function PermissionFields(
  props: Readonly<{
    model: PermissionGrantFormModel;
    owners: readonly PrincipalSummary[];
  }>,
): JSX.Element {
  return (
    <div class="permission-grant-fields">
      <label>
        <span>User or group</span>
        <select
          disabled={props.model.pending() || props.owners.length === 0}
          onChange={(event) => {
            props.model.setPrincipalId(event.currentTarget.value);
          }}
          value={props.model.principalId()}
        >
          <option value="">Choose an access holder</option>
          <For each={props.owners}>
            {(owner) => (
              <option value={owner.principal_id}>
                {owner.display_name} · {owner.kind}
              </option>
            )}
          </For>
        </select>
      </label>
      <AccessLevelField model={props.model} />
      <DateField label="Starts" model={props.model} starts />
      <DateField label="Ends" model={props.model} starts={false} />
    </div>
  );
}

function AccessLevelField(
  props: Readonly<{ model: PermissionGrantFormModel }>,
): JSX.Element {
  return (
    <label>
      <span>Access level</span>
      <select
        disabled={props.model.pending()}
        onChange={(event) => {
          const level = event.currentTarget.value;
          if (level === "view" || level === "edit" || level === "manage") {
            props.model.setLevel(level);
          }
        }}
        value={props.model.level()}
      >
        <option value="view">View</option>
        <option value="edit">Edit</option>
        <option value="manage">Manage</option>
      </select>
    </label>
  );
}

function DateField(
  props: Readonly<{
    label: string;
    model: PermissionGrantFormModel;
    starts: boolean;
  }>,
): JSX.Element {
  return (
    <label>
      <span>{props.label}</span>
      <input
        disabled={props.model.pending()}
        onInput={(event) => {
          const value = event.currentTarget.value;
          if (props.starts) props.model.setValidFrom(value);
          else props.model.setValidUntil(value);
        }}
        type="datetime-local"
        value={
          props.starts ? props.model.validFrom() : props.model.validUntil()
        }
      />
    </label>
  );
}

function ActivationFields(
  props: Readonly<{ model: PermissionGrantFormModel }>,
): JSX.Element {
  return (
    <>
      <label class="check-field activation-check">
        <input
          checked={props.model.activationRequired()}
          disabled={props.model.pending()}
          onChange={(event) => {
            props.model.setActivationRequired(event.currentTarget.checked);
          }}
          type="checkbox"
        />
        <span>Require the user to activate access with a reason</span>
      </label>
      <Show when={props.model.activationRequired()}>
        <label class="activation-duration">
          <span>Maximum activation time in hours</span>
          <input
            disabled={props.model.pending()}
            inputmode="decimal"
            max="8760"
            min="0.25"
            onInput={(event) => {
              props.model.setActivationHours(event.currentTarget.value);
            }}
            step="0.25"
            type="number"
            value={props.model.activationHours()}
          />
        </label>
      </Show>
    </>
  );
}

function FormActions(
  props: Readonly<{
    loadMoreOwners: () => Promise<void>;
    model: PermissionGrantFormModel;
    ownersAvailable: boolean;
    ownersHaveMore: boolean;
  }>,
): JSX.Element {
  return (
    <div class="permission-form-actions">
      <button
        class="primary-action"
        disabled={props.model.pending() || !props.ownersAvailable}
        type="submit"
      >
        {props.model.pending() ? "Committing access…" : "Grant access"}
      </button>
      <Show when={props.ownersHaveMore}>
        <button
          class="quiet-button"
          disabled={props.model.pending()}
          onClick={() => {
            void props.loadMoreOwners();
          }}
          type="button"
        >
          Load more users and groups
        </button>
      </Show>
    </div>
  );
}
