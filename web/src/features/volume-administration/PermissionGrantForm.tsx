// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type {
  CreateVolumePermissionGrantRequest,
  CreateVolumePermissionGrantResponse,
} from "../../generated/types.gen";
import type { PrincipalSummary } from "../identity-administration/model";
import type { PermissionGrantClient } from "./permission-grant-model";

type AccessLevel = "edit" | "manage" | "view";
type PermissionRight = CreateVolumePermissionGrantRequest["rights"][number];

const RIGHTS: Readonly<Record<AccessLevel, readonly PermissionRight[]>> = {
  view: ["traverse", "list", "read_data", "read_attributes"],
  edit: [
    "traverse",
    "list",
    "read_data",
    "create_child",
    "write_data",
    "append_data",
    "rename",
    "delete",
    "read_attributes",
    "write_attributes",
  ],
  manage: [
    "traverse",
    "list",
    "read_data",
    "create_child",
    "write_data",
    "append_data",
    "rename",
    "delete",
    "read_attributes",
    "write_attributes",
    "read_permissions",
    "change_permissions",
    "change_owner",
  ],
};

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
  const [principalId, setPrincipalId] = createSignal("");
  const [level, setLevel] = createSignal<AccessLevel>("edit");
  const [validFrom, setValidFrom] = createSignal("");
  const [validUntil, setValidUntil] = createSignal("");
  const [activationRequired, setActivationRequired] = createSignal(false);
  const [activationHours, setActivationHours] = createSignal("1");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    if (principalId().length === 0) {
      setError("Choose a user or group.");
      return;
    }
    let request: CreateVolumePermissionGrantRequest;
    try {
      request = buildRequest();
    } catch {
      setError("Check the validity window and activation duration.");
      return;
    }
    setPending(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      const response = await props.client.createVolumePermissionGrant(
        props.volumeId,
        request,
        props.csrfToken,
      );
      props.onCommitted(response);
      setSuccess("Access is committed across the swarm.");
    } catch {
      setError("MeshSpan could not commit this access grant.");
    } finally {
      setPending(false);
    }
  };

  const buildRequest = (): CreateVolumePermissionGrantRequest => {
    const from = localDateTimeToEpochMicros(validFrom());
    const until = localDateTimeToEpochMicros(validUntil());
    if (from !== null && until !== null && until <= from) {
      throw new RangeError("permission validity window is reversed");
    }
    const hours = Number(activationHours());
    if (
      activationRequired() &&
      (!Number.isFinite(hours) || hours <= 0 || hours > 8_760)
    ) {
      throw new RangeError("activation duration is invalid");
    }
    return {
      activation: activationRequired()
        ? {
            maximum_duration_micros: Math.round(hours * 3_600_000_000),
            minimum_assurance: "single_factor",
            reason_required: true,
          }
        : null,
      inheritance: "object_and_descendants",
      operation_id: crypto.randomUUID(),
      rights: [...RIGHTS[level()]],
      subject_principal_id: principalId(),
      valid_from_epoch_micros: from,
      valid_until_epoch_micros: until,
    };
  };

  return (
    <form
      class="permission-grant-form"
      onSubmit={(event) => void submit(event)}
    >
      <div class="permission-grant-fields">
        <label>
          <span>User or group</span>
          <select
            disabled={pending() || props.owners.length === 0}
            onChange={(event) => setPrincipalId(event.currentTarget.value)}
            value={principalId()}
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
        <label>
          <span>Access level</span>
          <select
            disabled={pending()}
            onChange={(event) =>
              setLevel(event.currentTarget.value as AccessLevel)
            }
            value={level()}
          >
            <option value="view">View</option>
            <option value="edit">Edit</option>
            <option value="manage">Manage</option>
          </select>
        </label>
        <label>
          <span>Starts</span>
          <input
            disabled={pending()}
            onInput={(event) => setValidFrom(event.currentTarget.value)}
            type="datetime-local"
            value={validFrom()}
          />
        </label>
        <label>
          <span>Ends</span>
          <input
            disabled={pending()}
            onInput={(event) => setValidUntil(event.currentTarget.value)}
            type="datetime-local"
            value={validUntil()}
          />
        </label>
      </div>
      <label class="check-field activation-check">
        <input
          checked={activationRequired()}
          disabled={pending()}
          onChange={(event) =>
            setActivationRequired(event.currentTarget.checked)
          }
          type="checkbox"
        />
        <span>Require the user to activate access with a reason</span>
      </label>
      <Show when={activationRequired()}>
        <label class="activation-duration">
          <span>Maximum activation time in hours</span>
          <input
            disabled={pending()}
            inputmode="decimal"
            max="8760"
            min="0.25"
            onInput={(event) => setActivationHours(event.currentTarget.value)}
            step="0.25"
            type="number"
            value={activationHours()}
          />
        </label>
      </Show>
      <div class="permission-form-actions">
        <button
          class="primary-action"
          disabled={pending() || props.owners.length === 0}
          type="submit"
        >
          {pending() ? "Committing access…" : "Grant access"}
        </button>
        <Show when={props.ownersHaveMore}>
          <button
            class="quiet-button"
            disabled={pending()}
            onClick={() => void props.loadMoreOwners()}
            type="button"
          >
            Load more users and groups
          </button>
        </Show>
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

function localDateTimeToEpochMicros(value: string): number | null {
  if (value.length === 0) {
    return null;
  }
  const instant = Temporal.PlainDateTime.from(value)
    .toZonedDateTime(Temporal.Now.timeZoneId())
    .toInstant();
  const epochMicros = instant.epochNanoseconds / 1_000n;
  if (epochMicros < 0n || epochMicros > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("permission instant is outside the API range");
  }
  return Number(epochMicros);
}
