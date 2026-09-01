// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor, type Setter } from "solid-js";

import type {
  CreateVolumePermissionGrantRequest,
  CreateVolumePermissionGrantResponse,
} from "../../generated/types.gen";
import type { PermissionGrantClient } from "./permission-grant-model";

export type AccessLevel = "edit" | "manage" | "view";
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

export type PermissionGrantFormModel = Readonly<{
  activationHours: Accessor<string>;
  activationRequired: Accessor<boolean>;
  error: Accessor<string | undefined>;
  level: Accessor<AccessLevel>;
  pending: Accessor<boolean>;
  principalId: Accessor<string>;
  setActivationHours: Setter<string>;
  setActivationRequired: Setter<boolean>;
  setLevel: Setter<AccessLevel>;
  setPrincipalId: Setter<string>;
  setValidFrom: Setter<string>;
  setValidUntil: Setter<string>;
  submit: () => Promise<void>;
  success: Accessor<string | undefined>;
  validFrom: Accessor<string>;
  validUntil: Accessor<string>;
}>;

export function createPermissionGrantFormModel(
  input: Readonly<{
    client: PermissionGrantClient;
    csrfToken: string;
    onCommitted: (response: CreateVolumePermissionGrantResponse) => void;
    volumeId: string;
  }>,
): PermissionGrantFormModel {
  const fields = createFields();
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();
  const submit = async (): Promise<void> => {
    if (pending() || fields.principalId().length === 0) {
      setError("Choose a user or group.");
      return;
    }
    let request: CreateVolumePermissionGrantRequest;
    try {
      request = buildRequest(fields);
    } catch {
      setError("Check the validity window and activation duration.");
      return;
    }
    setPending(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      const response = await input.client.createVolumePermissionGrant(
        input.volumeId,
        request,
        input.csrfToken,
      );
      input.onCommitted(response);
      setSuccess("Access is committed across the swarm.");
    } catch {
      setError("MeshSpan could not commit this access grant.");
    } finally {
      setPending(false);
    }
  };
  return { ...fields, error, pending, submit, success };
}

function createFields() {
  const [principalId, setPrincipalId] = createSignal("");
  const [level, setLevel] = createSignal<AccessLevel>("edit");
  const [validFrom, setValidFrom] = createSignal("");
  const [validUntil, setValidUntil] = createSignal("");
  const [activationRequired, setActivationRequired] = createSignal(false);
  const [activationHours, setActivationHours] = createSignal("1");
  return {
    activationHours,
    activationRequired,
    level,
    principalId,
    setActivationHours,
    setActivationRequired,
    setLevel,
    setPrincipalId,
    setValidFrom,
    setValidUntil,
    validFrom,
    validUntil,
  };
}

function buildRequest(
  fields: ReturnType<typeof createFields>,
): CreateVolumePermissionGrantRequest {
  const from = localDateTimeToEpochMicros(fields.validFrom());
  const until = localDateTimeToEpochMicros(fields.validUntil());
  if (from !== null && until !== null && until <= from) {
    throw new RangeError("permission validity window is reversed");
  }
  const hours = Number(fields.activationHours());
  if (
    fields.activationRequired() &&
    (!Number.isFinite(hours) || hours <= 0 || hours > 8_760)
  ) {
    throw new RangeError("activation duration is invalid");
  }
  return {
    activation: fields.activationRequired()
      ? {
          maximum_duration_micros: Math.round(hours * 3_600_000_000),
          minimum_assurance: "single_factor",
          reason_required: true,
        }
      : null,
    inheritance: "object_and_descendants",
    operation_id: crypto.randomUUID(),
    rights: [...RIGHTS[fields.level()]],
    subject_principal_id: fields.principalId(),
    valid_from_epoch_micros: from,
    valid_until_epoch_micros: until,
  };
}

function localDateTimeToEpochMicros(value: string): number | null {
  if (value.length === 0) return null;
  const instant = Temporal.PlainDateTime.from(value)
    .toZonedDateTime(Temporal.Now.timeZoneId())
    .toInstant();
  const epochMicros = instant.epochNanoseconds / 1_000n;
  if (epochMicros < 0n || epochMicros > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("permission instant is outside the API range");
  }
  return Number(epochMicros);
}
