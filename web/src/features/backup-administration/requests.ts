// SPDX-License-Identifier: GPL-2.0-only

import type {
  ConfigureBackupDestinationRequest,
  ConfigureBackupScheduleRequest,
} from "../../generated";
import {
  zConfigureBackupDestinationBody,
  zConfigureBackupScheduleBody,
} from "../../generated/zod.gen";
import type { BackupDestination, BackupTarget } from "./model";

export function scheduleRequest(
  form: FormData,
  expectedSequence: number,
): ConfigureBackupScheduleRequest {
  const request = zConfigureBackupScheduleBody.parse({
    operation_id: crypto.randomUUID(),
    expected_sequence: expectedSequence,
    policy: {
      enabled: form.has("enabled"),
      interval_seconds: integer(form, "interval_seconds"),
      retained_generations: integer(form, "retained_generations"),
      minimum_verified_copies: integer(form, "minimum_verified_copies"),
      minimum_independent_copies: integer(form, "minimum_independent_copies"),
    },
  });
  if (
    request.policy.minimum_independent_copies >
    request.policy.minimum_verified_copies
  ) {
    throw new RangeError(
      "Independent copies cannot exceed the required verified copies.",
    );
  }
  return request;
}

export function destinationRequest(
  form: FormData,
  targets: readonly BackupTarget[],
): ConfigureBackupDestinationRequest {
  const targetId = form.get("target_id");
  const target = targets.find(
    (item) => item.target_id === targetId && item.state === "active",
  );
  if (target === undefined)
    throw new TypeError("Choose an active registered folder.");
  return zConfigureBackupDestinationBody.parse({
    operation_id: crypto.randomUUID(),
    destination_id: crypto.randomUUID(),
    expected_revision: 0,
    name: form.get("name"),
    target_id: target.target_id,
    target_generation: target.generation,
    enabled: true,
  });
}

export function toggleDestination(
  destination: BackupDestination,
): ConfigureBackupDestinationRequest {
  if (
    destination.provider.kind !== "registered_target" ||
    destination.state === "retired"
  ) {
    throw new TypeError(
      "This destination cannot be changed through registered-folder controls.",
    );
  }
  return zConfigureBackupDestinationBody.parse({
    operation_id: crypto.randomUUID(),
    destination_id: destination.destination_id,
    expected_revision: destination.revision,
    name: destination.name,
    target_id: destination.provider.target_id,
    target_generation: destination.provider_generation,
    enabled: destination.state === "paused",
  });
}

function integer(form: FormData, name: string): number {
  const value = form.get(name);
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)$/u.test(value)) {
    throw new TypeError("Enter whole numbers without fractions or separators.");
  }
  const result = Number(value);
  if (!Number.isSafeInteger(result))
    throw new RangeError("That number is too large.");
  return result;
}
