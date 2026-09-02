// SPDX-License-Identifier: GPL-2.0-only

import { createEffect, createSignal, type Accessor, type Setter } from "solid-js";

import type { PublishSmbExportResponse } from "../../generated/types.gen";
import type { AdminVolume, VolumeAdministrationClient } from "./model";

type SmbExportContext = Readonly<{
  client: VolumeAdministrationClient;
  csrfToken: string;
  volume: AdminVolume;
}>;

export type SmbExportModel = Readonly<{
  encryptionRequired: Accessor<boolean>;
  error: Accessor<string | undefined>;
  pending: Accessor<"publish" | "withdraw" | undefined>;
  publication: Accessor<PublishSmbExportResponse | undefined>;
  publish: () => Promise<void>;
  setEncryptionRequired: Setter<boolean>;
  setShareName: Setter<string>;
  setWithdrawalReason: Setter<string>;
  shareName: Accessor<string>;
  withdraw: () => Promise<void>;
  withdrawalReason: Accessor<string>;
}>;

export function createSmbExportModel(context: SmbExportContext): SmbExportModel {
  const [shareName, setShareName] = createSignal("");
  const [encryptionRequired, setEncryptionRequired] = createSignal(true);
  const [publication, setPublication] = createSignal<PublishSmbExportResponse>();
  const [withdrawalReason, setWithdrawalReason] = createSignal("");
  const [pending, setPending] = createSignal<"publish" | "withdraw">();
  const [error, setError] = createSignal<string>();

  createEffect(
    () => context.volume,
    (volume) => {
      setShareName(volume.name);
      setEncryptionRequired(true);
      setPublication(undefined);
      setWithdrawalReason("");
      setPending(undefined);
      setError(undefined);
    },
  );

  const publish = async (): Promise<void> => {
    const name = shareName().trim();
    if (name.length === 0 || pending() !== undefined) {
      setError("Enter an SMB share name.");
      return;
    }
    setPending("publish");
    setError(undefined);
    try {
      setPublication(await publishExport(context, name, encryptionRequired()));
    } catch {
      setError("MeshSpan could not publish this SMB share.");
    } finally {
      setPending(undefined);
    }
  };

  const withdraw = async (): Promise<void> => {
    const current = publication();
    const reason = withdrawalReason().trim();
    if (current === undefined || reason.length === 0 || pending() !== undefined) {
      setError("Enter a reason before withdrawing the share.");
      return;
    }
    setPending("withdraw");
    setError(undefined);
    try {
      await context.client.withdrawSmbExport(
        current.export_id,
        { operation_id: crypto.randomUUID(), reason },
        context.csrfToken,
      );
      setPublication(undefined);
      setWithdrawalReason("");
    } catch {
      setError("MeshSpan could not withdraw this SMB share.");
    } finally {
      setPending(undefined);
    }
  };

  return {
    encryptionRequired,
    error,
    pending,
    publication,
    publish,
    setEncryptionRequired,
    setShareName,
    setWithdrawalReason,
    shareName,
    withdraw,
    withdrawalReason,
  };
}

async function publishExport(
  context: SmbExportContext,
  shareName: string,
  encryptionRequired: boolean,
): Promise<PublishSmbExportResponse> {
  return context.client.publishSmbExport(
    context.volume.volumeId,
    {
      encryption_required: encryptionRequired,
      gateways: { kind: "all_eligible" },
      operation_id: crypto.randomUUID(),
      root_object_id: context.volume.rootObjectId,
      share_name: shareName,
    },
    context.csrfToken,
  );
}
