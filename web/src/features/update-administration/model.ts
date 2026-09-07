// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor, type Setter } from "solid-js";
import type {
  ManageUpdateRequest,
  ManageUpdateResponse,
  MeshSpanFetchClient,
  UpdatesResponse,
} from "../../generated";
import { zManageUpdateBody } from "../../generated/zod.gen";
import { MeshSpanApiError } from "../../generated/fetch.gen";

export type UpdateClient = Pick<
  MeshSpanFetchClient,
  "getUpdates" | "manageUpdate" | "stageUpdateArtifact"
>;
export type UpdateModel = Readonly<{
  status: Accessor<UpdatesResponse | undefined>;
  busy: Accessor<boolean>;
  pending: Accessor<boolean>;
  message: Accessor<string>;
  error: Accessor<string>;
  load: () => Promise<void>;
  save: (input: unknown) => Promise<boolean>;
  retry: () => Promise<void>;
}>;

/** Owns the mounted view and exact in-memory retry; no request is persisted in browser storage. */
export function createUpdateModel(
  client: Accessor<UpdateClient>,
  csrf: Accessor<string>,
): UpdateModel {
  const controller = new UpdateController(client, csrf);
  onCleanup(controller.dispose);
  return controller;
}

class UpdateController implements UpdateModel {
  private readonly view = owned<UpdatesResponse | undefined>(undefined);
  private readonly working = owned(false);
  private readonly change = owned(false);
  private readonly notice = owned("");
  private readonly failure = owned("");
  private alive = true;
  private inFlight = false;
  private unresolved: ManageUpdateRequest | undefined;
  private selectedRollout: string | undefined;
  readonly status = this.view.read;
  readonly busy = this.working.read;
  readonly pending = this.change.read;
  readonly message = this.notice.read;
  readonly error = this.failure.read;

  constructor(
    private readonly client: Accessor<UpdateClient>,
    private readonly csrf: Accessor<string>,
  ) {}

  readonly dispose = (): void => {
    this.alive = false;
    this.unresolved = undefined;
  };

  readonly load = async (): Promise<void> => {
    if (!this.mounted() || this.inFlight || this.unresolved !== undefined)
      return;
    this.inFlight = true;
    this.working.write(true);
    this.failure.write("");
    this.view.write(undefined);
    await this.refresh();
    this.inFlight = false;
    if (this.mounted()) this.working.write(false);
  };

  readonly save = async (input: unknown): Promise<boolean> => {
    if (
      !this.mounted() ||
      this.inFlight ||
      this.unresolved !== undefined ||
      this.status() === undefined
    )
      return false;
    const parsed = zManageUpdateBody.safeParse(input);
    if (!parsed.success) {
      this.failure.write(
        "Check the publisher key, signed candidate and selected action.",
      );
      return false;
    }
    this.unresolved = parsed.data;
    this.change.write(true);
    return this.execute(parsed.data);
  };

  readonly retry = async (): Promise<void> => {
    if (this.unresolved !== undefined) await this.execute(this.unresolved);
  };

  private async execute(request: ManageUpdateRequest): Promise<boolean> {
    if (!this.mounted() || this.inFlight) return false;
    this.inFlight = true;
    this.working.write(true);
    this.failure.write("");
    this.notice.write("");
    try {
      validateReceipt(
        request,
        await this.client().manageUpdate(request, this.csrf()),
      );
      this.unresolved = undefined;
      if (!this.mounted()) return false;
      this.change.write(false);
      if (request.action.kind !== "configure_signer")
        this.selectedRollout = request.action.rollout_id;
      this.notice.write(
        "Update command saved. This does not confirm installation.",
      );
      this.view.write(undefined);
      await this.refresh();
      return true;
    } catch (failure: unknown) {
      if (this.mounted()) await this.recordFailure(failure);
      return false;
    } finally {
      this.inFlight = false;
      if (this.mounted()) this.working.write(false);
    }
  }

  private async recordFailure(failure: unknown): Promise<void> {
    if (
      failure instanceof MeshSpanApiError &&
      failure.apiError?.code === "operation_conflict"
    ) {
      this.unresolved = undefined;
      this.change.write(false);
      this.view.write(undefined);
      await this.refresh();
      if (this.mounted())
        this.failure.write(
          "The update command was rejected. Check the refreshed trust and rollout state before submitting a new change.",
        );
    } else
      this.failure.write(
        "This change is not confirmed. Retry the same change to establish its outcome.",
      );
  }

  private async refresh(): Promise<void> {
    try {
      const response = await this.client().getUpdates(this.selectedRollout);
      if (this.mounted()) this.view.write(response);
    } catch {
      if (this.mounted())
        this.failure.write(
          "Could not read update settings. Refresh when this node is reachable.",
        );
    }
  }

  private mounted(): boolean {
    return this.alive;
  }
}

function validateReceipt(
  request: ManageUpdateRequest,
  receipt: ManageUpdateResponse,
): void {
  if (
    receipt.operation_id !== request.operation_id ||
    receipt.resource_id !==
      (request.action.kind === "configure_signer"
        ? request.action.signer_id
        : request.action.rollout_id) ||
    receipt.committed_revision <= 0
  )
    throw new TypeError("Update receipt does not match this change.");
}

function owned<T>(
  initial: T,
): Readonly<{ read: Accessor<T>; write: Setter<T> }> {
  const [read, write] = createSignal<T>(() => initial, { ownedWrite: true });
  return { read, write };
}
