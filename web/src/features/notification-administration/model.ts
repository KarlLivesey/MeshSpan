// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor, type Setter } from "solid-js";
import type {
  ConfigureNotificationRequest,
  ConfigureNotificationResponse,
  MeshSpanFetchClient,
  NotificationsResponse,
} from "../../generated";
import { zConfigureNotificationBody } from "../../generated/zod.gen";
import { MeshSpanApiError } from "../../generated/fetch.gen";

export type NotificationClient = Pick<
  MeshSpanFetchClient,
  "getNotifications" | "configureNotification"
>;
export type NotificationModel = Readonly<{
  status: Accessor<NotificationsResponse | undefined>;
  busy: Accessor<boolean>;
  pending: Accessor<boolean>;
  message: Accessor<string>;
  error: Accessor<string>;
  load: () => Promise<void>;
  save: (input: unknown) => Promise<boolean>;
  retry: () => Promise<void>;
}>;

/** Owns the mounted view and exact in-memory retry; credentials never enter browser storage. */
export function createNotificationModel(
  client: Accessor<NotificationClient>,
  csrf: Accessor<string>,
): NotificationModel {
  const controller = new NotificationController(client, csrf);
  onCleanup(controller.dispose);
  return controller;
}

class NotificationController implements NotificationModel {
  private readonly view = owned<NotificationsResponse | undefined>(undefined);
  private readonly working = owned(false);
  private readonly change = owned(false);
  private readonly notice = owned("");
  private readonly failure = owned("");
  private alive = true;
  private inFlight = false;
  private unresolved: ConfigureNotificationRequest | undefined;
  readonly status = this.view.read;
  readonly busy = this.working.read;
  readonly pending = this.change.read;
  readonly message = this.notice.read;
  readonly error = this.failure.read;

  constructor(
    private readonly client: Accessor<NotificationClient>,
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
    const parsed = zConfigureNotificationBody.safeParse(input);
    if (!parsed.success) {
      this.failure.write(
        "Check the destination, credentials and selected events. HTTPS and encrypted email submission are required.",
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

  private async execute(
    request: ConfigureNotificationRequest,
  ): Promise<boolean> {
    if (!this.mounted() || this.inFlight) return false;
    this.inFlight = true;
    this.working.write(true);
    this.failure.write("");
    this.notice.write("");
    try {
      validateReceipt(
        request,
        await this.client().configureNotification(request, this.csrf()),
      );
      this.unresolved = undefined;
      if (!this.mounted()) return false;
      this.change.write(false);
      this.notice.write("Notification settings saved.");
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
          "Settings changed before this edit was saved. Reopen the channel using its refreshed settings.",
        );
    } else
      this.failure.write(
        "This change is not confirmed. Retry the same change to establish its outcome.",
      );
  }

  private async refresh(): Promise<void> {
    try {
      const response = await this.client().getNotifications();
      if (this.mounted()) this.view.write(response);
    } catch {
      if (this.mounted())
        this.failure.write(
          "Could not read notification settings. Refresh when this node is reachable.",
        );
    }
  }

  private mounted(): boolean {
    return this.alive;
  }
}

function validateReceipt(
  request: ConfigureNotificationRequest,
  receipt: ConfigureNotificationResponse,
): void {
  if (
    receipt.operation_id !== request.operation_id ||
    receipt.sequence !== request.expected_sequence + 1 ||
    receipt.committed_revision <= 0
  )
    throw new TypeError("Notification receipt does not match this change.");
}

function owned<T>(
  initial: T,
): Readonly<{ read: Accessor<T>; write: Setter<T> }> {
  const [read, write] = createSignal<T>(() => initial, { ownedWrite: true });
  return { read, write };
}
