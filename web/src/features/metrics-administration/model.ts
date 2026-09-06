// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor, type Setter } from "solid-js";
import type {
  ConfigureMetricsExporterRequest,
  ConfigureMetricsExporterResponse,
  MeshSpanFetchClient,
  MetricsExporterResponse,
} from "../../generated";
import { zConfigureMetricsExporterBody } from "../../generated/zod.gen";
import { MeshSpanApiError } from "../../generated/fetch.gen";

export type MetricsClient = Pick<
  MeshSpanFetchClient,
  | "getMetricsExporter"
  | "configureMetricsExporter"
  | "listUsers"
  | "listNextPrincipals"
>;
export type MetricsAdministration = Readonly<{
  configuration: Accessor<MetricsExporterResponse | undefined>;
  busy: Accessor<boolean>;
  pending: Accessor<ConfigureMetricsExporterRequest | undefined>;
  message: Accessor<string | undefined>;
  error: Accessor<string | undefined>;
  load: () => Promise<void>;
  save: (enabled: boolean, principals: readonly string[]) => Promise<void>;
  retry: () => Promise<void>;
}>;

/** Owns one mounted view and its exact request; navigation cannot apply late results. */
export function createMetricsAdministration(
  client: Accessor<MetricsClient>,
  csrf: Accessor<string>,
): MetricsAdministration {
  const controller = new MetricsController(client, csrf);
  onCleanup(controller.dispose);
  return controller;
}

/** Separate operations share admission and receipt state, not nested callback closures. */
class MetricsController implements MetricsAdministration {
  private readonly view = createOwnedField<MetricsExporterResponse | undefined>(
    undefined,
  );
  private readonly working = createOwnedField(false);
  private readonly change = createOwnedField<
    ConfigureMetricsExporterRequest | undefined
  >(undefined);
  private readonly notice = createOwnedField<string | undefined>(undefined);
  private readonly failure = createOwnedField<string | undefined>(undefined);
  private alive = true;
  private inFlight = false;
  private unresolved: ConfigureMetricsExporterRequest | undefined;
  readonly configuration = this.view.read;
  readonly busy = this.working.read;
  readonly pending = this.change.read;
  readonly message = this.notice.read;
  readonly error = this.failure.read;

  constructor(
    private readonly client: Accessor<MetricsClient>,
    private readonly csrf: Accessor<string>,
  ) {}

  readonly dispose = (): void => {
    this.alive = false;
  };

  readonly load = async (): Promise<void> => {
    if (!this.isMounted() || this.inFlight || this.unresolved !== undefined)
      return;
    this.inFlight = true;
    this.working.write(true);
    this.failure.write();
    this.view.write();
    await this.refresh();
    this.inFlight = false;
    if (this.isMounted()) this.working.write(false);
  };

  readonly save = async (
    enabled: boolean,
    principals: readonly string[],
  ): Promise<void> => {
    const current = this.configuration();
    if (
      !this.isMounted() ||
      this.inFlight ||
      this.unresolved !== undefined ||
      current === undefined
    )
      return;
    if (enabled && principals.length === 0) {
      this.failure.write(
        "Choose at least one user before enabling metrics access.",
      );
      return;
    }
    const parsed = zConfigureMetricsExporterBody.safeParse({
      operation_id: crypto.randomUUID(),
      expected_sequence: current.configuration?.sequence ?? 0,
      policy: {
        enabled,
        allowed_principals: [...new Set(principals)].toSorted((left, right) =>
          left.localeCompare(right),
        ),
      },
    });
    if (!parsed.success) {
      this.failure.write("Choose at most 64 valid users for metrics access.");
      return;
    }
    this.unresolved = parsed.data;
    this.change.write(parsed.data);
    await this.execute(parsed.data);
  };

  readonly retry = async (): Promise<void> => {
    if (this.unresolved !== undefined) await this.execute(this.unresolved);
  };

  private async execute(
    request: ConfigureMetricsExporterRequest,
  ): Promise<void> {
    if (!this.isMounted() || this.inFlight) return;
    this.inFlight = true;
    this.working.write(true);
    this.failure.write();
    this.notice.write();
    try {
      const receipt = await this.client().configureMetricsExporter(
        request,
        this.csrf(),
      );
      validateReceipt(request, receipt);
      this.unresolved = undefined;
      if (!this.isMounted()) return;
      this.change.write();
      this.notice.write("Metrics settings saved.");
      this.view.write();
      await this.refresh();
    } catch (error: unknown) {
      if (
        error instanceof MeshSpanApiError &&
        error.apiError?.code === "operation_conflict"
      ) {
        this.unresolved = undefined;
        if (!this.isMounted()) return;
        this.change.write();
        this.view.write();
        await this.refresh();
        this.failure.write(
          "The policy changed before this edit could be saved. Review the refreshed settings and try again.",
        );
      } else if (this.isMounted())
        this.failure.write(
          "The change is not confirmed. Check your access and retry the same change to establish its outcome.",
        );
    } finally {
      this.inFlight = false;
      if (this.isMounted()) this.working.write(false);
    }
  }

  private isMounted(): boolean {
    return this.alive;
  }

  private async refresh(): Promise<void> {
    try {
      const value = await this.client().getMetricsExporter();
      if (this.isMounted()) this.view.write(value);
    } catch {
      if (this.isMounted())
        this.failure.write(
          "Could not read current metrics settings. Refresh when the node is reachable before editing again.",
        );
    }
  }
}

function validateReceipt(
  request: ConfigureMetricsExporterRequest,
  receipt: ConfigureMetricsExporterResponse,
): void {
  if (
    receipt.operation_id !== request.operation_id ||
    receipt.sequence !== request.expected_sequence + 1 ||
    receipt.committed_revision <= 0
  )
    throw new TypeError("Metrics receipt does not match the request.");
}

function createOwnedField<T>(
  initial: T,
): Readonly<{ read: Accessor<T>; write: Setter<T> }> {
  const [read, write] = createSignal<T>(() => initial, { ownedWrite: true });
  return { read, write };
}
