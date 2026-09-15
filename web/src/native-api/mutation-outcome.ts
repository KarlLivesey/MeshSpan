// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

export type MutationOutcome<Receipt> =
  | Readonly<{ phase: "idle" }>
  | Readonly<{ phase: "submitting" | "unknown"; operationId: string }>
  | Readonly<{ phase: "committed"; receipt: Receipt; refreshWarning?: string }>;

export type ExactMutation<Request, Receipt> = Readonly<{
  locked: Accessor<boolean>;
  busy: Accessor<boolean>;
  state: Accessor<MutationOutcome<Receipt>>;
  submit: (request: Request) => Promise<void>;
  retry: () => Promise<void>;
}>;

/** Retains one private request snapshot across uncertain responses, only in memory. */
export function createExactMutation<
  Request extends { operation_id: string },
  Receipt,
>(
  send: (request: Request) => Promise<Receipt>,
  verify: (receipt: Receipt, request: Request) => void,
  refresh: () => Promise<void>,
): ExactMutation<Request, Receipt> {
  const [state, setState] = createSignal<MutationOutcome<Receipt>>(
    { phase: "idle" },
    { ownedWrite: true },
  );
  const [busy, setBusy] = createSignal(false, { ownedWrite: true });
  let retained: Request | undefined;
  let inFlight = false;
  const execute = async (): Promise<void> => {
    if (inFlight || retained === undefined) return;
    const request = retained;
    inFlight = true;
    setBusy(true);
    setState({ phase: "submitting", operationId: request.operation_id });
    try {
      // Neither caller edits nor a transport mutating its argument can change retry bytes.
      const receipt = await send(structuredClone(request));
      verify(receipt, request);
      retained = undefined;
      setState({ phase: "committed", receipt });
      try {
        await refresh();
      } catch {
        setState({
          phase: "committed",
          receipt,
          refreshWarning: "Saved; the current view could not refresh.",
        });
      }
    } catch {
      // An exception alone cannot establish rollback, including malformed receipts.
      setState({ phase: "unknown", operationId: request.operation_id });
    } finally {
      inFlight = false;
      setBusy(false);
    }
  };
  return {
    busy,
    locked: () => busy() || state().phase === "unknown",
    state,
    retry: execute,
    submit: async (request) => {
      if (inFlight || retained !== undefined) return;
      retained = structuredClone(request);
      await execute();
    },
  };
}

/** Describes only the outcome established by the receipt boundary. */
export function mutationMessage(
  state: MutationOutcome<unknown>,
): string | undefined {
  switch (state.phase) {
    case "unknown":
      return `The result is unknown. Retry the pending change to confirm operation ${state.operationId}.`;
    case "committed":
      return state.refreshWarning;
    case "idle":
    case "submitting":
      return undefined;
  }
}
