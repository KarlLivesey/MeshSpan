// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it, vi } from "vitest";
import { createExactMutation } from "../src/native-api/mutation-outcome";

interface Request {
  operation_id: string;
  fields: { name: string };
}
interface Receipt {
  operation_id: string;
  revision: number;
}
const request = (): Request => ({
  operation_id: "attempt-one",
  fields: { name: "Original" },
});
const verify = (receipt: Receipt, input: Request): void => {
  if (receipt.operation_id !== input.operation_id)
    throw new Error("receipt mismatch");
};

describe("retained exact mutation outcomes", () => {
  it("replays the private snapshot after response loss and refuses changed submissions", async () => {
    const send = vi
      .fn<(input: Request) => Promise<Receipt>>()
      .mockRejectedValueOnce(new Error("lost response"))
      .mockResolvedValue({ operation_id: "attempt-one", revision: 7 });
    const mutation = createExactMutation(send, verify, async () => undefined);
    const input = request();
    await mutation.submit(input);
    input.fields.name = "Edited";
    await mutation.submit({
      operation_id: "attempt-two",
      fields: { name: "Changed" },
    });
    expect(mutation.state()).toEqual({
      phase: "unknown",
      operationId: "attempt-one",
    });
    expect(send).toHaveBeenCalledTimes(1);
    await mutation.retry();
    expect(send.mock.calls).toEqual([[request()], [request()]]);
    expect(mutation.state()).toEqual({
      phase: "committed",
      receipt: { operation_id: "attempt-one", revision: 7 },
    });
    expect(mutation.locked()).toBe(false);
  });

  it("preserves a verified receipt when refreshing fails", async () => {
    const mutation = createExactMutation(
      async () => ({ operation_id: "attempt-one", revision: 7 }),
      verify,
      async () => {
        throw new Error("read unavailable");
      },
    );
    await mutation.submit(request());
    expect(mutation.state()).toEqual({
      phase: "committed",
      receipt: { operation_id: "attempt-one", revision: 7 },
      refreshWarning: "Saved; the current view could not refresh.",
    });
  });

  it("keeps a mismatched receipt unknown and does not refresh", async () => {
    const refresh = vi.fn(async () => undefined);
    const mutation = createExactMutation(
      async () => ({ operation_id: "other", revision: 9 }),
      verify,
      refresh,
    );
    await mutation.submit(request());
    expect(mutation.state()).toEqual({
      phase: "unknown",
      operationId: "attempt-one",
    });
    expect(refresh).not.toHaveBeenCalled();
    expect(mutation.locked()).toBe(true);
  });

  it("admits only one send before a reactive render can run", async () => {
    const deferred = Promise.withResolvers<Receipt>();
    const send = vi.fn(async () => deferred.promise);
    const mutation = createExactMutation(send, verify, async () => undefined);
    const first = mutation.submit(request());
    await mutation.retry();
    await mutation.submit(request());
    expect(send).toHaveBeenCalledTimes(1);
    deferred.resolve({ operation_id: "attempt-one", revision: 7 });
    await first;
    expect(mutation.state().phase).toBe("committed");
  });
});
