// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor, type Setter } from "solid-js";

import type { RegisterStorageFolderRequest } from "../../generated";

type UsageLimit = RegisterStorageFolderRequest["usage_limit"];
type LimitKind = UsageLimit["kind"];
export type FixedCapacityUnit = "MiB" | "GiB" | "TiB";

const UNIT_BYTES: Readonly<Record<FixedCapacityUnit, bigint>> = {
  GiB: 1024n ** 3n,
  MiB: 1024n ** 2n,
  TiB: 1024n ** 4n,
};
const MAXIMUM_FIXED_BYTES = 9_223_372_036_854_775_807n;

export type StorageCapacitySelection = Readonly<{
  fixedAmount: Accessor<string>;
  fixedUnit: Accessor<FixedCapacityUnit>;
  kind: Accessor<LimitKind>;
  percent: Accessor<string>;
  setFixedAmount: Setter<string>;
  setFixedUnit: Setter<FixedCapacityUnit>;
  setKind: Setter<LimitKind>;
  setPercent: Setter<string>;
  value: () => UsageLimit | undefined;
}>;

export function createStorageCapacitySelection(): StorageCapacitySelection {
  const [kind, setKind] = createSignal<LimitKind>("percent");
  const [percent, setPercent] = createSignal("95");
  const [fixedAmount, setFixedAmount] = createSignal("100");
  const [fixedUnit, setFixedUnit] = createSignal<FixedCapacityUnit>("GiB");
  const value = (): UsageLimit | undefined =>
    parseUsageLimit(kind(), percent(), fixedAmount(), fixedUnit());
  return {
    fixedAmount,
    fixedUnit,
    kind,
    percent,
    setFixedAmount,
    setFixedUnit,
    setKind,
    setPercent,
    value,
  };
}

function parseUsageLimit(
  kind: LimitKind,
  percent: string,
  fixedAmount: string,
  fixedUnit: FixedCapacityUnit,
): UsageLimit | undefined {
  if (kind === "percent") {
    const value = Number(percent);
    return Number.isInteger(value) && value >= 1 && value <= 100
      ? { kind, percent: value }
      : undefined;
  }
  if (!/^[1-9]\d*$/u.test(fixedAmount)) return undefined;
  const bytes = BigInt(fixedAmount) * UNIT_BYTES[fixedUnit];
  return bytes <= MAXIMUM_FIXED_BYTES
    ? { bytes: bytes.toString(), kind }
    : undefined;
}
