// SPDX-License-Identifier: GPL-2.0-only

import { Match, Switch } from "solid-js";
import type { JSX } from "@solidjs/web";

import type {
  FixedCapacityUnit,
  StorageCapacitySelection,
} from "./storage-capacity";

export function StorageCapacityFields(
  props: Readonly<{
    disabled: boolean;
    selection: StorageCapacitySelection;
  }>,
): JSX.Element {
  return (
    <fieldset class="owner-fields" disabled={props.disabled}>
      <legend>Maximum capacity</legend>
      <label class="check-field">
        <input
          checked={props.selection.kind() === "percent"}
          name="limit-kind"
          onChange={() => props.selection.setKind("percent")}
          type="radio"
        />
        <span>Percentage of this filesystem</span>
      </label>
      <label class="check-field">
        <input
          checked={props.selection.kind() === "bytes"}
          name="limit-kind"
          onChange={() => props.selection.setKind("bytes")}
          type="radio"
        />
        <span>Fixed capacity</span>
      </label>
      <Switch>
        <Match when={props.selection.kind() === "percent"}>
          <label class="volume-name-field">
            <span>Percent</span>
            <input
              inputmode="numeric"
              max="100"
              min="1"
              onInput={(event) =>
                props.selection.setPercent(event.currentTarget.value)
              }
              type="number"
              value={props.selection.percent()}
            />
          </label>
        </Match>
        <Match when={props.selection.kind() === "bytes"}>
          <FixedCapacityFields selection={props.selection} />
        </Match>
      </Switch>
    </fieldset>
  );
}

function FixedCapacityFields(
  props: Readonly<{ selection: StorageCapacitySelection }>,
): JSX.Element {
  return (
    <div class="capacity-fields">
      <label class="volume-name-field">
        <span>Amount</span>
        <input
          inputmode="numeric"
          min="1"
          onInput={(event) =>
            props.selection.setFixedAmount(event.currentTarget.value)
          }
          type="number"
          value={props.selection.fixedAmount()}
        />
      </label>
      <label class="volume-name-field">
        <span>Unit</span>
        <select
          onChange={(event) =>
            props.selection.setFixedUnit(
              event.currentTarget.value as FixedCapacityUnit,
            )
          }
          value={props.selection.fixedUnit()}
        >
          <option value="MiB">MiB</option>
          <option value="GiB">GiB</option>
          <option value="TiB">TiB</option>
        </select>
      </label>
    </div>
  );
}
