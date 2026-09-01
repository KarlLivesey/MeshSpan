// SPDX-License-Identifier: GPL-2.0-only

import {
  Match,
  Switch,
  createEffect,
  createSignal,
  onCleanup,
  untrack,
  type ParentProps,
} from "solid-js";
import type { JSX } from "@solidjs/web";

import type { MeshSpanFetchClient } from "../generated/fetch.gen";
import type { SetupStatusResponse } from "../generated/types.gen";
import { FirstStartPage } from "../features/setup/FirstStartPage";

type GateState = SetupStatusResponse["state"] | "checking" | "unavailable";

export function ApplianceGate(
  props: ParentProps<Readonly<{ client: MeshSpanFetchClient }>>,
): JSX.Element {
  const [state, setState] = createSignal<GateState>("checking");

  const refresh = async (): Promise<void> => {
    try {
      setState((await props.client.getSetupStatus()).state);
    } catch {
      setState("unavailable");
    }
  };

  untrack(() => void refresh());

  return (
    <Switch>
      <Match when={state() === "configured"}>{props.children}</Match>
      <Match when={state() === "claim_required"}>
        <FirstStartPage
          client={props.client}
          onComplete={() => setState("configured")}
          onJoinAccepted={() => setState("configuring")}
        />
      </Match>
      <Match when={state() === "configuring"}>
        <SetupStatus
          automatic
          description="MeshSpan is resuming its durable create or join operation."
          heading="Finishing first start"
          refresh={refresh}
        />
      </Match>
      <Match when={state() === "unavailable"}>
        <SetupStatus
          description="The local daemon did not return a valid setup state."
          heading="MeshSpan is not ready"
          refresh={refresh}
        />
      </Match>
      <Match when={state() === "checking"}>
        <section class="setup-status" aria-live="polite">
          <p class="eyebrow">First-start check</p>
          <h1>Checking this appliance…</h1>
        </section>
      </Match>
    </Switch>
  );
}

function SetupStatus(
  props: Readonly<{
    automatic?: boolean;
    description: string;
    heading: string;
    refresh: () => Promise<void>;
  }>,
): JSX.Element {
  createEffect(
    () => props.automatic === true,
    (automatic) => {
      if (!automatic) {
        return;
      }
      const timer = window.setInterval(() => {
        void props.refresh();
      }, 2_000);
      onCleanup(() => {
        window.clearInterval(timer);
      });
    },
  );
  return (
    <section class="setup-status" aria-live="polite">
      <p class="eyebrow">First start</p>
      <h1>{props.heading}</h1>
      <p>{props.description}</p>
      <button
        class="quiet-button"
        onClick={() => void props.refresh()}
        type="button"
      >
        Check again
      </button>
    </section>
  );
}
