// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { CertificateStatusResponse } from "../../generated";
import type { CertificateStatusResource } from "./model";

type CurrentCertificateStatus = NonNullable<
  CertificateStatusResponse["certificate"]
>;

export function CertificateStatusCard(
  props: Readonly<{ resource: CertificateStatusResource }>,
): JSX.Element {
  return (
    <section
      class="topology-section"
      aria-labelledby="certificate-status-heading"
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">Current HTTPS identity</p>
          <h2 id="certificate-status-heading">Certificate status</h2>
        </div>
        <button
          class="quiet-action"
          disabled={props.resource.loading()}
          onClick={() => void props.resource.load()}
          type="button"
        >
          Refresh
        </button>
      </div>
      <Show when={props.resource.error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
      <Show
        when={!props.resource.loading()}
        fallback={<p class="skeleton-line">Reading certificate status…</p>}
      >
        <Show
          when={props.resource.value()?.certificate}
          fallback={<p>No HTTPS certificate has been configured.</p>}
        >
          {(certificate) => (
            <article class="topology-card certificate-status-card">
              <div>
                <span class={`state-pill state-${certificate().state}`}>
                  {stateLabel(certificate().state)}
                </span>
                <h3>{sourceLabel(certificate().source)}</h3>
                <p>
                  Installed on {certificate().installed_gateway_count} of{" "}
                  {certificate().required_gateway_count} gateways
                </p>
              </div>
              <small>
                Valid until{" "}
                {formatInstant(certificate().not_after_epoch_micros)}
              </small>
            </article>
          )}
        </Show>
      </Show>
    </section>
  );
}

function stateLabel(state: CurrentCertificateStatus["state"]): string {
  if (state === "active") return "Ready";
  if (state === "distributing") return "Distributing";
  if (state === "not_yet_valid") return "Not valid yet";
  return "Expired";
}

function sourceLabel(source: CurrentCertificateStatus["source"]): string {
  if (source === "acme") return "Publicly trusted certificate";
  if (source === "external") return "Externally issued certificate";
  return "Mesh-local certificate";
}

function formatInstant(epochMicros: number): string {
  return instantFromEpochMicroseconds(epochMicros).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
