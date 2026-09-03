// SPDX-License-Identifier: GPL-2.0-only

import { Match, Switch } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { CertificateChallengeKind } from "./certificate-request";

export function CertificateChallengeFields(
  props: Readonly<{
    disabled: boolean;
    kind: CertificateChallengeKind;
    setKind: (kind: CertificateChallengeKind) => void;
  }>,
): JSX.Element {
  return (
    <fieldset class="certificate-challenge-fields" disabled={props.disabled}>
      <legend>Domain control</legend>
      <label>
        <span>Challenge method</span>
        <select
          name="challenge_kind"
          onChange={(event) => {
            props.setKind(
              event.currentTarget.value as CertificateChallengeKind,
            );
          }}
          value={props.kind}
        >
          <option value="http01">HTTP-01</option>
          <option value="dns01_cloudflare">DNS-01 · Cloudflare</option>
          <option value="dns01_rfc2136">DNS-01 · RFC 2136</option>
          <option value="dns01_webhook">DNS-01 · Webhook</option>
          <option value="dns01_manual">DNS-01 · Manual</option>
        </select>
      </label>
      <ChallengeExplanation kind={props.kind} />
      <Switch>
        <Match when={props.kind === "dns01_cloudflare"}>
          <CloudflareFields />
        </Match>
        <Match when={props.kind === "dns01_rfc2136"}>
          <Rfc2136Fields />
        </Match>
        <Match when={props.kind === "dns01_webhook"}>
          <WebhookFields />
        </Match>
      </Switch>
    </fieldset>
  );
}

function ChallengeExplanation(
  props: Readonly<{ kind: CertificateChallengeKind }>,
): JSX.Element {
  return (
    <Switch>
      <Match when={props.kind === "http01"}>
        <p class="field-note-reset">MeshSpan answers port 80 automatically.</p>
      </Match>
      <Match when={props.kind === "dns01_manual"}>
        <p class="field-note-reset">
          MeshSpan shows each exact TXT record below. Renewal needs
          administrator action.
        </p>
      </Match>
      <Match when={true}>
        <p class="field-note-reset">
          MeshSpan publishes and removes the required TXT records automatically.
        </p>
      </Match>
    </Switch>
  );
}

function CloudflareFields(): JSX.Element {
  return (
    <div class="certificate-provider-grid">
      <label>
        <span>Zone ID</span>
        <input
          autocomplete="off"
          maxlength="32"
          name="cloudflare_zone_id"
          required
          spellcheck={false}
        />
      </label>
      <SecretField label="Scoped API token" name="cloudflare_api_token" />
    </div>
  );
}

function Rfc2136Fields(): JSX.Element {
  return (
    <div class="certificate-provider-grid">
      <label>
        <span>DNS server</span>
        <input
          autocomplete="off"
          maxlength="128"
          name="rfc2136_server"
          placeholder="192.0.2.53:53"
          required
          spellcheck={false}
        />
      </label>
      <label>
        <span>Zone</span>
        <input
          maxlength="253"
          name="rfc2136_zone"
          required
          spellcheck={false}
        />
      </label>
      <label>
        <span>TSIG key name</span>
        <input
          autocomplete="off"
          maxlength="253"
          name="rfc2136_key_name"
          required
          spellcheck={false}
        />
      </label>
      <label>
        <span>TSIG algorithm</span>
        <select name="rfc2136_algorithm">
          <option value="hmac_sha256">HMAC-SHA-256</option>
          <option value="hmac_sha512">HMAC-SHA-512</option>
        </select>
      </label>
      <SecretField label="TSIG secret" name="rfc2136_secret" />
    </div>
  );
}

function WebhookFields(): JSX.Element {
  return (
    <div class="certificate-provider-grid">
      <label>
        <span>HTTPS endpoint</span>
        <input
          autocomplete="url"
          maxlength="2048"
          name="webhook_endpoint"
          placeholder="https://dns.example.test/acme"
          required
          type="url"
        />
      </label>
      <SecretField label="Bearer token" name="webhook_bearer_token" />
    </div>
  );
}

function SecretField(
  props: Readonly<{ label: string; name: string }>,
): JSX.Element {
  return (
    <label>
      <span>{props.label}</span>
      <input
        autocomplete="off"
        maxlength="2048"
        minlength="16"
        name={props.name}
        required
        spellcheck={false}
        type="password"
      />
    </label>
  );
}
