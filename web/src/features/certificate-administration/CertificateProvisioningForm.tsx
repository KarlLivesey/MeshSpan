// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { ProvisionCertificateRequest } from "../../generated";
import { CertificateChallengeFields } from "./CertificateChallengeFields";
import {
  buildCertificateRequest,
  type CertificateChallengeKind,
} from "./certificate-request";
import type { CertificateAdministrationClient } from "./model";

const DEFAULT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";

export function CertificateProvisioningForm(
  props: Readonly<{
    client: CertificateAdministrationClient;
    csrfToken: string;
    refreshTasks: () => Promise<void>;
  }>,
): JSX.Element {
  const [kind, setKind] = createSignal<CertificateChallengeKind>("http01");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) return;
    setPending(true);
    setError();
    setSuccess();
    try {
      const form = event.currentTarget as HTMLFormElement;
      const request: ProvisionCertificateRequest = buildCertificateRequest(
        new FormData(form),
        crypto.randomUUID(),
      );
      const client = props.client;
      const csrfToken = props.csrfToken;
      const response = await client.provisionCertificate(request, csrfToken);
      form.reset();
      setKind("http01");
      setSuccess(`Certificate order ${response.order_id} is now queued.`);
      await props.refreshTasks();
    } catch {
      setError(
        "MeshSpan could not queue that certificate. Check every name and provider setting, then try again.",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <form
      class="certificate-provision"
      onSubmit={(event) => void submit(event)}
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">Public HTTPS</p>
          <h2>Request a certificate</h2>
        </div>
      </div>
      <CertificateRequestFields
        kind={kind()}
        pending={pending()}
        setKind={setKind}
      />
      <button class="primary-action" disabled={pending()} type="submit">
        {pending() ? "Queueing certificate…" : "Request certificate"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={success()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
      </div>
    </form>
  );
}

function CertificateRequestFields(
  props: Readonly<{
    kind: CertificateChallengeKind;
    pending: boolean;
    setKind: (kind: CertificateChallengeKind) => void;
  }>,
): JSX.Element {
  return (
    <>
      <label class="certificate-names-field">
        <span>DNS names</span>
        <textarea
          autocomplete="off"
          disabled={props.pending}
          maxlength="65535"
          name="certificate_names"
          placeholder={"files.example.com\nadmin.example.com"}
          required
          rows="3"
          spellcheck={false}
        />
        <small>Enter names on separate lines or separated by commas.</small>
      </label>
      <label class="certificate-directory-field">
        <span>ACME directory</span>
        <input
          autocomplete="url"
          disabled={props.pending}
          maxlength="2048"
          name="directory_url"
          required
          type="url"
          value={DEFAULT_DIRECTORY}
        />
      </label>
      <CertificateChallengeFields
        disabled={props.pending}
        kind={props.kind}
        setKind={props.setKind}
      />
    </>
  );
}
