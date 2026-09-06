// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal, onCleanup, type Accessor } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { ProvisionMeshLocalCertificateRequest } from "../../generated";
import { zProvisionMeshLocalCertificateResponse } from "../../generated/zod.gen";
import { readCertificateNames } from "./certificate-request";
import type { CertificateAdministrationClient } from "./model";

type LocalCertificateProps = Readonly<{
  client: CertificateAdministrationClient;
  csrfToken: string;
}>;

type LocalCertificateState = Readonly<{
  names: Accessor<string>;
  pending: Accessor<boolean>;
  error: Accessor<string | undefined>;
  download: Accessor<string | undefined>;
  setNames: (value: string) => void;
  submit: (event: SubmitEvent) => Promise<void>;
}>;

/** Local HTTPS provisioning keeps the public trust download available during TLS replacement. */
export function MeshLocalCertificateForm(
  props: LocalCertificateProps,
): JSX.Element {
  const state = createLocalCertificateState(props);
  return (
    <form
      class="certificate-provision"
      onSubmit={(event) => void state.submit(event)}
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">No public domain required</p>
          <h2>Use a mesh-local certificate</h2>
        </div>
      </div>
      <p>
        Each connecting device must trust your mesh’s certificate authority. A
        domain with automated public certificates avoids this manual trust
        setup.
      </p>
      <label class="certificate-names-field">
        <span>Local hostnames</span>
        <textarea
          name="local_certificate_names"
          autocomplete="off"
          maxlength="65535"
          placeholder={"meshspan.local\nfiles.internal"}
          required
          rows="3"
          spellcheck={false}
          disabled={state.pending()}
          value={state.names()}
          onInput={(event) => {
            state.setNames(event.currentTarget.value);
          }}
        />
        <small>
          Enter the names clients use to reach this mesh, separated by lines or
          commas. This does not configure DNS.
        </small>
      </label>
      <p>
        The HTTPS identity will change. Keep this page open to download the
        public trust anchor, install it on your connecting devices, then reload.
      </p>
      <button class="primary-action" disabled={state.pending()} type="submit">
        {state.pending()
          ? "Preparing local certificate…"
          : "Use local certificate"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={state.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={state.download()}>
          {(url) => (
            <>
              <p>
                Certificate issuance is saved. Gateway installation is reported
                separately above.
              </p>
              <a href={url()} download="meshspan-local-ca.pem">
                Download public trust anchor
              </a>
              <p>
                This file contains no private key. Trust it only on devices that
                should trust this mesh.
              </p>
            </>
          )}
        </Show>
      </div>
    </form>
  );
}

function createLocalCertificateState(
  props: LocalCertificateProps,
): LocalCertificateState {
  const [names, setNames] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [download, setDownload] = createSignal<string>();
  let retry: ProvisionMeshLocalCertificateRequest | undefined;
  let disposed = false;
  onCleanup(() => {
    disposed = true;
    const url = download();
    if (url) URL.revokeObjectURL(url);
  });
  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) return;
    retry = requestForNames(names(), retry);
    setPending(true);
    setError();
    const client = props.client;
    const request = retry;
    try {
      const response = zProvisionMeshLocalCertificateResponse.parse(
        await client.provisionMeshLocalCertificate(request, props.csrfToken),
      );
      if (disposed || client !== props.client) return;
      if (
        response.operation_id !== request.operation_id ||
        JSON.stringify(response.certificate_names) !==
          JSON.stringify(request.certificate_names)
      ) {
        throw new TypeError(
          "Certificate response does not match this request.",
        );
      }
      const previous = download();
      const url = URL.createObjectURL(
        new Blob([response.trust_anchor_pem], {
          type: "application/x-pem-file",
        }),
      );
      setDownload(url);
      if (previous) URL.revokeObjectURL(previous);
    } catch {
      if (!disposed)
        setError(
          "Local certificate provisioning was not confirmed. Check your access and connection, then retry with the same names. A connection failure does not mean it was not saved.",
        );
    } finally {
      if (!disposed) setPending(false);
    }
  };
  return { names, pending, error, download, setNames, submit };
}

function requestForNames(
  value: string,
  previous: ProvisionMeshLocalCertificateRequest | undefined,
): ProvisionMeshLocalCertificateRequest {
  const certificateNames = readCertificateNames(value);
  if (
    previous &&
    JSON.stringify(previous.certificate_names) ===
      JSON.stringify(certificateNames)
  )
    return previous;
  return {
    certificate_names: certificateNames,
    operation_id: crypto.randomUUID(),
  };
}
