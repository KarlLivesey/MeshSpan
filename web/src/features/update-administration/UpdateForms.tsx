// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { UpdatesResponse } from "../../generated";
import type { UpdateModel } from "./model";

export function PublisherForm(
  props: Readonly<{ model: UpdateModel }>,
): JSX.Element {
  const [reading, setReading] = createSignal(false);
  const [error, setError] = createSignal("");
  const locked = (): boolean =>
    reading() || props.model.busy() || props.model.pending();
  const submit = async (data: FormData): Promise<void> => {
    if (locked()) return;
    setReading(true);
    setError("");
    try {
      const publicKey = await encodedFile(data, "publisher_key", 65, 65);
      await props.model.save({
        operation_id: crypto.randomUUID(),
        action: {
          kind: "configure_signer",
          signer_id: crypto.randomUUID(),
          expected_sequence: 0,
          public_key: publicKey,
          enabled: true,
        },
      });
    } catch {
      setError(
        "Choose a 65-byte uncompressed P-256 SEC1 public key obtained independently of the candidate.",
      );
    } finally {
      setReading(false);
    }
  };
  return (
    <form
      class="backup-settings"
      onSubmit={(event) => {
        event.preventDefault();
        void submit(new FormData(event.currentTarget));
      }}
    >
      <fieldset disabled={locked()}>
        <legend>Pin a publisher</legend>
        <label>
          Publisher public key
          <input
            name="publisher_key"
            type="file"
            required
            aria-describedby="publisher-help"
          />
        </label>
        <p id="publisher-help">
          This grants trust to software signed by this key. Check its source
          before adding it.
        </p>
        <button type="submit" class="quiet-action">
          Trust publisher key
        </button>
      </fieldset>
      <Show when={error()}>
        {(message) => (
          <p class="error" role="alert">
            {message()}
          </p>
        )}
      </Show>
    </form>
  );
}

export function CandidateForm(
  props: Readonly<{
    model: UpdateModel;
    signers: UpdatesResponse["signers"];
  }>,
): JSX.Element {
  const [reading, setReading] = createSignal(false);
  const [error, setError] = createSignal("");
  const enabled = (): UpdatesResponse["signers"] =>
    props.signers.filter((signer) => signer.enabled);
  const locked = (): boolean =>
    reading() || props.model.busy() || props.model.pending();
  const submit = async (data: FormData): Promise<void> => {
    if (locked()) return;
    setReading(true);
    setError("");
    try {
      const signer = props.signers.find(
        (item) => item.signer_id === data.get("signer_id") && item.enabled,
      );
      if (signer === undefined) throw new TypeError("publisher not selected");
      const manifest = await encodedFile(data, "manifest", 1, 16384);
      const signature = await encodedFile(data, "signature", 1, 72);
      await props.model.save({
        operation_id: crypto.randomUUID(),
        action: {
          kind: "select_candidate",
          rollout_id: crypto.randomUUID(),
          signer_id: signer.signer_id,
          signer_sequence: signer.sequence,
          manifest,
          signature,
          allow_service_interruption: data.has("allow_interruption"),
        },
      });
    } catch {
      setError(
        "Choose an enabled publisher, a manifest of at most 16 KiB and its detached signature of at most 72 bytes.",
      );
    } finally {
      setReading(false);
    }
  };
  return (
    <Show when={enabled().length > 0}>
      <details>
        <summary>Select a signed candidate</summary>
        <form
          class="backup-settings"
          onSubmit={(event) => {
            event.preventDefault();
            void submit(new FormData(event.currentTarget));
          }}
        >
          <fieldset disabled={locked()}>
            <CandidateFields signers={enabled()} />
          </fieldset>
        </form>
        <Show when={error()}>
          {(message) => (
            <p class="error" role="alert">
              {message()}
            </p>
          )}
        </Show>
      </details>
    </Show>
  );
}

async function encodedFile(
  data: FormData,
  name: string,
  minimum: number,
  maximum: number,
): Promise<string> {
  const file = data.get(name);
  if (!(file instanceof File) || file.size < minimum || file.size > maximum)
    throw new TypeError("update file exceeds its bounds");
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length !== file.size)
    throw new TypeError("update file changed while reading");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function CandidateFields(
  props: Readonly<{ signers: UpdatesResponse["signers"] }>,
): JSX.Element {
  return (
    <>
      <legend>Candidate verification</legend>
      <label>
        Publisher
        <select name="signer_id" required>
          <For each={props.signers}>
            {(signer) => (
              <option value={signer.signer_id}>{signer.signer_id}</option>
            )}
          </For>
        </select>
      </label>
      <label>
        Signed manifest
        <input name="manifest" type="file" required />
      </label>
      <label>
        Detached signature
        <input name="signature" type="file" required />
      </label>
      <label>
        <input name="allow_interruption" type="checkbox" /> Allow unavoidable
        service interruption for this update
      </label>
      <p>
        Leave unchecked to require remaining nodes to preserve service. A single
        machine may need an interruption to restart.
      </p>
      <button type="submit" class="primary-action">
        Select candidate
      </button>
    </>
  );
}
