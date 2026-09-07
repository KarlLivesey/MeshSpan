// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal, onCleanup, type Accessor } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { MeshSpanFetchClient, UpdatesResponse } from "../../generated";
import { MeshSpanApiError } from "../../generated/fetch.gen";

type UpdateArtifactDescriptor = NonNullable<
  UpdatesResponse["rollout"]
>["artifacts"][number];

type Attempt = Readonly<{
  rolloutId: string;
  artifact: UpdateArtifactDescriptor;
  operationId: string;
  bytes: File;
}>;
type UploadClient = Pick<MeshSpanFetchClient, "stageUpdateArtifact">;
type UploadProps = Readonly<{
  rollout: NonNullable<UpdatesResponse["rollout"]>;
  client: UploadClient;
  csrfToken: string;
}>;
type UploadModel = Readonly<{
  busy: Accessor<boolean>;
  pending: Accessor<Attempt | undefined>;
  notice: Accessor<string>;
  submit: (form: HTMLFormElement) => void;
  upload: (attempt: Attempt) => Promise<void>;
}>;

export function ArtifactUpload(props: UploadProps): JSX.Element {
  const model = createUploadModel(props);
  return (
    <details>
      <summary>Upload candidate executables</summary>
      <p>
        Upload each platform needed by the swarm. Files stream directly; the
        server checks the signed hash before storing them.
      </p>
      <ArtifactFields
        artifacts={props.rollout.artifacts}
        locked={model.busy() || model.pending() !== undefined}
        submit={model.submit}
      />
      <Show when={model.pending()}>
        {(attempt) => (
          <button
            type="button"
            class="quiet-action"
            disabled={model.busy()}
            onClick={() => void model.upload(attempt())}
          >
            Retry executable upload
          </button>
        )}
      </Show>
      <p role="status" aria-live="polite">
        {model.notice()}
      </p>
    </details>
  );
}

function createUploadModel(props: UploadProps): UploadModel {
  const [busy, setBusy] = createSignal(false, { ownedWrite: true });
  const [pending, setPending] = createSignal<Attempt | undefined>(
    () => undefined,
    { ownedWrite: true },
  );
  const [notice, setNotice] = createSignal("", { ownedWrite: true });
  let alive = true;
  const mounted = (): boolean => alive;
  onCleanup(() => {
    alive = false;
  });
  const upload = async (attempt: Attempt): Promise<void> => {
    if (busy() || !mounted()) return;
    setBusy(true);
    setPending(attempt);
    setNotice("Uploading and verifying executable…");
    try {
      await stageVerifiedArtifact(props.client, attempt, props.csrfToken);
      if (mounted()) {
        setPending(undefined);
        setNotice(
          "Executable verified and stored on this node. Installation is not confirmed.",
        );
      }
    } catch (error: unknown) {
      if (mounted()) {
        const rejected =
          error instanceof MeshSpanApiError &&
          (error.statusCode === 400 || error.statusCode === 409);
        if (rejected) setPending(undefined);
        setNotice(
          rejected
            ? "Executable rejected. Check the signed candidate and selected file."
            : "Upload outcome is not confirmed. Retry the same file and operation.",
        );
      }
    } finally {
      if (mounted()) setBusy(false);
    }
  };
  const submit = (form: HTMLFormElement): void => {
    if (busy() || pending() !== undefined) return;
    const data = new FormData(form);
    const bytes = data.get("update_executable");
    const artifact = props.rollout.artifacts.find(
      (item) => item.target === data.get("update_platform"),
    );
    if (!(bytes instanceof File) || bytes.size !== artifact?.byte_length) {
      setNotice(
        "Choose the executable for this platform with the exact signed byte length.",
      );
      return;
    }
    void upload({
      rolloutId: props.rollout.rollout_id,
      artifact,
      operationId: crypto.randomUUID(),
      bytes,
    });
  };
  return { busy, pending, notice, submit, upload };
}

async function stageVerifiedArtifact(
  client: UploadClient,
  attempt: Attempt,
  csrfToken: string,
): Promise<void> {
  const receipt = await client.stageUpdateArtifact(
    attempt.rolloutId,
    attempt.artifact.target,
    attempt.operationId,
    attempt.bytes,
    csrfToken,
  );
  if (
    receipt.operation_id !== attempt.operationId ||
    receipt.rollout_id !== attempt.rolloutId ||
    receipt.target !== attempt.artifact.target ||
    receipt.sha256 !== attempt.artifact.sha256 ||
    receipt.byte_length !== String(attempt.bytes.size)
  )
    throw new TypeError("artifact receipt mismatch");
}

function ArtifactFields(
  props: Readonly<{
    artifacts: UpdateArtifactDescriptor[];
    locked: boolean;
    submit: (form: HTMLFormElement) => void;
  }>,
): JSX.Element {
  return (
    <form
      class="backup-settings"
      onSubmit={(event) => {
        event.preventDefault();
        props.submit(event.currentTarget);
      }}
    >
      <fieldset disabled={props.locked}>
        <legend>Executable bytes</legend>
        <label>
          Executable platform
          <select name="update_platform" required>
            <For each={props.artifacts}>
              {(item) => (
                <option value={item.target}>
                  {item.target} — {item.byte_length} bytes
                </option>
              )}
            </For>
          </select>
        </label>
        <label>
          Executable file
          <input type="file" name="update_executable" required />
        </label>
        <button type="submit" class="quiet-action">
          Upload executable
        </button>
      </fieldset>
    </form>
  );
}
