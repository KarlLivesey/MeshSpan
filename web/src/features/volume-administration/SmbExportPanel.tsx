// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { AdminVolume, VolumeAdministrationClient } from "./model";
import {
  createSmbExportModel,
  type SmbExportModel,
} from "./smb-export-model";

type SmbExportPanelProps = Readonly<{
  client: VolumeAdministrationClient;
  csrfToken: string;
  volume: AdminVolume;
}>;

export function SmbExportPanel(props: SmbExportPanelProps): JSX.Element {
  const model = createSmbExportModel(props);
  return (
    <section class="smb-export-administration" aria-labelledby="smb-heading">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Connector</p>
          <h2 id="smb-heading">SMB access</h2>
        </div>
        <span>Publish through every eligible gateway by default.</span>
      </div>
      <Show
        when={model.publication()}
        fallback={<PublishSmbExportForm model={model} />}
      >
        {(publication) => (
          <WithdrawSmbExportForm
            model={model}
            shareName={publication().share_name}
          />
        )}
      </Show>
      <div class="form-message" aria-live="polite">
        <Show when={model.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
      </div>
    </section>
  );
}

function PublishSmbExportForm(
  props: Readonly<{ model: SmbExportModel }>,
): JSX.Element {
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void props.model.publish();
  };
  return (
    <form class="smb-export-form" onSubmit={submit}>
      <label>
        <span>Share name</span>
        <input
          autocomplete="off"
          disabled={props.model.pending() !== undefined}
          maxlength="240"
          onInput={(event) => {
            props.model.setShareName(event.currentTarget.value);
          }}
          value={props.model.shareName()}
        />
      </label>
      <label class="check-field">
        <input
          checked={props.model.encryptionRequired()}
          disabled={props.model.pending() !== undefined}
          onChange={(event) => {
            props.model.setEncryptionRequired(event.currentTarget.checked);
          }}
          type="checkbox"
        />
        <span>Require SMB encryption</span>
      </label>
      <button
        class="primary-action"
        disabled={props.model.pending() !== undefined}
        type="submit"
      >
        {props.model.pending() === "publish"
          ? "Publishing share…"
          : "Publish SMB share"}
      </button>
    </form>
  );
}

function WithdrawSmbExportForm(
  props: Readonly<{ model: SmbExportModel; shareName: string }>,
): JSX.Element {
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void props.model.withdraw();
  };
  return (
    <form class="smb-export-form" onSubmit={submit}>
      <p class="success">
        <strong>{props.shareName}</strong> is published through the selected
        gateways.
      </p>
      <label>
        <span>Reason for withdrawing access</span>
        <input
          autocomplete="off"
          disabled={props.model.pending() !== undefined}
          maxlength="1024"
          onInput={(event) => {
            props.model.setWithdrawalReason(event.currentTarget.value);
          }}
          value={props.model.withdrawalReason()}
        />
      </label>
      <button
        class="danger-action"
        disabled={props.model.pending() !== undefined}
        type="submit"
      >
        {props.model.pending() === "withdraw"
          ? "Withdrawing share…"
          : "Withdraw SMB share"}
      </button>
    </form>
  );
}
