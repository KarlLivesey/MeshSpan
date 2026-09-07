// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";
import {
  createNotificationModel,
  type NotificationModel,
  type NotificationClient,
} from "./model";
import { NotificationForm, type Channel } from "./NotificationForm";

export function NotificationAdministration(
  props: Readonly<{ client: NotificationClient; csrfToken: string }>,
): JSX.Element {
  const model = createNotificationModel(
    () => props.client,
    () => props.csrfToken,
  );
  const [editing, setEditing] = createSignal<
    { channel: Channel | undefined } | undefined
  >(undefined);
  const locked = (): boolean => model.busy() || model.pending();
  void model.load();
  return (
    <section class="topology-section" aria-labelledby="notification-heading">
      <h2 id="notification-heading">Notifications</h2>
      <p>
        Optional email and webhook alerts for certificates, manual DNS tasks and
        backups. No destination is enabled until you configure it.
      </p>
      <button
        type="button"
        class="quiet-action"
        disabled={locked()}
        onClick={() => {
          setEditing(undefined);
          void model.load();
        }}
      >
        Refresh notifications
      </button>
      <ChannelList
        model={model}
        locked={locked()}
        edit={(channel) => {
          setEditing({ channel });
        }}
      />
      <Show keyed when={editing()}>
        {(selection) => (
          <NotificationForm
            channel={selection.channel}
            model={model}
            close={() => {
              setEditing(undefined);
            }}
          />
        )}
      </Show>
      <Show when={model.pending()}>
        <button
          type="button"
          class="quiet-action"
          disabled={model.busy()}
          onClick={() => void model.retry()}
        >
          Retry notification change
        </button>
      </Show>
      <div aria-live="polite">
        <Show when={model.busy()}>
          <p>Working on notification settings…</p>
        </Show>
        <Show when={model.message()}>{(message) => <p>{message()}</p>}</Show>
      </div>
      <Show when={model.error()}>
        {(error) => (
          <p class="error" role="alert">
            {error()}
          </p>
        )}
      </Show>
    </section>
  );
}

function ChannelList(
  props: Readonly<{
    model: NotificationModel;
    locked: boolean;
    edit: (channel: Channel | undefined) => void;
  }>,
): JSX.Element {
  return (
    <Show
      when={props.model.status()}
      fallback={<p>Notification settings have not been loaded.</p>}
    >
      {(status) => (
        <>
          <p>
            Local delivery worker: <strong>{status().worker}</strong>. Remote
            acceptance does not guarantee inbox delivery.
          </p>
          <ul aria-label="Notification channels">
            <For
              each={status().channels}
              fallback={<li>No channels yet. Add one to receive alerts.</li>}
            >
              {(channel) => (
                <li>
                  <strong>{channel.display_name}</strong> — {channel.kind},{" "}
                  {channel.enabled ? "enabled" : "off"}{" "}
                  <DeliveryCounts channel={channel} />
                  <button
                    type="button"
                    class="quiet-action"
                    disabled={props.locked}
                    onClick={() => {
                      props.edit(channel);
                    }}
                  >
                    Edit {channel.display_name}
                  </button>
                </li>
              )}
            </For>
          </ul>
          <button
            type="button"
            class="quiet-action"
            disabled={props.locked || status().channels.length >= 64}
            onClick={() => {
              props.edit(undefined);
            }}
          >
            Add notification channel
          </button>
        </>
      )}
    </Show>
  );
}

function DeliveryCounts(props: Readonly<{ channel: Channel }>): JSX.Element {
  return (
    <>
      <p>
        {props.channel.deliveries.pending} pending ·{" "}
        {props.channel.deliveries.accepted} accepted ·{" "}
        {props.channel.deliveries.rejected} rejected ·{" "}
        {props.channel.deliveries.cancelled} cancelled
      </p>
      <Show when={props.channel.deliveries.rejected !== "0"}>
        <p class="error">
          Some deliveries were permanently rejected. Check the destination and
          credentials. Updated settings apply to future events; rejected events
          remain recorded.
        </p>
      </Show>
    </>
  );
}
