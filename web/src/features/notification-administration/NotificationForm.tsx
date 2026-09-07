// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal, untrack } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { NotificationsResponse } from "../../generated";
import type { NotificationModel } from "./model";

export type Channel = NotificationsResponse["channels"][number];
const EVENTS = [
  { bit: 1, label: "Certificate orders and renewals queued" },
  { bit: 2, label: "Certificate order outcomes (including retries)" },
  { bit: 4, label: "Manual DNS tasks changed" },
  { bit: 8, label: "Backup outcomes (including failures)" },
] as const;

export function NotificationForm(
  props: Readonly<{
    channel: Channel | undefined;
    model: NotificationModel;
    close: () => void;
  }>,
): JSX.Element {
  const [kind, setKind] = createSignal("webhook");
  const [replace, setReplace] = createSignal(false);
  const locked = (): boolean => props.model.busy() || props.model.pending();
  const submit = (
    event: SubmitEvent & { currentTarget: HTMLFormElement },
  ): void => {
    event.preventDefault();
    if (locked()) return;
    const data = new FormData(event.currentTarget);
    void props.model
      .save({
        operation_id: crypto.randomUUID(),
        channel_id: props.channel?.channel_id ?? crypto.randomUUID(),
        expected_sequence: props.channel?.sequence ?? 0,
        display_name: field(data, "display_name"),
        enabled: data.has("enabled"),
        event_filter: EVENTS.reduce(
          (sum, item) =>
            sum + (data.has(`event_${String(item.bit)}`) ? item.bit : 0),
          0,
        ),
        settings:
          props.channel === undefined || replace()
            ? { mode: "replace", destination: destination(data, kind()) }
            : { mode: "retain" },
      })
      .then((saved) => {
        if (saved)
          untrack(() => {
            props.close();
          });
      });
  };
  return (
    <form onSubmit={submit} class="backup-settings">
      <fieldset disabled={locked()}>
        <legend>
          {props.channel === undefined
            ? "Add notification channel"
            : "Edit notification channel"}
        </legend>
        <ChannelFields channel={props.channel} />
        <DestinationFields
          channel={props.channel}
          replace={props.channel === undefined || replace()}
          setReplace={setReplace}
          kind={kind()}
          setKind={setKind}
        />
        <p>
          Only event type, time and identifiers are sent—not filenames, paths or
          credentials. Changes cancel pending deliveries; messages already sent
          cannot be recalled.
        </p>
        <button class="primary-action" type="submit">
          Save notification channel
        </button>{" "}
        <button
          class="quiet-action"
          type="button"
          onClick={() => {
            props.close();
          }}
        >
          Cancel edit
        </button>
      </fieldset>
    </form>
  );
}

function EmailFields(): JSX.Element {
  return (
    <fieldset>
      <legend>Encrypted email submission</legend>
      <label>
        Relay host
        <input name="host" required maxlength={253} />
      </label>
      <label>
        Relay port
        <input
          name="port"
          type="number"
          required
          min={1}
          max={65535}
          value="465"
        />
      </label>
      <label>
        TLS mode
        <select name="tls">
          <option value="implicit">
            TLS from connection start (usually 465)
          </option>
          <option value="starttls">Required STARTTLS (usually 587)</option>
        </select>
      </label>
      <label>
        Relay username
        <input name="username" required maxlength={128} autocomplete="off" />
      </label>
      <label>
        Relay password
        <input
          name="password"
          type="password"
          required
          maxlength={128}
          autocomplete="off"
        />
      </label>
      <label>
        Sender address
        <input name="sender" type="email" required maxlength={254} />
      </label>
      <label>
        Recipient addresses
        <input
          name="recipients"
          type="email"
          multiple
          required
          maxlength={8192}
          aria-describedby="notification-recipients-help"
        />
      </label>
      <p id="notification-recipients-help">
        Separate addresses with commas. Up to 32 recipients; ASCII addresses and
        a TLS 1.3 relay supporting AUTH PLAIN are required.
      </p>
    </fieldset>
  );
}

function field(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

function destination(data: FormData, kind: string): unknown {
  if (kind === "webhook")
    return {
      kind,
      endpoint: field(data, "endpoint"),
      bearer_token: field(data, "bearer_token"),
    };
  return {
    kind: "email",
    host: field(data, "host"),
    port: Number(field(data, "port")),
    tls: field(data, "tls"),
    username: field(data, "username"),
    password: field(data, "password"),
    sender: field(data, "sender"),
    recipients: field(data, "recipients")
      .split(",")
      .map((value) => value.trim()),
  };
}

function ChannelFields(
  props: Readonly<{ channel: Channel | undefined }>,
): JSX.Element {
  return (
    <>
      {" "}
      <label>
        Channel name
        <input
          name="display_name"
          required
          maxlength={256}
          value={props.channel?.display_name ?? ""}
        />
      </label>
      <label>
        <input
          name="enabled"
          type="checkbox"
          checked={props.channel?.enabled ?? true}
        />{" "}
        Enable delivery
      </label>
      <fieldset>
        <legend>Events to send</legend>
        <For each={EVENTS}>
          {(item) => (
            <label>
              <input
                name={`event_${String(item.bit)}`}
                type="checkbox"
                checked={((props.channel?.event_filter ?? 15) & item.bit) !== 0}
              />{" "}
              {item.label}
            </label>
          )}
        </For>
      </fieldset>
    </>
  );
}

function DestinationFields(
  props: Readonly<{
    channel: Channel | undefined;
    replace: boolean;
    setReplace: (value: boolean) => void;
    kind: string;
    setKind: (value: string) => void;
  }>,
): JSX.Element {
  return (
    <>
      {" "}
      <Show when={props.channel !== undefined}>
        <label>
          <input
            type="checkbox"
            checked={props.replace}
            onChange={(event) => {
              props.setReplace(event.currentTarget.checked);
            }}
          />{" "}
          Replace destination and credentials
        </label>
        <p>
          Leave unchecked to keep the encrypted settings. Credentials are never
          returned to this panel.
        </p>
      </Show>
      <Show when={props.replace}>
        <label>
          Delivery method
          <select
            value={props.kind}
            onChange={(event) => {
              props.setKind(event.currentTarget.value);
            }}
          >
            <option value="webhook">HTTPS webhook</option>
            <option value="email">Email</option>
          </select>
        </label>
        <Show when={props.kind === "webhook"} fallback={<EmailFields />}>
          <label>
            HTTPS endpoint
            <input
              name="endpoint"
              type="url"
              required
              maxlength={2048}
              placeholder="https://notifications.example.net/events"
            />
          </label>
          <label>
            Bearer token
            <input
              name="bearer_token"
              type="password"
              required
              minlength={16}
              maxlength={2048}
              autocomplete="off"
            />
          </label>
        </Show>
      </Show>
    </>
  );
}
