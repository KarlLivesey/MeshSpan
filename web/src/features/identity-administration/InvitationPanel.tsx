// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import { createInvitation, type InvitationProps } from "./invitation-model";
import {
  InvitationStepUp,
  type InvitationStepUpAction,
} from "./InvitationStepUp";

export function InvitationPanel(
  props: InvitationProps & Readonly<{ stepUp: InvitationStepUpAction }>,
): JSX.Element {
  const model = createInvitation(props);
  return (
    <section class="security-action-card">
      <h2>Invite {props.principal.display_name} to sign in</h2>
      <p>
        For an active user who has no primary credential. The invitation expires
        after ten minutes.
      </p>
      <InvitationStepUp
        stepUp={props.stepUp}
        disabled={model.issuance.busy() || model.revocation.busy()}
      />
      <Show
        when={model.receipt()}
        fallback={
          <button
            type="button"
            disabled={
              model.issuance.busy() || props.principal.state !== "active"
            }
            onClick={() => void model.issue()}
          >
            {model.issuance.locked() ? "Retry invitation" : "Issue invitation"}
          </button>
        }
      >
        {(receipt) => (
          <div>
            <Show
              when={model.revocation.state().phase !== "committed"}
              fallback={
                <p>
                  Invitation revoked. Any credential already created remains
                  independently revocable.
                </p>
              }
            >
              <p>
                Invitation committed. Share the token privately and direct the
                recipient to <a href="/enroll">Accept your invitation</a>.
              </p>
              <p>
                Expires{" "}
                {instantFromEpochMicroseconds(
                  receipt().expires_at_epoch_micros,
                ).toLocaleString()}
                .
              </p>
              <output class="secret-output">{receipt().token}</output>
              <button
                type="button"
                disabled={model.revocation.busy()}
                onClick={() => void model.revoke()}
              >
                {model.revocation.locked()
                  ? "Retry revocation"
                  : "Revoke invitation"}
              </button>
            </Show>
          </div>
        )}
      </Show>
      <p aria-live="polite">{model.message()}</p>
    </section>
  );
}
