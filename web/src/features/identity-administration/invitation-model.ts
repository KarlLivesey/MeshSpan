// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type {
  IssueUserEnrollmentRequest,
  IssueUserEnrollmentResponse,
  RevokeUserEnrollmentResponse,
  RevokeUserEnrollmentRequest,
  ListPrincipalsResponse,
} from "../../generated/types.gen";
import {
  zIssueUserEnrollmentRequest,
  zRevokeUserEnrollmentRequest,
} from "../../generated/zod.gen";
import {
  createExactMutation,
  type ExactMutation,
  mutationMessage,
} from "../../native-api/mutation-outcome";

export type InvitationClient = Pick<
  MeshSpanFetchClient,
  "issueUserEnrollment" | "revokeUserEnrollment"
>;
export type InvitationProps = Readonly<{
  client: InvitationClient;
  csrfToken: string;
  principal: ListPrincipalsResponse["principals"][number];
  onLocked: (locked: boolean) => void;
}>;

type Issuance = IssueUserEnrollmentRequest & Readonly<{ principalId: string }>;
type Revocation = RevokeUserEnrollmentRequest &
  Readonly<{ enrollmentId: string }>;

type InvitationModel = Readonly<{
  receipt: Accessor<IssueUserEnrollmentResponse | undefined>;
  issue: () => Promise<void>;
  revoke: () => Promise<void>;
  issuance: ExactMutation<Issuance, IssueUserEnrollmentResponse>;
  revocation: ExactMutation<Revocation, RevokeUserEnrollmentResponse>;
  message: Accessor<string | undefined>;
}>;

export function createInvitation(props: InvitationProps): InvitationModel {
  const [localError, setLocalError] = createSignal<string>();
  const issuance = createIssuance(props);
  const revocation = createRevocation(props);
  const receipt = () => {
    const state = issuance.state();
    return state.phase === "committed" ? state.receipt : undefined;
  };
  const updateLock = (): void => {
    props.onLocked(issuance.locked() || revocation.locked());
  };
  const issue = async (): Promise<void> => {
    setLocalError(undefined);
    props.onLocked(true);
    try {
      if (issuance.locked()) {
        await issuance.retry();
        return;
      }
      if (receipt() !== undefined) return;
      const request = zIssueUserEnrollmentRequest.parse({
        operation_id: crypto.randomUUID(),
        expected_principal_revision: props.principal.revision,
        expires_at_epoch_micros: Number(
          Temporal.Now.instant().add({ minutes: 10 }).epochNanoseconds / 1_000n,
        ),
      });
      await issuance.submit({
        ...request,
        principalId: props.principal.principal_id,
      });
    } catch {
      setLocalError(
        "The invitation could not be prepared. Nothing was submitted.",
      );
    } finally {
      updateLock();
    }
  };
  const revoke = async (): Promise<void> => {
    const current = receipt();
    if (current === undefined) return;
    setLocalError(undefined);
    props.onLocked(true);
    try {
      if (revocation.locked()) {
        await revocation.retry();
        return;
      }
      if (revocation.state().phase === "committed") return;
      const request = zRevokeUserEnrollmentRequest.parse({
        operation_id: crypto.randomUUID(),
        expected_revision: current.committed_revision,
      });
      await revocation.submit({
        ...request,
        enrollmentId: current.operation_id,
      });
    } catch {
      setLocalError(
        "The revocation could not be prepared. Nothing was submitted.",
      );
    } finally {
      updateLock();
    }
  };
  return {
    receipt,
    issue,
    revoke,
    issuance,
    revocation,
    message: () =>
      localError() ??
      mutationMessage(revocation.state()) ??
      mutationMessage(issuance.state()),
  };
}

function createIssuance(
  props: InvitationProps,
): ExactMutation<Issuance, IssueUserEnrollmentResponse> {
  return createExactMutation(
    async ({ principalId, ...request }: Issuance) =>
      props.client.issueUserEnrollment(principalId, request, props.csrfToken),
    (receipt, request) => {
      if (
        receipt.operation_id !== request.operation_id ||
        receipt.principal_id !== request.principalId ||
        receipt.expires_at_epoch_micros !== request.expires_at_epoch_micros ||
        receipt.committed_revision < 1
      ) {
        throw new TypeError(
          "Invitation receipt does not match its recipient and request.",
        );
      }
    },
    async () => Promise.resolve(),
  );
}

function createRevocation(
  props: InvitationProps,
): ExactMutation<Revocation, RevokeUserEnrollmentResponse> {
  return createExactMutation(
    async ({ enrollmentId, ...request }: Revocation) =>
      props.client.revokeUserEnrollment(enrollmentId, request, props.csrfToken),
    (receipt, request) => {
      if (
        receipt.operation_id !== request.operation_id ||
        receipt.enrollment_operation_id !== request.enrollmentId ||
        receipt.committed_revision <= request.expected_revision
      ) {
        throw new TypeError(
          "Invitation revocation receipt does not match the request.",
        );
      }
    },
    async () => Promise.resolve(),
  );
}
