// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

export type ClientOptions = {
  baseUrl: `${string}://${string}/api/latest` | (string & {});
};

/**
 * AbortUploadRequest
 *
 * Permanently abandons one unpublished upload.
 */
export type AbortUploadRequest = {
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Exact current positive writer fence.
   */
  stage_fence: number;
};

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export type AbortUploadResponse = {
  /**
   * Exact current private-stage mutation sequence.
   */
  checkpoint_sequence: number;
  /**
   * Stable object published by a committed upload; otherwise null.
   */
  committed_object_id: string | null;
  /**
   * Immutable version published by a committed upload; otherwise null.
   */
  committed_version_id: string | null;
  /**
   * Exclusive server-authoritative expiry as Unix epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Highest byte written, exclusive; this does not imply gap-free coverage.
   */
  logical_extent: number;
  /**
   * Hard maximum logical file bytes.
   */
  maximum_bytes: number;
  /**
   * Canonical destination path.
   */
  path: string;
  /**
   * Absolute-path reference for bounded exact received-range pages.
   */
  ranges_url: string;
  /**
   * Positive current writer fence.
   */
  stage_fence: number;
  /**
   * Current durable lifecycle state.
   */
  state: "active" | "committing" | "committed" | "aborted";
  /**
   * Opaque upload identity.
   */
  upload_id: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * AddGroupMemberRequest
 *
 * Idempotent administrator request to add one direct user or nested-group member.
 */
export type AddGroupMemberRequest = {
  /**
   * Whether this edge requires explicit, reasoned, time-bounded user activation.
   */
  activation_required: boolean;
  /**
   * Direct user or group to add.
   */
  member_principal_id: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Omitted applies policy defaults, null is unbounded, and a value is exact.
   */
  valid_from_epoch_micros?: number | null;
  /**
   * Omitted applies policy defaults, null is unbounded, and a value is exact.
   */
  valid_until_epoch_micros?: number | null;
};

/**
 * AddGroupMemberResponse
 *
 * Durable result of adding or exactly replaying one direct membership.
 */
export type AddGroupMemberResponse = {
  /**
   * Newly active or exactly replayed direct membership.
   */
  membership: {
    /**
     * Whether the affected user must activate this membership before it contributes rights.
     */
    activation_required: boolean;
    /**
     * Original authoritative creation instant.
     */
    created_at_epoch_micros: number;
    /**
     * Administrator that originally created the current edge.
     */
    created_by: string;
    /**
     * Structurally containing group.
     */
    group_id: string;
    /**
     * Direct user or nested-group member.
     */
    member: {
      /**
       * Original authoritative creation instant as epoch microseconds.
       */
      created_at_epoch_micros: number;
      /**
       * Case-preserved NFC display name.
       */
      display_name: string;
      /**
       * User or nested group.
       */
      kind: "user" | "group";
      /**
       * Stable local identity.
       */
      principal_id: string;
      /**
       * Last authoritative metadata revision.
       */
      revision: number;
      /**
       * Current lifecycle state.
       */
      state: "active" | "suspended" | "retired";
    };
    /**
     * Last authoritative membership revision.
     */
    revision: number;
    /**
     * Inclusive validity start, or null when unbounded below.
     */
    valid_from_epoch_micros: number | null;
    /**
     * Exclusive validity end, or null when unbounded above.
     */
    valid_until_epoch_micros: number | null;
  };
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * ApiError
 *
 * Public error envelope that never includes raw untrusted values.
 */
export type ApiError = {
  /**
   * Stable machine-readable error category.
   */
  code:
    | "unauthenticated"
    | "forbidden"
    | "invalid_request"
    | "operation_conflict"
    | "not_found"
    | "state_conflict"
    | "busy"
    | "internal_contract";
  /**
   * Independently actionable field failures, capped at the trust boundary.
   */
  issues: Array<{
    /**
     * Stable violated-constraint label.
     */
    constraint: string;
    /**
     * JSON Pointer to the rejected field or collection element.
     */
    path: string;
  }>;
  /**
   * Plain bounded description safe to show to the caller.
   */
  message: string;
  /**
   * Mutation operation identifier, or null for requests without one.
   */
  operation_id: string | null;
  /**
   * Server request identifier for support correlation.
   */
  request_id: string;
};

/**
 * BeginUploadRequest
 *
 * Starts one durable private upload session.
 */
export type BeginUploadRequest = {
  /**
   * Final namespace precondition.
   */
  disposition:
    | {
        mode: "create_new";
      }
    | {
        mode: "replace_current";
      }
    | {
        mode: "replace_if_version";
        /**
         * Required current immutable version.
         */
        version_id: string;
      };
  /**
   * Hard maximum logical file bytes reserved for this upload.
   */
  maximum_bytes: number;
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Canonical root-relative destination path.
   */
  path: string;
};

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export type BeginUploadResponse = {
  /**
   * Exact current private-stage mutation sequence.
   */
  checkpoint_sequence: number;
  /**
   * Stable object published by a committed upload; otherwise null.
   */
  committed_object_id: string | null;
  /**
   * Immutable version published by a committed upload; otherwise null.
   */
  committed_version_id: string | null;
  /**
   * Exclusive server-authoritative expiry as Unix epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Highest byte written, exclusive; this does not imply gap-free coverage.
   */
  logical_extent: number;
  /**
   * Hard maximum logical file bytes.
   */
  maximum_bytes: number;
  /**
   * Canonical destination path.
   */
  path: string;
  /**
   * Absolute-path reference for bounded exact received-range pages.
   */
  ranges_url: string;
  /**
   * Positive current writer fence.
   */
  stage_fence: number;
  /**
   * Current durable lifecycle state.
   */
  state: "active" | "committing" | "committed" | "aborted";
  /**
   * Opaque upload identity.
   */
  upload_id: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * CommitUploadRequest
 *
 * Explicit final publication request for one complete checkpoint.
 */
export type CommitUploadRequest = {
  /**
   * Optional independently checked BLAKE3 digest of the complete logical file.
   */
  expected_blake3?: string | null;
  /**
   * Exact checkpoint sequence; later writes make this request stale.
   */
  expected_sequence: number;
  /**
   * Exact final logical file length.
   */
  final_length: number;
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Whether uncovered ranges are intentional logical zeroes.
   */
  sparse: boolean;
  /**
   * Exact current positive writer fence.
   */
  stage_fence: number;
};

/**
 * CommitUploadResponse
 *
 * Complete successful upload publication.
 */
export type CommitUploadResponse = {
  /**
   * Immutable metadata for the newly published exact version.
   */
  object: {
    /**
     * Immutable namespace view under which the path resolved.
     */
    namespace_commit_id: string;
    /**
     * Complete object metadata, including the immutable file version when applicable.
     */
    object: {
      /**
       * Monotonic name-reuse generation within the parent.
       */
      entry_generation: number;
      /**
       * Current immutable file version, or null for a directory.
       */
      file_version_id: string | null;
      /**
       * Directory or regular-file kind.
       */
      kind: "directory" | "file";
      /**
       * Logical file bytes, or null for a directory.
       */
      logical_length: number | null;
      /**
       * Case-preserved logical-object name.
       */
      name: string;
      /**
       * Stable logical-object identity.
       */
      object_id: string;
      /**
       * Exact immutable logical-object revision.
       */
      object_revision_id: string;
    };
    /**
     * Exact root-relative path which resolved the object.
     */
    path: string;
    /**
     * Selected logical volume.
     */
    volume_id: string;
  };
  /**
   * Terminal upload state.
   */
  upload: {
    /**
     * Exact current private-stage mutation sequence.
     */
    checkpoint_sequence: number;
    /**
     * Stable object published by a committed upload; otherwise null.
     */
    committed_object_id: string | null;
    /**
     * Immutable version published by a committed upload; otherwise null.
     */
    committed_version_id: string | null;
    /**
     * Exclusive server-authoritative expiry as Unix epoch microseconds.
     */
    expires_at_epoch_micros: number;
    /**
     * Highest byte written, exclusive; this does not imply gap-free coverage.
     */
    logical_extent: number;
    /**
     * Hard maximum logical file bytes.
     */
    maximum_bytes: number;
    /**
     * Canonical destination path.
     */
    path: string;
    /**
     * Absolute-path reference for bounded exact received-range pages.
     */
    ranges_url: string;
    /**
     * Positive current writer fence.
     */
    stage_fence: number;
    /**
     * Current durable lifecycle state.
     */
    state: "active" | "committing" | "committed" | "aborted";
    /**
     * Opaque upload identity.
     */
    upload_id: string;
    /**
     * Selected logical volume.
     */
    volume_id: string;
  };
};

/**
 * ConfirmRecoveryBundleRequest
 *
 * One authenticated idempotent save-verification request.
 */
export type ConfirmRecoveryBundleRequest = {
  /**
   * Exact mesh returned by first-mesh setup.
   */
  mesh_id: string;
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Short proof derived from the separately saved code and exact bundle.
   */
  recovery_challenge: string;
};

/**
 * ConfirmRecoveryBundleResponse
 *
 * Durable proof that the offline recovery bundle may no longer remain on the daemon.
 */
export type ConfirmRecoveryBundleResponse = {
  /**
   * Verified mesh.
   */
  mesh_id: string;
  /**
   * Exact operation which committed or replayed verification.
   */
  operation_id: string;
  /**
   * Authoritative revision which verified the bundle.
   */
  revision: number;
  /**
   * Authoritative verification instant.
   */
  verified_at_epoch_micros: number;
};

/**
 * CreateApiKeyRequest
 *
 * One idempotent request to issue a current-user API key.
 */
export type CreateApiKeyRequest = {
  /**
   * Omitted applies the server default, null means no automatic expiry, and a value is exact.
   */
  expires_at_epoch_micros?: number | null;
  /**
   * Human-readable independently revocable method label.
   */
  label: string;
  /**
   * Client-generated identity binding exact retries.
   */
  operation_id: string;
  /**
   * One connector through which an issued API key may authenticate.
   */
  scopes: Array<"https_session" | "headless_api" | "smb_session">;
};

/**
 * CreateApiKeyResponse
 *
 * One exactly replayable API-key issuance result.
 */
export type CreateApiKeyResponse = {
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Exclusive expiry, or null when the key does not expire automatically.
   */
  expires_at_epoch_micros: number | null;
  /**
   * Public key identity embedded in the returned secret.
   */
  key_id: string;
  /**
   * Independently revocable common authentication-method identity.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * One connector through which an issued API key may authenticate.
   */
  scopes: Array<"https_session" | "headless_api" | "smb_session">;
  /**
   * Secret-bearing key returned only from this issuance operation.
   */
  readonly secret: string;
  /**
   * Inclusive first accepted instant as epoch microseconds.
   */
  valid_from_epoch_micros: number;
};

/**
 * CreateDirectoryRequest
 *
 * Creates one empty logical directory at an exact path.
 */
export type CreateDirectoryRequest = {
  /**
   * Client-generated end-to-end idempotency identity.
   */
  operation_id: string;
  /**
   * Root-relative path of the new empty directory.
   */
  path: string;
};

/**
 * CreateDirectoryResponse
 *
 * Durable result of one atomic empty-directory creation.
 */
export type CreateDirectoryResponse = {
  /**
   * Resulting local branch-head sequence.
   */
  head_sequence: number;
  /**
   * Namespace commit made current by the operation.
   */
  namespace_commit_id: string;
  /**
   * Stable logical directory identity.
   */
  object_id: string;
  /**
   * Newly published immutable directory revision.
   */
  object_revision_id: string;
  /**
   * Exact operation which created or previously created the directory.
   */
  operation_id: string;
  /**
   * Exact created path.
   */
  path: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * CreateFaultGroupRequest
 *
 * Exact-retry request to create one shared-failure group.
 */
export type CreateFaultGroupRequest = {
  /**
   * Failure-boundary class, such as room, building, PSU or hypervisor.
   */
  class_name: string;
  /**
   * Concrete group within that class.
   */
  group_name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * CreateFaultGroupResponse
 *
 * Durable shared-failure-group creation result.
 */
export type CreateFaultGroupResponse = {
  /**
   * Current created group.
   */
  group: {
    /**
     * Stable failure-class identity.
     */
    class_id: string;
    /**
     * User-visible failure-class name, such as room or power source.
     */
    class_name: string;
    /**
     * Stable concrete group identity.
     */
    group_id: string;
    /**
     * User-visible concrete boundary name.
     */
    group_name: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
  };
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
};

/**
 * CreateGroupRequest
 *
 * Idempotent administrator request to create one nested group.
 */
export type CreateGroupRequest = {
  /**
   * Human-readable group name.
   */
  display_name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * CreateMeshSetupRequest
 *
 * One exact request to create the first mesh on an unclaimed daemon.
 */
export type CreateMeshSetupRequest = {
  /**
   * Human-readable first administrator name.
   */
  administrator_name: string;
  /**
   * Human-readable physical host name.
   */
  host_name: string;
  /**
   * Human-readable mesh name.
   */
  mesh_name: string;
  /**
   * Human-readable daemon-node name.
   */
  node_name: string;
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
};

/**
 * CreateMeshSetupResponse
 *
 * Successful, committed first-mesh creation result.
 */
export type CreateMeshSetupResponse = {
  /**
   * One-time presentation of the first administrator's ordinary API key.
   */
  api_key: string;
  /**
   * Stable UUID of the created mesh.
   */
  mesh_id: string;
  /**
   * Stable UUID of the first daemon node.
   */
  node_id: string;
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Exact encrypted recovery-bundle file; save it separately before enrolling more nodes.
   */
  recovery_bundle: string;
  /**
   * Short proof entered after the administrator has saved the exact file and code.
   */
  recovery_challenge: string;
  /**
   * One-time high-entropy recovery code which must be stored separately from the bundle.
   */
  recovery_code: string;
};

/**
 * CreateNodeJoinGrantRequest
 *
 * Administrator request for one bounded node join invitation.
 */
export type CreateNodeJoinGrantRequest = {
  /**
   * One role pre-authorised for a joining daemon.
   */
  allowed_roles: Array<"storage" | "gateway" | "metadata_eligible">;
  /**
   * HTTPS origin the joining daemon contacts; the UI normally supplies its current origin.
   */
  enrolment_endpoint: string;
  /**
   * Maximum successful node admissions.
   */
  maximum_uses: number;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Requested lifetime in whole seconds.
   */
  valid_for_seconds: number;
};

/**
 * CreateNodeJoinGrantResponse
 *
 * One exactly replayable join-grant issuance result.
 */
export type CreateNodeJoinGrantResponse = {
  /**
   * One role pre-authorised for a joining daemon.
   */
  allowed_roles: Array<"storage" | "gateway" | "metadata_eligible">;
  /**
   * Exclusive authoritative expiry as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Self-contained secret invitation returned only by this operation.
   */
  readonly join_code: string;
  /**
   * Exact committed use ceiling.
   */
  maximum_uses: number;
  /**
   * Exact operation whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * CreatePasskeyChallengeRequest
 *
 * Input for creating one short-lived passkey authentication challenge.
 */
export type CreatePasskeyChallengeRequest = {
  /**
   * Client-generated identity making challenge creation exactly replayable on this gateway.
   */
  operation_id: string;
};

/**
 * CreatePasskeyChallengeResponse
 *
 * Browser-ready options for one passkey authentication ceremony.
 */
export type CreatePasskeyChallengeResponse = {
  /**
   * Unpadded base64url random challenge supplied to `navigator.credentials.get`.
   */
  challenge: string;
  /**
   * Stable challenge identity supplied with the resulting assertion.
   */
  challenge_id: string;
  /**
   * Challenge-creation operation whose exact result this response represents.
   */
  operation_id: string;
  /**
   * Exact relying-party identifier against which authenticator data is verified.
   */
  relying_party_id: string;
  /**
   * Browser hint; server expiry remains authoritative.
   */
  timeout_milliseconds: number;
  /**
   * Require a PIN, biometric or equivalent authenticator-local verification.
   */
  user_verification: "required";
};

/**
 * CreatePasskeyRegistrationChallengeRequest
 *
 * One idempotent request for browser-ready current-user registration options.
 */
export type CreatePasskeyRegistrationChallengeRequest = {
  /**
   * Client-generated identity making challenge creation exactly replayable on this gateway.
   */
  operation_id: string;
};

/**
 * CreatePasskeyRegistrationChallengeResponse
 *
 * Browser-ready options for registering a current user's passkey.
 */
export type CreatePasskeyRegistrationChallengeResponse = {
  /**
   * Request privacy-preserving none attestation.
   */
  attestation: "none";
  /**
   * Canonical unpadded base64url random challenge.
   */
  challenge: string;
  /**
   * Stable gateway-local challenge identity supplied with completion.
   */
  challenge_id: string;
  /**
   * Existing current-user credentials the authenticator should not duplicate.
   */
  exclude_credentials: Array<{
    /**
     * Canonical unpadded base64url credential identity.
     */
    id: string;
    /**
     * A public-key credential.
     */
    type: "public-key";
  }>;
  /**
   * Challenge-creation operation whose exact result this response represents.
   */
  operation_id: string;
  /**
   * Exact supported public-key algorithms.
   */
  public_key_parameters: Array<{
    /**
     * COSE algorithm identifier; the initial profile supports ES256 only.
     */
    algorithm: number;
    /**
     * A public-key credential.
     */
    type: "public-key";
  }>;
  /**
   * Exact relying-party identifier against which authenticator data is verified.
   */
  relying_party_id: string;
  /**
   * Human-readable relying-party name shown by authenticators.
   */
  relying_party_name: string;
  /**
   * Require a discoverable credential for account-name-free authentication.
   */
  resident_key: "required";
  /**
   * Browser hint; server expiry remains authoritative.
   */
  timeout_milliseconds: number;
  /**
   * Human-readable current-user display name.
   */
  user_display_name: string;
  /**
   * Stable opaque `WebAuthn` user handle encoded as canonical unpadded base64url.
   */
  user_id: string;
  /**
   * Stable current-user account name shown by authenticators.
   */
  user_name: string;
  /**
   * Require a PIN, biometric or equivalent authenticator-local verification.
   */
  user_verification: "required";
};

/**
 * CreatePasskeyRegistrationRequest
 *
 * One exact registration response bound to a gateway-issued challenge.
 */
export type CreatePasskeyRegistrationRequest = {
  /**
   * Gateway-issued registration challenge consumed exactly once.
   */
  challenge_id: string;
  /**
   * User-visible method label.
   */
  label: string;
  /**
   * Client-generated identity for the authoritative method creation.
   */
  operation_id: string;
  /**
   * Authenticator transports reported for a newly registered credential.
   */
  transports: Array<
    "usb" | "nfc" | "ble" | "smart-card" | "hybrid" | "internal"
  >;
};

/**
 * CreatePasskeyRegistrationResponse
 *
 * Durable result of registering one current-user passkey.
 */
export type CreatePasskeyRegistrationResponse = {
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Newly created independently revocable authentication method.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed outcome was resolved.
   */
  operation_id: string;
};

/**
 * CreatePrincipalResponse
 *
 * Durable creation result shared by users and groups.
 */
export type CreatePrincipalResponse = {
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Newly created or exactly replayed principal.
   */
  principal: {
    /**
     * Original authoritative creation instant as epoch microseconds.
     */
    created_at_epoch_micros: number;
    /**
     * Case-preserved NFC display name.
     */
    display_name: string;
    /**
     * User or nested group.
     */
    kind: "user" | "group";
    /**
     * Stable local identity.
     */
    principal_id: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Current lifecycle state.
     */
    state: "active" | "suspended" | "retired";
  };
};

/**
 * CreateRecoveryCodesRequest
 *
 * One idempotent request to replace the current user's recovery-code set.
 */
export type CreateRecoveryCodesRequest = {
  /**
   * Human-readable independently revocable method label.
   */
  label: string;
  /**
   * Client-generated identity binding exact retries.
   */
  operation_id: string;
};

/**
 * CreateRecoveryCodesResponse
 *
 * One exactly replayable recovery-code set returned only by its issuance operation.
 */
export type CreateRecoveryCodesResponse = {
  /**
   * Ten independent, single-use secret-bearing recovery codes.
   */
  codes: [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Independently revocable common authentication-method identity.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * CreateSessionRequest
 *
 * Input for exchanging accepted authentication proofs for a session.
 */
export type CreateSessionRequest = {
  /**
   * Optional TOTP or recovery-code proof when policy requires another factor.
   */
  additional_factor?:
    | {
        method: "totp";
      }
    | {
        method: "recovery_code";
      }
    | null;
  /**
   * Primary API-key or passkey proof. It identifies the principal server-side.
   */
  authentication:
    | {
        method: "api_key";
      }
    | {
        /**
         * Server-issued challenge identity consumed exactly once.
         */
        challenge_id: string;
        method: "passkey";
      };
  /**
   * Optional client label: omitted means unchanged and null means clear.
   */
  client_label?: string | null;
  /**
   * Client-generated idempotency key.
   */
  operation_id: string;
  /**
   * Whether the caller requests the policy's longer-lived session profile.
   */
  remember: boolean;
};

/**
 * CreateSessionResponse
 *
 * Successful session creation response.
 */
export type CreateSessionResponse = {
  /**
   * Assurance reached by the accepted authentication factors.
   */
  assurance: "single_factor" | "multi_factor" | "recent_step_up";
  /**
   * Authoritative UTC instant as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * The operation whose durable outcome this response represents.
   */
  operation_id: string;
  /**
   * Newly created session identifier.
   */
  session_id: string;
};

/**
 * CreateTotpRegistrationChallengeRequest
 *
 * One idempotent request to create TOTP registration material.
 */
export type CreateTotpRegistrationChallengeRequest = {
  /**
   * Human-readable independently revocable method label.
   */
  label: string;
  /**
   * Client-generated identity making creation exactly replayable on this gateway.
   */
  operation_id: string;
};

/**
 * CreateTotpRegistrationChallengeResponse
 *
 * One exactly replayable TOTP seed presentation.
 */
export type CreateTotpRegistrationChallengeResponse = {
  /**
   * Interoperable HMAC-SHA-1 TOTP profile; SHA-1 is not used as a general digest.
   */
  algorithm: "SHA1";
  /**
   * Stable gateway-local ceremony identity supplied with confirmation.
   */
  challenge_id: string;
  /**
   * Exact decimal code width.
   */
  digits: number;
  /**
   * Exclusive ceremony expiry as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Challenge-creation operation whose exact result this response represents.
   */
  operation_id: string;
  /**
   * Exact TOTP timestep in seconds.
   */
  period_seconds: number;
  /**
   * Standard authenticator provisioning URI encoding the same seed and parameters.
   */
  readonly provisioning_uri: string;
  /**
   * Canonical RFC 4648 base32 seed without padding.
   */
  readonly secret: string;
};

/**
 * CreateTotpRegistrationRequest
 *
 * One idempotent request confirming a newly presented TOTP seed.
 */
export type CreateTotpRegistrationRequest = {
  /**
   * Exact short-lived registration ceremony being confirmed.
   */
  challenge_id: string;
  /**
   * Client-generated identity binding exact confirmation retries.
   */
  operation_id: string;
};

/**
 * CreateTotpRegistrationResponse
 *
 * Durable result of confirming one independently revocable TOTP method.
 */
export type CreateTotpRegistrationResponse = {
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Newly created common authentication-method identity.
   */
  method_id: string;
  /**
   * Exact confirmation operation whose result was resolved.
   */
  operation_id: string;
};

/**
 * CreateUserRequest
 *
 * Idempotent administrator request to create one user.
 */
export type CreateUserRequest = {
  /**
   * Human-readable user name.
   */
  display_name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * CreateVolumePermissionGrantRequest
 *
 * Idempotent administrator request to grant volume authority to one user or group.
 */
export type CreateVolumePermissionGrantRequest = {
  /**
   * Omitted applies policy defaults, null needs no activation, and a value defines activation.
   */
  activation?: {
    /**
     * Longest activation the user may request.
     */
    maximum_duration_micros: number;
    /**
     * Authentication assurance required when activating.
     */
    minimum_assurance: "single_factor" | "multi_factor" | "recent_step_up";
    /**
     * Whether every activation must contain a non-blank reason.
     */
    reason_required: boolean;
  } | null;
  /**
   * Whether authority applies to the root, descendants or both.
   */
  inheritance: "object" | "descendants" | "object_and_descendants";
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Protocol-neutral namespace authority currently available to this caller.
   */
  rights: Array<
    | "traverse"
    | "list"
    | "read_data"
    | "create_child"
    | "write_data"
    | "append_data"
    | "rename"
    | "delete"
    | "read_attributes"
    | "write_attributes"
    | "read_permissions"
    | "change_permissions"
    | "change_owner"
  >;
  /**
   * User or group receiving the rights.
   */
  subject_principal_id: string;
  /**
   * Omitted applies policy defaults, null is unbounded, and a value is exact.
   */
  valid_from_epoch_micros?: number | null;
  /**
   * Omitted applies policy defaults, null is unbounded, and a value is exact.
   */
  valid_until_epoch_micros?: number | null;
};

/**
 * CreateVolumePermissionGrantResponse
 *
 * Durable result of creating or exactly replaying one permission grant.
 */
export type CreateVolumePermissionGrantResponse = {
  /**
   * Newly active or exactly replayed grant.
   */
  grant: {
    /**
     * Policy that must be activated, or null when authority is immediately usable.
     */
    activation_policy_id: string | null;
    /**
     * Original authoritative creation instant.
     */
    created_at_epoch_micros: number;
    /**
     * Principal that created this grant.
     */
    created_by: string;
    /**
     * Stable grant identity.
     */
    grant_id: string;
    /**
     * Explicit descendant behaviour.
     */
    inheritance: "object" | "descendants" | "object_and_descendants";
    /**
     * Current authoritative grant revision.
     */
    revision: number;
    /**
     * Protocol-neutral namespace authority currently available to this caller.
     */
    rights: Array<
      | "traverse"
      | "list"
      | "read_data"
      | "create_child"
      | "write_data"
      | "append_data"
      | "rename"
      | "delete"
      | "read_attributes"
      | "write_attributes"
      | "read_permissions"
      | "change_permissions"
      | "change_owner"
    >;
    /**
     * User or group receiving the rights.
     */
    subject_principal_id: string;
    /**
     * Inclusive validity start, or null when unbounded below.
     */
    valid_from_epoch_micros: number | null;
    /**
     * Exclusive validity end, or null when unbounded above.
     */
    valid_until_epoch_micros: number | null;
    /**
     * Volume whose root defines this grant's scope.
     */
    volume_id: string;
  };
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * CreateVolumeRequest
 *
 * Idempotent administrator request to create one logical volume.
 */
export type CreateVolumeRequest = {
  /**
   * Human-readable logical-volume name.
   */
  name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Non-empty user/group owner set; ownership is never inferred from shard placement.
   */
  owner_principal_ids: Array<string>;
};

/**
 * CreateVolumeResponse
 *
 * Durable authoritative volume-creation outcome.
 */
export type CreateVolumeResponse = {
  /**
   * Original authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Case-preserved authoritative name.
   */
  name: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Exact immutable initial owner set.
   */
  owner_principal_ids: Array<string>;
  /**
   * Authoritative revision created by the operation.
   */
  revision: number;
  /**
   * Stable root-directory identity used by connectors.
   */
  root_object_id: string;
  /**
   * Stable logical-volume identity.
   */
  volume_id: string;
};

/**
 * CurrentSessionResponse
 *
 * Current caller identity and coarse panel-navigation authority.
 */
export type CurrentSessionResponse = {
  /**
   * Whether the current role projection permits entering administration.
   */
  administration_available: boolean;
  /**
   * Exclusive authoritative session expiry as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Current authenticated user principal.
   */
  principal_id: string;
  /**
   * Current committed session identity.
   */
  session_id: string;
};

/**
 * DeleteObjectRequest
 *
 * Logically deletes one exact current file or empty directory.
 */
export type DeleteObjectRequest = {
  /**
   * Client-generated end-to-end idempotency identity.
   */
  operation_id: string;
  /**
   * Exact current root-relative path to remove.
   */
  path: string;
};

/**
 * DeleteObjectResponse
 *
 * Durable result of one atomic logical namespace removal.
 */
export type DeleteObjectResponse = {
  /**
   * Resulting local branch-head sequence.
   */
  head_sequence: number;
  /**
   * Namespace commit made current by the operation.
   */
  namespace_commit_id: string;
  /**
   * Stable removed logical-object identity.
   */
  object_id: string;
  /**
   * Whether the removed object was a file or directory.
   */
  object_kind: "directory" | "file";
  /**
   * Exact immutable object revision removed from the namespace.
   */
  object_revision_id: string;
  /**
   * Exact operation which removed or previously removed the object.
   */
  operation_id: string;
  /**
   * Exact removed path.
   */
  path: string;
  /**
   * The complete local/cell branch mutation is durably committed.
   */
  scope: "branch_deleted";
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * EnrolNodeRequest
 *
 * One node-owned identity presentation for pre-authorised enrolment.
 */
export type EnrolNodeRequest = {
  /**
   * New or existing physical host binding.
   */
  host:
    | {
        kind: "new";
        /**
         * Human-facing host name.
         */
        name: string;
      }
    | {
        /**
         * Existing host identity.
         */
        host_id: string;
        kind: "existing";
      };
  /**
   * P-256 signature over the exact canonical enrolment transcript as lowercase DER hex.
   */
  identity_proof_signature_hex: string;
  /**
   * Canonical uncompressed P-256 SEC1 public identity bytes as lowercase hex.
   */
  node_identity_public_key_hex: string;
  /**
   * Human-facing daemon name.
   */
  node_name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Private QUIC endpoint advertised after certificate installation.
   */
  private_endpoint: string;
  /**
   * One role pre-authorised for a joining daemon.
   */
  requested_roles: Array<"storage" | "gateway" | "metadata_eligible">;
  /**
   * Canonical X25519 public secret-wrapping key as lowercase hex.
   */
  wrapping_public_key_hex: string;
};

/**
 * EnrolNodeResponse
 *
 * Exact replayable result of consuming one join-grant use.
 */
export type EnrolNodeResponse = {
  /**
   * Current enrolled bootstrap peers, never including the joining node.
   */
  bootstrap_peers: Array<{
    /**
     * Current leaf certificate DER as lowercase hex.
     */
    certificate_der_hex: string;
    /**
     * Permanent peer node identity.
     */
    node_id: string;
    /**
     * Current private QUIC endpoint.
     */
    private_endpoint: string;
  }>;
  /**
   * Target mesh proven by the invitation and response chain.
   */
  mesh_id: string;
  /**
   * Issued node leaf certificate DER as lowercase hex.
   */
  node_certificate_der_hex: string;
  /**
   * Permanent identity derived from the submitted public key.
   */
  node_id: string;
  /**
   * Root-signed online authority certificate DER as lowercase hex.
   */
  online_authority_certificate_der_hex: string;
  /**
   * Exact operation whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Offline mesh root certificate DER as lowercase hex.
   */
  root_certificate_der_hex: string;
  /**
   * Root metadata partition the joining learner must restore and follow.
   */
  root_partition_id: string;
  /**
   * Current non-zero route epoch for the root metadata partition.
   */
  routing_epoch: number;
};

/**
 * GetObjectResponse
 *
 * Complete immutable metadata for one logical object.
 */
export type GetObjectResponse = {
  /**
   * Immutable namespace view under which the path resolved.
   */
  namespace_commit_id: string;
  /**
   * Complete object metadata, including the immutable file version when applicable.
   */
  object: {
    /**
     * Monotonic name-reuse generation within the parent.
     */
    entry_generation: number;
    /**
     * Current immutable file version, or null for a directory.
     */
    file_version_id: string | null;
    /**
     * Directory or regular-file kind.
     */
    kind: "directory" | "file";
    /**
     * Logical file bytes, or null for a directory.
     */
    logical_length: number | null;
    /**
     * Case-preserved logical-object name.
     */
    name: string;
    /**
     * Stable logical-object identity.
     */
    object_id: string;
    /**
     * Exact immutable logical-object revision.
     */
    object_revision_id: string;
  };
  /**
   * Exact root-relative path which resolved the object.
   */
  path: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * HealthResponse
 *
 * Bounded anonymous health response.
 */
export type HealthResponse = {
  /**
   * Resolved rolling API label.
   */
  api_version: string;
  /**
   * Digest of the exact `OpenAPI` document served by this process.
   */
  schema_digest: string;
  /**
   * Current readiness state.
   */
  status: "starting" | "ready" | "degraded";
};

/**
 * JoinMeshSetupRequest
 *
 * One exact request to join an existing mesh from an unclaimed daemon.
 */
export type JoinMeshSetupRequest = {
  /**
   * Human-readable physical host name created by the destination mesh.
   */
  host_name: string;
  /**
   * Human-readable daemon-node name created by the destination mesh.
   */
  node_name: string;
  /**
   * Client-generated idempotency identity retained across the internal restart.
   */
  operation_id: string;
};

/**
 * JoinMeshSetupResponse
 *
 * Accepted restart-safe join intent.
 */
export type JoinMeshSetupResponse = {
  /**
   * Exact idempotency identity whose join will resume after the internal restart.
   */
  operation_id: string;
  /**
   * Same-origin operation resource which becomes authoritative after enrolment.
   */
  status_url: string;
};

/**
 * ListAuthenticationMethodsResponse
 *
 * One bounded current-user authentication-method page.
 */
export type ListAuthenticationMethodsResponse = {
  /**
   * Stable ordered, secret-free authentication methods.
   */
  methods: Array<{
    /**
     * Authoritative creation instant as epoch microseconds.
     */
    created_at_epoch_micros: number;
    /**
     * Method-specific public projection.
     */
    details:
      | {
          /**
           * Whether the authenticator reports that the credential can be backed up.
           */
          backup_eligible: boolean;
          /**
           * Last authoritative backed-up state reported by the authenticator.
           */
          backup_state: boolean;
          kind: "passkey";
        }
      | {
          kind: "totp";
        }
      | {
          kind: "recovery_codes";
          /**
           * Number of codes which have not yet been consumed.
           */
          remaining_codes: number;
        }
      | {
          /**
           * Public identity embedded in the key.
           */
          key_id: string;
          kind: "api_key";
          /**
           * One connector through which an issued API key may authenticate.
           */
          scopes: Array<"https_session" | "headless_api" | "smb_session">;
          /**
           * Inclusive first accepted instant as epoch microseconds.
           */
          valid_from_epoch_micros: number;
        };
    /**
     * Exclusive expiry, or null when the method has no automatic expiry.
     */
    expires_at_epoch_micros: number | null;
    /**
     * User-facing label assigned at registration or issuance.
     */
    label: string;
    /**
     * Last successful use, or null before first use.
     */
    last_used_at_epoch_micros: number | null;
    /**
     * Common stable method identity.
     */
    method_id: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Current authoritative lifecycle state.
     */
    state: "active" | "suspended" | "revoked";
  }>;
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
};

/**
 * ListDirectoryResponse
 *
 * One immutable, bounded directory page.
 */
export type ListDirectoryResponse = {
  /**
   * Stable selected-directory identity.
   */
  directory_object_id: string;
  /**
   * Exact immutable selected-directory revision.
   */
  directory_object_revision_id: string;
  /**
   * Deterministically ordered complete child metadata.
   */
  entries: Array<{
    /**
     * Monotonic name-reuse generation within the parent.
     */
    entry_generation: number;
    /**
     * Current immutable file version, or null for a directory.
     */
    file_version_id: string | null;
    /**
     * Directory or regular-file kind.
     */
    kind: "directory" | "file";
    /**
     * Logical file bytes, or null for a directory.
     */
    logical_length: number | null;
    /**
     * Case-preserved logical-object name.
     */
    name: string;
    /**
     * Stable logical-object identity.
     */
    object_id: string;
    /**
     * Exact immutable logical-object revision.
     */
    object_revision_id: string;
  }>;
  /**
   * Immutable namespace view shared by every entry.
   */
  namespace_commit_id: string;
  /**
   * Ready-to-follow relative URL, or null when this is the terminal page.
   */
  next_page_url: string | null;
  /**
   * Selected relative path, or null for the root.
   */
  path: string | null;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * ListFaultGroupMembershipsResponse
 *
 * One bounded page of overlapping membership edges.
 */
export type ListFaultGroupMembershipsResponse = {
  /**
   * Stable machine/group-ordered membership edges.
   */
  memberships: Array<{
    /**
     * Shared-failure group identity.
     */
    group_id: string;
    /**
     * Member machine identity.
     */
    host_id: string;
    /**
     * Last authoritative edge revision.
     */
    revision: number;
  }>;
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
};

/**
 * ListFaultGroupsResponse
 *
 * One bounded page of shared-failure groups.
 */
export type ListFaultGroupsResponse = {
  /**
   * Stable class/name-ordered groups.
   */
  groups: Array<{
    /**
     * Stable failure-class identity.
     */
    class_id: string;
    /**
     * User-visible failure-class name, such as room or power source.
     */
    class_name: string;
    /**
     * Stable concrete group identity.
     */
    group_id: string;
    /**
     * User-visible concrete boundary name.
     */
    group_name: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
  }>;
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
};

/**
 * ListGroupMembershipsResponse
 *
 * One bounded, stable direct-membership page.
 */
export type ListGroupMembershipsResponse = {
  /**
   * Group whose direct edges are represented.
   */
  group_id: string;
  /**
   * Direct active memberships ordered by stable member identity.
   */
  memberships: Array<{
    /**
     * Whether the affected user must activate this membership before it contributes rights.
     */
    activation_required: boolean;
    /**
     * Original authoritative creation instant.
     */
    created_at_epoch_micros: number;
    /**
     * Administrator that originally created the current edge.
     */
    created_by: string;
    /**
     * Structurally containing group.
     */
    group_id: string;
    /**
     * Direct user or nested-group member.
     */
    member: {
      /**
       * Original authoritative creation instant as epoch microseconds.
       */
      created_at_epoch_micros: number;
      /**
       * Case-preserved NFC display name.
       */
      display_name: string;
      /**
       * User or nested group.
       */
      kind: "user" | "group";
      /**
       * Stable local identity.
       */
      principal_id: string;
      /**
       * Last authoritative metadata revision.
       */
      revision: number;
      /**
       * Current lifecycle state.
       */
      state: "active" | "suspended" | "retired";
    };
    /**
     * Last authoritative membership revision.
     */
    revision: number;
    /**
     * Inclusive validity start, or null when unbounded below.
     */
    valid_from_epoch_micros: number | null;
    /**
     * Exclusive validity end, or null when unbounded above.
     */
    valid_until_epoch_micros: number | null;
  }>;
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
};

/**
 * ListOperationsResponse
 *
 * One bounded reverse-chronological administrator operation page.
 */
export type ListOperationsResponse = {
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Current authoritative operation projections, newest revision first.
   */
  operations: Array<{
    /**
     * Whether a cancellation request is currently safe and supported.
     */
    cancellation_available: boolean;
    /**
     * Terminal instant, or null while work remains non-terminal.
     */
    completed_at_epoch_micros: number | null;
    /**
     * Typed terminal failure, or null for non-failed states.
     */
    failure: {
      /**
       * Stable machine-readable failure category.
       */
      code: string;
      /**
       * Bounded plain-language explanation.
       */
      message: string;
      /**
       * Safe retry classification independent of the prose.
       */
      retry: "never" | "automatic" | "same_operation" | "action_required";
    } | null;
    /**
     * Stable work family.
     */
    kind:
      | "metadata_mutation"
      | "setup_join"
      | "placement"
      | "repair"
      | "scrub"
      | "drain"
      | "reconciliation"
      | "certificate"
      | "backup"
      | "update";
    /**
     * Exact operation being resolved.
     */
    operation_id: string;
    /**
     * Advisory bounded progress, or null when the work is not meaningfully countable.
     */
    progress: {
      /**
       * Completed work in the declared unit.
       */
      completed: number;
      /**
       * Current known total, which may increase as bounded discovery proceeds.
       */
      total: number;
      /**
       * Meaning of both counters.
       */
      unit: "steps" | "bytes" | "items" | "nodes" | "targets";
    } | null;
    /**
     * Ready-to-follow committed result URL when the result has an addressable resource.
     */
    result_url: string | null;
    /**
     * Authoritative operation revision used by conditional clients and event projections.
     */
    revision: number;
    /**
     * Original accepted instant.
     */
    started_at_epoch_micros: number;
    /**
     * Authoritative lifecycle state.
     */
    state:
      | "queued"
      | "running"
      | "awaiting_action"
      | "succeeded"
      | "failed"
      | "cancelled";
    /**
     * Ready-to-follow current status URL.
     */
    status_url: string;
    /**
     * Most recent authoritative lifecycle change.
     */
    updated_at_epoch_micros: number;
  }>;
};

/**
 * ListPrincipalsResponse
 *
 * One bounded, permission-filtered administrator identity page.
 */
export type ListPrincipalsResponse = {
  /**
   * Principal family selected by the endpoint.
   */
  kind: "user" | "group";
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable ordered identities.
   */
  principals: Array<{
    /**
     * Original authoritative creation instant as epoch microseconds.
     */
    created_at_epoch_micros: number;
    /**
     * Case-preserved NFC display name.
     */
    display_name: string;
    /**
     * User or nested group.
     */
    kind: "user" | "group";
    /**
     * Stable local identity.
     */
    principal_id: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Current lifecycle state.
     */
    state: "active" | "suspended" | "retired";
  }>;
};

/**
 * ListStorageFoldersResponse
 *
 * Current manager-only page of local storage folders.
 */
export type ListStorageFoldersResponse = {
  /**
   * Stable target-identity-ordered folder summaries.
   */
  folders: Array<{
    /**
     * Current immutable target generation as lossless positive decimal text.
     */
    generation: string;
    /**
     * Permanent daemon identity that owns this target generation.
     */
    node_id: string;
    /**
     * Exact local UTF-8 path, or null when a headless path cannot be represented safely.
     */
    path: string | null;
    /**
     * Current local serving state.
     */
    state: "configuring" | "active" | "unavailable";
    /**
     * Stable target identity independent of path spelling.
     */
    target_id: string;
    /**
     * Configured physical capacity ceiling.
     */
    usage_limit:
      | {
          kind: "percent";
          /**
           * Inclusive percentage from 1 through 100.
           */
          percent: number;
        }
      | {
          /**
           * Positive unsigned 64-bit decimal bytes.
           */
          bytes: string;
          kind: "bytes";
        };
  }>;
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
};

/**
 * ListTopologyNodesResponse
 *
 * One bounded page of daemon nodes.
 */
export type ListTopologyNodesResponse = {
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable name-ordered node summaries.
   */
  nodes: Array<{
    /**
     * User-visible node name.
     */
    display_name: string;
    /**
     * Stable machine identity shared by daemons on the same machine.
     */
    host_id: string;
    /**
     * Current restart incarnation as lossless positive decimal text.
     */
    incarnation: string;
    /**
     * Stable daemon identity.
     */
    node_id: string;
    /**
     * Private mesh endpoint once activated.
     */
    private_endpoint: string | null;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Configured daemon roles.
     */
    roles: {
      /**
       * May expose configured access protocols.
       */
      gateway: boolean;
      /**
       * Eligible for metadata learner/voter placement.
       */
      metadata_eligible: boolean;
      /**
       * May host encrypted storage shards.
       */
      storage: boolean;
    };
    /**
     * Current lifecycle state.
     */
    state: "joining" | "active" | "draining" | "retired";
  }>;
};

/**
 * ListTopologyTargetsResponse
 *
 * One bounded page of mesh-wide targets.
 */
export type ListTopologyTargetsResponse = {
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable name-ordered target summaries.
   */
  targets: Array<{
    /**
     * User-visible target name.
     */
    display_name: string;
    /**
     * Current authority-fenced generation as lossless positive decimal text.
     */
    generation: string;
    /**
     * Owning machine identity.
     */
    host_id: string;
    /**
     * Owning daemon identity.
     */
    node_id: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Current target state.
     */
    state: "configuring" | "active" | "draining" | "unavailable" | "retired";
    /**
     * Stable target identity.
     */
    target_id: string;
    /**
     * Current provider-owned capacity ceiling.
     */
    usage_limit:
      | {
          kind: "percent";
          /**
           * Inclusive percentage from 1 through 100.
           */
          percent: number;
        }
      | {
          /**
           * Positive unsigned 64-bit decimal bytes.
           */
          bytes: string;
          kind: "bytes";
        };
  }>;
};

/**
 * ListUploadRangesResponse
 *
 * Bounded exact coverage page pinned to one upload checkpoint.
 */
export type ListUploadRangesResponse = {
  /**
   * Immutable stage sequence represented by every page in this traversal.
   */
  checkpoint_sequence: number;
  /**
   * Complete next-page URL under current authority, or null at the end.
   */
  next_page_url: string | null;
  /**
   * Sorted, non-overlapping, non-adjacent exact received ranges.
   */
  ranges: Array<{
    /**
     * Exclusive end, strictly greater than start.
     */
    end: number;
    /**
     * First initialised byte.
     */
    start: number;
  }>;
  /**
   * Selected upload.
   */
  upload_id: string;
};

/**
 * ListVolumePermissionGrantsResponse
 *
 * One bounded stable page of active volume grants.
 */
export type ListVolumePermissionGrantsResponse = {
  /**
   * Stable grant records ordered by grant identity.
   */
  grants: Array<{
    /**
     * Policy that must be activated, or null when authority is immediately usable.
     */
    activation_policy_id: string | null;
    /**
     * Original authoritative creation instant.
     */
    created_at_epoch_micros: number;
    /**
     * Principal that created this grant.
     */
    created_by: string;
    /**
     * Stable grant identity.
     */
    grant_id: string;
    /**
     * Explicit descendant behaviour.
     */
    inheritance: "object" | "descendants" | "object_and_descendants";
    /**
     * Current authoritative grant revision.
     */
    revision: number;
    /**
     * Protocol-neutral namespace authority currently available to this caller.
     */
    rights: Array<
      | "traverse"
      | "list"
      | "read_data"
      | "create_child"
      | "write_data"
      | "append_data"
      | "rename"
      | "delete"
      | "read_attributes"
      | "write_attributes"
      | "read_permissions"
      | "change_permissions"
      | "change_owner"
    >;
    /**
     * User or group receiving the rights.
     */
    subject_principal_id: string;
    /**
     * Inclusive validity start, or null when unbounded below.
     */
    valid_from_epoch_micros: number | null;
    /**
     * Exclusive validity end, or null when unbounded above.
     */
    valid_until_epoch_micros: number | null;
    /**
     * Volume whose root defines this grant's scope.
     */
    volume_id: string;
  }>;
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Exact volume represented by the page.
   */
  volume_id: string;
};

/**
 * ListVolumesResponse
 *
 * One bounded current-user volume page.
 */
export type ListVolumesResponse = {
  /**
   * Ready-to-follow relative URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable ordered volumes visible under the caller's current permissions.
   */
  volumes: Array<{
    /**
     * Authoritative creation instant as epoch microseconds.
     */
    created_at_epoch_micros: number;
    /**
     * Protocol-neutral namespace authority currently available to this caller.
     */
    effective_rights: Array<
      | "traverse"
      | "list"
      | "read_data"
      | "create_child"
      | "write_data"
      | "append_data"
      | "rename"
      | "delete"
      | "read_attributes"
      | "write_attributes"
      | "read_permissions"
      | "change_permissions"
      | "change_owner"
    >;
    /**
     * Case-preserved user-facing name.
     */
    name: string;
    /**
     * Last authoritative metadata revision.
     */
    revision: number;
    /**
     * Current authoritative lifecycle state.
     */
    state: "active" | "suspended" | "draining" | "retired";
    /**
     * Stable logical-volume identity.
     */
    volume_id: string;
  }>;
};

/**
 * OperationStatusResponse
 *
 * Current durable state of one exact operation visible to the caller.
 */
export type OperationStatusResponse = {
  /**
   * Whether a cancellation request is currently safe and supported.
   */
  cancellation_available: boolean;
  /**
   * Terminal instant, or null while work remains non-terminal.
   */
  completed_at_epoch_micros: number | null;
  /**
   * Typed terminal failure, or null for non-failed states.
   */
  failure: {
    /**
     * Stable machine-readable failure category.
     */
    code: string;
    /**
     * Bounded plain-language explanation.
     */
    message: string;
    /**
     * Safe retry classification independent of the prose.
     */
    retry: "never" | "automatic" | "same_operation" | "action_required";
  } | null;
  /**
   * Stable work family.
   */
  kind:
    | "metadata_mutation"
    | "setup_join"
    | "placement"
    | "repair"
    | "scrub"
    | "drain"
    | "reconciliation"
    | "certificate"
    | "backup"
    | "update";
  /**
   * Exact operation being resolved.
   */
  operation_id: string;
  /**
   * Advisory bounded progress, or null when the work is not meaningfully countable.
   */
  progress: {
    /**
     * Completed work in the declared unit.
     */
    completed: number;
    /**
     * Current known total, which may increase as bounded discovery proceeds.
     */
    total: number;
    /**
     * Meaning of both counters.
     */
    unit: "steps" | "bytes" | "items" | "nodes" | "targets";
  } | null;
  /**
   * Ready-to-follow committed result URL when the result has an addressable resource.
   */
  result_url: string | null;
  /**
   * Authoritative operation revision used by conditional clients and event projections.
   */
  revision: number;
  /**
   * Original accepted instant.
   */
  started_at_epoch_micros: number;
  /**
   * Authoritative lifecycle state.
   */
  state:
    | "queued"
    | "running"
    | "awaiting_action"
    | "succeeded"
    | "failed"
    | "cancelled";
  /**
   * Ready-to-follow current status URL.
   */
  status_url: string;
  /**
   * Most recent authoritative lifecycle change.
   */
  updated_at_epoch_micros: number;
};

/**
 * PublishSmbExportRequest
 *
 * Exact-retry request to publish one existing volume or folder explicitly.
 */
export type PublishSmbExportRequest = {
  /**
   * Whether every packet after tree connection must be encrypted.
   */
  encryption_required: boolean;
  /**
   * Explicit gateway publication policy.
   */
  gateways:
    | {
        kind: "all_eligible";
      }
    | {
        kind: "selected";
        /**
         * Non-empty unique canonical node UUIDs.
         */
        node_ids: Array<string>;
      };
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Stable existing directory exposed as the share root.
   */
  root_object_id: string;
  /**
   * Chosen case-insensitive share name.
   */
  share_name: string;
};

/**
 * PublishSmbExportResponse
 *
 * Durable publication result.
 */
export type PublishSmbExportResponse = {
  /**
   * Committed tree-encryption policy.
   */
  encryption_required: boolean;
  /**
   * Stable export identity derived from that operation.
   */
  export_id: string;
  /**
   * Committed gateway policy.
   */
  gateways:
    | {
        kind: "all_eligible";
      }
    | {
        kind: "selected";
        /**
         * Non-empty unique canonical node UUIDs.
         */
        node_ids: Array<string>;
      };
  /**
   * Exact operation whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Authoritative committed revision.
   */
  revision: number;
  /**
   * Exact published directory.
   */
  root_object_id: string;
  /**
   * Case-preserved authoritative share name.
   */
  share_name: string;
  /**
   * Exact containing volume.
   */
  volume_id: string;
};

/**
 * RegisterStorageFolderRequest
 *
 * Exact-retry manager request to register one existing local folder.
 */
export type RegisterStorageFolderRequest = {
  /**
   * Client-generated idempotency identity persisted before touching the provider folder.
   */
  operation_id: string;
  /**
   * Existing local folder; sibling files are never read, changed or exposed.
   */
  path: string;
  /**
   * Maximum capacity `MeshSpan` may own beneath its private subdirectory.
   */
  usage_limit:
    | {
        kind: "percent";
        /**
         * Inclusive percentage from 1 through 100.
         */
        percent: number;
      }
    | {
        /**
         * Positive unsigned 64-bit decimal bytes.
         */
        bytes: string;
        kind: "bytes";
      };
};

/**
 * RegisterStorageFolderResponse
 *
 * Durable registration result after the target is open locally.
 */
export type RegisterStorageFolderResponse = {
  /**
   * Current registered local target.
   */
  folder: {
    /**
     * Current immutable target generation as lossless positive decimal text.
     */
    generation: string;
    /**
     * Permanent daemon identity that owns this target generation.
     */
    node_id: string;
    /**
     * Exact local UTF-8 path, or null when a headless path cannot be represented safely.
     */
    path: string | null;
    /**
     * Current local serving state.
     */
    state: "configuring" | "active" | "unavailable";
    /**
     * Stable target identity independent of path spelling.
     */
    target_id: string;
    /**
     * Configured physical capacity ceiling.
     */
    usage_limit:
      | {
          kind: "percent";
          /**
           * Inclusive percentage from 1 through 100.
           */
          percent: number;
        }
      | {
          /**
           * Positive unsigned 64-bit decimal bytes.
           */
          bytes: string;
          kind: "bytes";
        };
  };
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
};

/**
 * RemoveGroupMemberRequest
 *
 * Idempotent administrator request to remove one exact active direct membership.
 */
export type RemoveGroupMemberRequest = {
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Human-readable audit reason retained with the removal evidence.
   */
  reason: string;
};

/**
 * RemoveGroupMemberResponse
 *
 * Durable result of removing or exactly replaying one direct membership.
 */
export type RemoveGroupMemberResponse = {
  /**
   * Structurally containing group.
   */
  group_id: string;
  /**
   * Direct user or group removed from it.
   */
  member_principal_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Original authoritative removal instant used by exact retries.
   */
  removed_at_epoch_micros: number;
  /**
   * Authoritative removal revision.
   */
  revision: number;
};

/**
 * RenameObjectRequest
 *
 * Atomically renames or moves one object within a logical volume.
 */
export type RenameObjectRequest = {
  /**
   * Client-generated end-to-end idempotency identity.
   */
  operation_id: string;
  /**
   * Exact current root-relative path.
   */
  source_path: string;
  /**
   * Exact unoccupied destination, or the same canonical name with changed display case.
   */
  target_path: string;
};

/**
 * RenameObjectResponse
 *
 * Durable result of one atomic same-volume rename or move.
 */
export type RenameObjectResponse = {
  /**
   * Resulting local branch-head sequence.
   */
  head_sequence: number;
  /**
   * Namespace commit made current by the operation.
   */
  namespace_commit_id: string;
  /**
   * Stable moved logical-object identity.
   */
  object_id: string;
  /**
   * Immutable object revision retained by the move.
   */
  object_revision_id: string;
  /**
   * Exact operation which moved or previously moved the object.
   */
  operation_id: string;
  /**
   * Exact source path named by the operation.
   */
  source_path: string;
  /**
   * Exact resulting path.
   */
  target_path: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * RevokeAuthenticationMethodRequest
 *
 * One idempotent request to revoke an owned authentication method.
 */
export type RevokeAuthenticationMethodRequest = {
  /**
   * Client-generated identity binding exact retries.
   */
  operation_id: string;
  /**
   * Human-readable reason retained in the immutable audit history.
   */
  reason: string;
};

/**
 * RevokeAuthenticationMethodResponse
 *
 * Durable result of revoking one owned authentication method.
 */
export type RevokeAuthenticationMethodResponse = {
  /**
   * Authentication method which is now authoritatively unusable.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Authoritative revocation instant as epoch microseconds.
   */
  revoked_at_epoch_micros: number;
};

/**
 * RevokeCurrentSessionRequest
 *
 * Idempotent request to revoke the caller's current browser session.
 */
export type RevokeCurrentSessionRequest = {
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
};

/**
 * RevokeCurrentSessionResponse
 *
 * Durable result of revoking the caller's current browser session.
 */
export type RevokeCurrentSessionResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Authoritative revocation instant as epoch microseconds.
   */
  revoked_at_epoch_micros: number;
  /**
   * Session which is now authoritatively unusable.
   */
  session_id: string;
};

/**
 * RevokePermissionGrantRequest
 *
 * Idempotent administrator request to revoke one exact active grant.
 */
export type RevokePermissionGrantRequest = {
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Human-readable audit reason retained with revocation evidence.
   */
  reason: string;
};

/**
 * RevokePermissionGrantResponse
 *
 * Durable result of revoking or exactly replaying one permission grant.
 */
export type RevokePermissionGrantResponse = {
  /**
   * Exact grant that was revoked.
   */
  grant_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Authoritative revocation revision.
   */
  revision: number;
  /**
   * Original authoritative revocation instant used by exact retries.
   */
  revoked_at_epoch_micros: number;
};

/**
 * SetFaultGroupMembershipRequest
 *
 * Exact-retry desired machine/group membership.
 */
export type SetFaultGroupMembershipRequest = {
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * `true` to add the machine or `false` to remove it.
   */
  present: boolean;
};

/**
 * SetFaultGroupMembershipResponse
 *
 * Durable desired-membership result.
 */
export type SetFaultGroupMembershipResponse = {
  /**
   * Group identity from the route.
   */
  group_id: string;
  /**
   * Machine identity from the route.
   */
  host_id: string;
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Current desired membership state.
   */
  present: boolean;
  /**
   * Authoritative mutation revision.
   */
  revision: number;
};

/**
 * SetupStatusResponse
 *
 * Cheap anonymous first-start status safe for local-network discovery.
 */
export type SetupStatusResponse = {
  /**
   * Current coarse setup state; this response never includes claim material.
   */
  state: "claim_required" | "configuring" | "configured";
};

/**
 * StepUpCurrentSessionRequest
 *
 * Input for atomically rotating the current browser session after a fresh factor.
 */
export type StepUpCurrentSessionRequest = {
  /**
   * Fresh TOTP or single-use recovery proof; the current session supplies the primary proof.
   */
  additional_factor:
    | {
        method: "totp";
      }
    | {
        method: "recovery_code";
      };
  /**
   * Client-generated idempotency key for the exact rotation.
   */
  operation_id: string;
};

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export type UploadStatusResponse = {
  /**
   * Exact current private-stage mutation sequence.
   */
  checkpoint_sequence: number;
  /**
   * Stable object published by a committed upload; otherwise null.
   */
  committed_object_id: string | null;
  /**
   * Immutable version published by a committed upload; otherwise null.
   */
  committed_version_id: string | null;
  /**
   * Exclusive server-authoritative expiry as Unix epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Highest byte written, exclusive; this does not imply gap-free coverage.
   */
  logical_extent: number;
  /**
   * Hard maximum logical file bytes.
   */
  maximum_bytes: number;
  /**
   * Canonical destination path.
   */
  path: string;
  /**
   * Absolute-path reference for bounded exact received-range pages.
   */
  ranges_url: string;
  /**
   * Positive current writer fence.
   */
  stage_fence: number;
  /**
   * Current durable lifecycle state.
   */
  state: "active" | "committing" | "committed" | "aborted";
  /**
   * Opaque upload identity.
   */
  upload_id: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * WithdrawSmbExportRequest
 *
 * Exact-retry audited withdrawal request.
 */
export type WithdrawSmbExportRequest = {
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
  /**
   * Non-blank human audit reason.
   */
  reason: string;
};

/**
 * WithdrawSmbExportResponse
 *
 * Durable export-withdrawal result.
 */
export type WithdrawSmbExportResponse = {
  /**
   * Stable withdrawn export identity.
   */
  export_id: string;
  /**
   * Exact operation whose committed result was resolved.
   */
  operation_id: string;
  /**
   * Authoritative committed revision.
   */
  revision: number;
};

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export type WriteUploadRangeResponse = {
  /**
   * Exact current private-stage mutation sequence.
   */
  checkpoint_sequence: number;
  /**
   * Stable object published by a committed upload; otherwise null.
   */
  committed_object_id: string | null;
  /**
   * Immutable version published by a committed upload; otherwise null.
   */
  committed_version_id: string | null;
  /**
   * Exclusive server-authoritative expiry as Unix epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Highest byte written, exclusive; this does not imply gap-free coverage.
   */
  logical_extent: number;
  /**
   * Hard maximum logical file bytes.
   */
  maximum_bytes: number;
  /**
   * Canonical destination path.
   */
  path: string;
  /**
   * Absolute-path reference for bounded exact received-range pages.
   */
  ranges_url: string;
  /**
   * Positive current writer fence.
   */
  stage_fence: number;
  /**
   * Current durable lifecycle state.
   */
  state: "active" | "committing" | "committed" | "aborted";
  /**
   * Opaque upload identity.
   */
  upload_id: string;
  /**
   * Selected logical volume.
   */
  volume_id: string;
};

/**
 * CreateApiKeyResponse
 *
 * One exactly replayable API-key issuance result.
 */
export type CreateApiKeyResponseWritable = {
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Exclusive expiry, or null when the key does not expire automatically.
   */
  expires_at_epoch_micros: number | null;
  /**
   * Public key identity embedded in the returned secret.
   */
  key_id: string;
  /**
   * Independently revocable common authentication-method identity.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
  /**
   * One connector through which an issued API key may authenticate.
   */
  scopes: Array<"https_session" | "headless_api" | "smb_session">;
  /**
   * Inclusive first accepted instant as epoch microseconds.
   */
  valid_from_epoch_micros: number;
};

/**
 * CreateMeshSetupRequest
 *
 * One exact request to create the first mesh on an unclaimed daemon.
 */
export type CreateMeshSetupRequestWritable = {
  /**
   * Human-readable first administrator name.
   */
  administrator_name: string;
  /**
   * High-entropy single-use claim printed or written by the local daemon.
   */
  claim: string;
  /**
   * Human-readable physical host name.
   */
  host_name: string;
  /**
   * Human-readable mesh name.
   */
  mesh_name: string;
  /**
   * Human-readable daemon-node name.
   */
  node_name: string;
  /**
   * Client-generated idempotency identity.
   */
  operation_id: string;
};

/**
 * CreateNodeJoinGrantResponse
 *
 * One exactly replayable join-grant issuance result.
 */
export type CreateNodeJoinGrantResponseWritable = {
  /**
   * One role pre-authorised for a joining daemon.
   */
  allowed_roles: Array<"storage" | "gateway" | "metadata_eligible">;
  /**
   * Exclusive authoritative expiry as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Exact committed use ceiling.
   */
  maximum_uses: number;
  /**
   * Exact operation whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * CreatePasskeyRegistrationRequest
 *
 * One exact registration response bound to a gateway-issued challenge.
 */
export type CreatePasskeyRegistrationRequestWritable = {
  /**
   * Canonical unpadded base64url CBOR attestation object.
   */
  attestation_object: string;
  /**
   * Gateway-issued registration challenge consumed exactly once.
   */
  challenge_id: string;
  /**
   * Canonical unpadded base64url collected-client-data JSON.
   */
  client_data_json: string;
  /**
   * Canonical unpadded base64url credential identity.
   */
  credential_id: string;
  /**
   * User-visible method label.
   */
  label: string;
  /**
   * Client-generated identity for the authoritative method creation.
   */
  operation_id: string;
  /**
   * Authenticator transports reported for a newly registered credential.
   */
  transports: Array<
    "usb" | "nfc" | "ble" | "smart-card" | "hybrid" | "internal"
  >;
};

/**
 * CreateRecoveryCodesResponse
 *
 * One exactly replayable recovery-code set returned only by its issuance operation.
 */
export type CreateRecoveryCodesResponseWritable = {
  /**
   * Ten independent, single-use secret-bearing recovery codes.
   */
  codes: [];
  /**
   * Authoritative creation instant as epoch microseconds.
   */
  created_at_epoch_micros: number;
  /**
   * Independently revocable common authentication-method identity.
   */
  method_id: string;
  /**
   * Exact idempotency identity whose committed result was resolved.
   */
  operation_id: string;
};

/**
 * CreateSessionRequest
 *
 * Input for exchanging accepted authentication proofs for a session.
 */
export type CreateSessionRequestWritable = {
  /**
   * Optional TOTP or recovery-code proof when policy requires another factor.
   */
  additional_factor?:
    | {
        /**
         * Six-to-eight digit TOTP value.
         */
        code: string;
        method: "totp";
      }
    | {
        /**
         * Opaque recovery code consumed atomically on success.
         */
        code: string;
        method: "recovery_code";
      }
    | null;
  /**
   * Primary API-key or passkey proof. It identifies the principal server-side.
   */
  authentication:
    | {
        method: "api_key";
        /**
         * Opaque API-key secret. The key identity and scopes are resolved server-side.
         */
        secret: string;
      }
    | {
        /**
         * Base64url-encoded authenticator data.
         */
        authenticator_data: string;
        /**
         * Server-issued challenge identity consumed exactly once.
         */
        challenge_id: string;
        /**
         * Base64url-encoded `WebAuthn` client data JSON.
         */
        client_data_json: string;
        /**
         * Base64url-encoded `WebAuthn` credential identity.
         */
        credential_id: string;
        method: "passkey";
        /**
         * Base64url-encoded assertion signature.
         */
        signature: string;
        /**
         * Base64url-encoded user handle, null when the authenticator omitted it.
         */
        user_handle?: string | null;
      };
  /**
   * Optional client label: omitted means unchanged and null means clear.
   */
  client_label?: string | null;
  /**
   * Client-generated idempotency key.
   */
  operation_id: string;
  /**
   * Whether the caller requests the policy's longer-lived session profile.
   */
  remember: boolean;
};

/**
 * CreateTotpRegistrationChallengeResponse
 *
 * One exactly replayable TOTP seed presentation.
 */
export type CreateTotpRegistrationChallengeResponseWritable = {
  /**
   * Interoperable HMAC-SHA-1 TOTP profile; SHA-1 is not used as a general digest.
   */
  algorithm: "SHA1";
  /**
   * Stable gateway-local ceremony identity supplied with confirmation.
   */
  challenge_id: string;
  /**
   * Exact decimal code width.
   */
  digits: number;
  /**
   * Exclusive ceremony expiry as epoch microseconds.
   */
  expires_at_epoch_micros: number;
  /**
   * Challenge-creation operation whose exact result this response represents.
   */
  operation_id: string;
  /**
   * Exact TOTP timestep in seconds.
   */
  period_seconds: number;
};

/**
 * CreateTotpRegistrationRequest
 *
 * One idempotent request confirming a newly presented TOTP seed.
 */
export type CreateTotpRegistrationRequestWritable = {
  /**
   * Exact short-lived registration ceremony being confirmed.
   */
  challenge_id: string;
  /**
   * Current six-digit code proving the authenticator stored the seed.
   */
  code: string;
  /**
   * Client-generated identity binding exact confirmation retries.
   */
  operation_id: string;
};

/**
 * EnrolNodeRequest
 *
 * One node-owned identity presentation for pre-authorised enrolment.
 */
export type EnrolNodeRequestWritable = {
  /**
   * New or existing physical host binding.
   */
  host:
    | {
        kind: "new";
        /**
         * Human-facing host name.
         */
        name: string;
      }
    | {
        /**
         * Existing host identity.
         */
        host_id: string;
        kind: "existing";
      };
  /**
   * P-256 signature over the exact canonical enrolment transcript as lowercase DER hex.
   */
  identity_proof_signature_hex: string;
  /**
   * Self-contained administrator-issued invitation.
   */
  join_code: string;
  /**
   * Canonical uncompressed P-256 SEC1 public identity bytes as lowercase hex.
   */
  node_identity_public_key_hex: string;
  /**
   * Human-facing daemon name.
   */
  node_name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Private QUIC endpoint advertised after certificate installation.
   */
  private_endpoint: string;
  /**
   * One role pre-authorised for a joining daemon.
   */
  requested_roles: Array<"storage" | "gateway" | "metadata_eligible">;
  /**
   * Canonical X25519 public secret-wrapping key as lowercase hex.
   */
  wrapping_public_key_hex: string;
};

/**
 * JoinMeshSetupRequest
 *
 * One exact request to join an existing mesh from an unclaimed daemon.
 */
export type JoinMeshSetupRequestWritable = {
  /**
   * High-entropy single-use claim printed or written by this daemon.
   */
  claim: string;
  /**
   * Human-readable physical host name created by the destination mesh.
   */
  host_name: string;
  /**
   * Self-contained administrator-issued invitation for the destination mesh.
   */
  join_code: string;
  /**
   * Human-readable daemon-node name created by the destination mesh.
   */
  node_name: string;
  /**
   * Client-generated idempotency identity retained across the internal restart.
   */
  operation_id: string;
};

/**
 * StepUpCurrentSessionRequest
 *
 * Input for atomically rotating the current browser session after a fresh factor.
 */
export type StepUpCurrentSessionRequestWritable = {
  /**
   * Fresh TOTP or single-use recovery proof; the current session supplies the primary proof.
   */
  additional_factor:
    | {
        /**
         * Six-to-eight digit TOTP value.
         */
        code: string;
        method: "totp";
      }
    | {
        /**
         * Opaque recovery code consumed atomically on success.
         */
        code: string;
        method: "recovery_code";
      };
  /**
   * Client-generated idempotency key for the exact rotation.
   */
  operation_id: string;
};

export type ListGroupsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/groups";
};

export type ListGroupsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type ListGroupsError = ListGroupsErrors[keyof ListGroupsErrors];

export type ListGroupsResponses = {
  /**
   * One current principal page
   */
  200: ListPrincipalsResponse;
};

export type ListGroupsResponse = ListGroupsResponses[keyof ListGroupsResponses];

export type CreateGroupData = {
  /**
   * Principal creation
   */
  body: CreateGroupRequest;
  path?: never;
  query?: never;
  url: "/admin/groups";
};

export type CreateGroupErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateGroupError = CreateGroupErrors[keyof CreateGroupErrors];

export type CreateGroupResponses = {
  /**
   * Principal durably created or exactly replayed
   */
  201: CreatePrincipalResponse;
};

export type CreateGroupResponse =
  CreateGroupResponses[keyof CreateGroupResponses];

export type ListGroupMembersData = {
  body?: never;
  path: {
    /**
     * Containing group identity
     */
    group_id: string;
  };
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/groups/{group_id}/members";
};

export type ListGroupMembersErrors = {
  /**
   * Invalid group or query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Group not found
   */
  404: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type ListGroupMembersError =
  ListGroupMembersErrors[keyof ListGroupMembersErrors];

export type ListGroupMembersResponses = {
  /**
   * One current direct-membership page
   */
  200: ListGroupMembershipsResponse;
};

export type ListGroupMembersResponse =
  ListGroupMembersResponses[keyof ListGroupMembersResponses];

export type AddGroupMemberData = {
  /**
   * Direct membership addition
   */
  body: AddGroupMemberRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    /**
     * Containing group identity
     */
    group_id: string;
  };
  query?: never;
  url: "/admin/groups/{group_id}/members";
};

export type AddGroupMemberErrors = {
  /**
   * Invalid membership request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Group or member not found
   */
  404: ApiError;
  /**
   * Cycle, duplicate edge or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type AddGroupMemberError =
  AddGroupMemberErrors[keyof AddGroupMemberErrors];

export type AddGroupMemberResponses = {
  /**
   * Membership durably added or exactly replayed
   */
  201: AddGroupMemberResponse;
};

export type AddGroupMemberResponse2 =
  AddGroupMemberResponses[keyof AddGroupMemberResponses];

export type RemoveGroupMemberData = {
  /**
   * Audited direct membership removal
   */
  body: RemoveGroupMemberRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    /**
     * Containing group identity
     */
    group_id: string;
    /**
     * Direct member identity
     */
    member_principal_id: string;
  };
  query?: never;
  url: "/admin/groups/{group_id}/members/{member_principal_id}/removals";
};

export type RemoveGroupMemberErrors = {
  /**
   * Invalid membership request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Active direct membership not found
   */
  404: ApiError;
  /**
   * Operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type RemoveGroupMemberError =
  RemoveGroupMemberErrors[keyof RemoveGroupMemberErrors];

export type RemoveGroupMemberResponses = {
  /**
   * Membership durably removed or exactly replayed
   */
  200: RemoveGroupMemberResponse;
};

export type RemoveGroupMemberResponse2 =
  RemoveGroupMemberResponses[keyof RemoveGroupMemberResponses];

export type CreateNodeJoinGrantData = {
  /**
   * Join invitation policy
   */
  body: CreateNodeJoinGrantRequest;
  path?: never;
  query?: never;
  url: "/admin/node-join-grants";
};

export type CreateNodeJoinGrantErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication required
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Changed retry or grant conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Internal contract failure
   */
  500: ApiError;
  /**
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateNodeJoinGrantError =
  CreateNodeJoinGrantErrors[keyof CreateNodeJoinGrantErrors];

export type CreateNodeJoinGrantResponses = {
  /**
   * Committed join invitation
   */
  201: CreateNodeJoinGrantResponse;
};

export type CreateNodeJoinGrantResponse2 =
  CreateNodeJoinGrantResponses[keyof CreateNodeJoinGrantResponses];

export type ListOperationsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/operations";
};

export type ListOperationsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Operation authority temporarily unavailable
   */
  503: ApiError;
};

export type ListOperationsError =
  ListOperationsErrors[keyof ListOperationsErrors];

export type ListOperationsResponses = {
  /**
   * One reverse-chronological operation page
   */
  200: ListOperationsResponse;
};

export type ListOperationsResponse2 =
  ListOperationsResponses[keyof ListOperationsResponses];

export type ConfirmRecoveryBundleSavedData = {
  /**
   * Offline recovery save proof
   */
  body: ConfirmRecoveryBundleRequest;
  path?: never;
  query?: never;
  url: "/admin/recovery-bundle-verifications";
};

export type ConfirmRecoveryBundleSavedErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Wrong bundle proof or changed retry
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Internal contract failure
   */
  500: ApiError;
  /**
   * Recovery authority temporarily unavailable
   */
  503: ApiError;
};

export type ConfirmRecoveryBundleSavedError =
  ConfirmRecoveryBundleSavedErrors[keyof ConfirmRecoveryBundleSavedErrors];

export type ConfirmRecoveryBundleSavedResponses = {
  /**
   * Recovery bundle verified and removed from online state
   */
  200: ConfirmRecoveryBundleResponse;
};

export type ConfirmRecoveryBundleSavedResponse =
  ConfirmRecoveryBundleSavedResponses[keyof ConfirmRecoveryBundleSavedResponses];

export type WithdrawSmbExportData = {
  /**
   * Audited SMB export withdrawal
   */
  body: WithdrawSmbExportRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    export_id: string;
  };
  query?: never;
  url: "/admin/smb-exports/{export_id}/withdrawals";
};

export type WithdrawSmbExportErrors = {
  /**
   * Invalid withdrawal request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Active SMB export not found
   */
  404: ApiError;
  /**
   * Operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * SMB export authority temporarily unavailable
   */
  503: ApiError;
};

export type WithdrawSmbExportError =
  WithdrawSmbExportErrors[keyof WithdrawSmbExportErrors];

export type WithdrawSmbExportResponses = {
  /**
   * SMB export durably withdrawn or exactly replayed
   */
  200: WithdrawSmbExportResponse;
};

export type WithdrawSmbExportResponse2 =
  WithdrawSmbExportResponses[keyof WithdrawSmbExportResponses];

export type ListStorageFoldersData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/storage-folders";
};

export type ListStorageFoldersErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or local state failure
   */
  500: ApiError;
  /**
   * Storage authority temporarily unavailable
   */
  503: ApiError;
};

export type ListStorageFoldersError =
  ListStorageFoldersErrors[keyof ListStorageFoldersErrors];

export type ListStorageFoldersResponses = {
  /**
   * One local storage-folder page
   */
  200: ListStorageFoldersResponse;
};

export type ListStorageFoldersResponse2 =
  ListStorageFoldersResponses[keyof ListStorageFoldersResponses];

export type RegisterStorageFolderData = {
  /**
   * Local storage-folder registration
   */
  body: RegisterStorageFolderRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/storage-folders";
};

export type RegisterStorageFolderErrors = {
  /**
   * Invalid local folder request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Path, marker or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or local state failure
   */
  500: ApiError;
  /**
   * Storage authority temporarily unavailable
   */
  503: ApiError;
};

export type RegisterStorageFolderError =
  RegisterStorageFolderErrors[keyof RegisterStorageFolderErrors];

export type RegisterStorageFolderResponses = {
  /**
   * Storage folder registered and open
   */
  201: RegisterStorageFolderResponse;
};

export type RegisterStorageFolderResponse2 =
  RegisterStorageFolderResponses[keyof RegisterStorageFolderResponses];

export type ListFaultGroupMembershipsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/topology/fault-group-memberships";
};

export type ListFaultGroupMembershipsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type ListFaultGroupMembershipsError =
  ListFaultGroupMembershipsErrors[keyof ListFaultGroupMembershipsErrors];

export type ListFaultGroupMembershipsResponses = {
  /**
   * One bounded topology page
   */
  200: ListFaultGroupMembershipsResponse;
};

export type ListFaultGroupMembershipsResponse2 =
  ListFaultGroupMembershipsResponses[keyof ListFaultGroupMembershipsResponses];

export type ListFaultGroupsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/topology/fault-groups";
};

export type ListFaultGroupsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type ListFaultGroupsError =
  ListFaultGroupsErrors[keyof ListFaultGroupsErrors];

export type ListFaultGroupsResponses = {
  /**
   * One bounded topology page
   */
  200: ListFaultGroupsResponse;
};

export type ListFaultGroupsResponse2 =
  ListFaultGroupsResponses[keyof ListFaultGroupsResponses];

export type CreateFaultGroupData = {
  /**
   * Shared-failure group
   */
  body: CreateFaultGroupRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/topology/fault-groups";
};

export type CreateFaultGroupErrors = {
  /**
   * Invalid group request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateFaultGroupError =
  CreateFaultGroupErrors[keyof CreateFaultGroupErrors];

export type CreateFaultGroupResponses = {
  /**
   * Shared-failure group committed
   */
  201: CreateFaultGroupResponse;
};

export type CreateFaultGroupResponse2 =
  CreateFaultGroupResponses[keyof CreateFaultGroupResponses];

export type SetFaultGroupMembershipData = {
  /**
   * Desired membership
   */
  body: SetFaultGroupMembershipRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    /**
     * Shared-failure group identity
     */
    group_id: string;
    /**
     * Machine identity
     */
    host_id: string;
  };
  query?: never;
  url: "/admin/topology/fault-groups/{group_id}/hosts/{host_id}";
};

export type SetFaultGroupMembershipErrors = {
  /**
   * Invalid membership request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Machine or fault group does not exist
   */
  404: ApiError;
  /**
   * Operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type SetFaultGroupMembershipError =
  SetFaultGroupMembershipErrors[keyof SetFaultGroupMembershipErrors];

export type SetFaultGroupMembershipResponses = {
  /**
   * Desired membership committed
   */
  200: SetFaultGroupMembershipResponse;
};

export type SetFaultGroupMembershipResponse2 =
  SetFaultGroupMembershipResponses[keyof SetFaultGroupMembershipResponses];

export type ListTopologyNodesData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/topology/nodes";
};

export type ListTopologyNodesErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type ListTopologyNodesError =
  ListTopologyNodesErrors[keyof ListTopologyNodesErrors];

export type ListTopologyNodesResponses = {
  /**
   * One bounded topology page
   */
  200: ListTopologyNodesResponse;
};

export type ListTopologyNodesResponse2 =
  ListTopologyNodesResponses[keyof ListTopologyNodesResponses];

export type ListTopologyTargetsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/topology/targets";
};

export type ListTopologyTargetsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or topology integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type ListTopologyTargetsError =
  ListTopologyTargetsErrors[keyof ListTopologyTargetsErrors];

export type ListTopologyTargetsResponses = {
  /**
   * One bounded topology page
   */
  200: ListTopologyTargetsResponse;
};

export type ListTopologyTargetsResponse2 =
  ListTopologyTargetsResponses[keyof ListTopologyTargetsResponses];

export type ListUsersData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/users";
};

export type ListUsersErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type ListUsersError = ListUsersErrors[keyof ListUsersErrors];

export type ListUsersResponses = {
  /**
   * One current principal page
   */
  200: ListPrincipalsResponse;
};

export type ListUsersResponse = ListUsersResponses[keyof ListUsersResponses];

export type CreateUserData = {
  /**
   * Principal creation
   */
  body: CreateUserRequest;
  path?: never;
  query?: never;
  url: "/admin/users";
};

export type CreateUserErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Identity authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateUserError = CreateUserErrors[keyof CreateUserErrors];

export type CreateUserResponses = {
  /**
   * Principal durably created or exactly replayed
   */
  201: CreatePrincipalResponse;
};

export type CreateUserResponse = CreateUserResponses[keyof CreateUserResponses];

export type CreateVolumeData = {
  /**
   * Logical-volume creation
   */
  body: CreateVolumeRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/volumes";
};

export type CreateVolumeErrors = {
  /**
   * Invalid volume request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Name, owner or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Volume authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateVolumeError = CreateVolumeErrors[keyof CreateVolumeErrors];

export type CreateVolumeResponses = {
  /**
   * Volume durably created or exactly replayed
   */
  201: CreateVolumeResponse;
};

export type CreateVolumeResponse2 =
  CreateVolumeResponses[keyof CreateVolumeResponses];

export type ListVolumePermissionGrantsData = {
  body?: never;
  path: {
    volume_id: string;
  };
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/volumes/{volume_id}/permission-grants";
};

export type ListVolumePermissionGrantsErrors = {
  /**
   * Invalid volume or query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Volume not found
   */
  404: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Permission authority temporarily unavailable
   */
  503: ApiError;
};

export type ListVolumePermissionGrantsError =
  ListVolumePermissionGrantsErrors[keyof ListVolumePermissionGrantsErrors];

export type ListVolumePermissionGrantsResponses = {
  /**
   * One current volume permission-grant page
   */
  200: ListVolumePermissionGrantsResponse;
};

export type ListVolumePermissionGrantsResponse2 =
  ListVolumePermissionGrantsResponses[keyof ListVolumePermissionGrantsResponses];

export type CreateVolumePermissionGrantData = {
  /**
   * Volume permission grant
   */
  body: CreateVolumePermissionGrantRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/permission-grants";
};

export type CreateVolumePermissionGrantErrors = {
  /**
   * Invalid grant request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Volume or principal not found
   */
  404: ApiError;
  /**
   * Grant or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Permission authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateVolumePermissionGrantError =
  CreateVolumePermissionGrantErrors[keyof CreateVolumePermissionGrantErrors];

export type CreateVolumePermissionGrantResponses = {
  /**
   * Grant durably created or exactly replayed
   */
  201: CreateVolumePermissionGrantResponse;
};

export type CreateVolumePermissionGrantResponse2 =
  CreateVolumePermissionGrantResponses[keyof CreateVolumePermissionGrantResponses];

export type RevokePermissionGrantData = {
  /**
   * Audited permission revocation
   */
  body: RevokePermissionGrantRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
    /**
     * Exact active permission-grant identity
     */
    grant_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/permission-grants/{grant_id}/revocations";
};

export type RevokePermissionGrantErrors = {
  /**
   * Invalid revocation request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Active grant not found
   */
  404: ApiError;
  /**
   * Operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Permission authority temporarily unavailable
   */
  503: ApiError;
};

export type RevokePermissionGrantError =
  RevokePermissionGrantErrors[keyof RevokePermissionGrantErrors];

export type RevokePermissionGrantResponses = {
  /**
   * Grant durably revoked or exactly replayed
   */
  200: RevokePermissionGrantResponse;
};

export type RevokePermissionGrantResponse2 =
  RevokePermissionGrantResponses[keyof RevokePermissionGrantResponses];

export type PublishSmbExportData = {
  /**
   * SMB export publication
   */
  body: PublishSmbExportRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/smb-exports";
};

export type PublishSmbExportErrors = {
  /**
   * Invalid export request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Volume, directory or gateway not found
   */
  404: ApiError;
  /**
   * Share name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * SMB export authority temporarily unavailable
   */
  503: ApiError;
};

export type PublishSmbExportError =
  PublishSmbExportErrors[keyof PublishSmbExportErrors];

export type PublishSmbExportResponses = {
  /**
   * SMB export durably published or exactly replayed
   */
  201: PublishSmbExportResponse;
};

export type PublishSmbExportResponse2 =
  PublishSmbExportResponses[keyof PublishSmbExportResponses];

export type GetHealthData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/health";
};

export type GetHealthErrors = {
  /**
   * Outgoing contract failure
   */
  500: ApiError;
};

export type GetHealthError = GetHealthErrors[keyof GetHealthErrors];

export type GetHealthResponses = {
  /**
   * Process readiness
   */
  200: HealthResponse;
};

export type GetHealthResponse = GetHealthResponses[keyof GetHealthResponses];

export type GetOpenApiData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/openapi.json";
};

export type GetOpenApiResponses = {
  /**
   * This exact OpenAPI 3.1 document
   */
  200: {
    [key: string]: unknown;
  };
};

export type GetOpenApiResponse = GetOpenApiResponses[keyof GetOpenApiResponses];

export type GetOperationStatusData = {
  body?: never;
  path: {
    operation_id: string;
  };
  query?: never;
  url: "/operations/{operation_id}";
};

export type GetOperationStatusErrors = {
  /**
   * Invalid operation identity
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Operation not found or not visible
   */
  404: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Operation authority temporarily unavailable
   */
  503: ApiError;
};

export type GetOperationStatusError =
  GetOperationStatusErrors[keyof GetOperationStatusErrors];

export type GetOperationStatusResponses = {
  /**
   * Current durable operation state
   */
  200: OperationStatusResponse;
};

export type GetOperationStatusResponse =
  GetOperationStatusResponses[keyof GetOperationStatusResponses];

export type CreateSessionData = {
  body: CreateSessionRequestWritable;
  path?: never;
  query?: never;
  url: "/sessions";
};

export type CreateSessionErrors = {
  /**
   * Malformed or structurally invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Operation identifier conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateSessionError = CreateSessionErrors[keyof CreateSessionErrors];

export type CreateSessionResponses = {
  /**
   * Authenticated session created
   */
  201: CreateSessionResponse;
};

export type CreateSessionResponse2 =
  CreateSessionResponses[keyof CreateSessionResponses];

export type GetCurrentSessionData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/sessions/current";
};

export type GetCurrentSessionErrors = {
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type GetCurrentSessionError =
  GetCurrentSessionErrors[keyof GetCurrentSessionErrors];

export type GetCurrentSessionResponses = {
  /**
   * Current browser session
   */
  200: CurrentSessionResponse;
};

export type GetCurrentSessionResponse =
  GetCurrentSessionResponses[keyof GetCurrentSessionResponses];

export type RevokeCurrentSessionData = {
  /**
   * Current-session revocation
   */
  body: RevokeCurrentSessionRequest;
  path?: never;
  query?: never;
  url: "/sessions/current/revocations";
};

export type RevokeCurrentSessionErrors = {
  /**
   * Malformed or structurally invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Operation identifier conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type RevokeCurrentSessionError =
  RevokeCurrentSessionErrors[keyof RevokeCurrentSessionErrors];

export type RevokeCurrentSessionResponses = {
  /**
   * Session authoritatively revoked
   */
  200: RevokeCurrentSessionResponse;
};

export type RevokeCurrentSessionResponse2 =
  RevokeCurrentSessionResponses[keyof RevokeCurrentSessionResponses];

export type StepUpCurrentSessionData = {
  /**
   * Current-session step-up
   */
  body: StepUpCurrentSessionRequestWritable;
  path?: never;
  query?: never;
  url: "/sessions/current/step-ups";
};

export type StepUpCurrentSessionErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or rotation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type StepUpCurrentSessionError =
  StepUpCurrentSessionErrors[keyof StepUpCurrentSessionErrors];

export type StepUpCurrentSessionResponses = {
  /**
   * Committed replacement session; the source session is revoked
   */
  201: CreateSessionResponse;
};

export type StepUpCurrentSessionResponse =
  StepUpCurrentSessionResponses[keyof StepUpCurrentSessionResponses];

export type CreatePasskeyChallengeData = {
  /**
   * Passkey challenge creation
   */
  body: CreatePasskeyChallengeRequest;
  path?: never;
  query?: never;
  url: "/sessions/passkey/challenges";
};

export type CreatePasskeyChallengeErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Changed retry or ceremony conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication gateway temporarily unavailable
   */
  503: ApiError;
};

export type CreatePasskeyChallengeError =
  CreatePasskeyChallengeErrors[keyof CreatePasskeyChallengeErrors];

export type CreatePasskeyChallengeResponses = {
  /**
   * Browser-ready passkey request options
   */
  201: CreatePasskeyChallengeResponse;
};

export type CreatePasskeyChallengeResponse2 =
  CreatePasskeyChallengeResponses[keyof CreatePasskeyChallengeResponses];

export type EnrolNodeData = {
  /**
   * Node identity presentation
   */
  body: EnrolNodeRequestWritable;
  path?: never;
  query?: never;
  url: "/setup/enrolments";
};

export type EnrolNodeErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Join invitation rejected
   */
  401: ApiError;
  /**
   * Changed retry or node conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Internal contract failure
   */
  500: ApiError;
  /**
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type EnrolNodeError = EnrolNodeErrors[keyof EnrolNodeErrors];

export type EnrolNodeResponses = {
  /**
   * Admitted node and bootstrap trust
   */
  201: EnrolNodeResponse;
};

export type EnrolNodeResponse2 = EnrolNodeResponses[keyof EnrolNodeResponses];

export type JoinMeshSetupData = {
  /**
   * Existing-mesh setup
   */
  body: JoinMeshSetupRequestWritable;
  path?: never;
  query?: never;
  url: "/setup/joins";
};

export type JoinMeshSetupErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * First-boot claim or join invitation rejected
   */
  401: ApiError;
  /**
   * Changed retry or setup conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Internal contract failure
   */
  500: ApiError;
};

export type JoinMeshSetupError = JoinMeshSetupErrors[keyof JoinMeshSetupErrors];

export type JoinMeshSetupResponses = {
  /**
   * Durable join intent accepted
   */
  202: JoinMeshSetupResponse;
};

export type JoinMeshSetupResponse2 =
  JoinMeshSetupResponses[keyof JoinMeshSetupResponses];

export type CreateMeshSetupData = {
  /**
   * First-mesh setup
   */
  body: CreateMeshSetupRequestWritable;
  path?: never;
  query?: never;
  url: "/setup/meshes";
};

export type CreateMeshSetupErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * First-boot claim rejected
   */
  401: ApiError;
  /**
   * Changed retry or setup conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Internal contract failure
   */
  500: ApiError;
  /**
   * Bootstrap authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateMeshSetupError =
  CreateMeshSetupErrors[keyof CreateMeshSetupErrors];

export type CreateMeshSetupResponses = {
  /**
   * Committed first mesh
   */
  201: CreateMeshSetupResponse;
};

export type CreateMeshSetupResponse2 =
  CreateMeshSetupResponses[keyof CreateMeshSetupResponses];

export type GetSetupStatusData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/setup/status";
};

export type GetSetupStatusErrors = {
  /**
   * Outgoing contract failure
   */
  500: ApiError;
};

export type GetSetupStatusError =
  GetSetupStatusErrors[keyof GetSetupStatusErrors];

export type GetSetupStatusResponses = {
  /**
   * First-start state
   */
  200: SetupStatusResponse;
};

export type GetSetupStatusResponse =
  GetSetupStatusResponses[keyof GetSetupStatusResponses];

export type GetUploadData = {
  body?: never;
  path: {
    upload_id: string;
  };
  query?: never;
  url: "/uploads/{upload_id}";
};

export type GetUploadErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type GetUploadError = GetUploadErrors[keyof GetUploadErrors];

export type GetUploadResponses = {
  /**
   * Exact current upload state
   */
  200: UploadStatusResponse;
};

export type GetUploadResponse = GetUploadResponses[keyof GetUploadResponses];

export type AbortUploadData = {
  /**
   * Exact fenced upload abandonment intent
   */
  body: AbortUploadRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    upload_id: string;
  };
  query?: never;
  url: "/uploads/{upload_id}/aborts";
};

export type AbortUploadErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type AbortUploadError = AbortUploadErrors[keyof AbortUploadErrors];

export type AbortUploadResponses = {
  /**
   * Terminal abandoned upload state
   */
  200: AbortUploadResponse;
};

export type AbortUploadResponse2 =
  AbortUploadResponses[keyof AbortUploadResponses];

export type CommitUploadData = {
  /**
   * Exact private checkpoint publication intent
   */
  body: CommitUploadRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    upload_id: string;
  };
  query?: never;
  url: "/uploads/{upload_id}/commits";
};

export type CommitUploadErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type CommitUploadError = CommitUploadErrors[keyof CommitUploadErrors];

export type CommitUploadResponses = {
  /**
   * Committed immutable object version
   */
  200: CommitUploadResponse;
};

export type CommitUploadResponse2 =
  CommitUploadResponses[keyof CommitUploadResponses];

export type ListUploadRangesData = {
  body?: never;
  path: {
    upload_id: string;
  };
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/uploads/{upload_id}/ranges";
};

export type ListUploadRangesErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type ListUploadRangesError =
  ListUploadRangesErrors[keyof ListUploadRangesErrors];

export type ListUploadRangesResponses = {
  /**
   * One immutable checkpoint range page
   */
  200: ListUploadRangesResponse;
};

export type ListUploadRangesResponse2 =
  ListUploadRangesResponses[keyof ListUploadRangesResponses];

export type WriteUploadRangeData = {
  body: Blob | File;
  headers: {
    "MeshSpan-Operation-Id": string;
    "MeshSpan-Stage-Fence": number;
    "MeshSpan-Content-BLAKE3": string;
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    upload_id: string;
    offset: number;
  };
  query?: never;
  url: "/uploads/{upload_id}/ranges/{offset}";
};

export type WriteUploadRangeErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type WriteUploadRangeError =
  WriteUploadRangeErrors[keyof WriteUploadRangeErrors];

export type WriteUploadRangeResponses = {
  /**
   * Durable range acknowledgement and exact resulting checkpoint
   */
  200: WriteUploadRangeResponse;
};

export type WriteUploadRangeResponse2 =
  WriteUploadRangeResponses[keyof WriteUploadRangeResponses];

export type ListCurrentUserAuthenticationMethodsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/users/current/authentication-methods";
};

export type ListCurrentUserAuthenticationMethodsErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type ListCurrentUserAuthenticationMethodsError =
  ListCurrentUserAuthenticationMethodsErrors[keyof ListCurrentUserAuthenticationMethodsErrors];

export type ListCurrentUserAuthenticationMethodsResponses = {
  /**
   * One secret-free authentication-method page
   */
  200: ListAuthenticationMethodsResponse;
};

export type ListCurrentUserAuthenticationMethodsResponse =
  ListCurrentUserAuthenticationMethodsResponses[keyof ListCurrentUserAuthenticationMethodsResponses];

export type CreateCurrentUserApiKeyData = {
  /**
   * Current-user API-key issuance
   */
  body: CreateApiKeyRequest;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/api-keys";
};

export type CreateCurrentUserApiKeyErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or issuance conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserApiKeyError =
  CreateCurrentUserApiKeyErrors[keyof CreateCurrentUserApiKeyErrors];

export type CreateCurrentUserApiKeyResponses = {
  /**
   * Committed API key with its exactly replayable one-time secret
   */
  201: CreateApiKeyResponse;
};

export type CreateCurrentUserApiKeyResponse =
  CreateCurrentUserApiKeyResponses[keyof CreateCurrentUserApiKeyResponses];

export type CreateCurrentUserPasskeyData = {
  /**
   * Current-user passkey registration response
   */
  body: CreatePasskeyRegistrationRequestWritable;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/passkeys";
};

export type CreateCurrentUserPasskeyErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry, duplicate credential or ceremony conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserPasskeyError =
  CreateCurrentUserPasskeyErrors[keyof CreateCurrentUserPasskeyErrors];

export type CreateCurrentUserPasskeyResponses = {
  /**
   * Committed passkey authentication method
   */
  201: CreatePasskeyRegistrationResponse;
};

export type CreateCurrentUserPasskeyResponse =
  CreateCurrentUserPasskeyResponses[keyof CreateCurrentUserPasskeyResponses];

export type CreateCurrentUserPasskeyRegistrationChallengeData = {
  /**
   * Current-user passkey registration challenge
   */
  body: CreatePasskeyRegistrationChallengeRequest;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/passkeys/registration-challenges";
};

export type CreateCurrentUserPasskeyRegistrationChallengeErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or ceremony conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserPasskeyRegistrationChallengeError =
  CreateCurrentUserPasskeyRegistrationChallengeErrors[keyof CreateCurrentUserPasskeyRegistrationChallengeErrors];

export type CreateCurrentUserPasskeyRegistrationChallengeResponses = {
  /**
   * Browser-ready passkey creation options
   */
  201: CreatePasskeyRegistrationChallengeResponse;
};

export type CreateCurrentUserPasskeyRegistrationChallengeResponse =
  CreateCurrentUserPasskeyRegistrationChallengeResponses[keyof CreateCurrentUserPasskeyRegistrationChallengeResponses];

export type CreateCurrentUserRecoveryCodesData = {
  /**
   * Current-user recovery-code issuance
   */
  body: CreateRecoveryCodesRequest;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/recovery-codes";
};

export type CreateCurrentUserRecoveryCodesErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or issuance conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserRecoveryCodesError =
  CreateCurrentUserRecoveryCodesErrors[keyof CreateCurrentUserRecoveryCodesErrors];

export type CreateCurrentUserRecoveryCodesResponses = {
  /**
   * Committed recovery-code set with exactly replayable one-time secrets
   */
  201: CreateRecoveryCodesResponse;
};

export type CreateCurrentUserRecoveryCodesResponse =
  CreateCurrentUserRecoveryCodesResponses[keyof CreateCurrentUserRecoveryCodesResponses];

export type CreateCurrentUserTotpData = {
  /**
   * Current-user TOTP registration confirmation
   */
  body: CreateTotpRegistrationRequestWritable;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/totp";
};

export type CreateCurrentUserTotpErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or ceremony conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserTotpError =
  CreateCurrentUserTotpErrors[keyof CreateCurrentUserTotpErrors];

export type CreateCurrentUserTotpResponses = {
  /**
   * Committed TOTP authentication method
   */
  201: CreateTotpRegistrationResponse;
};

export type CreateCurrentUserTotpResponse =
  CreateCurrentUserTotpResponses[keyof CreateCurrentUserTotpResponses];

export type CreateCurrentUserTotpRegistrationChallengeData = {
  /**
   * Current-user TOTP registration material
   */
  body: CreateTotpRegistrationChallengeRequest;
  path?: never;
  query?: never;
  url: "/users/current/authentication-methods/totp/registration-challenges";
};

export type CreateCurrentUserTotpRegistrationChallengeErrors = {
  /**
   * Invalid request
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or ceremony conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateCurrentUserTotpRegistrationChallengeError =
  CreateCurrentUserTotpRegistrationChallengeErrors[keyof CreateCurrentUserTotpRegistrationChallengeErrors];

export type CreateCurrentUserTotpRegistrationChallengeResponses = {
  /**
   * Exactly replayable TOTP registration material
   */
  201: CreateTotpRegistrationChallengeResponse;
};

export type CreateCurrentUserTotpRegistrationChallengeResponse =
  CreateCurrentUserTotpRegistrationChallengeResponses[keyof CreateCurrentUserTotpRegistrationChallengeResponses];

export type RevokeCurrentUserAuthenticationMethodData = {
  /**
   * Authentication-method revocation
   */
  body: RevokeAuthenticationMethodRequest;
  path: {
    method_id: string;
  };
  query?: never;
  url: "/users/current/authentication-methods/{method_id}/revocations";
};

export type RevokeCurrentUserAuthenticationMethodErrors = {
  /**
   * Invalid request or method identity
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Changed retry or revocation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Bounded admission rejected the request
   */
  429: ApiError;
  /**
   * Outgoing contract failure
   */
  500: ApiError;
  /**
   * Authentication authority temporarily unavailable
   */
  503: ApiError;
};

export type RevokeCurrentUserAuthenticationMethodError =
  RevokeCurrentUserAuthenticationMethodErrors[keyof RevokeCurrentUserAuthenticationMethodErrors];

export type RevokeCurrentUserAuthenticationMethodResponses = {
  /**
   * Authentication method authoritatively revoked
   */
  200: RevokeAuthenticationMethodResponse;
};

export type RevokeCurrentUserAuthenticationMethodResponse =
  RevokeCurrentUserAuthenticationMethodResponses[keyof RevokeCurrentUserAuthenticationMethodResponses];

export type ListVolumesData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/volumes";
};

export type ListVolumesErrors = {
  /**
   * Invalid query
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Namespace authority temporarily unavailable
   */
  503: ApiError;
};

export type ListVolumesError = ListVolumesErrors[keyof ListVolumesErrors];

export type ListVolumesResponses = {
  /**
   * One current-authority volume page
   */
  200: ListVolumesResponse;
};

export type ListVolumesResponse2 =
  ListVolumesResponses[keyof ListVolumesResponses];

export type DeleteObjectData = {
  /**
   * Exact idempotent logical-delete intent
   */
  body: DeleteObjectRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/volumes/{volume_id}/deletions";
};

export type DeleteObjectErrors = {
  /**
   * Invalid namespace mutation
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Volume, object or parent not found
   */
  404: ApiError;
  /**
   * Namespace, sharing or idempotency conflict
   */
  409: ApiError;
  /**
   * Mutation body exceeds its byte limit
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Namespace authority or metadata temporarily unavailable
   */
  503: ApiError;
};

export type DeleteObjectError = DeleteObjectErrors[keyof DeleteObjectErrors];

export type DeleteObjectResponses = {
  /**
   * Durable branch-deleted receipt; physical reclamation is separate
   */
  200: DeleteObjectResponse;
};

export type DeleteObjectResponse2 =
  DeleteObjectResponses[keyof DeleteObjectResponses];

export type CreateDirectoryData = {
  /**
   * Exact idempotent directory-creation intent
   */
  body: CreateDirectoryRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/volumes/{volume_id}/directories";
};

export type CreateDirectoryErrors = {
  /**
   * Invalid namespace mutation
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Volume, object or parent not found
   */
  404: ApiError;
  /**
   * Namespace, sharing or idempotency conflict
   */
  409: ApiError;
  /**
   * Mutation body exceeds its byte limit
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Namespace authority or metadata temporarily unavailable
   */
  503: ApiError;
};

export type CreateDirectoryError =
  CreateDirectoryErrors[keyof CreateDirectoryErrors];

export type CreateDirectoryResponses = {
  /**
   * Durable local-branch directory-creation receipt
   */
  201: CreateDirectoryResponse;
};

export type CreateDirectoryResponse2 =
  CreateDirectoryResponses[keyof CreateDirectoryResponses];

export type ListDirectoryData = {
  body?: never;
  path: {
    volume_id: string;
  };
  query?: {
    path?: string;
    cursor?: string;
    limit?: number;
  };
  url: "/volumes/{volume_id}/directory-entries";
};

export type ListDirectoryErrors = {
  /**
   * Invalid query or volume identity
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Volume or directory not found
   */
  404: ApiError;
  /**
   * Continuation no longer names the current immutable view
   */
  409: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type ListDirectoryError = ListDirectoryErrors[keyof ListDirectoryErrors];

export type ListDirectoryResponses = {
  /**
   * Complete metadata for one immutable directory page
   */
  200: ListDirectoryResponse;
};

export type ListDirectoryResponse2 =
  ListDirectoryResponses[keyof ListDirectoryResponses];

export type ReadFileData = {
  body?: never;
  path: {
    volume_id: string;
  };
  query: {
    path: string;
    offset?: number;
    length?: number;
  };
  url: "/volumes/{volume_id}/file-content";
};

export type ReadFileErrors = {
  /**
   * Invalid path, range or volume identity
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Volume or regular file not found
   */
  404: ApiError;
  /**
   * Concurrent share mode rejected the read
   */
  409: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * File authority or content temporarily unavailable
   */
  503: ApiError;
};

export type ReadFileError = ReadFileErrors[keyof ReadFileErrors];

export type ReadFileResponses = {
  /**
   * Verified bounded logical-file bytes
   */
  200: Blob | File;
};

export type ReadFileResponse = ReadFileResponses[keyof ReadFileResponses];

export type GetObjectData = {
  body?: never;
  path: {
    volume_id: string;
  };
  query: {
    path: string;
  };
  url: "/volumes/{volume_id}/objects";
};

export type GetObjectErrors = {
  /**
   * Invalid path or volume identity
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Volume or object not found
   */
  404: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type GetObjectError = GetObjectErrors[keyof GetObjectErrors];

export type GetObjectResponses = {
  /**
   * Complete immutable metadata for the selected logical object
   */
  200: GetObjectResponse;
};

export type GetObjectResponse2 = GetObjectResponses[keyof GetObjectResponses];

export type RenameObjectData = {
  /**
   * Exact idempotent same-volume rename intent
   */
  body: RenameObjectRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/volumes/{volume_id}/renames";
};

export type RenameObjectErrors = {
  /**
   * Invalid namespace mutation
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Volume, object or parent not found
   */
  404: ApiError;
  /**
   * Namespace, sharing or idempotency conflict
   */
  409: ApiError;
  /**
   * Mutation body exceeds its byte limit
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Namespace authority or metadata temporarily unavailable
   */
  503: ApiError;
};

export type RenameObjectError = RenameObjectErrors[keyof RenameObjectErrors];

export type RenameObjectResponses = {
  /**
   * Durable local-branch rename receipt
   */
  200: RenameObjectResponse;
};

export type RenameObjectResponse2 =
  RenameObjectResponses[keyof RenameObjectResponses];

export type BeginUploadData = {
  /**
   * Bounded durable upload intent
   */
  body: BeginUploadRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
  };
  query?: never;
  url: "/volumes/{volume_id}/uploads";
};

export type BeginUploadErrors = {
  /**
   * Invalid upload input
   */
  400: ApiError;
  /**
   * Authentication rejected
   */
  401: ApiError;
  /**
   * Current principal is not authorised
   */
  403: ApiError;
  /**
   * Upload or destination volume not found
   */
  404: ApiError;
  /**
   * Fence, checkpoint, namespace or idempotency conflict
   */
  409: ApiError;
  /**
   * Range or JSON body exceeds its operation bound
   */
  413: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Upload authority, content or metadata temporarily unavailable
   */
  503: ApiError;
};

export type BeginUploadError = BeginUploadErrors[keyof BeginUploadErrors];

export type BeginUploadResponses = {
  /**
   * Ready durable upload session
   */
  201: BeginUploadResponse;
};

export type BeginUploadResponse2 =
  BeginUploadResponses[keyof BeginUploadResponses];
