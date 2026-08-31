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
