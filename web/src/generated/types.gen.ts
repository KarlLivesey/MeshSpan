// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

export type ClientOptions = {
  baseUrl: `${string}://${string}/api/latest` | (string & {});
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
