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
