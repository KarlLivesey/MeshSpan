// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

import * as z from "zod";

/**
 * ApiError
 *
 * Public error envelope that never includes raw untrusted values.
 */
export const zApiError = z
  .strictObject({
    code: z.union([
      z.literal("unauthenticated"),
      z.literal("forbidden"),
      z.literal("invalid_request"),
      z.literal("operation_conflict"),
      z.literal("busy"),
      z.literal("internal_contract"),
    ]),
    issues: z
      .array(
        z
          .strictObject({
            constraint: z
              .string()
              .min(1)
              .max(64)
              .regex(/^[a-z][a-z0-9_]*$/),
            path: z.string().max(256),
          })
          .strict(),
      )
      .max(16),
    message: z.string().min(1).max(512),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    request_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreateApiKeyRequest
 *
 * One idempotent request to issue a current-user API key.
 */
export const zCreateApiKeyRequest = z
  .strictObject({
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullish(),
    label: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    scopes: z
      .array(
        z.union([
          z.literal("https_session"),
          z.literal("headless_api"),
          z.literal("smb_session"),
        ]),
      )
      .min(1)
      .max(3),
  })
  .strict();

/**
 * CreateApiKeyResponse
 *
 * One exactly replayable API-key issuance result.
 */
export const zCreateApiKeyResponse = z
  .strictObject({
    created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullable(),
    key_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    method_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    scopes: z
      .array(
        z.union([
          z.literal("https_session"),
          z.literal("headless_api"),
          z.literal("smb_session"),
        ]),
      )
      .min(1)
      .max(3),
    secret: z
      .string()
      .length(113)
      .regex(/^meshspan-key-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .readonly(),
    valid_from_epoch_micros: z.int().gte(0).lte(9007199254740991),
  })
  .strict();

/**
 * CreateMeshSetupRequest
 *
 * One exact request to create the first mesh on an unclaimed daemon.
 */
export const zCreateMeshSetupRequest = z
  .strictObject({
    administrator_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    host_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    mesh_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    node_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreateMeshSetupResponse
 *
 * Successful, committed first-mesh creation result.
 */
export const zCreateMeshSetupResponse = z
  .strictObject({
    api_key: z
      .string()
      .length(113)
      .regex(/^meshspan-key-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/),
    mesh_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    node_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreatePasskeyChallengeRequest
 *
 * Input for creating one short-lived passkey authentication challenge.
 */
export const zCreatePasskeyChallengeRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreatePasskeyChallengeResponse
 *
 * Browser-ready options for one passkey authentication ceremony.
 */
export const zCreatePasskeyChallengeResponse = z
  .strictObject({
    challenge: z
      .string()
      .length(43)
      .regex(/^[A-Za-z0-9_-]{43}$/),
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    relying_party_id: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/),
    timeout_milliseconds: z.int().gte(30000).lte(600000),
    user_verification: z.literal("required"),
  })
  .strict();

/**
 * CreatePasskeyRegistrationChallengeRequest
 *
 * One idempotent request for browser-ready current-user registration options.
 */
export const zCreatePasskeyRegistrationChallengeRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreatePasskeyRegistrationChallengeResponse
 *
 * Browser-ready options for registering a current user's passkey.
 */
export const zCreatePasskeyRegistrationChallengeResponse = z
  .strictObject({
    attestation: z.literal("none"),
    challenge: z
      .string()
      .length(43)
      .regex(/^[A-Za-z0-9_-]{43}$/),
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    exclude_credentials: z
      .array(
        z
          .strictObject({
            id: z
              .string()
              .min(2)
              .max(1366)
              .regex(/^[A-Za-z0-9_-]+$/),
            type: z.literal("public-key"),
          })
          .strict(),
      )
      .max(64),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    public_key_parameters: z
      .array(
        z
          .strictObject({
            algorithm: z.int().gte(-7).lte(-7),
            type: z.literal("public-key"),
          })
          .strict(),
      )
      .min(1)
      .max(8),
    relying_party_id: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/),
    relying_party_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    resident_key: z.literal("required"),
    timeout_milliseconds: z.int().gte(30000).lte(600000),
    user_display_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    user_id: z
      .string()
      .length(22)
      .regex(/^[A-Za-z0-9_-]{22}$/),
    user_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    user_verification: z.literal("required"),
  })
  .strict();

/**
 * CreatePasskeyRegistrationRequest
 *
 * One exact registration response bound to a gateway-issued challenge.
 */
export const zCreatePasskeyRegistrationRequest = z
  .strictObject({
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    label: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    transports: z
      .array(
        z.union([
          z.literal("usb"),
          z.literal("nfc"),
          z.literal("ble"),
          z.literal("smart-card"),
          z.literal("hybrid"),
          z.literal("internal"),
        ]),
      )
      .max(6),
  })
  .strict();

/**
 * CreatePasskeyRegistrationResponse
 *
 * Durable result of registering one current-user passkey.
 */
export const zCreatePasskeyRegistrationResponse = z
  .strictObject({
    created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    method_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreateSessionRequest
 *
 * Input for exchanging accepted authentication proofs for a session.
 */
export const zCreateSessionRequest = z
  .strictObject({
    additional_factor: z
      .union([
        z
          .strictObject({
            method: z.literal("totp"),
          })
          .strict(),
        z
          .strictObject({
            method: z.literal("recovery_code"),
          })
          .strict(),
      ])
      .nullish(),
    authentication: z.union([
      z
        .strictObject({
          method: z.literal("api_key"),
        })
        .strict(),
      z
        .strictObject({
          challenge_id: z
            .string()
            .length(36)
            .regex(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            ),
          method: z.literal("passkey"),
        })
        .strict(),
    ]),
    client_label: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[^\x00-\x1f\x7f]+$/)
      .nullish(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    remember: z.boolean(),
  })
  .strict();

/**
 * CreateSessionResponse
 *
 * Successful session creation response.
 */
export const zCreateSessionResponse = z
  .strictObject({
    assurance: z.union([
      z.literal("single_factor"),
      z.literal("multi_factor"),
      z.literal("recent_step_up"),
    ]),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    session_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CurrentSessionResponse
 *
 * Current caller identity and coarse panel-navigation authority.
 */
export const zCurrentSessionResponse = z
  .strictObject({
    administration_available: z.boolean(),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    principal_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    session_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * HealthResponse
 *
 * Bounded anonymous health response.
 */
export const zHealthResponse = z
  .strictObject({
    api_version: z
      .string()
      .length(6)
      .regex(/^latest$/),
    schema_digest: z
      .string()
      .length(71)
      .regex(/^sha256:[0-9a-f]{64}$/),
    status: z.union([
      z.literal("starting"),
      z.literal("ready"),
      z.literal("degraded"),
    ]),
  })
  .strict();

/**
 * RevokeCurrentSessionRequest
 *
 * Idempotent request to revoke the caller's current browser session.
 */
export const zRevokeCurrentSessionRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * RevokeCurrentSessionResponse
 *
 * Durable result of revoking the caller's current browser session.
 */
export const zRevokeCurrentSessionResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    revoked_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    session_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * SetupStatusResponse
 *
 * Cheap anonymous first-start status safe for local-network discovery.
 */
export const zSetupStatusResponse = z
  .strictObject({
    state: z.union([
      z.literal("claim_required"),
      z.literal("configuring"),
      z.literal("configured"),
    ]),
  })
  .strict();

/**
 * CreateApiKeyResponse
 *
 * One exactly replayable API-key issuance result.
 */
export const zCreateApiKeyResponseWritable = z
  .strictObject({
    created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullable(),
    key_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    method_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    scopes: z
      .array(
        z.union([
          z.literal("https_session"),
          z.literal("headless_api"),
          z.literal("smb_session"),
        ]),
      )
      .min(1)
      .max(3),
    valid_from_epoch_micros: z.int().gte(0).lte(9007199254740991),
  })
  .strict();

/**
 * CreateMeshSetupRequest
 *
 * One exact request to create the first mesh on an unclaimed daemon.
 */
export const zCreateMeshSetupRequestWritable = z
  .strictObject({
    administrator_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    claim: z
      .string()
      .length(115)
      .regex(/^meshspan-claim-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/),
    host_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    mesh_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    node_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreatePasskeyRegistrationRequest
 *
 * One exact registration response bound to a gateway-issued challenge.
 */
export const zCreatePasskeyRegistrationRequestWritable = z
  .strictObject({
    attestation_object: z
      .string()
      .min(2)
      .max(21846)
      .regex(/^[A-Za-z0-9_-]+$/),
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    client_data_json: z
      .string()
      .min(2)
      .max(5462)
      .regex(/^[A-Za-z0-9_-]+$/),
    credential_id: z
      .string()
      .min(2)
      .max(1366)
      .regex(/^[A-Za-z0-9_-]+$/),
    label: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    transports: z
      .array(
        z.union([
          z.literal("usb"),
          z.literal("nfc"),
          z.literal("ble"),
          z.literal("smart-card"),
          z.literal("hybrid"),
          z.literal("internal"),
        ]),
      )
      .max(6),
  })
  .strict();

/**
 * CreateSessionRequest
 *
 * Input for exchanging accepted authentication proofs for a session.
 */
export const zCreateSessionRequestWritable = z
  .strictObject({
    additional_factor: z
      .union([
        z
          .strictObject({
            code: z.string().min(6).max(8),
            method: z.literal("totp"),
          })
          .strict(),
        z
          .strictObject({
            code: z.string().min(8).max(128),
            method: z.literal("recovery_code"),
          })
          .strict(),
      ])
      .nullish(),
    authentication: z.union([
      z
        .strictObject({
          method: z.literal("api_key"),
          secret: z.string().min(16).max(512),
        })
        .strict(),
      z
        .strictObject({
          authenticator_data: z.string().min(1).max(2048),
          challenge_id: z
            .string()
            .length(36)
            .regex(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            ),
          client_data_json: z.string().min(1).max(4096),
          credential_id: z.string().min(1).max(1024),
          method: z.literal("passkey"),
          signature: z.string().min(1).max(1024),
          user_handle: z.string().min(1).max(1024).nullish(),
        })
        .strict(),
    ]),
    client_label: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[^\x00-\x1f\x7f]+$/)
      .nullish(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    remember: z.boolean(),
  })
  .strict();

/**
 * Process readiness
 */
export const zGetHealthResponse = zHealthResponse;

/**
 * This exact OpenAPI 3.1 document
 */
export const zGetOpenApiResponse = z.record(z.string(), z.unknown());

export const zCreateSessionBody = zCreateSessionRequestWritable;

/**
 * Authenticated session created
 */
export const zCreateSessionResponse2 = zCreateSessionResponse;

/**
 * Current browser session
 */
export const zGetCurrentSessionResponse = zCurrentSessionResponse;

/**
 * Current-session revocation
 */
export const zRevokeCurrentSessionBody = zRevokeCurrentSessionRequest;

/**
 * Session authoritatively revoked
 */
export const zRevokeCurrentSessionResponse2 = zRevokeCurrentSessionResponse;

/**
 * Passkey challenge creation
 */
export const zCreatePasskeyChallengeBody = zCreatePasskeyChallengeRequest;

/**
 * Browser-ready passkey request options
 */
export const zCreatePasskeyChallengeResponse2 = zCreatePasskeyChallengeResponse;

/**
 * First-mesh setup
 */
export const zCreateMeshSetupBody = zCreateMeshSetupRequestWritable;

/**
 * Committed first mesh
 */
export const zCreateMeshSetupResponse2 = zCreateMeshSetupResponse;

/**
 * First-start state
 */
export const zGetSetupStatusResponse = zSetupStatusResponse;

/**
 * Current-user API-key issuance
 */
export const zCreateCurrentUserApiKeyBody = zCreateApiKeyRequest;

/**
 * Committed API key with its exactly replayable one-time secret
 */
export const zCreateCurrentUserApiKeyResponse = zCreateApiKeyResponse;

/**
 * Current-user passkey registration response
 */
export const zCreateCurrentUserPasskeyBody =
  zCreatePasskeyRegistrationRequestWritable;

/**
 * Committed passkey authentication method
 */
export const zCreateCurrentUserPasskeyResponse =
  zCreatePasskeyRegistrationResponse;

/**
 * Current-user passkey registration challenge
 */
export const zCreateCurrentUserPasskeyRegistrationChallengeBody =
  zCreatePasskeyRegistrationChallengeRequest;

/**
 * Browser-ready passkey creation options
 */
export const zCreateCurrentUserPasskeyRegistrationChallengeResponse =
  zCreatePasskeyRegistrationChallengeResponse;
