// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

import * as z from "zod";

/**
 * AbortUploadRequest
 *
 * Permanently abandons one unpublished upload.
 */
export const zAbortUploadRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    stage_fence: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export const zAbortUploadResponse = z
  .strictObject({
    checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
    committed_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    committed_version_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
    logical_extent: z.int().gte(0).lte(9007199254740991),
    maximum_bytes: z.int().gte(1).lte(9007199254740991),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    ranges_url: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^\/api\//),
    stage_fence: z.int().gte(1).lte(9007199254740991),
    state: z.union([
      z.literal("active"),
      z.literal("committing"),
      z.literal("committed"),
      z.literal("aborted"),
    ]),
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

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
      z.literal("not_found"),
      z.literal("state_conflict"),
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
 * BeginUploadRequest
 *
 * Starts one durable private upload session.
 */
export const zBeginUploadRequest = z
  .strictObject({
    disposition: z.union([
      z
        .object({
          mode: z.literal("create_new"),
        })
        .strict(),
      z
        .object({
          mode: z.literal("replace_current"),
        })
        .strict(),
      z
        .object({
          mode: z.literal("replace_if_version"),
          version_id: z
            .string()
            .length(36)
            .regex(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            ),
        })
        .strict(),
    ]),
    maximum_bytes: z.int().gte(1).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
  })
  .strict();

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export const zBeginUploadResponse = z
  .strictObject({
    checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
    committed_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    committed_version_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
    logical_extent: z.int().gte(0).lte(9007199254740991),
    maximum_bytes: z.int().gte(1).lte(9007199254740991),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    ranges_url: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^\/api\//),
    stage_fence: z.int().gte(1).lte(9007199254740991),
    state: z.union([
      z.literal("active"),
      z.literal("committing"),
      z.literal("committed"),
      z.literal("aborted"),
    ]),
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CommitUploadRequest
 *
 * Explicit final publication request for one complete checkpoint.
 */
export const zCommitUploadRequest = z
  .strictObject({
    expected_blake3: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/)
      .nullish(),
    expected_sequence: z.int().gte(0).lte(9007199254740991),
    final_length: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    sparse: z.boolean(),
    stage_fence: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * CommitUploadResponse
 *
 * Complete successful upload publication.
 */
export const zCommitUploadResponse = z
  .strictObject({
    object: z
      .strictObject({
        namespace_commit_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        object: z
          .strictObject({
            entry_generation: z.int().gte(0).lte(9007199254740991),
            file_version_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              )
              .nullable(),
            kind: z.union([z.literal("directory"), z.literal("file")]),
            logical_length: z.int().gte(0).lte(9007199254740991).nullable(),
            name: z
              .string()
              .min(1)
              .max(255)
              .regex(/^[^\x00-\x1f\x7f\x2f\\]+$/),
            object_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            object_revision_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
          })
          .strict(),
        path: z
          .string()
          .min(1)
          .max(4096)
          .regex(/^[^\x00-\x1f\x7f]+$/),
        volume_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      })
      .strict(),
    upload: z
      .strictObject({
        checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
        committed_object_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          )
          .nullable(),
        committed_version_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          )
          .nullable(),
        expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
        logical_extent: z.int().gte(0).lte(9007199254740991),
        maximum_bytes: z.int().gte(1).lte(9007199254740991),
        path: z
          .string()
          .min(1)
          .max(4096)
          .regex(/^[^\x00-\x1f\x7f]+$/),
        ranges_url: z
          .string()
          .min(1)
          .max(4096)
          .regex(/^\/api\//),
        stage_fence: z.int().gte(1).lte(9007199254740991),
        state: z.union([
          z.literal("active"),
          z.literal("committing"),
          z.literal("committed"),
          z.literal("aborted"),
        ]),
        upload_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        volume_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      })
      .strict(),
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
 * CreateDirectoryRequest
 *
 * Creates one empty logical directory at an exact path.
 */
export const zCreateDirectoryRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
  })
  .strict();

/**
 * CreateDirectoryResponse
 *
 * Durable result of one atomic empty-directory creation.
 */
export const zCreateDirectoryResponse = z
  .strictObject({
    head_sequence: z.int().gte(1).lte(9007199254740991),
    namespace_commit_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_revision_id: z
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
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreateGroupRequest
 *
 * Idempotent administrator request to create one nested group.
 */
export const zCreateGroupRequest = z
  .strictObject({
    display_name: z
      .string()
      .min(1)
      .max(256)
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
 * CreatePrincipalResponse
 *
 * Durable creation result shared by users and groups.
 */
export const zCreatePrincipalResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    principal: z
      .strictObject({
        created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
        display_name: z.string(),
        kind: z.union([z.literal("user"), z.literal("group")]),
        principal_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        revision: z.int().gte(1).lte(9007199254740991),
        state: z.union([
          z.literal("active"),
          z.literal("suspended"),
          z.literal("retired"),
        ]),
      })
      .strict(),
  })
  .strict();

/**
 * CreateRecoveryCodesRequest
 *
 * One idempotent request to replace the current user's recovery-code set.
 */
export const zCreateRecoveryCodesRequest = z
  .strictObject({
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
  })
  .strict();

/**
 * CreateRecoveryCodesResponse
 *
 * One exactly replayable recovery-code set returned only by its issuance operation.
 */
export const zCreateRecoveryCodesResponse = z
  .strictObject({
    codes: z.tuple([
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
      z
        .string()
        .length(118)
        .regex(/^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
        .readonly(),
    ]),
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
 * CreateTotpRegistrationChallengeRequest
 *
 * One idempotent request to create TOTP registration material.
 */
export const zCreateTotpRegistrationChallengeRequest = z
  .strictObject({
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
  })
  .strict();

/**
 * CreateTotpRegistrationChallengeResponse
 *
 * One exactly replayable TOTP seed presentation.
 */
export const zCreateTotpRegistrationChallengeResponse = z
  .strictObject({
    algorithm: z.literal("SHA1"),
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    digits: z.int().gte(6).lte(6),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    period_seconds: z.int().gte(30).lte(30),
    provisioning_uri: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^otpauth:\/\/totp\/[^\x00-\x20\x7f]+$/)
      .readonly(),
    secret: z
      .string()
      .length(32)
      .regex(/^[A-Z2-7]{32}$/)
      .readonly(),
  })
  .strict();

/**
 * CreateTotpRegistrationRequest
 *
 * One idempotent request confirming a newly presented TOTP seed.
 */
export const zCreateTotpRegistrationRequest = z
  .strictObject({
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
  })
  .strict();

/**
 * CreateTotpRegistrationResponse
 *
 * Durable result of confirming one independently revocable TOTP method.
 */
export const zCreateTotpRegistrationResponse = z
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
 * CreateUserRequest
 *
 * Idempotent administrator request to create one user.
 */
export const zCreateUserRequest = z
  .strictObject({
    display_name: z
      .string()
      .min(1)
      .max(256)
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
 * DeleteObjectRequest
 *
 * Logically deletes one exact current file or empty directory.
 */
export const zDeleteObjectRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
  })
  .strict();

/**
 * DeleteObjectResponse
 *
 * Durable result of one atomic logical namespace removal.
 */
export const zDeleteObjectResponse = z
  .strictObject({
    head_sequence: z.int().gte(1).lte(9007199254740991),
    namespace_commit_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_kind: z.union([z.literal("directory"), z.literal("file")]),
    object_revision_id: z
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
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    scope: z.literal("branch_deleted"),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * GetObjectResponse
 *
 * Complete immutable metadata for one logical object.
 */
export const zGetObjectResponse = z
  .strictObject({
    namespace_commit_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object: z
      .strictObject({
        entry_generation: z.int().gte(0).lte(9007199254740991),
        file_version_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          )
          .nullable(),
        kind: z.union([z.literal("directory"), z.literal("file")]),
        logical_length: z.int().gte(0).lte(9007199254740991).nullable(),
        name: z
          .string()
          .min(1)
          .max(255)
          .regex(/^[^\x00-\x1f\x7f\x2f\\]+$/),
        object_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        object_revision_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      })
      .strict(),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    volume_id: z
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
 * ListDirectoryResponse
 *
 * One immutable, bounded directory page.
 */
export const zListDirectoryResponse = z
  .strictObject({
    directory_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    directory_object_revision_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    entries: z
      .array(
        z
          .strictObject({
            entry_generation: z.int().gte(0).lte(9007199254740991),
            file_version_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              )
              .nullable(),
            kind: z.union([z.literal("directory"), z.literal("file")]),
            logical_length: z.int().gte(0).lte(9007199254740991).nullable(),
            name: z
              .string()
              .min(1)
              .max(255)
              .regex(/^[^\x00-\x1f\x7f\x2f\\]+$/),
            object_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            object_revision_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
          })
          .strict(),
      )
      .max(256),
    namespace_commit_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\//)
      .nullable(),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/)
      .nullable(),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * ListPrincipalsResponse
 *
 * One bounded, permission-filtered administrator identity page.
 */
export const zListPrincipalsResponse = z
  .strictObject({
    kind: z.union([z.literal("user"), z.literal("group")]),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\//)
      .nullable(),
    principals: z
      .array(
        z
          .strictObject({
            created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            display_name: z.string(),
            kind: z.union([z.literal("user"), z.literal("group")]),
            principal_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            revision: z.int().gte(1).lte(9007199254740991),
            state: z.union([
              z.literal("active"),
              z.literal("suspended"),
              z.literal("retired"),
            ]),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * ListUploadRangesResponse
 *
 * Bounded exact coverage page pinned to one upload checkpoint.
 */
export const zListUploadRangesResponse = z
  .strictObject({
    checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
    next_page_url: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^\/api\//)
      .nullable(),
    ranges: z
      .array(
        z
          .strictObject({
            end: z.int().gte(1).lte(9007199254740991),
            start: z.int().gte(0).lte(9007199254740991),
          })
          .strict(),
      )
      .max(256),
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * RenameObjectRequest
 *
 * Atomically renames or moves one object within a logical volume.
 */
export const zRenameObjectRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    source_path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    target_path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
  })
  .strict();

/**
 * RenameObjectResponse
 *
 * Durable result of one atomic same-volume rename or move.
 */
export const zRenameObjectResponse = z
  .strictObject({
    head_sequence: z.int().gte(1).lte(9007199254740991),
    namespace_commit_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    object_revision_id: z
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
    source_path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    target_path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * RevokeAuthenticationMethodRequest
 *
 * One idempotent request to revoke an owned authentication method.
 */
export const zRevokeAuthenticationMethodRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    reason: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[^\x00-\x20\x7f](?:[^\x00-\x1f\x7f]{0,1022}[^\x00-\x20\x7f])?$/),
  })
  .strict();

/**
 * RevokeAuthenticationMethodResponse
 *
 * Durable result of revoking one owned authentication method.
 */
export const zRevokeAuthenticationMethodResponse = z
  .strictObject({
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
    revoked_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
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
 * StepUpCurrentSessionRequest
 *
 * Input for atomically rotating the current browser session after a fresh factor.
 */
export const zStepUpCurrentSessionRequest = z
  .strictObject({
    additional_factor: z.union([
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
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export const zUploadStatusResponse = z
  .strictObject({
    checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
    committed_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    committed_version_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
    logical_extent: z.int().gte(0).lte(9007199254740991),
    maximum_bytes: z.int().gte(1).lte(9007199254740991),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    ranges_url: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^\/api\//),
    stage_fence: z.int().gte(1).lte(9007199254740991),
    state: z.union([
      z.literal("active"),
      z.literal("committing"),
      z.literal("committed"),
      z.literal("aborted"),
    ]),
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * UploadStatusResponse
 *
 * Common exact upload state returned after every lifecycle operation.
 */
export const zWriteUploadRangeResponse = z
  .strictObject({
    checkpoint_sequence: z.int().gte(0).lte(9007199254740991),
    committed_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    committed_version_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      )
      .nullable(),
    expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
    logical_extent: z.int().gte(0).lte(9007199254740991),
    maximum_bytes: z.int().gte(1).lte(9007199254740991),
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\x00-\x1f\x7f]+$/),
    ranges_url: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^\/api\//),
    stage_fence: z.int().gte(1).lte(9007199254740991),
    state: z.union([
      z.literal("active"),
      z.literal("committing"),
      z.literal("committed"),
      z.literal("aborted"),
    ]),
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
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
 * CreateRecoveryCodesResponse
 *
 * One exactly replayable recovery-code set returned only by its issuance operation.
 */
export const zCreateRecoveryCodesResponseWritable = z
  .strictObject({
    codes: z.tuple([]),
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
 * CreateTotpRegistrationChallengeResponse
 *
 * One exactly replayable TOTP seed presentation.
 */
export const zCreateTotpRegistrationChallengeResponseWritable = z
  .strictObject({
    algorithm: z.literal("SHA1"),
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    digits: z.int().gte(6).lte(6),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    period_seconds: z.int().gte(30).lte(30),
  })
  .strict();

/**
 * CreateTotpRegistrationRequest
 *
 * One idempotent request confirming a newly presented TOTP seed.
 */
export const zCreateTotpRegistrationRequestWritable = z
  .strictObject({
    challenge_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    code: z
      .string()
      .length(6)
      .regex(/^\d{6}$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * StepUpCurrentSessionRequest
 *
 * Input for atomically rotating the current browser session after a fresh factor.
 */
export const zStepUpCurrentSessionRequestWritable = z
  .strictObject({
    additional_factor: z.union([
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
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zListGroupsQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(256).optional(),
  })
  .strict();

/**
 * One current principal page
 */
export const zListGroupsResponse = zListPrincipalsResponse;

/**
 * Principal creation
 */
export const zCreateGroupBody = zCreateGroupRequest;

/**
 * Principal durably created or exactly replayed
 */
export const zCreateGroupResponse = zCreatePrincipalResponse;

export const zListUsersQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(256).optional(),
  })
  .strict();

/**
 * One current principal page
 */
export const zListUsersResponse = zListPrincipalsResponse;

/**
 * Principal creation
 */
export const zCreateUserBody = zCreateUserRequest;

/**
 * Principal durably created or exactly replayed
 */
export const zCreateUserResponse = zCreatePrincipalResponse;

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
 * Current-session step-up
 */
export const zStepUpCurrentSessionBody = zStepUpCurrentSessionRequestWritable;

/**
 * Committed replacement session; the source session is revoked
 */
export const zStepUpCurrentSessionResponse = zCreateSessionResponse;

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

export const zGetUploadPath = z
  .object({
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Exact current upload state
 */
export const zGetUploadResponse = zUploadStatusResponse;

/**
 * Exact fenced upload abandonment intent
 */
export const zAbortUploadBody = zAbortUploadRequest;

export const zAbortUploadHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zAbortUploadPath = z
  .object({
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Terminal abandoned upload state
 */
export const zAbortUploadResponse2 = zAbortUploadResponse;

/**
 * Exact private checkpoint publication intent
 */
export const zCommitUploadBody = zCommitUploadRequest;

export const zCommitUploadHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zCommitUploadPath = z
  .object({
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Committed immutable object version
 */
export const zCommitUploadResponse2 = zCommitUploadResponse;

export const zListUploadRangesPath = z
  .object({
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zListUploadRangesQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(256).optional(),
  })
  .strict();

/**
 * One immutable checkpoint range page
 */
export const zListUploadRangesResponse2 = zListUploadRangesResponse;

export const zWriteUploadRangeBody = z.string().min(1).max(8388608);

export const zWriteUploadRangeHeaders = z
  .object({
    "MeshSpan-Operation-Id": z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    "MeshSpan-Stage-Fence": z.int().gte(1).lte(9007199254740991),
    "MeshSpan-Content-BLAKE3": z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zWriteUploadRangePath = z
  .object({
    upload_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    offset: z.int().gte(0).lte(9007199254740991),
  })
  .strict();

/**
 * Durable range acknowledgement and exact resulting checkpoint
 */
export const zWriteUploadRangeResponse2 = zWriteUploadRangeResponse;

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

/**
 * Current-user recovery-code issuance
 */
export const zCreateCurrentUserRecoveryCodesBody = zCreateRecoveryCodesRequest;

/**
 * Committed recovery-code set with exactly replayable one-time secrets
 */
export const zCreateCurrentUserRecoveryCodesResponse =
  zCreateRecoveryCodesResponse;

/**
 * Current-user TOTP registration confirmation
 */
export const zCreateCurrentUserTotpBody =
  zCreateTotpRegistrationRequestWritable;

/**
 * Committed TOTP authentication method
 */
export const zCreateCurrentUserTotpResponse = zCreateTotpRegistrationResponse;

/**
 * Current-user TOTP registration material
 */
export const zCreateCurrentUserTotpRegistrationChallengeBody =
  zCreateTotpRegistrationChallengeRequest;

/**
 * Exactly replayable TOTP registration material
 */
export const zCreateCurrentUserTotpRegistrationChallengeResponse =
  zCreateTotpRegistrationChallengeResponse;

/**
 * Authentication-method revocation
 */
export const zRevokeCurrentUserAuthenticationMethodBody =
  zRevokeAuthenticationMethodRequest;

export const zRevokeCurrentUserAuthenticationMethodPath = z
  .object({
    method_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Authentication method authoritatively revoked
 */
export const zRevokeCurrentUserAuthenticationMethodResponse =
  zRevokeAuthenticationMethodResponse;

/**
 * Exact idempotent logical-delete intent
 */
export const zDeleteObjectBody = zDeleteObjectRequest;

export const zDeleteObjectHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zDeleteObjectPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Durable branch-deleted receipt; physical reclamation is separate
 */
export const zDeleteObjectResponse2 = zDeleteObjectResponse;

/**
 * Exact idempotent directory-creation intent
 */
export const zCreateDirectoryBody = zCreateDirectoryRequest;

export const zCreateDirectoryHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zCreateDirectoryPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Durable local-branch directory-creation receipt
 */
export const zCreateDirectoryResponse2 = zCreateDirectoryResponse;

export const zListDirectoryPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zListDirectoryQuery = z
  .object({
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\u0000-\u001f\u007f]+$/)
      .optional(),
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(256).optional(),
  })
  .strict();

/**
 * Complete metadata for one immutable directory page
 */
export const zListDirectoryResponse2 = zListDirectoryResponse;

export const zReadFilePath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zReadFileQuery = z
  .object({
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\u0000-\u001f\u007f]+$/),
    offset: z.int().gte(0).lte(9007199254740991).optional().default(0),
    length: z.int().gte(1).lte(8388608).optional().default(8388608),
  })
  .strict();

/**
 * Verified bounded logical-file bytes
 */
export const zReadFileResponse = z.string().max(8388608);

export const zGetObjectPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zGetObjectQuery = z
  .object({
    path: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\u0000-\u001f\u007f]+$/),
  })
  .strict();

/**
 * Complete immutable metadata for the selected logical object
 */
export const zGetObjectResponse2 = zGetObjectResponse;

/**
 * Exact idempotent same-volume rename intent
 */
export const zRenameObjectBody = zRenameObjectRequest;

export const zRenameObjectHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zRenameObjectPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Durable local-branch rename receipt
 */
export const zRenameObjectResponse2 = zRenameObjectResponse;

/**
 * Bounded durable upload intent
 */
export const zBeginUploadBody = zBeginUploadRequest;

export const zBeginUploadHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zBeginUploadPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Ready durable upload session
 */
export const zBeginUploadResponse2 = zBeginUploadResponse;
