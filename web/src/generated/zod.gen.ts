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
 * AddGroupMemberRequest
 *
 * Idempotent administrator request to add one direct user or nested-group member.
 */
export const zAddGroupMemberRequest = z
  .strictObject({
    activation_required: z.boolean(),
    member_principal_id: z
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
    valid_from_epoch_micros: z.int().gte(0).lte(9007199254740991).nullish(),
    valid_until_epoch_micros: z.int().gte(0).lte(9007199254740991).nullish(),
  })
  .strict();

/**
 * AddGroupMemberResponse
 *
 * Durable result of adding or exactly replaying one direct membership.
 */
export const zAddGroupMemberResponse = z
  .strictObject({
    membership: z
      .strictObject({
        activation_required: z.boolean(),
        created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
        created_by: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        group_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        member: z
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
        revision: z.int().gte(1).lte(9007199254740991),
        valid_from_epoch_micros: z
          .int()
          .gte(0)
          .lte(9007199254740991)
          .nullable(),
        valid_until_epoch_micros: z
          .int()
          .gte(0)
          .lte(9007199254740991)
          .nullable(),
      })
      .strict(),
    operation_id: z
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
 * AssignVolumePlacementPolicyRequest
 *
 * Exact-retry request selecting a policy for one volume.
 */
export const zAssignVolumePlacementPolicyRequest = z
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
 * AssignVolumePlacementPolicyResponse
 *
 * Durable volume placement-policy selection result.
 */
export const zAssignVolumePlacementPolicyResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    revision: z.int().gte(1).lte(9007199254740991),
    volume_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
  })
  .strict();

/**
 * AssignVolumeProtectionPolicyRequest
 *
 * Exact-retry request selecting an immutable policy for one volume.
 */
export const zAssignVolumeProtectionPolicyRequest = z
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
 * AssignVolumeProtectionPolicyResponse
 *
 * Durable volume survival-policy selection result.
 */
export const zAssignVolumeProtectionPolicyResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    revision: z.int().gte(1).lte(9007199254740991),
    volume_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
  })
  .strict();

/**
 * BackupScheduleResponse
 *
 * Current backup schedule for the gateway's authoritative partition.
 */
export const zBackupScheduleResponse = z
  .strictObject({
    partition_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    schedule: z
      .strictObject({
        next_due_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
        policy: z
          .strictObject({
            enabled: z.boolean(),
            interval_seconds: z.int().gte(1).lte(4294967295),
            minimum_independent_copies: z.int().gte(0).lte(255),
            minimum_verified_copies: z.int().gte(1).lte(255),
            retained_generations: z.int().gte(1).lte(1024),
          })
          .strict(),
        sequence: z.int().gte(1).lte(9007199254740991),
      })
      .strict()
      .nullable(),
  })
  .strict();

/**
 * BeginStorageDrainRequest
 *
 * Exact-retry request to start one safe storage drain.
 */
export const zBeginStorageDrainRequest = z
  .strictObject({
    allow_temporary_degraded: z.boolean(),
    cleanup_requested: z.boolean(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    scope: z.union([
      z
        .strictObject({
          generation: z
            .string()
            .min(1)
            .max(20)
            .regex(/^[1-9][0-9]{0,19}$/),
          kind: z.literal("target"),
          target_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
        })
        .strict(),
      z
        .strictObject({
          incarnation: z
            .string()
            .min(1)
            .max(20)
            .regex(/^[1-9][0-9]{0,19}$/),
          kind: z.literal("node"),
          node_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
        })
        .strict(),
      z
        .strictObject({
          fault_group_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
          kind: z.literal("fault_group"),
        })
        .strict(),
    ]),
  })
  .strict();

/**
 * BeginStorageDrainResponse
 *
 * Durable result returned after drain admission.
 */
export const zBeginStorageDrainResponse = z
  .strictObject({
    drain: z
      .strictObject({
        allow_temporary_degraded: z.boolean(),
        cleanup_requested: z.boolean(),
        drain_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        requested_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
        revision: z.int().gte(1).lte(9007199254740991),
        safe_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullable(),
        scope: z.union([
          z
            .strictObject({
              generation: z
                .string()
                .min(1)
                .max(20)
                .regex(/^[1-9][0-9]{0,19}$/),
              kind: z.literal("target"),
              target_id: z
                .string()
                .length(36)
                .regex(/^[0-9a-f-]{36}$/),
            })
            .strict(),
          z
            .strictObject({
              incarnation: z
                .string()
                .min(1)
                .max(20)
                .regex(/^[1-9][0-9]{0,19}$/),
              kind: z.literal("node"),
              node_id: z
                .string()
                .length(36)
                .regex(/^[0-9a-f-]{36}$/),
            })
            .strict(),
          z
            .strictObject({
              fault_group_id: z
                .string()
                .length(36)
                .regex(/^[0-9a-f-]{36}$/),
              kind: z.literal("fault_group"),
            })
            .strict(),
        ]),
        state: z.union([
          z.literal("evacuating"),
          z.literal("membership_fenced"),
          z.literal("safe_to_detach"),
        ]),
        status_url: z
          .string()
          .min(1)
          .max(512)
          .regex(/^\/api\/latest\/admin\/storage-drains\//),
      })
      .strict(),
    operation_id: z
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
 * CertificateStatusResponse
 *
 * Current certificate status; `certificate` is `null` before a source is configured.
 */
export const zCertificateStatusResponse = z
  .strictObject({
    certificate: z
      .strictObject({
        delivery_generation: z
          .string()
          .min(1)
          .max(20)
          .regex(/^[1-9][0-9]{0,19}$/),
        installed_gateway_count: z.int().gte(0).lte(1000000),
        not_after_epoch_micros: z.int().gte(1).lte(9007199254740991),
        not_before_epoch_micros: z.int().gte(0).lte(9007199254740991),
        required_gateway_count: z.int().gte(0).lte(1000000),
        source: z.union([
          z.literal("acme"),
          z.literal("external"),
          z.literal("mesh_local"),
        ]),
        source_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        source_revision: z
          .string()
          .min(1)
          .max(20)
          .regex(/^[1-9][0-9]{0,19}$/),
        state: z.union([
          z.literal("active"),
          z.literal("distributing"),
          z.literal("not_yet_valid"),
          z.literal("expired"),
        ]),
      })
      .strict()
      .nullable(),
    observed_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
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
    acknowledgement: z
      .strictObject({
        achieved_protection_blake3: z
          .string()
          .length(64)
          .regex(/^[0-9a-f]{64}$/),
        acknowledged_consistency: z.union([
          z.literal("eventual"),
          z.literal("strong"),
        ]),
        configured_consistency: z.union([
          z.literal("eventual"),
          z.literal("strong"),
        ]),
        durability_scope: z.union([
          z.literal("node_local"),
          z.literal("cell_replicated"),
          z.literal("globally_converged"),
        ]),
        eventual_shard_receipts: z.int().gte(0).lte(9007199254740991),
        fallback_applied: z.boolean(),
        pending_debt_blake3: z
          .string()
          .length(64)
          .regex(/^[0-9a-f]{64}$/),
        pending_eventual_shards: z.int().gte(0).lte(9007199254740991),
        policy_committed: z.boolean(),
        policy_evidence_blake3: z
          .string()
          .length(64)
          .regex(/^[0-9a-f]{64}$/),
        required_shard_receipts: z.int().gte(0).lte(9007199254740991),
      })
      .strict(),
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
 * ConfigureBackupDestinationRequest
 *
 * One registered target selected for encrypted recovery copies.
 */
export const zConfigureBackupDestinationRequest = z
  .strictObject({
    destination_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    enabled: z.boolean(),
    expected_revision: z.int().gte(0).lte(9007199254740991),
    name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^\P{Cc}+$/u),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    target_generation: z
      .string()
      .min(1)
      .max(20)
      .regex(/^[1-9][0-9]{0,19}$/),
    target_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * ConfigureBackupDestinationResponse
 *
 * Original durable receipt; configuration does not imply completed backup protection.
 */
export const zConfigureBackupDestinationResponse = z
  .strictObject({
    committed_revision: z.int().gte(1).lte(9007199254740991),
    destination_id: z
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
 * ConfigureBackupScheduleRequest
 *
 * Exact-retry replacement of the current partition backup policy.
 */
export const zConfigureBackupScheduleRequest = z
  .strictObject({
    expected_sequence: z.int().gte(0).lte(9007199254740990),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy: z
      .strictObject({
        enabled: z.boolean(),
        interval_seconds: z.int().gte(1).lte(4294967295),
        minimum_independent_copies: z.int().gte(0).lte(255),
        minimum_verified_copies: z.int().gte(1).lte(255),
        retained_generations: z.int().gte(1).lte(1024),
      })
      .strict(),
  })
  .strict();

/**
 * ConfigureBackupScheduleResponse
 *
 * Original durable configuration receipt, including when a later policy supersedes it.
 */
export const zConfigureBackupScheduleResponse = z
  .strictObject({
    committed_revision: z.int().gte(1).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    sequence: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * ConfirmRecoveryBundleRequest
 *
 * One authenticated idempotent save-verification request.
 */
export const zConfirmRecoveryBundleRequest = z
  .strictObject({
    mesh_id: z
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
    recovery_challenge: z
      .string()
      .length(34)
      .regex(/^meshspan-check-v1\.[0-9a-f]{16}$/),
  })
  .strict();

/**
 * ConfirmRecoveryBundleResponse
 *
 * Durable proof that the offline recovery bundle may no longer remain on the daemon.
 */
export const zConfirmRecoveryBundleResponse = z
  .strictObject({
    mesh_id: z
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
    revision: z.coerce
      .bigint()
      .gte(BigInt(1))
      .max(BigInt("18446744073709551615"), {
        error: "Invalid value: Expected uint64 to be <= 18446744073709551615",
      }),
    verified_at_epoch_micros: z.coerce
      .bigint()
      .min(BigInt("-9223372036854775808"), {
        error: "Invalid value: Expected int64 to be >= -9223372036854775808",
      })
      .max(BigInt("9223372036854775807"), {
        error: "Invalid value: Expected int64 to be <= 9223372036854775807",
      }),
  })
  .strict();

/**
 * CreateAcknowledgementPolicyRequest
 *
 * Exact-retry request to create one immutable acknowledgement policy.
 */
export const zCreateAcknowledgementPolicyRequest = z
  .strictObject({
    cells: z
      .array(
        z
          .strictObject({
            cell_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            local_protection_policy_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/)
              .nullish(),
            minimum_distinct_nodes: z.int().gte(1).lte(65535).nullish(),
            minimum_durable_targets: z.int().gte(1).lte(65535).nullish(),
            mode: z.union([
              z.literal("required_before_commit"),
              z.literal("eventual"),
              z.literal("excluded"),
            ]),
          })
          .strict(),
      )
      .max(256),
    consistency: z.union([z.literal("eventual"), z.literal("strong")]),
    fallback: z.union([
      z.literal("remain_pending"),
      z.literal("fail_at_deadline"),
      z.literal("eventual"),
    ]),
    minimum_distinct_nodes: z.int().gte(1).lte(65535),
    minimum_durable_targets: z.int().gte(1).lte(65535),
    name: z
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
    required_scenario_ids: z
      .array(
        z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      )
      .max(64),
    strong_wait_micros: z.int().gte(1).lte(9007199254740991).nullish(),
  })
  .strict();

/**
 * CreateAcknowledgementPolicyResponse
 *
 * Durable acknowledgement-policy creation result.
 */
export const zCreateAcknowledgementPolicyResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy: z
      .strictObject({
        cells: z
          .array(
            z
              .strictObject({
                cell_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/),
                local_protection_policy_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/)
                  .nullable(),
                minimum_distinct_nodes: z.int().gte(1).lte(65535).nullable(),
                minimum_durable_targets: z.int().gte(1).lte(65535).nullable(),
                mode: z.union([
                  z.literal("required_before_commit"),
                  z.literal("eventual"),
                  z.literal("excluded"),
                ]),
              })
              .strict(),
          )
          .max(256),
        consistency: z.union([z.literal("eventual"), z.literal("strong")]),
        fallback: z.union([
          z.literal("remain_pending"),
          z.literal("fail_at_deadline"),
          z.literal("eventual"),
        ]),
        minimum_distinct_nodes: z.int().gte(0).lte(65535),
        minimum_durable_targets: z.int().gte(0).lte(65535),
        name: z.string().min(1).max(256),
        policy_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        required_scenario_ids: z
          .array(
            z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
          )
          .max(64),
        revision: z.int().gte(1).lte(9007199254740991),
        strong_wait_micros: z.coerce
          .bigint()
          .gte(BigInt(0))
          .max(BigInt("18446744073709551615"), {
            error:
              "Invalid value: Expected uint64 to be <= 18446744073709551615",
          })
          .nullable(),
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
 * CreateAvailabilityCellRequest
 *
 * Exact-retry request to create one availability locality.
 */
export const zCreateAvailabilityCellRequest = z
  .strictObject({
    name: z
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
    parent_cell_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/)
      .nullish(),
  })
  .strict();

/**
 * CreateAvailabilityCellResponse
 *
 * Durable availability-cell creation result.
 */
export const zCreateAvailabilityCellResponse = z
  .strictObject({
    cell: z
      .strictObject({
        cell_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        name: z.string().min(1).max(256),
        parent_cell_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/)
          .nullable(),
        revision: z.int().gte(1).lte(9007199254740991),
      })
      .strict(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
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
 * CreateFaultGroupRequest
 *
 * Exact-retry request to create one shared-failure group.
 */
export const zCreateFaultGroupRequest = z
  .strictObject({
    class_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    group_name: z
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
 * CreateFaultGroupResponse
 *
 * Durable shared-failure-group creation result.
 */
export const zCreateFaultGroupResponse = z
  .strictObject({
    group: z
      .strictObject({
        class_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        class_name: z.string().min(1).max(128),
        group_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        group_name: z.string().min(1).max(256),
        revision: z.int().gte(1).lte(9007199254740991),
      })
      .strict(),
    operation_id: z
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
 * CreateLocalityPolicyRequest
 *
 * Exact-retry request to create one immutable desired-locality policy.
 */
export const zCreateLocalityPolicyRequest = z
  .strictObject({
    maximum_lag_micros: z.int().gte(1).lte(9007199254740991).nullish(),
    name: z
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
    requirements: z
      .array(
        z
          .strictObject({
            cell_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            local_protection_policy_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/)
              .nullish(),
          })
          .strict(),
      )
      .min(1)
      .max(64),
  })
  .strict();

/**
 * CreateLocalityPolicyResponse
 *
 * Durable locality-policy creation result.
 */
export const zCreateLocalityPolicyResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy: z
      .strictObject({
        maximum_lag_micros: z.int().gte(1).lte(9007199254740991).nullable(),
        name: z.string().min(1).max(256),
        policy_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        requirements: z
          .array(
            z
              .strictObject({
                cell_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/),
                local_protection_policy_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/)
                  .nullable(),
                requirement_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/),
              })
              .strict(),
          )
          .min(1)
          .max(64),
        revision: z.int().gte(1).lte(9007199254740991),
      })
      .strict(),
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
    recovery_bundle: z
      .string()
      .min(256)
      .max(33000)
      .regex(/^meshspan-recovery-file-v1\.[0-9a-f]+$/),
    recovery_challenge: z
      .string()
      .length(34)
      .regex(/^meshspan-check-v1\.[0-9a-f]{16}$/),
    recovery_code: z
      .string()
      .length(84)
      .regex(/^meshspan-offline-v1\.[0-9a-f]{64}$/),
  })
  .strict();

/**
 * CreateNodeJoinGrantRequest
 *
 * Administrator request for one bounded node join invitation.
 */
export const zCreateNodeJoinGrantRequest = z
  .strictObject({
    allowed_roles: z
      .array(
        z.union([
          z.literal("storage"),
          z.literal("gateway"),
          z.literal("metadata_eligible"),
        ]),
      )
      .min(1)
      .max(3),
    enrolment_endpoint: z
      .string()
      .min(12)
      .max(512)
      .regex(/^https:\/\/[a-z0-9.\-\[\]:]+$/),
    maximum_uses: z.int().gte(1).lte(1000),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    valid_for_seconds: z.int().gte(60).lte(604800),
  })
  .strict();

/**
 * CreateNodeJoinGrantResponse
 *
 * One exactly replayable join-grant issuance result.
 */
export const zCreateNodeJoinGrantResponse = z
  .strictObject({
    allowed_roles: z
      .array(
        z.union([
          z.literal("storage"),
          z.literal("gateway"),
          z.literal("metadata_eligible"),
        ]),
      )
      .min(1)
      .max(3),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    join_code: z
      .string()
      .min(250)
      .max(1250)
      .regex(/^meshspan-join-v2\.[0-9a-f]+(?:\.[0-9a-f]+){4}$/)
      .readonly(),
    maximum_uses: z.int().gte(1).lte(1000),
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
 * CreateProtectionPolicyRequest
 *
 * Exact-retry request to create one immutable survival policy.
 */
export const zCreateProtectionPolicyRequest = z
  .strictObject({
    name: z
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
    scenarios: z
      .array(
        z
          .strictObject({
            name: z
              .string()
              .min(1)
              .max(256)
              .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
            terms: z
              .array(
                z
                  .strictObject({
                    class_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/),
                    failure_count: z.int().gte(1).lte(65535),
                  })
                  .strict(),
              )
              .min(1)
              .max(16),
          })
          .strict(),
      )
      .min(1)
      .max(16),
  })
  .strict();

/**
 * CreateProtectionPolicyResponse
 *
 * Durable survival-policy creation result.
 */
export const zCreateProtectionPolicyResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy: z
      .strictObject({
        name: z.string().min(1).max(256),
        policy_id: z
          .string()
          .length(36)
          .regex(/^[0-9a-f-]{36}$/),
        revision: z.int().gte(1).lte(9007199254740991),
        scenarios: z
          .array(
            z
              .strictObject({
                name: z.string().min(1).max(256),
                scenario_id: z
                  .string()
                  .length(36)
                  .regex(/^[0-9a-f-]{36}$/),
                terms: z
                  .array(
                    z
                      .strictObject({
                        class_id: z
                          .string()
                          .length(36)
                          .regex(/^[0-9a-f-]{36}$/),
                        class_name: z.string().min(1).max(128),
                        failure_count: z.int().gte(1).lte(65535),
                      })
                      .strict(),
                  )
                  .min(1)
                  .max(16),
              })
              .strict(),
          )
          .min(1)
          .max(16),
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
 * CreateVolumePermissionGrantRequest
 *
 * Idempotent administrator request to grant volume authority to one user or group.
 */
export const zCreateVolumePermissionGrantRequest = z
  .strictObject({
    activation: z
      .strictObject({
        maximum_duration_micros: z.int().gte(1).lte(9007199254740991),
        minimum_assurance: z.union([
          z.literal("single_factor"),
          z.literal("multi_factor"),
          z.literal("recent_step_up"),
        ]),
        reason_required: z.boolean(),
      })
      .strict()
      .nullish(),
    inheritance: z.union([
      z.literal("object"),
      z.literal("descendants"),
      z.literal("object_and_descendants"),
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    rights: z
      .array(
        z.union([
          z.literal("traverse"),
          z.literal("list"),
          z.literal("read_data"),
          z.literal("create_child"),
          z.literal("write_data"),
          z.literal("append_data"),
          z.literal("rename"),
          z.literal("delete"),
          z.literal("read_attributes"),
          z.literal("write_attributes"),
          z.literal("read_permissions"),
          z.literal("change_permissions"),
          z.literal("change_owner"),
        ]),
      )
      .min(1)
      .max(13),
    subject_principal_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    valid_from_epoch_micros: z.int().gte(0).lte(9007199254740991).nullish(),
    valid_until_epoch_micros: z.int().gte(0).lte(9007199254740991).nullish(),
  })
  .strict();

/**
 * CreateVolumePermissionGrantResponse
 *
 * Durable result of creating or exactly replaying one permission grant.
 */
export const zCreateVolumePermissionGrantResponse = z
  .strictObject({
    grant: z
      .strictObject({
        activation_policy_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          )
          .nullable(),
        created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
        created_by: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        grant_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        inheritance: z.union([
          z.literal("object"),
          z.literal("descendants"),
          z.literal("object_and_descendants"),
        ]),
        revision: z.int().gte(1).lte(9007199254740991),
        rights: z
          .array(
            z.union([
              z.literal("traverse"),
              z.literal("list"),
              z.literal("read_data"),
              z.literal("create_child"),
              z.literal("write_data"),
              z.literal("append_data"),
              z.literal("rename"),
              z.literal("delete"),
              z.literal("read_attributes"),
              z.literal("write_attributes"),
              z.literal("read_permissions"),
              z.literal("change_permissions"),
              z.literal("change_owner"),
            ]),
          )
          .min(1)
          .max(13),
        subject_principal_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        valid_from_epoch_micros: z
          .int()
          .gte(0)
          .lte(9007199254740991)
          .nullable(),
        valid_until_epoch_micros: z
          .int()
          .gte(0)
          .lte(9007199254740991)
          .nullable(),
        volume_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      })
      .strict(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * CreateVolumeRequest
 *
 * Idempotent administrator request to create one logical volume.
 */
export const zCreateVolumeRequest = z
  .strictObject({
    name: z
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
    owner_principal_ids: z
      .array(
        z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      )
      .min(1)
      .max(1024),
  })
  .strict();

/**
 * CreateVolumeResponse
 *
 * Durable authoritative volume-creation outcome.
 */
export const zCreateVolumeResponse = z
  .strictObject({
    created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    name: z.string(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    owner_principal_ids: z
      .array(
        z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
      )
      .min(1)
      .max(1024),
    revision: z.int().gte(1).lte(9007199254740991),
    root_object_id: z
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
 * EnrolNodeRequest
 *
 * One node-owned identity presentation for pre-authorised enrolment.
 */
export const zEnrolNodeRequest = z
  .strictObject({
    host: z.union([
      z
        .strictObject({
          kind: z.literal("new"),
          name: z
            .string()
            .min(1)
            .max(128)
            .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
        })
        .strict(),
      z
        .strictObject({
          host_id: z
            .string()
            .length(36)
            .regex(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            ),
          kind: z.literal("existing"),
        })
        .strict(),
    ]),
    identity_proof_signature_hex: z
      .string()
      .min(128)
      .max(144)
      .regex(/^[0-9a-f]+$/),
    node_identity_public_key_hex: z
      .string()
      .length(130)
      .regex(/^04[0-9a-f]{128}$/),
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
    private_endpoint: z
      .string()
      .min(3)
      .max(512)
      .regex(/^[a-z0-9.\-\[\]:]+$/),
    requested_roles: z
      .array(
        z.union([
          z.literal("storage"),
          z.literal("gateway"),
          z.literal("metadata_eligible"),
        ]),
      )
      .min(1)
      .max(3),
    wrapping_public_key_hex: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
  })
  .strict();

/**
 * EnrolNodeResponse
 *
 * Exact replayable result of consuming one join-grant use.
 */
export const zEnrolNodeResponse = z
  .strictObject({
    bootstrap_peers: z
      .array(
        z
          .strictObject({
            certificate_der_hex: z
              .string()
              .min(2)
              .max(131072)
              .regex(/^[0-9a-f]+$/),
            node_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            private_endpoint: z.string().min(3).max(512),
          })
          .strict(),
      )
      .min(1)
      .max(1024),
    mesh_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    node_certificate_der_hex: z
      .string()
      .min(2)
      .max(131072)
      .regex(/^[0-9a-f]+$/),
    node_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    online_authority_certificate_der_hex: z
      .string()
      .min(2)
      .max(16384)
      .regex(/^[0-9a-f]+$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    root_certificate_der_hex: z
      .string()
      .min(2)
      .max(16384)
      .regex(/^[0-9a-f]+$/),
    root_partition_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    routing_epoch: z.coerce
      .bigint()
      .gte(BigInt(1))
      .max(BigInt("18446744073709551615"), {
        error: "Invalid value: Expected uint64 to be <= 18446744073709551615",
      }),
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
 * JoinMeshSetupRequest
 *
 * One exact request to join an existing mesh from an unclaimed daemon.
 */
export const zJoinMeshSetupRequest = z
  .strictObject({
    host_name: z
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
 * JoinMeshSetupResponse
 *
 * Accepted restart-safe join intent.
 */
export const zJoinMeshSetupResponse = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    status_url: z
      .string()
      .length(59)
      .regex(
        /^\/api\/latest\/operations\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * ListAcknowledgementPoliciesResponse
 *
 * One bounded page of write-acknowledgement policies.
 */
export const zListAcknowledgementPoliciesResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/acknowledgement-policies/)
      .nullable(),
    policies: z
      .array(
        z
          .strictObject({
            cells: z
              .array(
                z
                  .strictObject({
                    cell_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/),
                    local_protection_policy_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/)
                      .nullable(),
                    minimum_distinct_nodes: z
                      .int()
                      .gte(1)
                      .lte(65535)
                      .nullable(),
                    minimum_durable_targets: z
                      .int()
                      .gte(1)
                      .lte(65535)
                      .nullable(),
                    mode: z.union([
                      z.literal("required_before_commit"),
                      z.literal("eventual"),
                      z.literal("excluded"),
                    ]),
                  })
                  .strict(),
              )
              .max(256),
            consistency: z.union([z.literal("eventual"), z.literal("strong")]),
            fallback: z.union([
              z.literal("remain_pending"),
              z.literal("fail_at_deadline"),
              z.literal("eventual"),
            ]),
            minimum_distinct_nodes: z.int().gte(0).lte(65535),
            minimum_durable_targets: z.int().gte(0).lte(65535),
            name: z.string().min(1).max(256),
            policy_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            required_scenario_ids: z
              .array(
                z
                  .string()
                  .length(36)
                  .regex(
                    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
                  ),
              )
              .max(64),
            revision: z.int().gte(1).lte(9007199254740991),
            strong_wait_micros: z.coerce
              .bigint()
              .gte(BigInt(0))
              .max(BigInt("18446744073709551615"), {
                error:
                  "Invalid value: Expected uint64 to be <= 18446744073709551615",
              })
              .nullable(),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * ListAuthenticationMethodsResponse
 *
 * One bounded current-user authentication-method page.
 */
export const zListAuthenticationMethodsResponse = z
  .strictObject({
    methods: z
      .array(
        z
          .strictObject({
            created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            details: z.union([
              z
                .object({
                  backup_eligible: z.boolean(),
                  backup_state: z.boolean(),
                  kind: z.literal("passkey"),
                })
                .strict(),
              z
                .object({
                  kind: z.literal("totp"),
                })
                .strict(),
              z
                .object({
                  kind: z.literal("recovery_codes"),
                  remaining_codes: z.int().gte(0).lte(64),
                })
                .strict(),
              z
                .object({
                  key_id: z
                    .string()
                    .length(36)
                    .regex(
                      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
                    ),
                  kind: z.literal("api_key"),
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
                .strict(),
            ]),
            expires_at_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            label: z
              .string()
              .min(1)
              .max(80)
              .regex(/^[^\x00-\x1f\x7f]+$/),
            last_used_at_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            method_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            revision: z.int().gte(1).lte(9007199254740991),
            state: z.union([
              z.literal("active"),
              z.literal("suspended"),
              z.literal("revoked"),
            ]),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/users\/current\/authentication-methods/)
      .nullable(),
  })
  .strict();

/**
 * ListAvailabilityCellsResponse
 *
 * One bounded page of availability localities.
 */
export const zListAvailabilityCellsResponse = z
  .strictObject({
    cells: z
      .array(
        z
          .strictObject({
            cell_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            name: z.string().min(1).max(256),
            parent_cell_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/)
              .nullable(),
            revision: z.int().gte(1).lte(9007199254740991),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/topology\/availability-cells/)
      .nullable(),
  })
  .strict();

/**
 * ListBackupDestinationsQuery
 *
 * Bounded live inventory of configured destinations, including paused entries.
 */
export const zListBackupDestinationsQuery = z
  .strictObject({
    cursor: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9._-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(256).optional(),
  })
  .strict();

/**
 * ListBackupDestinationsResponse
 *
 * One current-authorisation inventory page, ordered by destination identity.
 */
export const zListBackupDestinationsResponse = z
  .strictObject({
    destinations: z
      .array(
        z
          .strictObject({
            destination_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            failure_relationship: z.union([
              z.literal("unknown"),
              z.literal("overlapping"),
              z.literal("independent"),
            ]),
            name: z
              .string()
              .min(1)
              .max(128)
              .regex(/^\P{Cc}+$/u),
            provider: z.union([
              z
                .strictObject({
                  kind: z.literal("registered_target"),
                  target_id: z
                    .string()
                    .length(36)
                    .regex(
                      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
                    ),
                })
                .strict(),
              z
                .strictObject({
                  kind: z.literal("federated_mesh"),
                  remote_mesh_id: z
                    .string()
                    .length(36)
                    .regex(
                      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
                    ),
                })
                .strict(),
              z
                .strictObject({
                  instance_id: z
                    .string()
                    .length(36)
                    .regex(
                      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
                    ),
                  kind: z.literal("component_provider"),
                })
                .strict(),
            ]),
            provider_generation: z
              .string()
              .min(1)
              .max(20)
              .regex(/^[1-9][0-9]{0,19}$/),
            revision: z.int().gte(1).lte(9007199254740991),
            state: z.union([
              z.literal("active"),
              z.literal("paused"),
              z.literal("retired"),
            ]),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .max(512)
      .regex(
        /^\/api\/latest\/admin\/backups\/destinations\?limit=[0-9]+&cursor=[a-zA-Z0-9._-]+$/,
      )
      .nullable(),
  })
  .strict();

/**
 * ListBackupRunsQuery
 *
 * Bounded newest-first history. Continuations preserve position, not stale authority.
 */
export const zListBackupRunsQuery = z
  .strictObject({
    cursor: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9._-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(100).optional(),
  })
  .strict();

/**
 * ListBackupRunsResponse
 *
 * One live, newest-first page. Refresh starts at the newest occurrence.
 */
export const zListBackupRunsResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .max(512)
      .regex(
        /^\/api\/latest\/admin\/backups\/runs\?limit=[0-9]+&cursor=[a-zA-Z0-9._-]+$/,
      )
      .nullable(),
    runs: z
      .array(
        z
          .strictObject({
            backup_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            completed_at_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            minimum_independent_copies: z.int().gte(0).lte(255),
            minimum_verified_copies: z.int().gte(1).lte(255),
            run_sequence: z
              .string()
              .min(1)
              .max(19)
              .regex(/^[1-9][0-9]*$/),
            schedule_sequence: z
              .string()
              .min(1)
              .max(19)
              .regex(/^[1-9][0-9]*$/),
            scheduled_for_epoch_micros: z.int().gte(0).lte(9007199254740991),
            state: z.union([
              z.literal("queued"),
              z.literal("claimed"),
              z.literal("recorded"),
              z.literal("protected"),
              z.literal("incomplete"),
            ]),
          })
          .strict(),
      )
      .max(100),
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
 * ListFaultGroupMembershipsResponse
 *
 * One bounded page of overlapping membership edges.
 */
export const zListFaultGroupMembershipsResponse = z
  .strictObject({
    memberships: z
      .array(
        z
          .strictObject({
            group_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            host_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            revision: z.int().gte(1).lte(9007199254740991),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/topology\/fault-group-memberships/)
      .nullable(),
  })
  .strict();

/**
 * ListFaultGroupsResponse
 *
 * One bounded page of shared-failure groups.
 */
export const zListFaultGroupsResponse = z
  .strictObject({
    groups: z
      .array(
        z
          .strictObject({
            class_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            class_name: z.string().min(1).max(128),
            group_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            group_name: z.string().min(1).max(256),
            revision: z.int().gte(1).lte(9007199254740991),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/topology\/fault-groups/)
      .nullable(),
  })
  .strict();

/**
 * ListGroupMembershipsResponse
 *
 * One bounded, stable direct-membership page.
 */
export const zListGroupMembershipsResponse = z
  .strictObject({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    memberships: z
      .array(
        z
          .strictObject({
            activation_required: z.boolean(),
            created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            created_by: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            group_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            member: z
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
            revision: z.int().gte(1).lte(9007199254740991),
            valid_from_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            valid_until_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/groups\//)
      .nullable(),
  })
  .strict();

/**
 * ListLocalityPoliciesResponse
 *
 * One bounded page of desired-locality policies.
 */
export const zListLocalityPoliciesResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/locality-policies/)
      .nullable(),
    policies: z
      .array(
        z
          .strictObject({
            maximum_lag_micros: z.int().gte(1).lte(9007199254740991).nullable(),
            name: z.string().min(1).max(256),
            policy_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            requirements: z
              .array(
                z
                  .strictObject({
                    cell_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/),
                    local_protection_policy_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/)
                      .nullable(),
                    requirement_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/),
                  })
                  .strict(),
              )
              .min(1)
              .max(64),
            revision: z.int().gte(1).lte(9007199254740991),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * ListManualDnsTasksResponse
 *
 * One bounded deadline-ordered page of current manual DNS work.
 */
export const zListManualDnsTasksResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/certificate-tasks\/manual-dns/)
      .nullable(),
    tasks: z
      .array(
        z
          .strictObject({
            action: z.union([z.literal("publish"), z.literal("remove")]),
            created_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
            expires_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
            order_fence: z
              .string()
              .min(1)
              .max(20)
              .regex(/^[1-9][0-9]{0,19}$/),
            order_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            record_name: z
              .string()
              .min(1)
              .max(253)
              .regex(/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$/),
            record_value: z
              .string()
              .min(1)
              .max(512)
              .regex(/^[A-Za-z0-9_-]+$/),
            revision: z.int().gte(1).lte(9007199254740991),
            task_digest: z
              .string()
              .length(64)
              .regex(/^[0-9a-f]{64}$/),
            transitioned_at_epoch_micros: z.int().gte(1).lte(9007199254740991),
          })
          .strict(),
      )
      .max(200),
  })
  .strict();

/**
 * ListOperationsResponse
 *
 * One bounded reverse-chronological administrator operation page.
 */
export const zListOperationsResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/operations/)
      .nullable(),
    operations: z
      .array(
        z
          .strictObject({
            cancellation_available: z.boolean(),
            completed_at_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            failure: z
              .strictObject({
                code: z
                  .string()
                  .min(1)
                  .max(64)
                  .regex(/^[a-z][a-z0-9_]*$/),
                message: z.string().min(1).max(512),
                retry: z.union([
                  z.literal("never"),
                  z.literal("automatic"),
                  z.literal("same_operation"),
                  z.literal("action_required"),
                ]),
              })
              .strict()
              .nullable(),
            kind: z.union([
              z.literal("metadata_mutation"),
              z.literal("setup_join"),
              z.literal("placement"),
              z.literal("repair"),
              z.literal("scrub"),
              z.literal("drain"),
              z.literal("reconciliation"),
              z.literal("certificate"),
              z.literal("backup"),
              z.literal("update"),
            ]),
            operation_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            progress: z
              .strictObject({
                completed: z.int().gte(0).lte(9007199254740991),
                total: z.int().gte(1).lte(9007199254740991),
                unit: z.union([
                  z.literal("steps"),
                  z.literal("bytes"),
                  z.literal("items"),
                  z.literal("nodes"),
                  z.literal("targets"),
                ]),
              })
              .strict()
              .nullable(),
            result_url: z
              .string()
              .min(1)
              .max(16384)
              .regex(/^\/api\/latest\//)
              .nullable(),
            revision: z.int().gte(1).lte(9007199254740991),
            started_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            state: z.union([
              z.literal("queued"),
              z.literal("running"),
              z.literal("awaiting_action"),
              z.literal("succeeded"),
              z.literal("failed"),
              z.literal("cancelled"),
            ]),
            status_url: z
              .string()
              .min(1)
              .max(512)
              .regex(/^\/api\/latest\/operations\//),
            updated_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
          })
          .strict(),
      )
      .max(200),
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
 * ListProtectionPoliciesResponse
 *
 * One bounded page of immutable survival policies.
 */
export const zListProtectionPoliciesResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/protection-policies/)
      .nullable(),
    policies: z
      .array(
        z
          .strictObject({
            name: z.string().min(1).max(256),
            policy_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            revision: z.int().gte(1).lte(9007199254740991),
            scenarios: z
              .array(
                z
                  .strictObject({
                    name: z.string().min(1).max(256),
                    scenario_id: z
                      .string()
                      .length(36)
                      .regex(/^[0-9a-f-]{36}$/),
                    terms: z
                      .array(
                        z
                          .strictObject({
                            class_id: z
                              .string()
                              .length(36)
                              .regex(/^[0-9a-f-]{36}$/),
                            class_name: z.string().min(1).max(128),
                            failure_count: z.int().gte(1).lte(65535),
                          })
                          .strict(),
                      )
                      .min(1)
                      .max(16),
                  })
                  .strict(),
              )
              .min(1)
              .max(16),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * ListStorageDrainsResponse
 *
 * One current manager-only storage-drain page.
 */
export const zListStorageDrainsResponse = z
  .strictObject({
    drains: z
      .array(
        z
          .strictObject({
            allow_temporary_degraded: z.boolean(),
            cleanup_requested: z.boolean(),
            drain_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            requested_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            revision: z.int().gte(1).lte(9007199254740991),
            safe_at_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            scope: z.union([
              z
                .strictObject({
                  generation: z
                    .string()
                    .min(1)
                    .max(20)
                    .regex(/^[1-9][0-9]{0,19}$/),
                  kind: z.literal("target"),
                  target_id: z
                    .string()
                    .length(36)
                    .regex(/^[0-9a-f-]{36}$/),
                })
                .strict(),
              z
                .strictObject({
                  incarnation: z
                    .string()
                    .min(1)
                    .max(20)
                    .regex(/^[1-9][0-9]{0,19}$/),
                  kind: z.literal("node"),
                  node_id: z
                    .string()
                    .length(36)
                    .regex(/^[0-9a-f-]{36}$/),
                })
                .strict(),
              z
                .strictObject({
                  fault_group_id: z
                    .string()
                    .length(36)
                    .regex(/^[0-9a-f-]{36}$/),
                  kind: z.literal("fault_group"),
                })
                .strict(),
            ]),
            state: z.union([
              z.literal("evacuating"),
              z.literal("membership_fenced"),
              z.literal("safe_to_detach"),
            ]),
            status_url: z
              .string()
              .min(1)
              .max(512)
              .regex(/^\/api\/latest\/admin\/storage-drains\//),
          })
          .strict(),
      )
      .max(200),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/storage-drains/)
      .nullable(),
  })
  .strict();

/**
 * ListStorageFoldersResponse
 *
 * Current manager-only page of local storage folders.
 */
export const zListStorageFoldersResponse = z
  .strictObject({
    folders: z
      .array(
        z
          .strictObject({
            generation: z
              .string()
              .min(1)
              .max(20)
              .regex(/^[1-9][0-9]{0,19}$/),
            node_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            path: z
              .string()
              .min(1)
              .max(16384)
              .regex(/^\/[^\x00-\x1f\x7f]*$/)
              .nullable(),
            state: z.union([
              z.literal("configuring"),
              z.literal("active"),
              z.literal("unavailable"),
            ]),
            target_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            usage_limit: z.union([
              z
                .strictObject({
                  kind: z.literal("percent"),
                  percent: z.int().gte(1).lte(100),
                })
                .strict(),
              z
                .strictObject({
                  bytes: z
                    .string()
                    .min(1)
                    .max(20)
                    .regex(/^[1-9][0-9]{0,19}$/),
                  kind: z.literal("bytes"),
                })
                .strict(),
            ]),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/storage-folders/)
      .nullable(),
  })
  .strict();

/**
 * ListTopologyNodesResponse
 *
 * One bounded page of daemon nodes.
 */
export const zListTopologyNodesResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/topology\/nodes/)
      .nullable(),
    nodes: z
      .array(
        z
          .strictObject({
            display_name: z.string().min(1).max(256),
            host_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            incarnation: z
              .string()
              .min(1)
              .max(20)
              .regex(/^[1-9][0-9]{0,19}$/),
            node_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            private_endpoint: z.string().min(3).max(512).nullable(),
            revision: z.int().gte(1).lte(9007199254740991),
            roles: z
              .strictObject({
                gateway: z.boolean(),
                metadata_eligible: z.boolean(),
                storage: z.boolean(),
              })
              .strict(),
            state: z.union([
              z.literal("joining"),
              z.literal("active"),
              z.literal("draining"),
              z.literal("retired"),
            ]),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * ListTopologyTargetsResponse
 *
 * One bounded page of mesh-wide targets.
 */
export const zListTopologyTargetsResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/topology\/targets/)
      .nullable(),
    targets: z
      .array(
        z
          .strictObject({
            display_name: z.string().min(1).max(256),
            generation: z
              .string()
              .min(1)
              .max(20)
              .regex(/^[1-9][0-9]{0,19}$/),
            host_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            node_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            revision: z.int().gte(1).lte(9007199254740991),
            state: z.union([
              z.literal("configuring"),
              z.literal("active"),
              z.literal("draining"),
              z.literal("unavailable"),
              z.literal("retired"),
            ]),
            target_id: z
              .string()
              .length(36)
              .regex(/^[0-9a-f-]{36}$/),
            usage_limit: z.union([
              z
                .strictObject({
                  kind: z.literal("percent"),
                  percent: z.int().gte(1).lte(100),
                })
                .strict(),
              z
                .strictObject({
                  bytes: z
                    .string()
                    .min(1)
                    .max(20)
                    .regex(/^[1-9][0-9]{0,19}$/),
                  kind: z.literal("bytes"),
                })
                .strict(),
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
 * ListVolumePermissionGrantsResponse
 *
 * One bounded stable page of active volume grants.
 */
export const zListVolumePermissionGrantsResponse = z
  .strictObject({
    grants: z
      .array(
        z
          .strictObject({
            activation_policy_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              )
              .nullable(),
            created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            created_by: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            grant_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            inheritance: z.union([
              z.literal("object"),
              z.literal("descendants"),
              z.literal("object_and_descendants"),
            ]),
            revision: z.int().gte(1).lte(9007199254740991),
            rights: z
              .array(
                z.union([
                  z.literal("traverse"),
                  z.literal("list"),
                  z.literal("read_data"),
                  z.literal("create_child"),
                  z.literal("write_data"),
                  z.literal("append_data"),
                  z.literal("rename"),
                  z.literal("delete"),
                  z.literal("read_attributes"),
                  z.literal("write_attributes"),
                  z.literal("read_permissions"),
                  z.literal("change_permissions"),
                  z.literal("change_owner"),
                ]),
              )
              .min(1)
              .max(13),
            subject_principal_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            valid_from_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            valid_until_epoch_micros: z
              .int()
              .gte(0)
              .lte(9007199254740991)
              .nullable(),
            volume_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
          })
          .strict(),
      )
      .max(256),
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/admin\/volumes\//)
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
 * ListVolumesResponse
 *
 * One bounded current-user volume page.
 */
export const zListVolumesResponse = z
  .strictObject({
    next_page_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\/volumes/)
      .nullable(),
    volumes: z
      .array(
        z
          .strictObject({
            created_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
            effective_rights: z
              .array(
                z.union([
                  z.literal("traverse"),
                  z.literal("list"),
                  z.literal("read_data"),
                  z.literal("create_child"),
                  z.literal("write_data"),
                  z.literal("append_data"),
                  z.literal("rename"),
                  z.literal("delete"),
                  z.literal("read_attributes"),
                  z.literal("write_attributes"),
                  z.literal("read_permissions"),
                  z.literal("change_permissions"),
                  z.literal("change_owner"),
                ]),
              )
              .min(2)
              .max(13),
            name: z
              .string()
              .min(1)
              .max(256)
              .regex(/^[^\x00-\x1f\x7f]+$/),
            revision: z.int().gte(1).lte(9007199254740991),
            root_object_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
            state: z.union([
              z.literal("active"),
              z.literal("suspended"),
              z.literal("draining"),
              z.literal("retired"),
            ]),
            volume_id: z
              .string()
              .length(36)
              .regex(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
              ),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();

/**
 * OperationStatusResponse
 *
 * Current durable state of one exact operation visible to the caller.
 */
export const zOperationStatusResponse = z
  .strictObject({
    cancellation_available: z.boolean(),
    completed_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullable(),
    failure: z
      .strictObject({
        code: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[a-z][a-z0-9_]*$/),
        message: z.string().min(1).max(512),
        retry: z.union([
          z.literal("never"),
          z.literal("automatic"),
          z.literal("same_operation"),
          z.literal("action_required"),
        ]),
      })
      .strict()
      .nullable(),
    kind: z.union([
      z.literal("metadata_mutation"),
      z.literal("setup_join"),
      z.literal("placement"),
      z.literal("repair"),
      z.literal("scrub"),
      z.literal("drain"),
      z.literal("reconciliation"),
      z.literal("certificate"),
      z.literal("backup"),
      z.literal("update"),
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    progress: z
      .strictObject({
        completed: z.int().gte(0).lte(9007199254740991),
        total: z.int().gte(1).lte(9007199254740991),
        unit: z.union([
          z.literal("steps"),
          z.literal("bytes"),
          z.literal("items"),
          z.literal("nodes"),
          z.literal("targets"),
        ]),
      })
      .strict()
      .nullable(),
    result_url: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^\/api\/latest\//)
      .nullable(),
    revision: z.int().gte(1).lte(9007199254740991),
    started_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    state: z.union([
      z.literal("queued"),
      z.literal("running"),
      z.literal("awaiting_action"),
      z.literal("succeeded"),
      z.literal("failed"),
      z.literal("cancelled"),
    ]),
    status_url: z
      .string()
      .min(1)
      .max(512)
      .regex(/^\/api\/latest\/operations\//),
    updated_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
  })
  .strict();

/**
 * ProvisionCertificateRequest
 *
 * Idempotent request to provision automatic public certificates.
 */
export const zProvisionCertificateRequest = z
  .strictObject({
    certificate_names: z.array(z.string()).min(1).max(256),
    challenge: z.union([
      z
        .strictObject({
          kind: z.literal("http01"),
        })
        .strict(),
      z
        .strictObject({
          kind: z.literal("dns01_manual"),
        })
        .strict(),
      z
        .strictObject({
          algorithm: z.union([
            z.literal("hmac_sha256"),
            z.literal("hmac_sha512"),
          ]),
          key_name: z.string().min(1).max(253),
          kind: z.literal("dns01_rfc2136"),
          secret: z
            .string()
            .min(16)
            .max(2048)
            .regex(/^[\x21-\x7e]+$/),
          server: z.string().min(3).max(128),
          zone: z.string().min(1).max(253),
        })
        .strict(),
      z
        .strictObject({
          api_token: z
            .string()
            .min(16)
            .max(2048)
            .regex(/^[\x21-\x7e]+$/),
          kind: z.literal("dns01_cloudflare"),
          zone_id: z
            .string()
            .length(32)
            .regex(/^[0-9a-f]{32}$/),
        })
        .strict(),
      z
        .strictObject({
          bearer_token: z
            .string()
            .min(16)
            .max(2048)
            .regex(/^[\x21-\x7e]+$/),
          endpoint: z
            .string()
            .min(9)
            .max(2048)
            .regex(/^https:\/\//),
          kind: z.literal("dns01_webhook"),
        })
        .strict(),
    ]),
    directory_url: z
      .string()
      .min(9)
      .max(2048)
      .regex(/^https:\/\//),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * ProvisionCertificateResponse
 *
 * Durable result of one public-certificate provisioning operation.
 */
export const zProvisionCertificateResponse = z
  .strictObject({
    certificate_names: z.array(z.string()).min(1).max(256),
    configuration_id: z
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
    order_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    revision: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * ProvisionMeshLocalCertificateRequest
 *
 * Exact-retry request for an automatically trusted mesh-local HTTPS identity.
 */
export const zProvisionMeshLocalCertificateRequest = z
  .strictObject({
    certificate_names: z.array(z.string()).min(1).max(256),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * ProvisionMeshLocalCertificateResponse
 *
 * Secret-free result of one mesh-local HTTPS certificate issuance.
 */
export const zProvisionMeshLocalCertificateResponse = z
  .strictObject({
    authority_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    certificate_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    certificate_names: z.array(z.string()).min(1).max(256),
    generation: z
      .string()
      .min(1)
      .max(20)
      .regex(/^[1-9][0-9]{0,19}$/),
    issuance_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    not_after_epoch_micros: z.int().gte(1).lte(9007199254740991),
    not_before_epoch_micros: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    public_key_fingerprint: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
    revision: z.int().gte(1).lte(9007199254740991),
    trust_anchor_pem: z.string().min(64).max(32768),
  })
  .strict();

/**
 * PublishExternalCertificateRequest
 *
 * Exact-retry automated publication of a certificate issued outside `MeshSpan`.
 */
export const zPublishExternalCertificateRequest = z
  .strictObject({
    certificate_chain_pem: z.string().min(64).max(98304),
    certificate_names: z.array(z.string()).min(1).max(256),
    generation: z
      .string()
      .min(1)
      .max(20)
      .regex(/^[1-9][0-9]{0,19}$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    private_key_pkcs8_pem: z.string().min(64).max(16384),
  })
  .strict();

/**
 * PublishExternalCertificateResponse
 *
 * Secret-free durable result of one automated external-certificate publication.
 */
export const zPublishExternalCertificateResponse = z
  .strictObject({
    certificate_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    certificate_names: z.array(z.string()).min(1).max(256),
    generation: z
      .string()
      .min(1)
      .max(20)
      .regex(/^[1-9][0-9]{0,19}$/),
    not_after_epoch_micros: z.int().gte(1).lte(9007199254740991),
    not_before_epoch_micros: z.int().gte(0).lte(9007199254740991),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    public_key_fingerprint: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
    publication_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    revision: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * PublishSmbExportRequest
 *
 * Exact-retry request to publish one existing volume or folder explicitly.
 */
export const zPublishSmbExportRequest = z
  .strictObject({
    encryption_required: z.boolean(),
    gateways: z.union([
      z
        .strictObject({
          kind: z.literal("all_eligible"),
        })
        .strict(),
      z
        .strictObject({
          kind: z.literal("selected"),
          node_ids: z.array(z.string()).min(1).max(1024),
        })
        .strict(),
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    root_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    share_name: z
      .string()
      .min(1)
      .max(240)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
  })
  .strict();

/**
 * PublishSmbExportResponse
 *
 * Durable publication result.
 */
export const zPublishSmbExportResponse = z
  .strictObject({
    encryption_required: z.boolean(),
    export_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    gateways: z.union([
      z
        .strictObject({
          kind: z.literal("all_eligible"),
        })
        .strict(),
      z
        .strictObject({
          kind: z.literal("selected"),
          node_ids: z.array(z.string()).min(1).max(1024),
        })
        .strict(),
    ]),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    revision: z.int().gte(1).lte(9007199254740991),
    root_object_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    share_name: z
      .string()
      .min(1)
      .max(240)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * RegisterStorageFolderRequest
 *
 * Exact-retry manager request to register one existing local folder.
 */
export const zRegisterStorageFolderRequest = z
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
      .max(16384)
      .regex(/^\/[^\x00-\x1f\x7f]*$/),
    usage_limit: z.union([
      z
        .strictObject({
          kind: z.literal("percent"),
          percent: z.int().gte(1).lte(100),
        })
        .strict(),
      z
        .strictObject({
          bytes: z
            .string()
            .min(1)
            .max(20)
            .regex(/^[1-9][0-9]{0,19}$/),
          kind: z.literal("bytes"),
        })
        .strict(),
    ]),
  })
  .strict();

/**
 * RegisterStorageFolderResponse
 *
 * Durable registration result after the target is open locally.
 */
export const zRegisterStorageFolderResponse = z
  .strictObject({
    folder: z
      .strictObject({
        generation: z
          .string()
          .min(1)
          .max(20)
          .regex(/^[1-9][0-9]{0,19}$/),
        node_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        path: z
          .string()
          .min(1)
          .max(16384)
          .regex(/^\/[^\x00-\x1f\x7f]*$/)
          .nullable(),
        state: z.union([
          z.literal("configuring"),
          z.literal("active"),
          z.literal("unavailable"),
        ]),
        target_id: z
          .string()
          .length(36)
          .regex(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          ),
        usage_limit: z.union([
          z
            .strictObject({
              kind: z.literal("percent"),
              percent: z.int().gte(1).lte(100),
            })
            .strict(),
          z
            .strictObject({
              bytes: z
                .string()
                .min(1)
                .max(20)
                .regex(/^[1-9][0-9]{0,19}$/),
              kind: z.literal("bytes"),
            })
            .strict(),
        ]),
      })
      .strict(),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * RemoveGroupMemberRequest
 *
 * Idempotent administrator request to remove one exact active direct membership.
 */
export const zRemoveGroupMemberRequest = z
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
      .max(512)
      .regex(/^\S(?:[\s\S]*\S)?$/),
  })
  .strict();

/**
 * RemoveGroupMemberResponse
 *
 * Durable result of removing or exactly replaying one direct membership.
 */
export const zRemoveGroupMemberResponse = z
  .strictObject({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    member_principal_id: z
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
    removed_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    revision: z.int().gte(1).lte(9007199254740991),
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
 * RevokePermissionGrantRequest
 *
 * Idempotent administrator request to revoke one exact active grant.
 */
export const zRevokePermissionGrantRequest = z
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
      .max(512)
      .regex(/^\S(?:[\s\S]*\S)?$/),
  })
  .strict();

/**
 * RevokePermissionGrantResponse
 *
 * Durable result of revoking or exactly replaying one permission grant.
 */
export const zRevokePermissionGrantResponse = z
  .strictObject({
    grant_id: z
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
    revision: z.int().gte(1).lte(9007199254740991),
    revoked_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
  })
  .strict();

/**
 * SetAvailabilityCellMembershipResponse
 *
 * Durable desired membership of a machine or target in one availability cell.
 */
export const zSetAvailabilityCellMembershipResponse = z
  .strictObject({
    cell_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    member_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    present: z.boolean(),
    revision: z.int().gte(1).lte(9007199254740991),
  })
  .strict();

/**
 * SetFaultGroupMembershipRequest
 *
 * Exact-retry desired machine/group membership.
 */
export const zSetFaultGroupMembershipRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    present: z.boolean(),
  })
  .strict();

/**
 * SetFaultGroupMembershipResponse
 *
 * Durable desired-membership result.
 */
export const zSetFaultGroupMembershipResponse = z
  .strictObject({
    group_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    host_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    present: z.boolean(),
    revision: z.int().gte(1).lte(9007199254740991),
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
 * StorageDrainSummary
 *
 * One current manager-visible storage drain.
 */
export const zStorageDrainSummary = z
  .strictObject({
    allow_temporary_degraded: z.boolean(),
    cleanup_requested: z.boolean(),
    drain_id: z
      .string()
      .length(36)
      .regex(/^[0-9a-f-]{36}$/),
    requested_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    revision: z.int().gte(1).lte(9007199254740991),
    safe_at_epoch_micros: z.int().gte(0).lte(9007199254740991).nullable(),
    scope: z.union([
      z
        .strictObject({
          generation: z
            .string()
            .min(1)
            .max(20)
            .regex(/^[1-9][0-9]{0,19}$/),
          kind: z.literal("target"),
          target_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
        })
        .strict(),
      z
        .strictObject({
          incarnation: z
            .string()
            .min(1)
            .max(20)
            .regex(/^[1-9][0-9]{0,19}$/),
          kind: z.literal("node"),
          node_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
        })
        .strict(),
      z
        .strictObject({
          fault_group_id: z
            .string()
            .length(36)
            .regex(/^[0-9a-f-]{36}$/),
          kind: z.literal("fault_group"),
        })
        .strict(),
    ]),
    state: z.union([
      z.literal("evacuating"),
      z.literal("membership_fenced"),
      z.literal("safe_to_detach"),
    ]),
    status_url: z
      .string()
      .min(1)
      .max(512)
      .regex(/^\/api\/latest\/admin\/storage-drains\//),
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
 * WithdrawSmbExportRequest
 *
 * Exact-retry audited withdrawal request.
 */
export const zWithdrawSmbExportRequest = z
  .strictObject({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    reason: z.string().min(1).max(1024).regex(/\S/),
  })
  .strict();

/**
 * WithdrawSmbExportResponse
 *
 * Durable export-withdrawal result.
 */
export const zWithdrawSmbExportResponse = z
  .strictObject({
    export_id: z
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
    revision: z.int().gte(1).lte(9007199254740991),
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
 * CreateNodeJoinGrantResponse
 *
 * One exactly replayable join-grant issuance result.
 */
export const zCreateNodeJoinGrantResponseWritable = z
  .strictObject({
    allowed_roles: z
      .array(
        z.union([
          z.literal("storage"),
          z.literal("gateway"),
          z.literal("metadata_eligible"),
        ]),
      )
      .min(1)
      .max(3),
    expires_at_epoch_micros: z.int().gte(0).lte(9007199254740991),
    maximum_uses: z.int().gte(1).lte(1000),
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
 * EnrolNodeRequest
 *
 * One node-owned identity presentation for pre-authorised enrolment.
 */
export const zEnrolNodeRequestWritable = z
  .strictObject({
    host: z.union([
      z
        .strictObject({
          kind: z.literal("new"),
          name: z
            .string()
            .min(1)
            .max(128)
            .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
        })
        .strict(),
      z
        .strictObject({
          host_id: z
            .string()
            .length(36)
            .regex(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            ),
          kind: z.literal("existing"),
        })
        .strict(),
    ]),
    identity_proof_signature_hex: z
      .string()
      .min(128)
      .max(144)
      .regex(/^[0-9a-f]+$/),
    join_code: z
      .string()
      .min(250)
      .max(1250)
      .regex(/^meshspan-join-v2\.[0-9a-f]+(?:\.[0-9a-f]+){4}$/),
    node_identity_public_key_hex: z
      .string()
      .length(130)
      .regex(/^04[0-9a-f]{128}$/),
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
    private_endpoint: z
      .string()
      .min(3)
      .max(512)
      .regex(/^[a-z0-9.\-\[\]:]+$/),
    requested_roles: z
      .array(
        z.union([
          z.literal("storage"),
          z.literal("gateway"),
          z.literal("metadata_eligible"),
        ]),
      )
      .min(1)
      .max(3),
    wrapping_public_key_hex: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
  })
  .strict();

/**
 * JoinMeshSetupRequest
 *
 * One exact request to join an existing mesh from an unclaimed daemon.
 */
export const zJoinMeshSetupRequestWritable = z
  .strictObject({
    claim: z
      .string()
      .length(115)
      .regex(/^meshspan-claim-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/),
    host_name: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[^\x00-\x1f\x2f\x7f\\]+$/),
    join_code: z
      .string()
      .min(250)
      .max(1250)
      .regex(/^meshspan-join-v2\.[0-9a-f]+(?:\.[0-9a-f]+){4}$/),
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

export const zListAcknowledgementPoliciesQuery = z
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
 * One bounded topology page
 */
export const zListAcknowledgementPoliciesResponse2 =
  zListAcknowledgementPoliciesResponse;

/**
 * Immutable placement policy
 */
export const zCreateAcknowledgementPolicyBody =
  zCreateAcknowledgementPolicyRequest;

export const zCreateAcknowledgementPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Placement policy committed
 */
export const zCreateAcknowledgementPolicyResponse2 =
  zCreateAcknowledgementPolicyResponse;

export const zListBackupDestinationsQuery2 = z
  .object({
    limit: z.int().gte(1).lte(256).optional(),
    cursor: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9._-]+$/)
      .optional(),
  })
  .strict();

/**
 * Current destination page with a relative next-page URL
 */
export const zListBackupDestinationsResponse2 = zListBackupDestinationsResponse;

/**
 * Complete destination and exact-retry identity
 */
export const zConfigureBackupDestinationBody =
  zConfigureBackupDestinationRequest;

export const zConfigureBackupDestinationHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Original committed configuration receipt
 */
export const zConfigureBackupDestinationResponse2 =
  zConfigureBackupDestinationResponse;

export const zListBackupRunsQuery2 = z
  .object({
    limit: z.int().gte(1).lte(100).optional(),
    cursor: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9._-]+$/)
      .optional(),
  })
  .strict();

/**
 * Bounded historical run outcomes and relative continuation
 */
export const zListBackupRunsResponse2 = zListBackupRunsResponse;

/**
 * Current policy, or null before configuration
 */
export const zGetBackupScheduleResponse = zBackupScheduleResponse;

/**
 * Complete policy and exact-retry identity
 */
export const zConfigureBackupScheduleBody = zConfigureBackupScheduleRequest;

export const zConfigureBackupScheduleHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Original committed configuration receipt
 */
export const zConfigureBackupScheduleResponse2 =
  zConfigureBackupScheduleResponse;

export const zListManualDnsTasksQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(200).optional(),
  })
  .strict();

/**
 * One deadline-ordered manual DNS task page
 */
export const zListManualDnsTasksResponse2 = zListManualDnsTasksResponse;

/**
 * Public-certificate provisioning
 */
export const zProvisionCertificateBody = zProvisionCertificateRequest;

export const zProvisionCertificateHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Configuration and initial order durably committed or exactly replayed
 */
export const zProvisionCertificateResponse2 = zProvisionCertificateResponse;

/**
 * External certificate publication
 */
export const zPublishExternalCertificateBody =
  zPublishExternalCertificateRequest;

/**
 * Encrypted certificate generation durably published or exactly replayed
 */
export const zPublishExternalCertificateResponse2 =
  zPublishExternalCertificateResponse;

/**
 * Mesh-local certificate provisioning
 */
export const zProvisionMeshLocalCertificateBody =
  zProvisionMeshLocalCertificateRequest;

export const zProvisionMeshLocalCertificateHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Encrypted certificate generation durably issued or exactly replayed
 */
export const zProvisionMeshLocalCertificateResponse2 =
  zProvisionMeshLocalCertificateResponse;

/**
 * Current secret-free certificate status
 */
export const zGetCertificateStatusResponse = zCertificateStatusResponse;

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

export const zListGroupMembersPath = z
  .object({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zListGroupMembersQuery = z
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
 * One current direct-membership page
 */
export const zListGroupMembersResponse = zListGroupMembershipsResponse;

/**
 * Direct membership addition
 */
export const zAddGroupMemberBody = zAddGroupMemberRequest;

export const zAddGroupMemberHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zAddGroupMemberPath = z
  .object({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Membership durably added or exactly replayed
 */
export const zAddGroupMemberResponse2 = zAddGroupMemberResponse;

/**
 * Audited direct membership removal
 */
export const zRemoveGroupMemberBody = zRemoveGroupMemberRequest;

export const zRemoveGroupMemberHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zRemoveGroupMemberPath = z
  .object({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    member_principal_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Membership durably removed or exactly replayed
 */
export const zRemoveGroupMemberResponse2 = zRemoveGroupMemberResponse;

export const zListLocalityPoliciesQuery = z
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
 * One bounded topology page
 */
export const zListLocalityPoliciesResponse2 = zListLocalityPoliciesResponse;

/**
 * Immutable placement policy
 */
export const zCreateLocalityPolicyBody = zCreateLocalityPolicyRequest;

export const zCreateLocalityPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Placement policy committed
 */
export const zCreateLocalityPolicyResponse2 = zCreateLocalityPolicyResponse;

/**
 * Join invitation policy
 */
export const zCreateNodeJoinGrantBody = zCreateNodeJoinGrantRequest;

/**
 * Committed join invitation
 */
export const zCreateNodeJoinGrantResponse2 = zCreateNodeJoinGrantResponse;

export const zListOperationsQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(200).optional(),
  })
  .strict();

/**
 * One reverse-chronological operation page
 */
export const zListOperationsResponse2 = zListOperationsResponse;

export const zListProtectionPoliciesQuery = z
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
 * One bounded topology page
 */
export const zListProtectionPoliciesResponse2 = zListProtectionPoliciesResponse;

/**
 * Combined failure scenarios
 */
export const zCreateProtectionPolicyBody = zCreateProtectionPolicyRequest;

export const zCreateProtectionPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Survival policy committed
 */
export const zCreateProtectionPolicyResponse2 = zCreateProtectionPolicyResponse;

/**
 * Offline recovery save proof
 */
export const zConfirmRecoveryBundleSavedBody = zConfirmRecoveryBundleRequest;

/**
 * Recovery bundle verified and removed from online state
 */
export const zConfirmRecoveryBundleSavedResponse =
  zConfirmRecoveryBundleResponse;

/**
 * Audited SMB export withdrawal
 */
export const zWithdrawSmbExportBody = zWithdrawSmbExportRequest;

export const zWithdrawSmbExportHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zWithdrawSmbExportPath = z
  .object({
    export_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * SMB export durably withdrawn or exactly replayed
 */
export const zWithdrawSmbExportResponse2 = zWithdrawSmbExportResponse;

export const zListStorageDrainsQuery = z
  .object({
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9._~-]+$/)
      .optional(),
    limit: z.int().gte(1).lte(200).optional(),
  })
  .strict();

/**
 * One newest-first storage-drain page
 */
export const zListStorageDrainsResponse2 = zListStorageDrainsResponse;

/**
 * Exact storage scope and safe-removal policy
 */
export const zBeginStorageDrainBody = zBeginStorageDrainRequest;

export const zBeginStorageDrainHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Storage drain durably admitted
 */
export const zBeginStorageDrainResponse2 = zBeginStorageDrainResponse;

export const zGetStorageDrainPath = z
  .object({
    drain_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Current authoritative drain state
 */
export const zGetStorageDrainResponse = zStorageDrainSummary;

export const zListStorageFoldersQuery = z
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
 * One local storage-folder page
 */
export const zListStorageFoldersResponse2 = zListStorageFoldersResponse;

/**
 * Local storage-folder registration
 */
export const zRegisterStorageFolderBody = zRegisterStorageFolderRequest;

export const zRegisterStorageFolderHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Storage folder registered and open
 */
export const zRegisterStorageFolderResponse2 = zRegisterStorageFolderResponse;

export const zListAvailabilityCellsQuery = z
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
 * One bounded topology page
 */
export const zListAvailabilityCellsResponse2 = zListAvailabilityCellsResponse;

/**
 * Availability locality
 */
export const zCreateAvailabilityCellBody = zCreateAvailabilityCellRequest;

export const zCreateAvailabilityCellHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Availability cell committed
 */
export const zCreateAvailabilityCellResponse2 = zCreateAvailabilityCellResponse;

/**
 * Desired membership
 */
export const zSetAvailabilityCellHostMembershipBody =
  zSetFaultGroupMembershipRequest;

export const zSetAvailabilityCellHostMembershipHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zSetAvailabilityCellHostMembershipPath = z
  .object({
    cell_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    host_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Desired membership committed
 */
export const zSetAvailabilityCellHostMembershipResponse =
  zSetAvailabilityCellMembershipResponse;

/**
 * Desired membership
 */
export const zSetAvailabilityCellTargetMembershipBody =
  zSetFaultGroupMembershipRequest;

export const zSetAvailabilityCellTargetMembershipHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zSetAvailabilityCellTargetMembershipPath = z
  .object({
    cell_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    target_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Desired membership committed
 */
export const zSetAvailabilityCellTargetMembershipResponse =
  zSetAvailabilityCellMembershipResponse;

export const zListFaultGroupMembershipsQuery = z
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
 * One bounded topology page
 */
export const zListFaultGroupMembershipsResponse2 =
  zListFaultGroupMembershipsResponse;

export const zListFaultGroupsQuery = z
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
 * One bounded topology page
 */
export const zListFaultGroupsResponse2 = zListFaultGroupsResponse;

/**
 * Shared-failure group
 */
export const zCreateFaultGroupBody = zCreateFaultGroupRequest;

export const zCreateFaultGroupHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Shared-failure group committed
 */
export const zCreateFaultGroupResponse2 = zCreateFaultGroupResponse;

/**
 * Desired membership
 */
export const zSetFaultGroupMembershipBody = zSetFaultGroupMembershipRequest;

export const zSetFaultGroupMembershipHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zSetFaultGroupMembershipPath = z
  .object({
    group_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    host_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Desired membership committed
 */
export const zSetFaultGroupMembershipResponse2 =
  zSetFaultGroupMembershipResponse;

export const zListTopologyNodesQuery = z
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
 * One bounded topology page
 */
export const zListTopologyNodesResponse2 = zListTopologyNodesResponse;

export const zListTopologyTargetsQuery = z
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
 * One bounded topology page
 */
export const zListTopologyTargetsResponse2 = zListTopologyTargetsResponse;

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
 * Logical-volume creation
 */
export const zCreateVolumeBody = zCreateVolumeRequest;

export const zCreateVolumeHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

/**
 * Volume durably created or exactly replayed
 */
export const zCreateVolumeResponse2 = zCreateVolumeResponse;

/**
 * Exact-retry assignment
 */
export const zAssignVolumeAcknowledgementPolicyBody =
  zAssignVolumePlacementPolicyRequest;

export const zAssignVolumeAcknowledgementPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zAssignVolumeAcknowledgementPolicyPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Volume policy selection committed
 */
export const zAssignVolumeAcknowledgementPolicyResponse =
  zAssignVolumePlacementPolicyResponse;

/**
 * Exact-retry assignment
 */
export const zAssignVolumeLocalityPolicyBody =
  zAssignVolumePlacementPolicyRequest;

export const zAssignVolumeLocalityPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zAssignVolumeLocalityPolicyPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Volume policy selection committed
 */
export const zAssignVolumeLocalityPolicyResponse =
  zAssignVolumePlacementPolicyResponse;

export const zListVolumePermissionGrantsPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

export const zListVolumePermissionGrantsQuery = z
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
 * One current volume permission-grant page
 */
export const zListVolumePermissionGrantsResponse2 =
  zListVolumePermissionGrantsResponse;

/**
 * Volume permission grant
 */
export const zCreateVolumePermissionGrantBody =
  zCreateVolumePermissionGrantRequest;

export const zCreateVolumePermissionGrantHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zCreateVolumePermissionGrantPath = z
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
 * Grant durably created or exactly replayed
 */
export const zCreateVolumePermissionGrantResponse2 =
  zCreateVolumePermissionGrantResponse;

/**
 * Audited permission revocation
 */
export const zRevokePermissionGrantBody = zRevokePermissionGrantRequest;

export const zRevokePermissionGrantHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zRevokePermissionGrantPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    grant_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Grant durably revoked or exactly replayed
 */
export const zRevokePermissionGrantResponse2 = zRevokePermissionGrantResponse;

/**
 * Exact-retry assignment
 */
export const zAssignVolumeProtectionPolicyBody =
  zAssignVolumeProtectionPolicyRequest;

export const zAssignVolumeProtectionPolicyHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zAssignVolumeProtectionPolicyPath = z
  .object({
    volume_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    policy_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Volume policy selection committed
 */
export const zAssignVolumeProtectionPolicyResponse2 =
  zAssignVolumeProtectionPolicyResponse;

/**
 * SMB export publication
 */
export const zPublishSmbExportBody = zPublishSmbExportRequest;

export const zPublishSmbExportHeaders = z
  .object({
    "MeshSpan-CSRF-Token": z
      .string()
      .regex(/^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();

export const zPublishSmbExportPath = z
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
 * SMB export durably published or exactly replayed
 */
export const zPublishSmbExportResponse2 = zPublishSmbExportResponse;

/**
 * Process readiness
 */
export const zGetHealthResponse = zHealthResponse;

/**
 * This exact OpenAPI 3.1 document
 */
export const zGetOpenApiResponse = z.record(z.string(), z.unknown());

export const zGetOperationStatusPath = z
  .object({
    operation_id: z
      .string()
      .length(36)
      .regex(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
  })
  .strict();

/**
 * Current durable operation state
 */
export const zGetOperationStatusResponse = zOperationStatusResponse;

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
 * Node identity presentation
 */
export const zEnrolNodeBody = zEnrolNodeRequestWritable;

/**
 * Admitted node and bootstrap trust
 */
export const zEnrolNodeResponse2 = zEnrolNodeResponse;

/**
 * Existing-mesh setup
 */
export const zJoinMeshSetupBody = zJoinMeshSetupRequestWritable;

/**
 * Durable join intent accepted
 */
export const zJoinMeshSetupResponse2 = zJoinMeshSetupResponse;

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

export const zListCurrentUserAuthenticationMethodsQuery = z
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
 * One secret-free authentication-method page
 */
export const zListCurrentUserAuthenticationMethodsResponse =
  zListAuthenticationMethodsResponse;

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

export const zListVolumesQuery = z
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
 * One current-authority volume page
 */
export const zListVolumesResponse2 = zListVolumesResponse;

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
