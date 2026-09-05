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
 * AssignVolumePlacementPolicyRequest
 *
 * Exact-retry request selecting a policy for one volume.
 */
export type AssignVolumePlacementPolicyRequest = {
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * AssignVolumePlacementPolicyResponse
 *
 * Durable volume placement-policy selection result.
 */
export type AssignVolumePlacementPolicyResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Selected immutable policy.
   */
  policy_id: string;
  /**
   * Authoritative assignment revision.
   */
  revision: number;
  /**
   * Volume receiving the immutable policy.
   */
  volume_id: string;
};

/**
 * AssignVolumeProtectionPolicyRequest
 *
 * Exact-retry request selecting an immutable policy for one volume.
 */
export type AssignVolumeProtectionPolicyRequest = {
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * AssignVolumeProtectionPolicyResponse
 *
 * Durable volume survival-policy selection result.
 */
export type AssignVolumeProtectionPolicyResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Selected immutable policy.
   */
  policy_id: string;
  /**
   * Authoritative assignment revision.
   */
  revision: number;
  /**
   * Volume receiving the immutable policy.
   */
  volume_id: string;
};

/**
 * BackupExportHeaders
 *
 * Headers binding a streamed encrypted container to authoritative catalogue evidence.
 */
export type BackupExportHeaders = {
  /**
   * Exact encrypted-container length as a lossless decimal string.
   */
  "Content-Length": string;
  /**
   * SHA-256 of the complete encrypted container, verified during streaming.
   */
  "MeshSpan-Backup-Digest": string;
  /**
   * Exact generation; not a statement of current protection or restore readiness.
   */
  "MeshSpan-Backup-ID": string;
};

/**
 * BackupExportPath
 *
 * Exact native encrypted-export path. No provider path or private key is accepted.
 */
export type BackupExportPath = {
  /**
   * Backup generation selected from the administration history.
   */
  backup_id: string;
};

/**
 * BackupScheduleResponse
 *
 * Current backup schedule for the gateway's authoritative partition.
 */
export type BackupScheduleResponse = {
  /**
   * Exact partition whose policy is returned.
   */
  partition_id: string;
  /**
   * Explicitly null until the first policy is configured.
   */
  schedule: {
    /**
     * Next eligible attempt time; an unfinished run can delay it.
     */
    next_due_at_epoch_micros: number;
    /**
     * Complete desired policy.
     */
    policy: {
      /**
       * Whether automatic backup attempts are enabled.
       */
      enabled: boolean;
      /**
       * Delay between completed attempts, in seconds.
       */
      interval_seconds: number;
      /**
       * Required independent copies; cannot exceed the verified-copy threshold.
       */
      minimum_independent_copies: number;
      /**
       * Verified destination copies required before reporting protection.
       */
      minimum_verified_copies: number;
      /**
       * Number of newest usable generations to retain.
       */
      retained_generations: number;
    };
    /**
     * Immutable configuration sequence used for compare-and-swap updates.
     */
    sequence: number;
  } | null;
};

/**
 * BeginStorageDrainRequest
 *
 * Exact-retry request to start one safe storage drain.
 */
export type BeginStorageDrainRequest = {
  /**
   * Permit safe removal while desired redundancy is temporarily degraded.
   */
  allow_temporary_degraded: boolean;
  /**
   * Reclaim physical shard bytes after the safe-to-detach proof commits.
   */
  cleanup_requested: boolean;
  /**
   * Client-generated idempotency identity; also becomes the stable drain identity.
   */
  operation_id: string;
  /**
   * Exact target, node incarnation or fault group to remove.
   */
  scope:
    | {
        /**
         * Exact generation so path reuse cannot inherit a drain.
         */
        generation: string;
        kind: "target";
        /**
         * Stable target identity.
         */
        target_id: string;
      }
    | {
        /**
         * Exact restart incarnation.
         */
        incarnation: string;
        kind: "node";
        /**
         * Stable daemon identity.
         */
        node_id: string;
      }
    | {
        /**
         * Stable fault-group identity.
         */
        fault_group_id: string;
        kind: "fault_group";
      };
};

/**
 * BeginStorageDrainResponse
 *
 * Durable result returned after drain admission.
 */
export type BeginStorageDrainResponse = {
  /**
   * Current admitted drain.
   */
  drain: {
    /**
     * Whether temporary protection debt was accepted.
     */
    allow_temporary_degraded: boolean;
    /**
     * Whether post-proof physical cleanup was requested.
     */
    cleanup_requested: boolean;
    /**
     * Stable drain identity.
     */
    drain_id: string;
    /**
     * Authority-agreed admission instant.
     */
    requested_at_epoch_micros: number;
    /**
     * Latest authoritative revision.
     */
    revision: number;
    /**
     * Terminal safe instant, or null until detachment is proved safe.
     */
    safe_at_epoch_micros: number | null;
    /**
     * Exact fenced scope.
     */
    scope:
      | {
          /**
           * Exact generation so path reuse cannot inherit a drain.
           */
          generation: string;
          kind: "target";
          /**
           * Stable target identity.
           */
          target_id: string;
        }
      | {
          /**
           * Exact restart incarnation.
           */
          incarnation: string;
          kind: "node";
          /**
           * Stable daemon identity.
           */
          node_id: string;
        }
      | {
          /**
           * Stable fault-group identity.
           */
          fault_group_id: string;
          kind: "fault_group";
        };
    /**
     * Current authoritative lifecycle.
     */
    state: "evacuating" | "membership_fenced" | "safe_to_detach";
    /**
     * Ready-to-follow current-status URL.
     */
    status_url: string;
  };
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
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
 * CertificateStatusResponse
 *
 * Current certificate status; `certificate` is `null` before a source is configured.
 */
export type CertificateStatusResponse = {
  /**
   * Current secret-free certificate state, or `null` when HTTPS has no configured identity.
   */
  certificate: {
    /**
     * Current encrypted delivery generation represented exactly outside JavaScript numbers.
     */
    delivery_generation: string;
    /**
     * Gateways which acknowledged live selection of the current generation.
     */
    installed_gateway_count: number;
    /**
     * Exclusive certificate validity end as epoch microseconds.
     */
    not_after_epoch_micros: number;
    /**
     * Inclusive certificate validity start as epoch microseconds.
     */
    not_before_epoch_micros: number;
    /**
     * Gateways included in the current encrypted delivery generation.
     */
    required_gateway_count: number;
    /**
     * Certificate authority family.
     */
    source: "acme" | "external" | "mesh_local";
    /**
     * Stable source identity as canonical UUID text.
     */
    source_id: string;
    /**
     * Authoritative source revision represented exactly outside JavaScript numbers.
     */
    source_revision: string;
    /**
     * Derived state at the response's authority-agreed observation time.
     */
    state: "active" | "distributing" | "not_yet_valid" | "expired";
  } | null;
  /**
   * Authority-agreed time used for validity classification.
   */
  observed_at_epoch_micros: number;
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
   * Exact policy, receipt and outstanding-debt evidence for the success response.
   */
  acknowledgement: {
    /**
     * BLAKE3 digest binding the exact durable shard receipts.
     */
    achieved_protection_blake3: string;
    /**
     * Consistency class actually reached by this successful acknowledgement.
     */
    acknowledged_consistency: "eventual" | "strong";
    /**
     * Consistency class selected by the immutable policy snapshot.
     */
    configured_consistency: "eventual" | "strong";
    /**
     * Honest durability scope reached by this publication.
     */
    durability_scope: "node_local" | "cell_replicated" | "globally_converged";
    /**
     * Number of non-blocking shard placements already completed.
     */
    eventual_shard_receipts: number;
    /**
     * True only when an explicit strong-policy eventual fallback was applied.
     */
    fallback_applied: boolean;
    /**
     * BLAKE3 digest binding the exact non-blocking shard debt at acknowledgement.
     */
    pending_debt_blake3: string;
    /**
     * Number of non-blocking shard placements still owed by automatic reconciliation.
     */
    pending_eventual_shards: number;
    /**
     * True only after every predicate required by the selected policy has committed.
     */
    policy_committed: boolean;
    /**
     * BLAKE3 digest binding the fixed-revision acknowledgement predicates.
     */
    policy_evidence_blake3: string;
    /**
     * Number of required durable shard receipts included in the achieved evidence.
     */
    required_shard_receipts: number;
  };
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
 * ConfigureBackupDestinationRequest
 *
 * One registered target selected for encrypted recovery copies.
 */
export type ConfigureBackupDestinationRequest = {
  /**
   * Stable destination identity. A different provider requires a new identity.
   */
  destination_id: string;
  /**
   * Accept new backup copies when true; false pauses future copies, not deletion.
   */
  enabled: boolean;
  /**
   * Observed destination revision; zero creates a destination.
   */
  expected_revision: number;
  /**
   * Human-facing name, without control characters.
   */
  name: string;
  /**
   * Stable logical identity retained across retries.
   */
  operation_id: string;
  /**
   * Observed target generation. A returned or replaced target must match it.
   */
  target_generation: string;
  /**
   * Exact registered storage target, never a raw path.
   */
  target_id: string;
};

/**
 * ConfigureBackupDestinationResponse
 *
 * Original durable receipt; configuration does not imply completed backup protection.
 */
export type ConfigureBackupDestinationResponse = {
  /**
   * Destination revision created by this operation, even if later superseded.
   */
  committed_revision: number;
  /**
   * Exact destination configured.
   */
  destination_id: string;
  /**
   * Original operation identity.
   */
  operation_id: string;
};

/**
 * ConfigureBackupScheduleRequest
 *
 * Exact-retry replacement of the current partition backup policy.
 */
export type ConfigureBackupScheduleRequest = {
  /**
   * Observed policy sequence; zero creates the first policy.
   */
  expected_sequence: number;
  /**
   * Stable logical operation identity, retained across retries.
   */
  operation_id: string;
  /**
   * Complete desired policy; omission never silently resets a field.
   */
  policy: {
    /**
     * Whether automatic backup attempts are enabled.
     */
    enabled: boolean;
    /**
     * Delay between completed attempts, in seconds.
     */
    interval_seconds: number;
    /**
     * Required independent copies; cannot exceed the verified-copy threshold.
     */
    minimum_independent_copies: number;
    /**
     * Verified destination copies required before reporting protection.
     */
    minimum_verified_copies: number;
    /**
     * Number of newest usable generations to retain.
     */
    retained_generations: number;
  };
};

/**
 * ConfigureBackupScheduleResponse
 *
 * Original durable configuration receipt, including when a later policy supersedes it.
 */
export type ConfigureBackupScheduleResponse = {
  /**
   * Original committed metadata revision.
   */
  committed_revision: number;
  /**
   * Original logical operation identity.
   */
  operation_id: string;
  /**
   * Immutable policy sequence created by this operation.
   */
  sequence: number;
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
 * CreateAcknowledgementPolicyRequest
 *
 * Exact-retry request to create one immutable acknowledgement policy.
 */
export type CreateAcknowledgementPolicyRequest = {
  /**
   * Cell-specific acknowledgement and placement predicates.
   */
  cells: Array<{
    /**
     * Stable availability-cell identity.
     */
    cell_id: string;
    /**
     * Optional survival policy evaluated within this cell.
     */
    local_protection_policy_id?: string | null;
    /**
     * Optional minimum distinct machines within this cell.
     */
    minimum_distinct_nodes?: number | null;
    /**
     * Optional minimum durable targets within this cell.
     */
    minimum_durable_targets?: number | null;
    /**
     * Synchronous, eventual, or excluded participation.
     */
    mode: "required_before_commit" | "eventual" | "excluded";
  }>;
  /**
   * Availability-first or strong publication semantics.
   */
  consistency: "eventual" | "strong";
  /**
   * Explicit deadline result.
   */
  fallback: "remain_pending" | "fail_at_deadline" | "eventual";
  /**
   * Minimum distinct machine count represented by durable targets.
   */
  minimum_distinct_nodes: number;
  /**
   * Minimum durable target count required before acknowledgement.
   */
  minimum_durable_targets: number;
  /**
   * User-visible policy name.
   */
  name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Protection-scenario identities which must be proved before acknowledgement.
   */
  required_scenario_ids: Array<string>;
  /**
   * Optional deadline used only by strong policies.
   */
  strong_wait_micros?: number | null;
};

/**
 * CreateAcknowledgementPolicyResponse
 *
 * Durable acknowledgement-policy creation result.
 */
export type CreateAcknowledgementPolicyResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Current created immutable policy.
   */
  policy: {
    /**
     * Cell-specific acknowledgement and placement predicates.
     */
    cells: Array<{
      /**
       * Stable availability-cell identity.
       */
      cell_id: string;
      /**
       * Optional survival policy evaluated within this cell.
       */
      local_protection_policy_id: string | null;
      /**
       * Optional minimum distinct machines within this cell.
       */
      minimum_distinct_nodes: number | null;
      /**
       * Optional minimum durable targets within this cell.
       */
      minimum_durable_targets: number | null;
      /**
       * Synchronous, eventual, or excluded participation.
       */
      mode: "required_before_commit" | "eventual" | "excluded";
    }>;
    /**
     * Availability-first or strong publication semantics.
     */
    consistency: "eventual" | "strong";
    /**
     * Explicit deadline result.
     */
    fallback: "remain_pending" | "fail_at_deadline" | "eventual";
    /**
     * Minimum distinct machine count.
     */
    minimum_distinct_nodes: number;
    /**
     * Minimum durable target count.
     */
    minimum_durable_targets: number;
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Protection scenarios required before acknowledgement.
     */
    required_scenario_ids: Array<string>;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
    /**
     * Optional strong acknowledgement deadline.
     */
    strong_wait_micros: number | null;
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
 * CreateAvailabilityCellRequest
 *
 * Exact-retry request to create one availability locality.
 */
export type CreateAvailabilityCellRequest = {
  /**
   * Human-readable locality name.
   */
  name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Optional existing parent cell.
   */
  parent_cell_id?: string | null;
};

/**
 * CreateAvailabilityCellResponse
 *
 * Durable availability-cell creation result.
 */
export type CreateAvailabilityCellResponse = {
  /**
   * Current created cell.
   */
  cell: {
    /**
     * Stable cell identity.
     */
    cell_id: string;
    /**
     * User-visible cell name.
     */
    name: string;
    /**
     * Optional parent used for presentation and inherited target membership.
     */
    parent_cell_id: string | null;
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
 * CreateLocalityPolicyRequest
 *
 * Exact-retry request to create one immutable desired-locality policy.
 */
export type CreateLocalityPolicyRequest = {
  /**
   * Optional lag limit used to prioritise incomplete-locality repair.
   */
  maximum_lag_micros?: number | null;
  /**
   * User-visible policy name.
   */
  name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Cells which must each independently reconstruct the selected version.
   */
  requirements: Array<{
    /**
     * Stable availability-cell identity.
     */
    cell_id: string;
    /**
     * Optional data-survival policy evaluated only inside this cell.
     */
    local_protection_policy_id?: string | null;
  }>;
};

/**
 * CreateLocalityPolicyResponse
 *
 * Durable locality-policy creation result.
 */
export type CreateLocalityPolicyResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Current created immutable policy.
   */
  policy: {
    /**
     * Optional lag limit used to prioritise repair debt.
     */
    maximum_lag_micros: number | null;
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Ordered complete-local requirements.
     */
    requirements: Array<{
      /**
       * Stable availability-cell identity.
       */
      cell_id: string;
      /**
       * Optional survival policy evaluated within the cell.
       */
      local_protection_policy_id: string | null;
      /**
       * Stable requirement identity.
       */
      requirement_id: string;
    }>;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
  };
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
 * CreateProtectionPolicyRequest
 *
 * Exact-retry request to create one immutable survival policy.
 */
export type CreateProtectionPolicyRequest = {
  /**
   * User-visible policy name.
   */
  name: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
  /**
   * Alternative combined failure scenarios; every scenario must remain decodable.
   */
  scenarios: Array<{
    /**
     * User-visible scenario name.
     */
    name: string;
    /**
     * Failure terms which occur together, such as two machines and three devices.
     */
    terms: Array<{
      /**
       * Stable failure-class identity, including built-in machine and storage-device classes.
       */
      class_id: string;
      /**
       * Number of members of this failure class which may fail simultaneously.
       */
      failure_count: number;
    }>;
  }>;
};

/**
 * CreateProtectionPolicyResponse
 *
 * Durable survival-policy creation result.
 */
export type CreateProtectionPolicyResponse = {
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Current created immutable policy.
   */
  policy: {
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
    /**
     * Alternative failure scenarios; every scenario is independently promised.
     */
    scenarios: Array<{
      /**
       * User-visible scenario name.
       */
      name: string;
      /**
       * Stable scenario identity.
       */
      scenario_id: string;
      /**
       * Failure terms which happen together in this scenario.
       */
      terms: Array<{
        /**
         * Stable failure-class identity.
         */
        class_id: string;
        /**
         * User-visible failure-class name.
         */
        class_name: string;
        /**
         * Simultaneous failures promised by this term.
         */
        failure_count: number;
      }>;
    }>;
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
 * ListAcknowledgementPoliciesResponse
 *
 * One bounded page of write-acknowledgement policies.
 */
export type ListAcknowledgementPoliciesResponse = {
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable name-ordered policy summaries.
   */
  policies: Array<{
    /**
     * Cell-specific acknowledgement and placement predicates.
     */
    cells: Array<{
      /**
       * Stable availability-cell identity.
       */
      cell_id: string;
      /**
       * Optional survival policy evaluated within this cell.
       */
      local_protection_policy_id: string | null;
      /**
       * Optional minimum distinct machines within this cell.
       */
      minimum_distinct_nodes: number | null;
      /**
       * Optional minimum durable targets within this cell.
       */
      minimum_durable_targets: number | null;
      /**
       * Synchronous, eventual, or excluded participation.
       */
      mode: "required_before_commit" | "eventual" | "excluded";
    }>;
    /**
     * Availability-first or strong publication semantics.
     */
    consistency: "eventual" | "strong";
    /**
     * Explicit deadline result.
     */
    fallback: "remain_pending" | "fail_at_deadline" | "eventual";
    /**
     * Minimum distinct machine count.
     */
    minimum_distinct_nodes: number;
    /**
     * Minimum durable target count.
     */
    minimum_durable_targets: number;
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Protection scenarios required before acknowledgement.
     */
    required_scenario_ids: Array<string>;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
    /**
     * Optional strong acknowledgement deadline.
     */
    strong_wait_micros: number | null;
  }>;
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
 * ListAvailabilityCellsResponse
 *
 * One bounded page of availability localities.
 */
export type ListAvailabilityCellsResponse = {
  /**
   * Stable name-ordered cells.
   */
  cells: Array<{
    /**
     * Stable cell identity.
     */
    cell_id: string;
    /**
     * User-visible cell name.
     */
    name: string;
    /**
     * Optional parent used for presentation and inherited target membership.
     */
    parent_cell_id: string | null;
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
 * ListBackupDestinationsQuery
 *
 * Bounded live inventory of configured destinations, including paused entries.
 */
export type ListBackupDestinationsQuery = {
  /**
   * Opaque continuation returned by this inventory for this caller and partition.
   */
  cursor?: string;
  /**
   * Page size; defaults to 50.
   */
  limit?: number;
};

/**
 * ListBackupDestinationsResponse
 *
 * One current-authorisation inventory page, ordered by destination identity.
 */
export type ListBackupDestinationsResponse = {
  /**
   * At most the requested number of current destination records.
   */
  destinations: Array<{
    /**
     * Stable destination identity.
     */
    destination_id: string;
    /**
     * Honest failure relationship; registration alone cannot establish independence.
     */
    failure_relationship: "unknown" | "overlapping" | "independent";
    /**
     * Human-facing display name.
     */
    name: string;
    /**
     * Exact provider identity, without paths or credentials.
     */
    provider:
      | {
          kind: "registered_target";
          /**
           * Registered target identity.
           */
          target_id: string;
        }
      | {
          kind: "federated_mesh";
          /**
           * Remote swarm identity.
           */
          remote_mesh_id: string;
        }
      | {
          /**
           * Component instance identity.
           */
          instance_id: string;
          kind: "component_provider";
        };
    /**
     * Provider generation fenced into copy receipts.
     */
    provider_generation: string;
    /**
     * Destination-specific compare-and-swap revision.
     */
    revision: number;
    /**
     * Current desired eligibility.
     */
    state: "active" | "paused" | "retired";
  }>;
  /**
   * Relative continuation URL, or explicitly null at the end.
   */
  next_page_url: string | null;
};

/**
 * ListBackupRunsQuery
 *
 * Bounded newest-first history. Continuations preserve position, not stale authority.
 */
export type ListBackupRunsQuery = {
  /**
   * Opaque caller-bound continuation from the preceding page.
   */
  cursor?: string;
  /**
   * Maximum records; defaults to 25.
   */
  limit?: number;
};

/**
 * ListBackupRunsResponse
 *
 * One live, newest-first page. Refresh starts at the newest occurrence.
 */
export type ListBackupRunsResponse = {
  /**
   * Exact relative continuation, or null at the end.
   */
  next_page_url: string | null;
  /**
   * Bounded records, ordered by decreasing run sequence.
   */
  runs: Array<{
    /**
     * Exact immutable backup identity.
     */
    backup_id: string;
    /**
     * Null until terminal; never inferred from a worker lease or timeout.
     */
    completed_at_epoch_micros: number | null;
    /**
     * Independent-copy requirement at queue time.
     */
    minimum_independent_copies: number;
    /**
     * Verified-copy requirement at queue time.
     */
    minimum_verified_copies: number;
    /**
     * Lossless monotonic occurrence number, not wall-clock ordering.
     */
    run_sequence: string;
    /**
     * Exact policy revision used by this occurrence.
     */
    schedule_sequence: string;
    /**
     * Scheduled occurrence time in Unix microseconds.
     */
    scheduled_for_epoch_micros: number;
    /**
     * Historical execution outcome, not current safety.
     */
    state: "queued" | "claimed" | "recorded" | "protected" | "incomplete";
  }>;
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
 * ListLocalityPoliciesResponse
 *
 * One bounded page of desired-locality policies.
 */
export type ListLocalityPoliciesResponse = {
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable name-ordered policy summaries.
   */
  policies: Array<{
    /**
     * Optional lag limit used to prioritise repair debt.
     */
    maximum_lag_micros: number | null;
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Ordered complete-local requirements.
     */
    requirements: Array<{
      /**
       * Stable availability-cell identity.
       */
      cell_id: string;
      /**
       * Optional survival policy evaluated within the cell.
       */
      local_protection_policy_id: string | null;
      /**
       * Stable requirement identity.
       */
      requirement_id: string;
    }>;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
  }>;
};

/**
 * ListManualDnsTasksResponse
 *
 * One bounded deadline-ordered page of current manual DNS work.
 */
export type ListManualDnsTasksResponse = {
  /**
   * Ready-to-follow same-origin URL, or null when the page is terminal.
   */
  next_page_url: string | null;
  /**
   * Tasks ordered by deadline, creation time and digest.
   */
  tasks: Array<{
    /**
     * Required operator action.
     */
    action: "publish" | "remove";
    /**
     * Original authoritative task creation instant.
     */
    created_at_epoch_micros: number;
    /**
     * Exclusive challenge deadline as epoch microseconds.
     */
    expires_at_epoch_micros: number;
    /**
     * Exact positive order fence represented without JavaScript precision loss.
     */
    order_fence: string;
    /**
     * Certificate order owning the task.
     */
    order_id: string;
    /**
     * Canonical TXT owner name without a trailing dot.
     */
    record_name: string;
    /**
     * Exact unquoted ACME TXT value.
     */
    record_value: string;
    /**
     * Current authoritative revision.
     */
    revision: number;
    /**
     * Lower-case SHA-256 identity of this exact fenced task.
     */
    task_digest: string;
    /**
     * Most recent authoritative task transition.
     */
    transitioned_at_epoch_micros: number;
  }>;
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
 * ListProtectionPoliciesResponse
 *
 * One bounded page of immutable survival policies.
 */
export type ListProtectionPoliciesResponse = {
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
  /**
   * Stable name-ordered policy summaries.
   */
  policies: Array<{
    /**
     * User-visible policy name.
     */
    name: string;
    /**
     * Stable policy identity.
     */
    policy_id: string;
    /**
     * Immutable authoritative policy revision.
     */
    revision: number;
    /**
     * Alternative failure scenarios; every scenario is independently promised.
     */
    scenarios: Array<{
      /**
       * User-visible scenario name.
       */
      name: string;
      /**
       * Stable scenario identity.
       */
      scenario_id: string;
      /**
       * Failure terms which happen together in this scenario.
       */
      terms: Array<{
        /**
         * Stable failure-class identity.
         */
        class_id: string;
        /**
         * User-visible failure-class name.
         */
        class_name: string;
        /**
         * Simultaneous failures promised by this term.
         */
        failure_count: number;
      }>;
    }>;
  }>;
};

/**
 * ListStorageDrainsResponse
 *
 * One current manager-only storage-drain page.
 */
export type ListStorageDrainsResponse = {
  /**
   * Newest-first authoritative drain summaries.
   */
  drains: Array<{
    /**
     * Whether temporary protection debt was accepted.
     */
    allow_temporary_degraded: boolean;
    /**
     * Whether post-proof physical cleanup was requested.
     */
    cleanup_requested: boolean;
    /**
     * Stable drain identity.
     */
    drain_id: string;
    /**
     * Authority-agreed admission instant.
     */
    requested_at_epoch_micros: number;
    /**
     * Latest authoritative revision.
     */
    revision: number;
    /**
     * Terminal safe instant, or null until detachment is proved safe.
     */
    safe_at_epoch_micros: number | null;
    /**
     * Exact fenced scope.
     */
    scope:
      | {
          /**
           * Exact generation so path reuse cannot inherit a drain.
           */
          generation: string;
          kind: "target";
          /**
           * Stable target identity.
           */
          target_id: string;
        }
      | {
          /**
           * Exact restart incarnation.
           */
          incarnation: string;
          kind: "node";
          /**
           * Stable daemon identity.
           */
          node_id: string;
        }
      | {
          /**
           * Stable fault-group identity.
           */
          fault_group_id: string;
          kind: "fault_group";
        };
    /**
     * Current authoritative lifecycle.
     */
    state: "evacuating" | "membership_fenced" | "safe_to_detach";
    /**
     * Ready-to-follow current-status URL.
     */
    status_url: string;
  }>;
  /**
   * Ready-to-follow same-origin URL, or null at the terminal page.
   */
  next_page_url: string | null;
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
     * Stable root-directory identity used by connectors and administration.
     */
    root_object_id: string;
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
 * ProvisionCertificateRequest
 *
 * Idempotent request to provision automatic public certificates.
 */
export type ProvisionCertificateRequest = {
  /**
   * Sorted, unique lower-case DNS names requested on the certificate.
   */
  certificate_names: Array<string>;
  /**
   * HTTP-01 or one DNS-01 publication method.
   */
  challenge:
    | {
        kind: "http01";
      }
    | {
        kind: "dns01_manual";
      }
    | {
        /**
         * TSIG HMAC family.
         */
        algorithm: "hmac_sha256" | "hmac_sha512";
        /**
         * Canonical lower-case TSIG key name.
         */
        key_name: string;
        kind: "dns01_rfc2136";
        /**
         * Raw printable TSIG secret supplied by the administrator.
         */
        secret: string;
        /**
         * Literal DNS server socket address, including port.
         */
        server: string;
        /**
         * Canonical lower-case zone apex.
         */
        zone: string;
      }
    | {
        /**
         * Scoped Cloudflare API token.
         */
        api_token: string;
        kind: "dns01_cloudflare";
        /**
         * Exact 32-character lower-case hexadecimal Cloudflare zone identity.
         */
        zone_id: string;
      }
    | {
        /**
         * Bearer token sent only to the configured endpoint.
         */
        bearer_token: string;
        /**
         * HTTPS webhook endpoint.
         */
        endpoint: string;
        kind: "dns01_webhook";
      };
  /**
   * HTTPS ACME directory endpoint.
   */
  directory_url: string;
  /**
   * Client-generated exact-retry identity.
   */
  operation_id: string;
};

/**
 * ProvisionCertificateResponse
 *
 * Durable result of one public-certificate provisioning operation.
 */
export type ProvisionCertificateResponse = {
  /**
   * Canonical certificate names retained by the authority.
   */
  certificate_names: Array<string>;
  /**
   * Immutable configuration created by the operation.
   */
  configuration_id: string;
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * Initial durable order created by the operation.
   */
  order_id: string;
  /**
   * Authoritative revision created by the operation.
   */
  revision: number;
};

/**
 * ProvisionMeshLocalCertificateRequest
 *
 * Exact-retry request for an automatically trusted mesh-local HTTPS identity.
 */
export type ProvisionMeshLocalCertificateRequest = {
  /**
   * Sorted, unique lower-case DNS names requested on the endpoint certificate.
   */
  certificate_names: Array<string>;
  /**
   * Client-generated identity binding exact retries.
   */
  operation_id: string;
};

/**
 * ProvisionMeshLocalCertificateResponse
 *
 * Secret-free result of one mesh-local HTTPS certificate issuance.
 */
export type ProvisionMeshLocalCertificateResponse = {
  /**
   * Immutable mesh-local trust-authority identity.
   */
  authority_id: string;
  /**
   * Immutable public-certificate identity.
   */
  certificate_id: string;
  /**
   * Canonical DNS names bound to the leaf certificate.
   */
  certificate_names: Array<string>;
  /**
   * Monotonic mesh-local endpoint generation.
   */
  generation: string;
  /**
   * Immutable issuance identity.
   */
  issuance_id: string;
  /**
   * Exclusive leaf validity end as epoch microseconds.
   */
  not_after_epoch_micros: number;
  /**
   * Inclusive leaf validity start as epoch microseconds.
   */
  not_before_epoch_micros: number;
  /**
   * Exact idempotency identity whose result was committed or resolved.
   */
  operation_id: string;
  /**
   * Lower-case SHA-256 fingerprint of the leaf subject public key.
   */
  public_key_fingerprint: string;
  /**
   * Authoritative revision containing the encrypted endpoint generation.
   */
  revision: number;
  /**
   * Public trust anchor in PEM form; no private material is returned.
   */
  trust_anchor_pem: string;
};

/**
 * PublishExternalCertificateRequest
 *
 * Exact-retry automated publication of a certificate issued outside `MeshSpan`.
 */
export type PublishExternalCertificateRequest = {
  /**
   * Complete leaf-first certificate chain in PEM form.
   */
  certificate_chain_pem: string;
  /**
   * Sorted, unique lower-case DNS names expected in the leaf certificate.
   */
  certificate_names: Array<string>;
  /**
   * Monotonic generation chosen by the external issuer integration.
   */
  generation: string;
  /**
   * Client-generated identity binding exact retries.
   */
  operation_id: string;
  /**
   * Matching unencrypted PKCS#8 PEM private key, accepted only on this protected request.
   */
  private_key_pkcs8_pem: string;
};

/**
 * PublishExternalCertificateResponse
 *
 * Secret-free durable result of one automated external-certificate publication.
 */
export type PublishExternalCertificateResponse = {
  /**
   * Immutable public-certificate identity.
   */
  certificate_id: string;
  /**
   * Canonical DNS names bound to the leaf certificate.
   */
  certificate_names: Array<string>;
  /**
   * Accepted external generation.
   */
  generation: string;
  /**
   * Exclusive leaf validity end as epoch microseconds.
   */
  not_after_epoch_micros: number;
  /**
   * Inclusive leaf validity start as epoch microseconds.
   */
  not_before_epoch_micros: number;
  /**
   * Exact idempotency identity whose result was committed or resolved.
   */
  operation_id: string;
  /**
   * Lower-case SHA-256 fingerprint of the leaf subject public key.
   */
  public_key_fingerprint: string;
  /**
   * Stable publication identity.
   */
  publication_id: string;
  /**
   * Authoritative revision containing the encrypted generation.
   */
  revision: number;
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
 * SetAvailabilityCellMembershipResponse
 *
 * Durable desired membership of a machine or target in one availability cell.
 */
export type SetAvailabilityCellMembershipResponse = {
  /**
   * Availability-cell identity from the route.
   */
  cell_id: string;
  /**
   * Machine or target identity from the route.
   */
  member_id: string;
  /**
   * Exact idempotency identity whose result was resolved.
   */
  operation_id: string;
  /**
   * `true` when the member is present after this operation.
   */
  present: boolean;
  /**
   * Authoritative mutation revision.
   */
  revision: number;
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
 * StorageDrainSummary
 *
 * One current manager-visible storage drain.
 */
export type StorageDrainSummary = {
  /**
   * Whether temporary protection debt was accepted.
   */
  allow_temporary_degraded: boolean;
  /**
   * Whether post-proof physical cleanup was requested.
   */
  cleanup_requested: boolean;
  /**
   * Stable drain identity.
   */
  drain_id: string;
  /**
   * Authority-agreed admission instant.
   */
  requested_at_epoch_micros: number;
  /**
   * Latest authoritative revision.
   */
  revision: number;
  /**
   * Terminal safe instant, or null until detachment is proved safe.
   */
  safe_at_epoch_micros: number | null;
  /**
   * Exact fenced scope.
   */
  scope:
    | {
        /**
         * Exact generation so path reuse cannot inherit a drain.
         */
        generation: string;
        kind: "target";
        /**
         * Stable target identity.
         */
        target_id: string;
      }
    | {
        /**
         * Exact restart incarnation.
         */
        incarnation: string;
        kind: "node";
        /**
         * Stable daemon identity.
         */
        node_id: string;
      }
    | {
        /**
         * Stable fault-group identity.
         */
        fault_group_id: string;
        kind: "fault_group";
      };
  /**
   * Current authoritative lifecycle.
   */
  state: "evacuating" | "membership_fenced" | "safe_to_detach";
  /**
   * Ready-to-follow current-status URL.
   */
  status_url: string;
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

export type ListAcknowledgementPoliciesData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/acknowledgement-policies";
};

export type ListAcknowledgementPoliciesErrors = {
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

export type ListAcknowledgementPoliciesError =
  ListAcknowledgementPoliciesErrors[keyof ListAcknowledgementPoliciesErrors];

export type ListAcknowledgementPoliciesResponses = {
  /**
   * One bounded topology page
   */
  200: ListAcknowledgementPoliciesResponse;
};

export type ListAcknowledgementPoliciesResponse2 =
  ListAcknowledgementPoliciesResponses[keyof ListAcknowledgementPoliciesResponses];

export type CreateAcknowledgementPolicyData = {
  /**
   * Immutable placement policy
   */
  body: CreateAcknowledgementPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/acknowledgement-policies";
};

export type CreateAcknowledgementPolicyErrors = {
  /**
   * Invalid policy request
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
   * Referenced policy or cell not found
   */
  404: ApiError;
  /**
   * Name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateAcknowledgementPolicyError =
  CreateAcknowledgementPolicyErrors[keyof CreateAcknowledgementPolicyErrors];

export type CreateAcknowledgementPolicyResponses = {
  /**
   * Placement policy committed
   */
  201: CreateAcknowledgementPolicyResponse;
};

export type CreateAcknowledgementPolicyResponse2 =
  CreateAcknowledgementPolicyResponses[keyof CreateAcknowledgementPolicyResponses];

export type ListBackupDestinationsData = {
  body?: never;
  path?: never;
  query?: {
    /**
     * Page size; defaults to 50.
     */
    limit?: number;
    /**
     * Opaque continuation returned by this inventory for this caller and partition.
     */
    cursor?: string;
  };
  url: "/admin/backups/destinations";
};

export type ListBackupDestinationsErrors = {
  /**
   * Invalid query or substituted continuation
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
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type ListBackupDestinationsError =
  ListBackupDestinationsErrors[keyof ListBackupDestinationsErrors];

export type ListBackupDestinationsResponses = {
  /**
   * Current destination page with a relative next-page URL
   */
  200: ListBackupDestinationsResponse;
};

export type ListBackupDestinationsResponse2 =
  ListBackupDestinationsResponses[keyof ListBackupDestinationsResponses];

export type ConfigureBackupDestinationData = {
  /**
   * Complete destination and exact-retry identity
   */
  body: ConfigureBackupDestinationRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/backups/destinations";
};

export type ConfigureBackupDestinationErrors = {
  /**
   * Invalid destination
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
   * Changed retry or stale destination revision
   */
  409: ApiError;
  /**
   * Request body exceeds its bound
   */
  413: ApiError;
  /**
   * JSON content type required
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type ConfigureBackupDestinationError =
  ConfigureBackupDestinationErrors[keyof ConfigureBackupDestinationErrors];

export type ConfigureBackupDestinationResponses = {
  /**
   * Original committed configuration receipt
   */
  200: ConfigureBackupDestinationResponse;
};

export type ConfigureBackupDestinationResponse2 =
  ConfigureBackupDestinationResponses[keyof ConfigureBackupDestinationResponses];

export type ListBackupRunsData = {
  body?: never;
  path?: never;
  query?: {
    /**
     * Maximum records; defaults to 25.
     */
    limit?: number;
    /**
     * Opaque caller-bound continuation from the preceding page.
     */
    cursor?: string;
  };
  url: "/admin/backups/runs";
};

export type ListBackupRunsErrors = {
  /**
   * Invalid query or continuation
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
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type ListBackupRunsError =
  ListBackupRunsErrors[keyof ListBackupRunsErrors];

export type ListBackupRunsResponses = {
  /**
   * Bounded historical run outcomes and relative continuation
   */
  200: ListBackupRunsResponse;
};

export type ListBackupRunsResponse2 =
  ListBackupRunsResponses[keyof ListBackupRunsResponses];

export type GetBackupScheduleData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/admin/backups/schedule";
};

export type GetBackupScheduleErrors = {
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
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type GetBackupScheduleError =
  GetBackupScheduleErrors[keyof GetBackupScheduleErrors];

export type GetBackupScheduleResponses = {
  /**
   * Current policy, or null before configuration
   */
  200: BackupScheduleResponse;
};

export type GetBackupScheduleResponse =
  GetBackupScheduleResponses[keyof GetBackupScheduleResponses];

export type ConfigureBackupScheduleData = {
  /**
   * Complete policy and exact-retry identity
   */
  body: ConfigureBackupScheduleRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/backups/schedule";
};

export type ConfigureBackupScheduleErrors = {
  /**
   * Invalid policy
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
   * Changed retry or stale policy sequence
   */
  409: ApiError;
  /**
   * Request body exceeds its bound
   */
  413: ApiError;
  /**
   * JSON content type required
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Authority temporarily unavailable
   */
  503: ApiError;
};

export type ConfigureBackupScheduleError =
  ConfigureBackupScheduleErrors[keyof ConfigureBackupScheduleErrors];

export type ConfigureBackupScheduleResponses = {
  /**
   * Original committed configuration receipt
   */
  200: ConfigureBackupScheduleResponse;
};

export type ConfigureBackupScheduleResponse2 =
  ConfigureBackupScheduleResponses[keyof ConfigureBackupScheduleResponses];

export type ExportMetadataBackupData = {
  body?: never;
  path: {
    /**
     * Backup generation selected from the administration history.
     */
    backup_id: string;
  };
  query?: never;
  url: "/admin/backups/{backup_id}/export";
};

export type ExportMetadataBackupErrors = {
  /**
   * Invalid identifier or unsupported query
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
   * Selected generation is not exportable
   */
  409: ApiError;
  /**
   * Outgoing evidence failed validation
   */
  500: ApiError;
  /**
   * Export capacity or authority unavailable
   */
  503: ApiError;
};

export type ExportMetadataBackupError =
  ExportMetadataBackupErrors[keyof ExportMetadataBackupErrors];

export type ExportMetadataBackupResponses = {
  /**
   * Exact encrypted container; completion requires verified bytes
   */
  200: Blob | File;
};

export type ExportMetadataBackupResponse =
  ExportMetadataBackupResponses[keyof ExportMetadataBackupResponses];

export type ListManualDnsTasksData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/certificate-tasks/manual-dns";
};

export type ListManualDnsTasksErrors = {
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
   * Certificate authority temporarily unavailable
   */
  503: ApiError;
};

export type ListManualDnsTasksError =
  ListManualDnsTasksErrors[keyof ListManualDnsTasksErrors];

export type ListManualDnsTasksResponses = {
  /**
   * One deadline-ordered manual DNS task page
   */
  200: ListManualDnsTasksResponse;
};

export type ListManualDnsTasksResponse2 =
  ListManualDnsTasksResponses[keyof ListManualDnsTasksResponses];

export type ProvisionCertificateData = {
  /**
   * Public-certificate provisioning
   */
  body: ProvisionCertificateRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/certificates/acme";
};

export type ProvisionCertificateErrors = {
  /**
   * Invalid certificate request
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
   * Operation conflicts with committed state
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
   * Certificate authority temporarily unavailable
   */
  503: ApiError;
};

export type ProvisionCertificateError =
  ProvisionCertificateErrors[keyof ProvisionCertificateErrors];

export type ProvisionCertificateResponses = {
  /**
   * Configuration and initial order durably committed or exactly replayed
   */
  201: ProvisionCertificateResponse;
};

export type ProvisionCertificateResponse2 =
  ProvisionCertificateResponses[keyof ProvisionCertificateResponses];

export type PublishExternalCertificateData = {
  /**
   * External certificate publication
   */
  body: PublishExternalCertificateRequest;
  path?: never;
  query?: never;
  url: "/admin/certificates/external";
};

export type PublishExternalCertificateErrors = {
  /**
   * Invalid certificate publication
   */
  400: ApiError;
  /**
   * API-key authentication rejected
   */
  401: ApiError;
  /**
   * System-manager authority required
   */
  403: ApiError;
  /**
   * Operation or generation conflicts with committed state
   */
  409: ApiError;
  /**
   * Publication body exceeds its bound
   */
  413: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Certificate authority temporarily unavailable
   */
  503: ApiError;
};

export type PublishExternalCertificateError =
  PublishExternalCertificateErrors[keyof PublishExternalCertificateErrors];

export type PublishExternalCertificateResponses = {
  /**
   * Encrypted certificate generation durably published or exactly replayed
   */
  201: PublishExternalCertificateResponse;
};

export type PublishExternalCertificateResponse2 =
  PublishExternalCertificateResponses[keyof PublishExternalCertificateResponses];

export type ProvisionMeshLocalCertificateData = {
  /**
   * Mesh-local certificate provisioning
   */
  body: ProvisionMeshLocalCertificateRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/certificates/local";
};

export type ProvisionMeshLocalCertificateErrors = {
  /**
   * Invalid certificate request
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
   * Operation conflicts with committed state
   */
  409: ApiError;
  /**
   * Request body exceeds its bound
   */
  413: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Certificate authority temporarily unavailable
   */
  503: ApiError;
};

export type ProvisionMeshLocalCertificateError =
  ProvisionMeshLocalCertificateErrors[keyof ProvisionMeshLocalCertificateErrors];

export type ProvisionMeshLocalCertificateResponses = {
  /**
   * Encrypted certificate generation durably issued or exactly replayed
   */
  201: ProvisionMeshLocalCertificateResponse;
};

export type ProvisionMeshLocalCertificateResponse2 =
  ProvisionMeshLocalCertificateResponses[keyof ProvisionMeshLocalCertificateResponses];

export type GetCertificateStatusData = {
  body?: never;
  path?: never;
  query?: never;
  url: "/admin/certificates/status";
};

export type GetCertificateStatusErrors = {
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
   * Certificate authority temporarily unavailable
   */
  503: ApiError;
};

export type GetCertificateStatusError =
  GetCertificateStatusErrors[keyof GetCertificateStatusErrors];

export type GetCertificateStatusResponses = {
  /**
   * Current secret-free certificate status
   */
  200: CertificateStatusResponse;
};

export type GetCertificateStatusResponse =
  GetCertificateStatusResponses[keyof GetCertificateStatusResponses];

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

export type ListLocalityPoliciesData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/locality-policies";
};

export type ListLocalityPoliciesErrors = {
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

export type ListLocalityPoliciesError =
  ListLocalityPoliciesErrors[keyof ListLocalityPoliciesErrors];

export type ListLocalityPoliciesResponses = {
  /**
   * One bounded topology page
   */
  200: ListLocalityPoliciesResponse;
};

export type ListLocalityPoliciesResponse2 =
  ListLocalityPoliciesResponses[keyof ListLocalityPoliciesResponses];

export type CreateLocalityPolicyData = {
  /**
   * Immutable placement policy
   */
  body: CreateLocalityPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/locality-policies";
};

export type CreateLocalityPolicyErrors = {
  /**
   * Invalid policy request
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
   * Referenced policy or cell not found
   */
  404: ApiError;
  /**
   * Name or operation conflict
   */
  409: ApiError;
  /**
   * Unsupported request media type
   */
  415: ApiError;
  /**
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateLocalityPolicyError =
  CreateLocalityPolicyErrors[keyof CreateLocalityPolicyErrors];

export type CreateLocalityPolicyResponses = {
  /**
   * Placement policy committed
   */
  201: CreateLocalityPolicyResponse;
};

export type CreateLocalityPolicyResponse2 =
  CreateLocalityPolicyResponses[keyof CreateLocalityPolicyResponses];

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

export type ListProtectionPoliciesData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/protection-policies";
};

export type ListProtectionPoliciesErrors = {
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

export type ListProtectionPoliciesError =
  ListProtectionPoliciesErrors[keyof ListProtectionPoliciesErrors];

export type ListProtectionPoliciesResponses = {
  /**
   * One bounded topology page
   */
  200: ListProtectionPoliciesResponse;
};

export type ListProtectionPoliciesResponse2 =
  ListProtectionPoliciesResponses[keyof ListProtectionPoliciesResponses];

export type CreateProtectionPolicyData = {
  /**
   * Combined failure scenarios
   */
  body: CreateProtectionPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/protection-policies";
};

export type CreateProtectionPolicyErrors = {
  /**
   * Invalid policy request
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
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type CreateProtectionPolicyError =
  CreateProtectionPolicyErrors[keyof CreateProtectionPolicyErrors];

export type CreateProtectionPolicyResponses = {
  /**
   * Survival policy committed
   */
  201: CreateProtectionPolicyResponse;
};

export type CreateProtectionPolicyResponse2 =
  CreateProtectionPolicyResponses[keyof CreateProtectionPolicyResponses];

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

export type ListStorageDrainsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/storage-drains";
};

export type ListStorageDrainsErrors = {
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
   * Storage-drain authority temporarily unavailable
   */
  503: ApiError;
};

export type ListStorageDrainsError =
  ListStorageDrainsErrors[keyof ListStorageDrainsErrors];

export type ListStorageDrainsResponses = {
  /**
   * One newest-first storage-drain page
   */
  200: ListStorageDrainsResponse;
};

export type ListStorageDrainsResponse2 =
  ListStorageDrainsResponses[keyof ListStorageDrainsResponses];

export type BeginStorageDrainData = {
  /**
   * Exact storage scope and safe-removal policy
   */
  body: BeginStorageDrainRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/storage-drains";
};

export type BeginStorageDrainErrors = {
  /**
   * Invalid drain request
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
   * Scope, lifecycle or operation conflict
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
   * Storage-drain authority temporarily unavailable
   */
  503: ApiError;
};

export type BeginStorageDrainError =
  BeginStorageDrainErrors[keyof BeginStorageDrainErrors];

export type BeginStorageDrainResponses = {
  /**
   * Storage drain durably admitted
   */
  202: BeginStorageDrainResponse;
};

export type BeginStorageDrainResponse2 =
  BeginStorageDrainResponses[keyof BeginStorageDrainResponses];

export type GetStorageDrainData = {
  body?: never;
  path: {
    /**
     * Storage-drain identity
     */
    drain_id: string;
  };
  query?: never;
  url: "/admin/storage-drains/{drain_id}";
};

export type GetStorageDrainErrors = {
  /**
   * Invalid drain identity
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
   * Storage drain not found
   */
  404: ApiError;
  /**
   * Outgoing contract or integrity failure
   */
  500: ApiError;
  /**
   * Storage-drain authority temporarily unavailable
   */
  503: ApiError;
};

export type GetStorageDrainError =
  GetStorageDrainErrors[keyof GetStorageDrainErrors];

export type GetStorageDrainResponses = {
  /**
   * Current authoritative drain state
   */
  200: StorageDrainSummary;
};

export type GetStorageDrainResponse =
  GetStorageDrainResponses[keyof GetStorageDrainResponses];

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

export type ListAvailabilityCellsData = {
  body?: never;
  path?: never;
  query?: {
    cursor?: string;
    limit?: number;
  };
  url: "/admin/topology/availability-cells";
};

export type ListAvailabilityCellsErrors = {
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

export type ListAvailabilityCellsError =
  ListAvailabilityCellsErrors[keyof ListAvailabilityCellsErrors];

export type ListAvailabilityCellsResponses = {
  /**
   * One bounded topology page
   */
  200: ListAvailabilityCellsResponse;
};

export type ListAvailabilityCellsResponse2 =
  ListAvailabilityCellsResponses[keyof ListAvailabilityCellsResponses];

export type CreateAvailabilityCellData = {
  /**
   * Availability locality
   */
  body: CreateAvailabilityCellRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path?: never;
  query?: never;
  url: "/admin/topology/availability-cells";
};

export type CreateAvailabilityCellErrors = {
  /**
   * Invalid cell request
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
   * Parent cell not found
   */
  404: ApiError;
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

export type CreateAvailabilityCellError =
  CreateAvailabilityCellErrors[keyof CreateAvailabilityCellErrors];

export type CreateAvailabilityCellResponses = {
  /**
   * Availability cell committed
   */
  201: CreateAvailabilityCellResponse;
};

export type CreateAvailabilityCellResponse2 =
  CreateAvailabilityCellResponses[keyof CreateAvailabilityCellResponses];

export type SetAvailabilityCellHostMembershipData = {
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
     * Availability-cell identity
     */
    cell_id: string;
    /**
     * Machine identity
     */
    host_id: string;
  };
  query?: never;
  url: "/admin/topology/availability-cells/{cell_id}/hosts/{host_id}";
};

export type SetAvailabilityCellHostMembershipErrors = {
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
   * Cell or member not found
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

export type SetAvailabilityCellHostMembershipError =
  SetAvailabilityCellHostMembershipErrors[keyof SetAvailabilityCellHostMembershipErrors];

export type SetAvailabilityCellHostMembershipResponses = {
  /**
   * Desired membership committed
   */
  200: SetAvailabilityCellMembershipResponse;
};

export type SetAvailabilityCellHostMembershipResponse =
  SetAvailabilityCellHostMembershipResponses[keyof SetAvailabilityCellHostMembershipResponses];

export type SetAvailabilityCellTargetMembershipData = {
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
     * Availability-cell identity
     */
    cell_id: string;
    /**
     * Storage-target identity
     */
    target_id: string;
  };
  query?: never;
  url: "/admin/topology/availability-cells/{cell_id}/targets/{target_id}";
};

export type SetAvailabilityCellTargetMembershipErrors = {
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
   * Cell or member not found
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

export type SetAvailabilityCellTargetMembershipError =
  SetAvailabilityCellTargetMembershipErrors[keyof SetAvailabilityCellTargetMembershipErrors];

export type SetAvailabilityCellTargetMembershipResponses = {
  /**
   * Desired membership committed
   */
  200: SetAvailabilityCellMembershipResponse;
};

export type SetAvailabilityCellTargetMembershipResponse =
  SetAvailabilityCellTargetMembershipResponses[keyof SetAvailabilityCellTargetMembershipResponses];

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

export type AssignVolumeAcknowledgementPolicyData = {
  /**
   * Exact-retry assignment
   */
  body: AssignVolumePlacementPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
    /**
     * Immutable policy identity
     */
    policy_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/acknowledgement-policies/{policy_id}";
};

export type AssignVolumeAcknowledgementPolicyErrors = {
  /**
   * Invalid assignment request
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
   * Volume or policy not found
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
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type AssignVolumeAcknowledgementPolicyError =
  AssignVolumeAcknowledgementPolicyErrors[keyof AssignVolumeAcknowledgementPolicyErrors];

export type AssignVolumeAcknowledgementPolicyResponses = {
  /**
   * Volume policy selection committed
   */
  200: AssignVolumePlacementPolicyResponse;
};

export type AssignVolumeAcknowledgementPolicyResponse =
  AssignVolumeAcknowledgementPolicyResponses[keyof AssignVolumeAcknowledgementPolicyResponses];

export type AssignVolumeLocalityPolicyData = {
  /**
   * Exact-retry assignment
   */
  body: AssignVolumePlacementPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
    /**
     * Immutable policy identity
     */
    policy_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/locality-policies/{policy_id}";
};

export type AssignVolumeLocalityPolicyErrors = {
  /**
   * Invalid assignment request
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
   * Volume or policy not found
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
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type AssignVolumeLocalityPolicyError =
  AssignVolumeLocalityPolicyErrors[keyof AssignVolumeLocalityPolicyErrors];

export type AssignVolumeLocalityPolicyResponses = {
  /**
   * Volume policy selection committed
   */
  200: AssignVolumePlacementPolicyResponse;
};

export type AssignVolumeLocalityPolicyResponse =
  AssignVolumeLocalityPolicyResponses[keyof AssignVolumeLocalityPolicyResponses];

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

export type AssignVolumeProtectionPolicyData = {
  /**
   * Exact-retry assignment
   */
  body: AssignVolumeProtectionPolicyRequest;
  headers?: {
    /**
     * Required for browser-cookie authentication and omitted for API-key authentication.
     */
    "MeshSpan-CSRF-Token"?: string;
  };
  path: {
    volume_id: string;
    /**
     * Immutable survival-policy identity
     */
    policy_id: string;
  };
  query?: never;
  url: "/admin/volumes/{volume_id}/protection-policies/{policy_id}";
};

export type AssignVolumeProtectionPolicyErrors = {
  /**
   * Invalid assignment request
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
   * Volume or policy not found
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
   * Outgoing contract or policy integrity failure
   */
  500: ApiError;
  /**
   * Metadata authority temporarily unavailable
   */
  503: ApiError;
};

export type AssignVolumeProtectionPolicyError =
  AssignVolumeProtectionPolicyErrors[keyof AssignVolumeProtectionPolicyErrors];

export type AssignVolumeProtectionPolicyResponses = {
  /**
   * Volume policy selection committed
   */
  200: AssignVolumeProtectionPolicyResponse;
};

export type AssignVolumeProtectionPolicyResponse2 =
  AssignVolumeProtectionPolicyResponses[keyof AssignVolumeProtectionPolicyResponses];

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
