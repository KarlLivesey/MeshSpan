// SPDX-License-Identifier: GPL-2.0-only

import type {
  BackupScheduleResponse,
  ConfigureBackupDestinationRequest,
  ConfigureBackupScheduleRequest,
  ListBackupDestinationsResponse,
  ListTopologyTargetsResponse,
  MeshSpanFetchClient,
} from "../../generated";

export type BackupAdministrationClient = Pick<
  MeshSpanFetchClient,
  | "getBackupSchedule"
  | "listBackupRuns"
  | "listNextBackupRuns"
  | "metadataBackupDownloadUrl"
  | "checkMetadataBackupReadiness"
  | "configureBackupSchedule"
  | "listBackupDestinations"
  | "listNextBackupDestinations"
  | "configureBackupDestination"
  | "listTopologyTargets"
  | "listNextTopologyTargets"
>;
export type BackupDestination =
  ListBackupDestinationsResponse["destinations"][number];
export type BackupTarget = ListTopologyTargetsResponse["targets"][number];
export type BackupChange =
  | Readonly<{ kind: "schedule"; request: ConfigureBackupScheduleRequest }>
  | Readonly<{
      kind: "destination";
      request: ConfigureBackupDestinationRequest;
    }>;
export type BackupView = Readonly<{
  schedule: BackupScheduleResponse;
  destinations: ListBackupDestinationsResponse;
  targets: ListTopologyTargetsResponse;
}>;
