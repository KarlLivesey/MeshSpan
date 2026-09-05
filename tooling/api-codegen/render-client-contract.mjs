// SPDX-License-Identifier: GPL-2.0-only

import { renderAuthenticationClientInterface } from "./render-authentication-client.mjs";
import { renderBackupScheduleClientInterface } from "./render-backup-schedule-client.mjs";
import { renderBackupDestinationClientInterface } from "./render-backup-destination-client.mjs";
import { renderBackupHistoryClientInterface } from "./render-backup-history-client.mjs";
import { renderBackupExportClientInterface } from "./render-backup-export-client.mjs";
import {
  renderCertificateClientInterface,
  renderCertificateRequestTypes,
} from "./render-certificate-client.mjs";
import {
  renderDirectoryClientInterface,
  renderDirectoryRequestTypes,
} from "./render-directory-client.mjs";
import { renderIdentityAdministrationClientInterface } from "./render-identity-administration-client.mjs";
import { renderNamespaceMutationClientInterface } from "./render-namespace-mutation-client.mjs";
import {
  renderOperationStatusClientInterface,
  renderOperationStatusRequestTypes,
} from "./render-operation-status-client.mjs";
import {
  renderPermissionAdministrationClientInterface,
  renderPermissionAdministrationRequestTypes,
} from "./render-permission-administration-client.mjs";
import { renderSetupClientInterface } from "./render-setup-client.mjs";
import { renderSmbExportClientInterface } from "./render-smb-export-client.mjs";
import {
  renderStorageDrainClientInterface,
  renderStorageDrainRequestTypes,
} from "./render-storage-drain-client.mjs";
import {
  renderStorageFolderClientInterface,
  renderStorageFolderRequestTypes,
} from "./render-storage-folder-client.mjs";
import {
  renderUploadClientInterface,
  renderUploadRequestTypes,
} from "./render-upload-client.mjs";
import { renderVolumeClientInterface } from "./render-volume-client.mjs";
import {
  renderTopologyClientInterface,
  renderTopologyRequestTypes,
} from "./render-topology-client.mjs";

/** Renders the generated client's public request, result and operation surface. */
export function renderClientContract() {
  return `${renderClientRequestTypes()}

${renderClientInterface()}`;
}

function renderClientRequestTypes() {
  return `export type MeshSpanFetchClientOptions = Readonly<{
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  apiKey?: string;
}>;

${renderDirectoryRequestTypes()}

${renderCertificateRequestTypes()}

export type GetObjectRequest = Readonly<{
  volumeId: string;
  path: string;
}>;

export type ReadFileRequest = Readonly<{
  volumeId: string;
  path: string;
  offset?: number;
  length?: number;
}>;

export type ReadFileResult = Readonly<{
  bytes: Uint8Array;
  fileVersionId: string;
  offset: number;
}>;

export type ListPrincipalsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type ListGroupMembersRequest = Readonly<{
  groupId: string;
  cursor?: string;
  limit?: number;
}>;

export type ListAuthenticationMethodsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type ListVolumesRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

${renderPermissionAdministrationRequestTypes()}

${renderOperationStatusRequestTypes()}

${renderStorageDrainRequestTypes()}

${renderStorageFolderRequestTypes()}

${renderTopologyRequestTypes()}

${renderUploadRequestTypes()}

export type CreateSessionResult = Readonly<{
  csrfToken: string;
  session: CreateSessionResponse;
}>;`;
}

function renderClientInterface() {
  return `export interface MeshSpanFetchClient {
  ${renderAuthenticationClientInterface()}
  ${renderCertificateClientInterface()}
  ${renderBackupScheduleClientInterface()}
  ${renderBackupDestinationClientInterface()}
  ${renderBackupHistoryClientInterface()}
  ${renderBackupExportClientInterface()}
  ${renderIdentityAdministrationClientInterface()}
  ${renderNamespaceMutationClientInterface()}
  ${renderUploadClientInterface()}
  ${renderVolumeClientInterface()}
  ${renderSmbExportClientInterface()}
  ${renderPermissionAdministrationClientInterface()}
  ${renderOperationStatusClientInterface()}
  ${renderStorageDrainClientInterface()}
  ${renderStorageFolderClientInterface()}
  ${renderTopologyClientInterface()}
  ${renderDirectoryClientInterface()}
  ${renderSetupClientInterface()}
  createSession(request: CreateSessionRequestWritable): Promise<CreateSessionResult>;
  getCurrentSession(): Promise<CurrentSessionResponse>;
  getObject(request: GetObjectRequest): Promise<GetObjectResponse>;
  getHealth(): Promise<HealthResponse>;
  getOpenApi(): Promise<Record<string, unknown>>;
  getSetupStatus(): Promise<SetupStatusResponse>;
  readFile(request: ReadFileRequest): Promise<ReadFileResult>;
  revokeCurrentSession(
    request: RevokeCurrentSessionRequest,
    csrfToken: string,
  ): Promise<RevokeCurrentSessionResponse>;
}`;
}
