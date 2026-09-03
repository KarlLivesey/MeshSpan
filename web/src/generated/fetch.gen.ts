// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

import type {
  AbortUploadRequest,
  AbortUploadResponse,
  AddGroupMemberRequest,
  AddGroupMemberResponse,
  ApiError,
  BeginStorageDrainRequest,
  BeginStorageDrainResponse,
  BeginUploadRequest,
  BeginUploadResponse,
  CommitUploadRequest,
  CommitUploadResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateDirectoryRequest,
  CreateDirectoryResponse,
  CreateFaultGroupRequest,
  CreateFaultGroupResponse,
  CreateGroupRequest,
  CreatePasskeyChallengeRequest,
  CreatePasskeyChallengeResponse,
  CreatePasskeyRegistrationChallengeRequest,
  CreatePasskeyRegistrationChallengeResponse,
  CreatePasskeyRegistrationRequestWritable,
  CreatePasskeyRegistrationResponse,
  CreateRecoveryCodesRequest,
  CreateRecoveryCodesResponse,
  CreateMeshSetupRequestWritable,
  CreateMeshSetupResponse,
  CreateSessionRequestWritable,
  CreateSessionResponse,
  CreateTotpRegistrationChallengeRequest,
  CreateTotpRegistrationChallengeResponse,
  CreateTotpRegistrationRequestWritable,
  CreateTotpRegistrationResponse,
  CreatePrincipalResponse,
  CreateUserRequest,
  CreateVolumePermissionGrantRequest,
  CreateVolumePermissionGrantResponse,
  CreateVolumeRequest,
  CreateVolumeResponse,
  CertificateStatusResponse,
  CurrentSessionResponse,
  DeleteObjectRequest,
  DeleteObjectResponse,
  GetObjectResponse,
  HealthResponse,
  JoinMeshSetupRequestWritable,
  JoinMeshSetupResponse,
  ListDirectoryResponse,
  ListFaultGroupMembershipsResponse,
  ListFaultGroupsResponse,
  ListGroupMembershipsResponse,
  ListManualDnsTasksResponse,
  ListOperationsResponse,
  ListAuthenticationMethodsResponse,
  ListPrincipalsResponse,
  ListStorageFoldersResponse,
  ListStorageDrainsResponse,
  ListTopologyNodesResponse,
  ListTopologyTargetsResponse,
  ListUploadRangesResponse,
  ListVolumePermissionGrantsResponse,
  ListVolumesResponse,
  OperationStatusResponse,
  PublishSmbExportRequest,
  PublishSmbExportResponse,
  ProvisionCertificateRequest,
  ProvisionCertificateResponse,
  RevokeAuthenticationMethodRequest,
  RevokeAuthenticationMethodResponse,
  RevokeCurrentSessionRequest,
  RevokeCurrentSessionResponse,
  RevokePermissionGrantRequest,
  RevokePermissionGrantResponse,
  RenameObjectRequest,
  RenameObjectResponse,
  RemoveGroupMemberRequest,
  RemoveGroupMemberResponse,
  RegisterStorageFolderRequest,
  RegisterStorageFolderResponse,
  SetupStatusResponse,
  StorageDrainSummary,
  SetFaultGroupMembershipRequest,
  SetFaultGroupMembershipResponse,
  StepUpCurrentSessionRequestWritable,
  UploadStatusResponse,
  WithdrawSmbExportRequest,
  WithdrawSmbExportResponse,
  WriteUploadRangeResponse,
} from "./types.gen";
import {
  zAbortUploadBody,
  zAbortUploadPath,
  zAbortUploadResponse2,
  zApiError,
  zAddGroupMemberBody,
  zAddGroupMemberPath,
  zAddGroupMemberResponse2,
  zBeginUploadBody,
  zBeginUploadPath,
  zBeginUploadResponse2,
  zBeginStorageDrainBody,
  zBeginStorageDrainResponse2,
  zCommitUploadBody,
  zCommitUploadPath,
  zCommitUploadResponse2,
  zCreateCurrentUserApiKeyBody,
  zCreateCurrentUserApiKeyResponse,
  zCreateCurrentUserPasskeyBody,
  zCreateCurrentUserPasskeyRegistrationChallengeBody,
  zCreateCurrentUserPasskeyRegistrationChallengeResponse,
  zCreateCurrentUserPasskeyResponse,
  zCreateCurrentUserRecoveryCodesBody,
  zCreateCurrentUserRecoveryCodesResponse,
  zCreateCurrentUserTotpBody,
  zCreateCurrentUserTotpRegistrationChallengeBody,
  zCreateCurrentUserTotpRegistrationChallengeResponse,
  zCreateCurrentUserTotpResponse,
  zCreateDirectoryBody,
  zCreateDirectoryPath,
  zCreateDirectoryResponse2,
  zCreateFaultGroupBody,
  zCreateFaultGroupResponse2,
  zCreateGroupBody,
  zCreateGroupResponse,
  zCreateMeshSetupBody,
  zCreateMeshSetupResponse2,
  zCreatePasskeyChallengeBody,
  zCreatePasskeyChallengeResponse2,
  zCreateSessionBody,
  zCreateSessionResponse2,
  zCreateUserBody,
  zCreateUserResponse,
  zCreateVolumePermissionGrantBody,
  zCreateVolumePermissionGrantPath,
  zCreateVolumePermissionGrantResponse2,
  zCreateVolumeBody,
  zCreateVolumeResponse2,
  zDeleteObjectBody,
  zDeleteObjectPath,
  zDeleteObjectResponse2,
  zGetCertificateStatusResponse,
  zGetCurrentSessionResponse,
  zGetHealthResponse,
  zGetObjectPath,
  zGetObjectQuery,
  zGetObjectResponse2,
  zGetOperationStatusPath,
  zGetOperationStatusResponse,
  zGetStorageDrainPath,
  zGetStorageDrainResponse,
  zGetOpenApiResponse,
  zGetSetupStatusResponse,
  zGetUploadPath,
  zGetUploadResponse,
  zJoinMeshSetupBody,
  zJoinMeshSetupResponse2,
  zListDirectoryPath,
  zListDirectoryQuery,
  zListDirectoryResponse2,
  zListFaultGroupMembershipsQuery,
  zListFaultGroupMembershipsResponse2,
  zListFaultGroupsQuery,
  zListFaultGroupsResponse2,
  zListGroupsQuery,
  zListGroupsResponse,
  zListManualDnsTasksQuery,
  zListManualDnsTasksResponse2,
  zListOperationsQuery,
  zListOperationsResponse,
  zListStorageFoldersQuery,
  zListStorageFoldersResponse2,
  zListStorageDrainsQuery,
  zListStorageDrainsResponse2,
  zListTopologyNodesQuery,
  zListTopologyNodesResponse2,
  zListTopologyTargetsQuery,
  zListTopologyTargetsResponse2,
  zListGroupMembersPath,
  zListGroupMembersQuery,
  zListGroupMembersResponse,
  zListCurrentUserAuthenticationMethodsQuery,
  zListCurrentUserAuthenticationMethodsResponse,
  zListPrincipalsResponse,
  zListUploadRangesPath,
  zListUploadRangesQuery,
  zListUploadRangesResponse2,
  zListUsersQuery,
  zListUsersResponse,
  zListVolumePermissionGrantsPath,
  zListVolumePermissionGrantsQuery,
  zListVolumePermissionGrantsResponse2,
  zListVolumesQuery,
  zListVolumesResponse2,
  zReadFilePath,
  zReadFileQuery,
  zPublishSmbExportBody,
  zPublishSmbExportPath,
  zPublishSmbExportResponse2,
  zProvisionCertificateBody,
  zProvisionCertificateResponse2,
  zRevokeCurrentUserAuthenticationMethodBody,
  zRevokeCurrentUserAuthenticationMethodPath,
  zRevokeCurrentUserAuthenticationMethodResponse,
  zRevokeCurrentSessionBody,
  zRevokeCurrentSessionResponse2,
  zRevokePermissionGrantBody,
  zRevokePermissionGrantPath,
  zRevokePermissionGrantResponse2,
  zRenameObjectBody,
  zRenameObjectPath,
  zRenameObjectResponse2,
  zRemoveGroupMemberBody,
  zRemoveGroupMemberPath,
  zRemoveGroupMemberResponse2,
  zRegisterStorageFolderBody,
  zRegisterStorageFolderResponse2,
  zSetFaultGroupMembershipBody,
  zSetFaultGroupMembershipPath,
  zSetFaultGroupMembershipResponse2,
  zStepUpCurrentSessionBody,
  zStepUpCurrentSessionResponse,
  zWriteUploadRangeHeaders,
  zWriteUploadRangePath,
  zWriteUploadRangeResponse2,
  zWithdrawSmbExportBody,
  zWithdrawSmbExportPath,
  zWithdrawSmbExportResponse2,
} from "./zod.gen";
import {
  appendQuery,
  authenticatedHeaders,
  parseSafeDecimalHeader,
  substitutePathParameter,
  validateNamespacePath,
} from "../native-api/request";
import {
  readBoundedBytes,
  rejectOversizedContentLength,
} from "../native-api/response";

const MAX_JSON_RESPONSE_BYTES = 65_536;
const MAX_FILE_READ_BYTES = 8_388_608;
const MAX_UPLOAD_RANGE_BYTES = 8_388_608;
const SCHEMA_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CSRF_TOKEN_PATTERN = /^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/u;
const API_KEY_PATTERN = /^meshspan-key-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/u;
const FILE_VERSION_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type MeshSpanFetchClientOptions = Readonly<{
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  apiKey?: string;
}>;

export type ListDirectoryRequest = Readonly<{
  volumeId: string;
  path?: string;
  cursor?: string;
  limit?: number;
}>;

export type ListManualDnsTasksRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

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

export type ListVolumePermissionGrantsRequest = Readonly<{
  volumeId: string;
  cursor?: string;
  limit?: number;
}>;

export type ListOperationsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type ListStorageDrainsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type ListStorageFoldersRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type ListTopologyRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type SetFaultGroupMembershipInput = Readonly<{
  groupId: string;
  hostId: string;
  request: SetFaultGroupMembershipRequest;
}>;

export type ListUploadRangesRequest = Readonly<{
  uploadId: string;
  cursor?: string;
  limit?: number;
}>;

export type WriteUploadRangeRequest = Readonly<{
  uploadId: string;
  offset: number;
  operationId: string;
  stageFence: number;
  contentBlake3: string;
  bytes: Uint8Array;
}>;

export type CreateSessionResult = Readonly<{
  csrfToken: string;
  session: CreateSessionResponse;
}>;

export interface MeshSpanFetchClient {
  createPasskeyChallenge(
    request: CreatePasskeyChallengeRequest,
  ): Promise<CreatePasskeyChallengeResponse>;
  createCurrentUserApiKey(
    request: CreateApiKeyRequest,
    csrfToken: string,
  ): Promise<CreateApiKeyResponse>;
  createCurrentUserPasskey(
    request: CreatePasskeyRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationResponse>;
  createCurrentUserPasskeyRegistrationChallenge(
    request: CreatePasskeyRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationChallengeResponse>;
  createCurrentUserRecoveryCodes(
    request: CreateRecoveryCodesRequest,
    csrfToken: string,
  ): Promise<CreateRecoveryCodesResponse>;
  createCurrentUserTotp(
    request: CreateTotpRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationResponse>;
  createCurrentUserTotpRegistrationChallenge(
    request: CreateTotpRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationChallengeResponse>;
  listCurrentUserAuthenticationMethods(
    request?: ListAuthenticationMethodsRequest,
  ): Promise<ListAuthenticationMethodsResponse>;
  listNextCurrentUserAuthenticationMethods(
    nextPageUrl: string,
  ): Promise<ListAuthenticationMethodsResponse>;
  revokeCurrentUserAuthenticationMethod(
    methodId: string,
    request: RevokeAuthenticationMethodRequest,
    csrfToken: string,
  ): Promise<RevokeAuthenticationMethodResponse>;
  stepUpCurrentSession(
    request: StepUpCurrentSessionRequestWritable,
    csrfToken: string,
  ): Promise<CreateSessionResult>;
  getCertificateStatus(): Promise<CertificateStatusResponse>;
  listManualDnsTasks(
    request?: ListManualDnsTasksRequest,
  ): Promise<ListManualDnsTasksResponse>;
  listNextManualDnsTasks(
    nextPageUrl: string,
  ): Promise<ListManualDnsTasksResponse>;
  provisionCertificate(
    request: ProvisionCertificateRequest,
    csrfToken?: string,
  ): Promise<ProvisionCertificateResponse>;
  addGroupMember(
    groupId: string,
    request: AddGroupMemberRequest,
    csrfToken?: string,
  ): Promise<AddGroupMemberResponse>;
  createGroup(
    request: CreateGroupRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  createUser(
    request: CreateUserRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  listGroups(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listGroupMembers(
    request: ListGroupMembersRequest,
  ): Promise<ListGroupMembershipsResponse>;
  listNextGroupMembers(
    nextPageUrl: string,
  ): Promise<ListGroupMembershipsResponse>;
  listUsers(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listNextPrincipals(nextPageUrl: string): Promise<ListPrincipalsResponse>;
  removeGroupMember(
    groupId: string,
    memberPrincipalId: string,
    request: RemoveGroupMemberRequest,
    csrfToken?: string,
  ): Promise<RemoveGroupMemberResponse>;
  createDirectory(
    volumeId: string,
    request: CreateDirectoryRequest,
    csrfToken?: string,
  ): Promise<CreateDirectoryResponse>;
  deleteObject(
    volumeId: string,
    request: DeleteObjectRequest,
    csrfToken?: string,
  ): Promise<DeleteObjectResponse>;
  renameObject(
    volumeId: string,
    request: RenameObjectRequest,
    csrfToken?: string,
  ): Promise<RenameObjectResponse>;
  abortUpload(
    uploadId: string,
    request: AbortUploadRequest,
    csrfToken?: string,
  ): Promise<AbortUploadResponse>;
  beginUpload(
    volumeId: string,
    request: BeginUploadRequest,
    csrfToken?: string,
  ): Promise<BeginUploadResponse>;
  commitUpload(
    uploadId: string,
    request: CommitUploadRequest,
    csrfToken?: string,
  ): Promise<CommitUploadResponse>;
  getUpload(uploadId: string): Promise<UploadStatusResponse>;
  listUploadRanges(
    request: ListUploadRangesRequest,
  ): Promise<ListUploadRangesResponse>;
  writeUploadRange(
    request: WriteUploadRangeRequest,
    csrfToken?: string,
  ): Promise<WriteUploadRangeResponse>;
  createVolume(
    request: CreateVolumeRequest,
    csrfToken?: string,
  ): Promise<CreateVolumeResponse>;
  listVolumes(request?: ListVolumesRequest): Promise<ListVolumesResponse>;
  listNextVolumes(nextPageUrl: string): Promise<ListVolumesResponse>;
  publishSmbExport(
    volumeId: string,
    request: PublishSmbExportRequest,
    csrfToken?: string,
  ): Promise<PublishSmbExportResponse>;
  withdrawSmbExport(
    exportId: string,
    request: WithdrawSmbExportRequest,
    csrfToken?: string,
  ): Promise<WithdrawSmbExportResponse>;
  createVolumePermissionGrant(
    volumeId: string,
    request: CreateVolumePermissionGrantRequest,
    csrfToken?: string,
  ): Promise<CreateVolumePermissionGrantResponse>;
  listVolumePermissionGrants(
    request: ListVolumePermissionGrantsRequest,
  ): Promise<ListVolumePermissionGrantsResponse>;
  listNextVolumePermissionGrants(
    nextPageUrl: string,
  ): Promise<ListVolumePermissionGrantsResponse>;
  revokePermissionGrant(
    volumeId: string,
    grantId: string,
    request: RevokePermissionGrantRequest,
    csrfToken?: string,
  ): Promise<RevokePermissionGrantResponse>;
  getOperationStatus(operationId: string): Promise<OperationStatusResponse>;
  listOperations(
    request?: ListOperationsRequest,
  ): Promise<ListOperationsResponse>;
  listNextOperations(nextPageUrl: string): Promise<ListOperationsResponse>;
  beginStorageDrain(
    request: BeginStorageDrainRequest,
    csrfToken?: string,
  ): Promise<BeginStorageDrainResponse>;
  getStorageDrain(drainId: string): Promise<StorageDrainSummary>;
  listStorageDrains(
    request?: ListStorageDrainsRequest,
  ): Promise<ListStorageDrainsResponse>;
  listNextStorageDrains(
    nextPageUrl: string,
  ): Promise<ListStorageDrainsResponse>;
  listStorageFolders(
    request?: ListStorageFoldersRequest,
  ): Promise<ListStorageFoldersResponse>;
  listNextStorageFolders(
    nextPageUrl: string,
  ): Promise<ListStorageFoldersResponse>;
  registerStorageFolder(
    request: RegisterStorageFolderRequest,
    csrfToken?: string,
  ): Promise<RegisterStorageFolderResponse>;
  listTopologyNodes(
    request?: ListTopologyRequest,
  ): Promise<ListTopologyNodesResponse>;
  listNextTopologyNodes(
    nextPageUrl: string,
  ): Promise<ListTopologyNodesResponse>;
  listTopologyTargets(
    request?: ListTopologyRequest,
  ): Promise<ListTopologyTargetsResponse>;
  listNextTopologyTargets(
    nextPageUrl: string,
  ): Promise<ListTopologyTargetsResponse>;
  listFaultGroups(
    request?: ListTopologyRequest,
  ): Promise<ListFaultGroupsResponse>;
  listNextFaultGroups(nextPageUrl: string): Promise<ListFaultGroupsResponse>;
  listFaultGroupMemberships(
    request?: ListTopologyRequest,
  ): Promise<ListFaultGroupMembershipsResponse>;
  listNextFaultGroupMemberships(
    nextPageUrl: string,
  ): Promise<ListFaultGroupMembershipsResponse>;
  createFaultGroup(
    request: CreateFaultGroupRequest,
    csrfToken?: string,
  ): Promise<CreateFaultGroupResponse>;
  setFaultGroupMembership(
    input: SetFaultGroupMembershipInput,
    csrfToken?: string,
  ): Promise<SetFaultGroupMembershipResponse>;
  listDirectory(request: ListDirectoryRequest): Promise<ListDirectoryResponse>;
  listNextDirectory(nextPageUrl: string): Promise<ListDirectoryResponse>;

  createMeshSetup(
    request: CreateMeshSetupRequestWritable,
  ): Promise<CreateMeshSetupResponse>;
  joinMeshSetup(
    request: JoinMeshSetupRequestWritable,
  ): Promise<JoinMeshSetupResponse>;
  createSession(
    request: CreateSessionRequestWritable,
  ): Promise<CreateSessionResult>;
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
}

export class MeshSpanApiError extends Error {
  public readonly apiError: ApiError | undefined;
  public readonly statusCode: number;

  public constructor(statusCode: number, apiError?: ApiError) {
    super(apiError?.message ?? "MeshSpan rejected the request");
    this.name = "MeshSpanApiError";
    this.apiError = apiError;
    this.statusCode = statusCode;
  }
}

interface JsonParser<T> {
  parse(value: unknown): T;
}

interface RequestContext {
  apiRoot: URL;
  authorization: string | undefined;
  fetch: typeof globalThis.fetch;
}

export function createMeshSpanFetchClient(
  options: MeshSpanFetchClientOptions,
): MeshSpanFetchClient {
  if (options.apiKey !== undefined && !API_KEY_PATTERN.test(options.apiKey)) {
    throw new TypeError("client has an invalid MeshSpan API key");
  }
  const context: RequestContext = {
    apiRoot: normalizeApiRoot(options.baseUrl),
    authorization:
      options.apiKey === undefined ? undefined : `Bearer ${options.apiKey}`,
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
  };

  return {
    async createPasskeyChallenge(
      request,
    ): Promise<CreatePasskeyChallengeResponse> {
      const body = zCreatePasskeyChallengeBody.parse(request);
      return requestJson(
        context,
        "/sessions/passkey/challenges",
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
        zCreatePasskeyChallengeResponse2,
      );
    },
    async createCurrentUserPasskeyRegistrationChallenge(
      request,
      csrfToken,
    ): Promise<CreatePasskeyRegistrationChallengeResponse> {
      const body =
        zCreateCurrentUserPasskeyRegistrationChallengeBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/passkeys/registration-challenges",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserPasskeyRegistrationChallengeResponse,
      );
    },
    async createCurrentUserTotpRegistrationChallenge(
      request,
      csrfToken,
    ): Promise<CreateTotpRegistrationChallengeResponse> {
      const body =
        zCreateCurrentUserTotpRegistrationChallengeBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/totp/registration-challenges",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserTotpRegistrationChallengeResponse,
      );
    },
    async createCurrentUserApiKey(
      request,
      csrfToken,
    ): Promise<CreateApiKeyResponse> {
      const body = zCreateCurrentUserApiKeyBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/api-keys",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserApiKeyResponse,
      );
    },
    async createCurrentUserPasskey(
      request,
      csrfToken,
    ): Promise<CreatePasskeyRegistrationResponse> {
      const body = zCreateCurrentUserPasskeyBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/passkeys",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserPasskeyResponse,
      );
    },
    async createCurrentUserRecoveryCodes(
      request,
      csrfToken,
    ): Promise<CreateRecoveryCodesResponse> {
      const body = zCreateCurrentUserRecoveryCodesBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/recovery-codes",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserRecoveryCodesResponse,
      );
    },
    async createCurrentUserTotp(
      request,
      csrfToken,
    ): Promise<CreateTotpRegistrationResponse> {
      const body = zCreateCurrentUserTotpBody.parse(request);
      return requestJson(
        context,
        "/users/current/authentication-methods/totp",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateCurrentUserTotpResponse,
      );
    },
    async listCurrentUserAuthenticationMethods(
      request = {},
    ): Promise<ListAuthenticationMethodsResponse> {
      const query = zListCurrentUserAuthenticationMethodsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/users/current/authentication-methods", query),
        { method: "GET" },
        zListCurrentUserAuthenticationMethodsResponse,
      );
    },
    async listNextCurrentUserAuthenticationMethods(
      nextPageUrl,
    ): Promise<ListAuthenticationMethodsResponse> {
      return requestJson(
        context,
        validateAuthenticationMethodPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListCurrentUserAuthenticationMethodsResponse,
      );
    },
    async revokeCurrentUserAuthenticationMethod(
      methodId,
      request,
      csrfToken,
    ): Promise<RevokeAuthenticationMethodResponse> {
      const path = zRevokeCurrentUserAuthenticationMethodPath.parse({
        method_id: methodId,
      });
      const body = zRevokeCurrentUserAuthenticationMethodBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/users/current/authentication-methods/{method_id}/revocations",
          "method_id",
          path.method_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zRevokeCurrentUserAuthenticationMethodResponse,
      );
    },
    async stepUpCurrentSession(
      request,
      csrfToken,
    ): Promise<CreateSessionResult> {
      const body = zStepUpCurrentSessionBody.parse(request);
      const response = await requestJsonResponse(
        context,
        "/sessions/current/step-ups",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zStepUpCurrentSessionResponse,
      );
      return {
        csrfToken: readCsrfToken(response.headers),
        session: response.body,
      };
    },
    async getCertificateStatus(): Promise<CertificateStatusResponse> {
      return requestJson(
        context,
        "/admin/certificates/status",
        { method: "GET" },
        zGetCertificateStatusResponse,
      );
    },
    async listManualDnsTasks(
      request = {},
    ): Promise<ListManualDnsTasksResponse> {
      const query = zListManualDnsTasksQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/certificate-tasks/manual-dns", query),
        { method: "GET" },
        zListManualDnsTasksResponse2,
      );
    },
    async listNextManualDnsTasks(
      nextPageUrl,
    ): Promise<ListManualDnsTasksResponse> {
      return requestJson(
        context,
        validateManualDnsTaskPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListManualDnsTasksResponse2,
      );
    },
    async provisionCertificate(
      request,
      csrfToken,
    ): Promise<ProvisionCertificateResponse> {
      const body = zProvisionCertificateBody.parse(request);
      return requestJson(
        context,
        "/admin/certificates/acme",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zProvisionCertificateResponse2,
      );
    },
    async addGroupMember(
      groupId,
      request,
      csrfToken,
    ): Promise<AddGroupMemberResponse> {
      const path = zAddGroupMemberPath.parse({ group_id: groupId });
      const body = zAddGroupMemberBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/admin/groups/{group_id}/members",
          "group_id",
          path.group_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zAddGroupMemberResponse2,
      );
    },
    async listGroupMembers(request): Promise<ListGroupMembershipsResponse> {
      const path = zListGroupMembersPath.parse({ group_id: request.groupId });
      const query = zListGroupMembersQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            "/admin/groups/{group_id}/members",
            "group_id",
            path.group_id,
          ),
          query,
        ),
        { method: "GET" },
        zListGroupMembersResponse,
      );
    },
    async listNextGroupMembers(
      nextPageUrl,
    ): Promise<ListGroupMembershipsResponse> {
      return requestJson(
        context,
        validateGroupMembershipPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListGroupMembersResponse,
      );
    },
    async removeGroupMember(
      groupId,
      memberPrincipalId,
      request,
      csrfToken,
    ): Promise<RemoveGroupMemberResponse> {
      const path = zRemoveGroupMemberPath.parse({
        group_id: groupId,
        member_principal_id: memberPrincipalId,
      });
      const body = zRemoveGroupMemberBody.parse(request);
      const groupRoute = substitutePathParameter(
        "/admin/groups/{group_id}/members/{member_principal_id}/removals",
        "group_id",
        path.group_id,
      );
      return requestJson(
        context,
        substitutePathParameter(
          groupRoute,
          "member_principal_id",
          path.member_principal_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zRemoveGroupMemberResponse2,
      );
    },
    async createGroup(request, csrfToken): Promise<CreatePrincipalResponse> {
      const body = zCreateGroupBody.parse(request);
      return requestJson(
        context,
        "/admin/groups",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateGroupResponse,
      );
    },
    async createUser(request, csrfToken): Promise<CreatePrincipalResponse> {
      const body = zCreateUserBody.parse(request);
      return requestJson(
        context,
        "/admin/users",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateUserResponse,
      );
    },
    async listGroups(request = {}): Promise<ListPrincipalsResponse> {
      const query = zListGroupsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/groups", query),
        { method: "GET" },
        zListGroupsResponse,
      );
    },
    async listUsers(request = {}): Promise<ListPrincipalsResponse> {
      const query = zListUsersQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/users", query),
        { method: "GET" },
        zListUsersResponse,
      );
    },
    async listNextPrincipals(nextPageUrl): Promise<ListPrincipalsResponse> {
      return requestJson(
        context,
        validatePrincipalPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListPrincipalsResponse,
      );
    },
    async createDirectory(
      volumeId,
      request,
      csrfToken,
    ): Promise<CreateDirectoryResponse> {
      const path = zCreateDirectoryPath.parse({ volume_id: volumeId });
      const body = zCreateDirectoryBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          "/volumes/{volume_id}/directories",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateDirectoryResponse2,
      );
    },
    async deleteObject(
      volumeId,
      request,
      csrfToken,
    ): Promise<DeleteObjectResponse> {
      const path = zDeleteObjectPath.parse({ volume_id: volumeId });
      const body = zDeleteObjectBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          "/volumes/{volume_id}/deletions",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zDeleteObjectResponse2,
      );
    },
    async renameObject(
      volumeId,
      request,
      csrfToken,
    ): Promise<RenameObjectResponse> {
      const path = zRenameObjectPath.parse({ volume_id: volumeId });
      const body = zRenameObjectBody.parse(request);
      validateNamespacePath(body.source_path);
      validateNamespacePath(body.target_path);
      if (body.source_path === body.target_path) {
        throw new TypeError("rename source and target must differ");
      }
      return requestJson(
        context,
        substitutePathParameter(
          "/volumes/{volume_id}/renames",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zRenameObjectResponse2,
      );
    },
    async abortUpload(
      uploadId,
      request,
      csrfToken,
    ): Promise<AbortUploadResponse> {
      const path = zAbortUploadPath.parse({ upload_id: uploadId });
      const body = zAbortUploadBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/uploads/{upload_id}/aborts",
          "upload_id",
          path.upload_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zAbortUploadResponse2,
      );
    },
    async beginUpload(
      volumeId,
      request,
      csrfToken,
    ): Promise<BeginUploadResponse> {
      const path = zBeginUploadPath.parse({ volume_id: volumeId });
      const body = zBeginUploadBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          "/volumes/{volume_id}/uploads",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zBeginUploadResponse2,
      );
    },
    async commitUpload(
      uploadId,
      request,
      csrfToken,
    ): Promise<CommitUploadResponse> {
      const path = zCommitUploadPath.parse({ upload_id: uploadId });
      const body = zCommitUploadBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/uploads/{upload_id}/commits",
          "upload_id",
          path.upload_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCommitUploadResponse2,
      );
    },
    async getUpload(uploadId): Promise<UploadStatusResponse> {
      const path = zGetUploadPath.parse({ upload_id: uploadId });
      return requestJson(
        context,
        substitutePathParameter(
          "/uploads/{upload_id}",
          "upload_id",
          path.upload_id,
        ),
        { method: "GET" },
        zGetUploadResponse,
      );
    },
    async listUploadRanges(request): Promise<ListUploadRangesResponse> {
      const path = zListUploadRangesPath.parse({ upload_id: request.uploadId });
      const query = zListUploadRangesQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            "/uploads/{upload_id}/ranges",
            "upload_id",
            path.upload_id,
          ),
          query,
        ),
        { method: "GET" },
        zListUploadRangesResponse2,
      );
    },
    async writeUploadRange(
      request,
      csrfToken,
    ): Promise<WriteUploadRangeResponse> {
      const path = zWriteUploadRangePath.parse({
        offset: request.offset,
        upload_id: request.uploadId,
      });
      const headers = zWriteUploadRangeHeaders.parse({
        "MeshSpan-Content-BLAKE3": request.contentBlake3,
        "MeshSpan-Operation-Id": request.operationId,
        "MeshSpan-Stage-Fence": request.stageFence,
      });
      if (request.bytes.byteLength === 0) {
        throw new RangeError("upload range must not be empty");
      }
      if (request.bytes.byteLength > MAX_UPLOAD_RANGE_BYTES) {
        throw new RangeError("upload range exceeds the native byte limit");
      }
      const body = new Uint8Array(request.bytes).buffer;
      return requestJson(
        context,
        substitutePathParameter(
          substitutePathParameter(
            "/uploads/{upload_id}/ranges/{offset}",
            "upload_id",
            path.upload_id,
          ),
          "offset",
          String(path.offset),
        ),
        {
          body,
          headers: {
            ...mutationHeaders("application/octet-stream", csrfToken),
            "MeshSpan-Content-BLAKE3": headers["MeshSpan-Content-BLAKE3"],
            "MeshSpan-Operation-Id": headers["MeshSpan-Operation-Id"],
            "MeshSpan-Stage-Fence": String(headers["MeshSpan-Stage-Fence"]),
          },
          method: "PUT",
        },
        zWriteUploadRangeResponse2,
      );
    },
    async createVolume(request, csrfToken): Promise<CreateVolumeResponse> {
      const body = zCreateVolumeBody.parse(request);
      return requestJson(
        context,
        "/admin/volumes",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateVolumeResponse2,
      );
    },
    async listVolumes(request = {}): Promise<ListVolumesResponse> {
      const query = zListVolumesQuery.parse(request);
      return validateVolumePage(
        await requestJson(
          context,
          appendQuery("/volumes", query),
          { method: "GET" },
          zListVolumesResponse2,
        ),
      );
    },
    async listNextVolumes(nextPageUrl): Promise<ListVolumesResponse> {
      return validateVolumePage(
        await requestJson(
          context,
          validateVolumePageUrl(context.apiRoot, nextPageUrl),
          { method: "GET" },
          zListVolumesResponse2,
        ),
      );
    },
    async publishSmbExport(
      volumeId,
      request,
      csrfToken,
    ): Promise<PublishSmbExportResponse> {
      const path = zPublishSmbExportPath.parse({ volume_id: volumeId });
      const body = zPublishSmbExportBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/admin/volumes/{volume_id}/smb-exports",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zPublishSmbExportResponse2,
      );
    },
    async withdrawSmbExport(
      exportId,
      request,
      csrfToken,
    ): Promise<WithdrawSmbExportResponse> {
      const path = zWithdrawSmbExportPath.parse({ export_id: exportId });
      const body = zWithdrawSmbExportBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/admin/smb-exports/{export_id}/withdrawals",
          "export_id",
          path.export_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zWithdrawSmbExportResponse2,
      );
    },
    async createVolumePermissionGrant(
      volumeId,
      request,
      csrfToken,
    ): Promise<CreateVolumePermissionGrantResponse> {
      const path = zCreateVolumePermissionGrantPath.parse({
        volume_id: volumeId,
      });
      const body = zCreateVolumePermissionGrantBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          "/admin/volumes/{volume_id}/permission-grants",
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateVolumePermissionGrantResponse2,
      );
    },
    async listVolumePermissionGrants(
      request,
    ): Promise<ListVolumePermissionGrantsResponse> {
      const path = zListVolumePermissionGrantsPath.parse({
        volume_id: request.volumeId,
      });
      const query = zListVolumePermissionGrantsQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            "/admin/volumes/{volume_id}/permission-grants",
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: "GET" },
        zListVolumePermissionGrantsResponse2,
      );
    },
    async listNextVolumePermissionGrants(
      nextPageUrl,
    ): Promise<ListVolumePermissionGrantsResponse> {
      return requestJson(
        context,
        validatePermissionGrantPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListVolumePermissionGrantsResponse2,
      );
    },
    async revokePermissionGrant(
      volumeId,
      grantId,
      request,
      csrfToken,
    ): Promise<RevokePermissionGrantResponse> {
      const path = zRevokePermissionGrantPath.parse({
        grant_id: grantId,
        volume_id: volumeId,
      });
      const body = zRevokePermissionGrantBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          substitutePathParameter(
            "/admin/volumes/{volume_id}/permission-grants/{grant_id}/revocations",
            "volume_id",
            path.volume_id,
          ),
          "grant_id",
          path.grant_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zRevokePermissionGrantResponse2,
      );
    },
    async getOperationStatus(operationId): Promise<OperationStatusResponse> {
      const path = zGetOperationStatusPath.parse({ operation_id: operationId });
      return requestJson(
        context,
        substitutePathParameter(
          "/operations/{operation_id}",
          "operation_id",
          path.operation_id,
        ),
        { method: "GET" },
        zGetOperationStatusResponse,
      );
    },
    async listOperations(request = {}): Promise<ListOperationsResponse> {
      const query = zListOperationsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/operations", query),
        { method: "GET" },
        zListOperationsResponse,
      );
    },
    async listNextOperations(nextPageUrl): Promise<ListOperationsResponse> {
      return requestJson(
        context,
        validateOperationPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListOperationsResponse,
      );
    },
    async beginStorageDrain(
      request,
      csrfToken,
    ): Promise<BeginStorageDrainResponse> {
      const body = zBeginStorageDrainBody.parse(request);
      return requestJson(
        context,
        "/admin/storage-drains",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zBeginStorageDrainResponse2,
      );
    },
    async getStorageDrain(drainId): Promise<StorageDrainSummary> {
      const path = zGetStorageDrainPath.parse({ drain_id: drainId });
      return requestJson(
        context,
        substitutePathParameter(
          "/admin/storage-drains/{drain_id}",
          "drain_id",
          path.drain_id,
        ),
        { method: "GET" },
        zGetStorageDrainResponse,
      );
    },
    async listStorageDrains(request = {}): Promise<ListStorageDrainsResponse> {
      const query = zListStorageDrainsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/storage-drains", query),
        { method: "GET" },
        zListStorageDrainsResponse2,
      );
    },
    async listNextStorageDrains(
      nextPageUrl,
    ): Promise<ListStorageDrainsResponse> {
      return requestJson(
        context,
        validateStorageDrainPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListStorageDrainsResponse2,
      );
    },
    async listStorageFolders(
      request = {},
    ): Promise<ListStorageFoldersResponse> {
      const query = zListStorageFoldersQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/storage-folders", query),
        { method: "GET" },
        zListStorageFoldersResponse2,
      );
    },
    async listNextStorageFolders(
      nextPageUrl,
    ): Promise<ListStorageFoldersResponse> {
      return requestJson(
        context,
        validateStorageFolderPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListStorageFoldersResponse2,
      );
    },
    async registerStorageFolder(
      request,
      csrfToken,
    ): Promise<RegisterStorageFolderResponse> {
      const body = zRegisterStorageFolderBody.parse(request);
      return requestJson(
        context,
        "/admin/storage-folders",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zRegisterStorageFolderResponse2,
      );
    },
    async listTopologyNodes(request = {}) {
      const query = zListTopologyNodesQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/topology/nodes", query),
        { method: "GET" },
        zListTopologyNodesResponse2,
      );
    },
    async listNextTopologyNodes(nextPageUrl) {
      return requestJson(
        context,
        validateTopologyPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListTopologyNodesResponse2,
      );
    },
    async listTopologyTargets(request = {}) {
      const query = zListTopologyTargetsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/topology/targets", query),
        { method: "GET" },
        zListTopologyTargetsResponse2,
      );
    },
    async listNextTopologyTargets(nextPageUrl) {
      return requestJson(
        context,
        validateTopologyPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListTopologyTargetsResponse2,
      );
    },
    async listFaultGroups(request = {}) {
      const query = zListFaultGroupsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/topology/fault-groups", query),
        { method: "GET" },
        zListFaultGroupsResponse2,
      );
    },
    async listNextFaultGroups(nextPageUrl) {
      return requestJson(
        context,
        validateTopologyPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListFaultGroupsResponse2,
      );
    },
    async listFaultGroupMemberships(request = {}) {
      const query = zListFaultGroupMembershipsQuery.parse(request);
      return requestJson(
        context,
        appendQuery("/admin/topology/fault-group-memberships", query),
        { method: "GET" },
        zListFaultGroupMembershipsResponse2,
      );
    },
    async listNextFaultGroupMemberships(nextPageUrl) {
      return requestJson(
        context,
        validateTopologyPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListFaultGroupMembershipsResponse2,
      );
    },
    async createFaultGroup(request, csrfToken) {
      const body = zCreateFaultGroupBody.parse(request);
      return requestJson(
        context,
        "/admin/topology/fault-groups",
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "POST",
        },
        zCreateFaultGroupResponse2,
      );
    },
    async setFaultGroupMembership(input, csrfToken) {
      const path = zSetFaultGroupMembershipPath.parse({
        group_id: input.groupId,
        host_id: input.hostId,
      });
      const body = zSetFaultGroupMembershipBody.parse(input.request);
      const route = substitutePathParameter(
        substitutePathParameter(
          "/admin/topology/fault-groups/{group_id}/hosts/{host_id}",
          "group_id",
          path.group_id,
        ),
        "host_id",
        path.host_id,
      );
      return requestJson(
        context,
        route,
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: "PUT",
        },
        zSetFaultGroupMembershipResponse2,
      );
    },
    async listDirectory(request): Promise<ListDirectoryResponse> {
      const path = zListDirectoryPath.parse({ volume_id: request.volumeId });
      const query = zListDirectoryQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
        path: request.path,
      });
      if (query.path !== undefined) {
        validateNamespacePath(query.path);
      }
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            "/volumes/{volume_id}/directory-entries",
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: "GET" },
        zListDirectoryResponse2,
      );
    },
    async listNextDirectory(nextPageUrl): Promise<ListDirectoryResponse> {
      return requestJson(
        context,
        validateDirectoryPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListDirectoryResponse2,
      );
    },

    async createMeshSetup(request): Promise<CreateMeshSetupResponse> {
      const body = zCreateMeshSetupBody.parse(request);
      return requestJson(
        context,
        "/setup/meshes",
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
        zCreateMeshSetupResponse2,
      );
    },
    async joinMeshSetup(request): Promise<JoinMeshSetupResponse> {
      const body = zJoinMeshSetupBody.parse(request);
      return requestJson(
        context,
        "/setup/joins",
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
        zJoinMeshSetupResponse2,
      );
    },
    async createSession(request): Promise<CreateSessionResult> {
      const body = zCreateSessionBody.parse(request);
      const response = await requestJsonResponse(
        context,
        "/sessions",
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
        zCreateSessionResponse2,
      );
      return {
        csrfToken: readCsrfToken(response.headers),
        session: response.body,
      };
    },
    async getHealth(): Promise<HealthResponse> {
      return requestJson(
        context,
        "/health",
        { method: "GET" },
        zGetHealthResponse,
      );
    },
    async getCurrentSession(): Promise<CurrentSessionResponse> {
      return requestJson(
        context,
        "/sessions/current",
        { method: "GET" },
        zGetCurrentSessionResponse,
      );
    },
    async getObject(request): Promise<GetObjectResponse> {
      const path = zGetObjectPath.parse({ volume_id: request.volumeId });
      const query = zGetObjectQuery.parse({ path: request.path });
      validateNamespacePath(query.path);
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            "/volumes/{volume_id}/objects",
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: "GET" },
        zGetObjectResponse2,
      );
    },
    async getOpenApi(): Promise<Record<string, unknown>> {
      return requestJson(
        context,
        "/openapi.json",
        { method: "GET" },
        zGetOpenApiResponse,
      );
    },
    async getSetupStatus(): Promise<SetupStatusResponse> {
      return requestJson(
        context,
        "/setup/status",
        { method: "GET" },
        zGetSetupStatusResponse,
      );
    },
    async readFile(request): Promise<ReadFileResult> {
      const path = zReadFilePath.parse({ volume_id: request.volumeId });
      const query = zReadFileQuery.parse({
        length: request.length,
        offset: request.offset,
        path: request.path,
      });
      validateNamespacePath(query.path);
      return requestFileRange(
        context,
        appendQuery(
          substitutePathParameter(
            "/volumes/{volume_id}/file-content",
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        query.offset,
        query.length,
      );
    },
    async revokeCurrentSession(
      request,
      csrfToken,
    ): Promise<RevokeCurrentSessionResponse> {
      const body = zRevokeCurrentSessionBody.parse(request);
      if (!CSRF_TOKEN_PATTERN.test(csrfToken)) {
        throw new TypeError("request has an invalid MeshSpan CSRF token");
      }
      return requestJson(
        context,
        "/sessions/current/revocations",
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: "POST",
        },
        zRevokeCurrentSessionResponse2,
      );
    },
  };
}

async function requestJson<T>(
  context: RequestContext,
  route: string,
  request: RequestInit,
  parser: JsonParser<T>,
): Promise<T> {
  return (await requestJsonResponse(context, route, request, parser)).body;
}

type JsonResponse<T> = Readonly<{
  body: T;
  headers: Headers;
}>;

async function requestJsonResponse<T>(
  context: RequestContext,
  route: string,
  request: RequestInit,
  parser: JsonParser<T>,
): Promise<JsonResponse<T>> {
  const headers = authenticatedHeaders(context.authorization, request.headers);
  headers.set("Accept", "application/json");
  const response = await context.fetch(resolveRoute(context.apiRoot, route), {
    ...request,
    credentials: context.authorization === undefined ? "same-origin" : "omit",
    headers,
  });
  validateContractHeaders(response);
  const value = await readBoundedJson(response);

  if (!response.ok) {
    const parsedError = zApiError.safeParse(value);
    throw new MeshSpanApiError(
      response.status,
      parsedError.success ? parsedError.data : undefined,
    );
  }

  return { body: parser.parse(value), headers: response.headers };
}

async function requestFileRange(
  context: RequestContext,
  route: string,
  expectedOffset: number,
  maximumBytes: number,
): Promise<ReadFileResult> {
  if (maximumBytes > MAX_FILE_READ_BYTES) {
    throw new RangeError("file request exceeds the native range limit");
  }
  const response = await context.fetch(resolveRoute(context.apiRoot, route), {
    credentials: context.authorization === undefined ? "same-origin" : "omit",
    headers: authenticatedHeaders(context.authorization, {
      Accept: "application/octet-stream",
    }),
    method: "GET",
  });
  validateContractHeaders(response);
  if (!response.ok) {
    const value = await readBoundedJson(response);
    const parsedError = zApiError.safeParse(value);
    throw new MeshSpanApiError(
      response.status,
      parsedError.success ? parsedError.data : undefined,
    );
  }
  if (response.headers.get("content-type") !== "application/octet-stream") {
    throw new TypeError("file response is not application/octet-stream");
  }
  const version = response.headers.get("MeshSpan-File-Version");
  if (version === null || !FILE_VERSION_PATTERN.test(version)) {
    throw new TypeError("file response has an invalid immutable version");
  }
  const offset = parseSafeDecimalHeader(
    response.headers.get("MeshSpan-Read-Offset"),
  );
  if (offset !== expectedOffset) {
    throw new TypeError("file response has an unexpected range offset");
  }
  rejectOversizedContentLength(
    response.headers.get("content-length"),
    maximumBytes,
  );
  const bytes = await readBoundedBytes(response.body, maximumBytes);
  return { bytes, fileVersionId: version, offset };
}

function mutationHeaders(
  contentType: string,
  csrfToken?: string,
): Record<string, string> {
  if (csrfToken === undefined) {
    return { "Content-Type": contentType };
  }
  if (!CSRF_TOKEN_PATTERN.test(csrfToken)) {
    throw new TypeError("request has an invalid MeshSpan CSRF token");
  }
  return {
    "Content-Type": contentType,
    "MeshSpan-CSRF-Token": csrfToken,
  };
}

function readCsrfToken(headers: Headers): string {
  const token = headers.get("MeshSpan-CSRF-Token");
  if (token === null || !CSRF_TOKEN_PATTERN.test(token)) {
    throw new TypeError("response has an invalid MeshSpan CSRF token");
  }
  return token;
}

function normalizeApiRoot(value: string): URL {
  const apiRoot = new URL(value);
  if (apiRoot.username || apiRoot.password) {
    throw new TypeError("the MeshSpan API URL must not contain credentials");
  }
  if (!apiRoot.pathname.endsWith("/")) {
    apiRoot.pathname += "/";
  }
  return apiRoot;
}

function resolveRoute(apiRoot: URL, route: string): URL {
  if (route.startsWith("/api/")) {
    return new URL(route, apiRoot.origin);
  }
  return new URL(route.replace(/^\/+/, ""), apiRoot);
}

function validateContractHeaders(response: Response): void {
  if (response.headers.get("MeshSpan-API-Version") !== "latest") {
    throw new TypeError("response has an unexpected MeshSpan API version");
  }
  const digest = response.headers.get("MeshSpan-API-Schema");
  if (digest === null || !SCHEMA_DIGEST_PATTERN.test(digest)) {
    throw new TypeError("response has an invalid MeshSpan API schema digest");
  }
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type");
  if (!contentType?.startsWith("application/json")) {
    throw new TypeError("response is not application/json");
  }
  rejectOversizedContentLength(
    response.headers.get("content-length"),
    MAX_JSON_RESPONSE_BYTES,
  );
  const bytes = await readBoundedBytes(response.body, MAX_JSON_RESPONSE_BYTES);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(text) as unknown;
}

function validateDirectoryPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("directory page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  validateDirectoryPageLocation(apiRoot, route);
  validateDirectoryPageQuery(route);
  return route.pathname + route.search;
}

function validateDirectoryPageLocation(apiRoot: URL, route: URL): void {
  const segments = route.pathname.split("/");
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    segments.length !== 6 ||
    segments[1] !== "api" ||
    segments[2] !== "latest" ||
    segments[3] !== "volumes" ||
    segments[5] !== "directory-entries"
  ) {
    throw new TypeError("directory page URL is outside the native file API");
  }
  zListDirectoryPath.parse({ volume_id: segments[4] });
}

function validateDirectoryPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some(
      (name) => name !== "cursor" && name !== "limit" && name !== "path",
    ) ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("directory page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  const query = zListDirectoryQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
    path: route.searchParams.get("path") ?? undefined,
  });
  if (query.path !== undefined) {
    validateNamespacePath(query.path);
  }
}

function validatePrincipalPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("principal page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  validatePrincipalPageLocation(apiRoot, route);
  validatePrincipalPageQuery(route);
  return route.pathname + route.search;
}

function validatePrincipalPageLocation(apiRoot: URL, route: URL): void {
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    !["/api/latest/admin/groups", "/api/latest/admin/users"].includes(
      route.pathname,
    )
  ) {
    throw new TypeError("principal page URL is outside the administration API");
  }
}

function validatePrincipalPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("principal page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  const query = {
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  };
  if (route.pathname.endsWith("/groups")) {
    zListGroupsQuery.parse(query);
  } else {
    zListUsersQuery.parse(query);
  }
}

function validateGroupMembershipPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("group-membership page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  const prefix = "/api/latest/admin/groups/";
  const suffix = "/members";
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    !route.pathname.startsWith(prefix) ||
    !route.pathname.endsWith(suffix)
  ) {
    throw new TypeError(
      "group-membership page URL is outside the administration API",
    );
  }
  const groupId = route.pathname.slice(prefix.length, -suffix.length);
  zListGroupMembersPath.parse({ group_id: groupId });
  validateGroupMembershipPageQuery(route);
  return route.pathname + route.search;
}

function validateGroupMembershipPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("group-membership page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListGroupMembersQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}

function validateAuthenticationMethodPageUrl(
  apiRoot: URL,
  value: string,
): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("authentication-method page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== "/api/latest/users/current/authentication-methods"
  ) {
    throw new TypeError(
      "authentication-method page URL is outside the current-user API",
    );
  }
  validateAuthenticationMethodPageQuery(route);
  return route.pathname + route.search;
}

function validateAuthenticationMethodPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError(
      "authentication-method page URL has invalid query fields",
    );
  }
  const rawLimit = route.searchParams.get("limit");
  zListCurrentUserAuthenticationMethodsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}

function validateManualDnsTaskPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("manual DNS task page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== "/api/latest/admin/certificate-tasks/manual-dns"
  ) {
    throw new TypeError(
      "manual DNS task page URL is outside the administration API",
    );
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("manual DNS task page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListManualDnsTasksQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

const VOLUME_RIGHT_ORDER = [
  "traverse",
  "list",
  "read_data",
  "create_child",
  "write_data",
  "append_data",
  "rename",
  "delete",
  "read_attributes",
  "write_attributes",
  "read_permissions",
  "change_permissions",
  "change_owner",
] as const;

function validateVolumePage(page: ListVolumesResponse): ListVolumesResponse {
  for (const volume of page.volumes) {
    validateVolumeRights(volume.effective_rights);
  }
  return page;
}

function validateVolumeRights(rights: readonly string[]): void {
  let previous = -1;
  for (const right of rights) {
    const position = VOLUME_RIGHT_ORDER.indexOf(
      right as (typeof VOLUME_RIGHT_ORDER)[number],
    );
    if (position <= previous) {
      throw new TypeError("volume rights are duplicated or out of order");
    }
    previous = position;
  }
  if (rights[0] !== "traverse" || rights[1] !== "list") {
    throw new TypeError("volume page contains a non-browseable volume");
  }
}

function validateVolumePageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("volume page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== "/api/latest/volumes"
  ) {
    throw new TypeError("volume page URL is outside the volume API");
  }
  validateVolumePageQuery(route);
  return route.pathname + route.search;
}

function validateVolumePageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("volume page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListVolumesQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}

function validatePermissionGrantPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("permission-grant page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  const prefix = "/api/latest/admin/volumes/";
  const suffix = "/permission-grants";
  if (!isPermissionGrantPageRoute(apiRoot, route, prefix, suffix)) {
    throw new TypeError(
      "permission-grant page URL is outside the administration API",
    );
  }
  const volumeId = route.pathname.slice(prefix.length, -suffix.length);
  zListVolumePermissionGrantsPath.parse({ volume_id: volumeId });
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("permission-grant page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListVolumePermissionGrantsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

function isPermissionGrantPageRoute(
  apiRoot: URL,
  route: URL,
  prefix: string,
  suffix: string,
): boolean {
  return (
    route.origin === apiRoot.origin &&
    route.username === "" &&
    route.password === "" &&
    route.hash === "" &&
    route.pathname.startsWith(prefix) &&
    route.pathname.endsWith(suffix)
  );
}

function validateOperationPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("operation page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (!isOperationPageRoute(apiRoot, route)) {
    throw new TypeError("operation page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("operation page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListOperationsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

function isOperationPageRoute(apiRoot: URL, route: URL): boolean {
  return (
    route.origin === apiRoot.origin &&
    route.username === "" &&
    route.password === "" &&
    route.hash === "" &&
    route.pathname === "/api/latest/admin/operations"
  );
}

function validateStorageDrainPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("storage-drain page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== "/api/latest/admin/storage-drains"
  ) {
    throw new TypeError(
      "storage-drain page URL is outside the administration API",
    );
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("storage-drain page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListStorageDrainsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

function validateStorageFolderPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("storage-folder page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== "/api/latest/admin/storage-folders"
  ) {
    throw new TypeError(
      "storage-folder page URL is outside the administration API",
    );
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("storage-folder page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListStorageFoldersQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

function validateTopologyPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("topology page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    ![
      "/api/latest/admin/topology/nodes",
      "/api/latest/admin/topology/targets",
      "/api/latest/admin/topology/fault-groups",
      "/api/latest/admin/topology/fault-group-memberships",
    ].includes(route.pathname)
  ) {
    throw new TypeError("topology page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("topology page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListTopologyNodesQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}
