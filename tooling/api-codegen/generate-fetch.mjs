// SPDX-License-Identifier: GPL-2.0-only

import { readFile } from "node:fs/promises";

import {
  parseContract,
  readBoundedUtf8,
  readRequiredRoutes,
  regexLiteral,
  writeAtomically,
} from "./fetch-contract.mjs";
import { renderUploadClientMethods } from "./render-upload-client.mjs";
import { renderNamespaceMutationClientMethods } from "./render-namespace-mutation-client.mjs";
import { renderFetchRuntime } from "./render-fetch-runtime.mjs";
import {
  renderIdentityAdministrationClientMethods,
  renderIdentityAdministrationRuntime,
} from "./render-identity-administration-client.mjs";
import {
  renderAuthenticationClientMethods,
  renderAuthenticationClientRuntime,
} from "./render-authentication-client.mjs";
import {
  renderVolumeClientMethods,
  renderVolumeClientRuntime,
} from "./render-volume-client.mjs";
import {
  renderDirectoryClientMethods,
  renderDirectoryClientRuntime,
} from "./render-directory-client.mjs";
import {
  renderPermissionAdministrationClientMethods,
  renderPermissionAdministrationRuntime,
} from "./render-permission-administration-client.mjs";
import {
  renderOperationStatusClientMethods,
  renderOperationStatusRuntime,
} from "./render-operation-status-client.mjs";
import { renderSetupClientMethods } from "./render-setup-client.mjs";
import {
  renderStorageFolderClientMethods,
  renderStorageFolderRuntime,
} from "./render-storage-folder-client.mjs";
import { renderClientContract } from "./render-client-contract.mjs";
import {
  renderTopologyClientMethods,
  renderTopologyRuntime,
} from "./render-topology-client.mjs";

const OPENAPI_PATH = new URL(
  "../../contracts/openapi/latest.json",
  import.meta.url,
);
const OUTPUT_PATH = new URL(
  "../../web/src/generated/fetch.gen.ts",
  import.meta.url,
);
const INDEX_PATH = new URL("../../web/src/generated/index.ts", import.meta.url);

const openApi = parseContract(await readBoundedUtf8(OPENAPI_PATH));
const routes = readRequiredRoutes(openApi);

const source = `// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

import type {
  AbortUploadRequest,
  AbortUploadResponse,
  AddGroupMemberRequest,
  AddGroupMemberResponse,
  ApiError,
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
  ListOperationsResponse,
  ListAuthenticationMethodsResponse,
  ListPrincipalsResponse,
  ListStorageFoldersResponse,
  ListTopologyNodesResponse,
  ListTopologyTargetsResponse,
  ListUploadRangesResponse,
  ListVolumePermissionGrantsResponse,
  ListVolumesResponse,
  OperationStatusResponse,
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
  SetFaultGroupMembershipRequest,
  SetFaultGroupMembershipResponse,
  StepUpCurrentSessionRequestWritable,
  UploadStatusResponse,
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
  zGetCurrentSessionResponse,
  zGetHealthResponse,
  zGetObjectPath,
  zGetObjectQuery,
  zGetObjectResponse2,
  zGetOperationStatusPath,
  zGetOperationStatusResponse,
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
  zListOperationsQuery,
  zListOperationsResponse,
  zListStorageFoldersQuery,
  zListStorageFoldersResponse2,
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
const CSRF_TOKEN_PATTERN = ${regexLiteral(routes.createSession.csrfPattern)};
const API_KEY_PATTERN = /^meshspan-key-v1\\.[0-9a-f]{32}\\.[0-9a-f]{64}$/u;
const FILE_VERSION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

${renderClientContract()}

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
      options.apiKey === undefined ? undefined : \`Bearer \${options.apiKey}\`,
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
  };

  return {
    ${renderAuthenticationClientMethods(routes)}
    ${renderIdentityAdministrationClientMethods(routes)}
    ${renderNamespaceMutationClientMethods(routes)}
    ${renderUploadClientMethods(routes)}
    ${renderVolumeClientMethods(routes)}
    ${renderPermissionAdministrationClientMethods(routes)}
    ${renderOperationStatusClientMethods(routes)}
    ${renderStorageFolderClientMethods(routes)}
    ${renderTopologyClientMethods(routes)}
    ${renderDirectoryClientMethods(routes)}
    ${renderSetupClientMethods(routes)}
    async createSession(request): Promise<CreateSessionResult> {
      const body = zCreateSessionBody.parse(request);
      const response = await requestJsonResponse(
        context,
        ${JSON.stringify(routes.createSession.route)},
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.createSession.method)},
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
        ${JSON.stringify(routes.getHealth.route)},
        { method: ${JSON.stringify(routes.getHealth.method)} },
        zGetHealthResponse,
      );
    },
    async getCurrentSession(): Promise<CurrentSessionResponse> {
      return requestJson(
        context,
        ${JSON.stringify(routes.getCurrentSession.route)},
        { method: ${JSON.stringify(routes.getCurrentSession.method)} },
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
            ${JSON.stringify(routes.getObject.route)},
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.getObject.method)} },
        zGetObjectResponse2,
      );
    },
    async getOpenApi(): Promise<Record<string, unknown>> {
      return requestJson(
        context,
        ${JSON.stringify(routes.getOpenApi.route)},
        { method: ${JSON.stringify(routes.getOpenApi.method)} },
        zGetOpenApiResponse,
      );
    },
    async getSetupStatus(): Promise<SetupStatusResponse> {
      return requestJson(
        context,
        ${JSON.stringify(routes.getSetupStatus.route)},
        { method: ${JSON.stringify(routes.getSetupStatus.method)} },
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
            ${JSON.stringify(routes.readFile.route)},
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
        ${JSON.stringify(routes.revokeCurrentSession.route)},
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: ${JSON.stringify(routes.revokeCurrentSession.method)},
        },
        zRevokeCurrentSessionResponse2,
      );
    },
  };
}

${renderFetchRuntime()}

${renderDirectoryClientRuntime()}

${renderIdentityAdministrationRuntime(routes)}

${renderAuthenticationClientRuntime(routes)}

${renderVolumeClientRuntime(routes)}

${renderPermissionAdministrationRuntime()}

${renderOperationStatusRuntime()}

${renderStorageFolderRuntime(routes)}

${renderTopologyRuntime(routes)}

`;

await writeAtomically(OUTPUT_PATH, source);
const generatedIndex = await readFile(INDEX_PATH, "utf8");
await writeAtomically(
  INDEX_PATH,
  `${generatedIndex}export * from './fetch.gen';\n`,
);
