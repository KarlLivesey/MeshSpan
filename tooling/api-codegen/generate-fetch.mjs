// SPDX-License-Identifier: GPL-2.0-only

import { readFile } from "node:fs/promises";

import {
  parseContract,
  readBoundedUtf8,
  readRequiredRoutes,
  regexLiteral,
  writeAtomically,
} from "./fetch-contract.mjs";
import {
  renderUploadClientInterface,
  renderUploadClientMethods,
  renderUploadRequestTypes,
} from "./render-upload-client.mjs";
import {
  renderNamespaceMutationClientInterface,
  renderNamespaceMutationClientMethods,
} from "./render-namespace-mutation-client.mjs";
import { renderFetchRuntime } from "./render-fetch-runtime.mjs";

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
  ApiError,
  BeginUploadRequest,
  BeginUploadResponse,
  CommitUploadRequest,
  CommitUploadResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateDirectoryRequest,
  CreateDirectoryResponse,
  CreateMeshSetupRequestWritable,
  CreateMeshSetupResponse,
  CreateSessionRequestWritable,
  CreateSessionResponse,
  CurrentSessionResponse,
  DeleteObjectRequest,
  DeleteObjectResponse,
  GetObjectResponse,
  HealthResponse,
  ListDirectoryResponse,
  ListUploadRangesResponse,
  RevokeAuthenticationMethodRequest,
  RevokeAuthenticationMethodResponse,
  RevokeCurrentSessionRequest,
  RevokeCurrentSessionResponse,
  RenameObjectRequest,
  RenameObjectResponse,
  SetupStatusResponse,
  UploadStatusResponse,
  WriteUploadRangeResponse,
} from "./types.gen";
import {
  zAbortUploadBody,
  zAbortUploadPath,
  zAbortUploadResponse2,
  zApiError,
  zBeginUploadBody,
  zBeginUploadPath,
  zBeginUploadResponse2,
  zCommitUploadBody,
  zCommitUploadPath,
  zCommitUploadResponse2,
  zCreateCurrentUserApiKeyBody,
  zCreateCurrentUserApiKeyResponse,
  zCreateDirectoryBody,
  zCreateDirectoryPath,
  zCreateDirectoryResponse2,
  zCreateMeshSetupBody,
  zCreateMeshSetupResponse2,
  zCreateSessionBody,
  zCreateSessionResponse2,
  zDeleteObjectBody,
  zDeleteObjectPath,
  zDeleteObjectResponse2,
  zGetCurrentSessionResponse,
  zGetHealthResponse,
  zGetObjectPath,
  zGetObjectQuery,
  zGetObjectResponse2,
  zGetOpenApiResponse,
  zGetSetupStatusResponse,
  zGetUploadPath,
  zGetUploadResponse,
  zListDirectoryPath,
  zListDirectoryQuery,
  zListDirectoryResponse2,
  zListUploadRangesPath,
  zListUploadRangesQuery,
  zListUploadRangesResponse2,
  zReadFilePath,
  zReadFileQuery,
  zRevokeCurrentUserAuthenticationMethodBody,
  zRevokeCurrentUserAuthenticationMethodPath,
  zRevokeCurrentUserAuthenticationMethodResponse,
  zRevokeCurrentSessionBody,
  zRevokeCurrentSessionResponse2,
  zRenameObjectBody,
  zRenameObjectPath,
  zRenameObjectResponse2,
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

${renderUploadRequestTypes()}

export type CreateSessionResult = Readonly<{
  csrfToken: string;
  session: CreateSessionResponse;
}>;

export interface MeshSpanFetchClient {
  ${renderNamespaceMutationClientInterface()}
  ${renderUploadClientInterface()}
  createCurrentUserApiKey(
    request: CreateApiKeyRequest,
    csrfToken: string,
  ): Promise<CreateApiKeyResponse>;
  createMeshSetup(request: CreateMeshSetupRequestWritable): Promise<CreateMeshSetupResponse>;
  createSession(request: CreateSessionRequestWritable): Promise<CreateSessionResult>;
  getCurrentSession(): Promise<CurrentSessionResponse>;
  getObject(request: GetObjectRequest): Promise<GetObjectResponse>;
  getHealth(): Promise<HealthResponse>;
  getOpenApi(): Promise<Record<string, unknown>>;
  getSetupStatus(): Promise<SetupStatusResponse>;
  listDirectory(request: ListDirectoryRequest): Promise<ListDirectoryResponse>;
  readFile(request: ReadFileRequest): Promise<ReadFileResult>;
  revokeCurrentSession(
    request: RevokeCurrentSessionRequest,
    csrfToken: string,
  ): Promise<RevokeCurrentSessionResponse>;
  revokeCurrentUserAuthenticationMethod(
    methodId: string,
    request: RevokeAuthenticationMethodRequest,
    csrfToken: string,
  ): Promise<RevokeAuthenticationMethodResponse>;
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
      options.apiKey === undefined ? undefined : \`Bearer \${options.apiKey}\`,
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
  };

  return {
    ${renderNamespaceMutationClientMethods(routes)}
    ${renderUploadClientMethods(routes)}
    async createCurrentUserApiKey(
      request,
      csrfToken,
    ): Promise<CreateApiKeyResponse> {
      const body = zCreateCurrentUserApiKeyBody.parse(request);
      if (!CSRF_TOKEN_PATTERN.test(csrfToken)) {
        throw new TypeError("request has an invalid MeshSpan CSRF token");
      }
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserApiKey.route)},
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: ${JSON.stringify(routes.createCurrentUserApiKey.method)},
        },
        zCreateCurrentUserApiKeyResponse,
      );
    },
    async createMeshSetup(request): Promise<CreateMeshSetupResponse> {
      const body = zCreateMeshSetupBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createMeshSetup.route)},
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.createMeshSetup.method)},
        },
        zCreateMeshSetupResponse2,
      );
    },
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
            ${JSON.stringify(routes.listDirectory.route)},
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.listDirectory.method)} },
        zListDirectoryResponse2,
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
    async revokeCurrentUserAuthenticationMethod(
      methodId,
      request,
      csrfToken,
    ): Promise<RevokeAuthenticationMethodResponse> {
      const path = zRevokeCurrentUserAuthenticationMethodPath.parse({
        method_id: methodId,
      });
      const body = zRevokeCurrentUserAuthenticationMethodBody.parse(request);
      if (!CSRF_TOKEN_PATTERN.test(csrfToken)) {
        throw new TypeError("request has an invalid MeshSpan CSRF token");
      }
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.revokeCurrentUserAuthenticationMethod.route)},
          "method_id",
          path.method_id,
        ),
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: ${JSON.stringify(routes.revokeCurrentUserAuthenticationMethod.method)},
        },
        zRevokeCurrentUserAuthenticationMethodResponse,
      );
    },
  };
}

${renderFetchRuntime()}

`;

await writeAtomically(OUTPUT_PATH, source);
const generatedIndex = await readFile(INDEX_PATH, "utf8");
await writeAtomically(
  INDEX_PATH,
  `${generatedIndex}export * from './fetch.gen';\n`,
);
