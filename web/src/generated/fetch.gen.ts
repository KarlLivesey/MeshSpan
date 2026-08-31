// SPDX-License-Identifier: GPL-2.0-only
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
  CreateMeshSetupRequestWritable,
  CreateMeshSetupResponse,
  CreateSessionRequestWritable,
  CreateSessionResponse,
  CurrentSessionResponse,
  GetObjectResponse,
  HealthResponse,
  ListDirectoryResponse,
  ListUploadRangesResponse,
  RevokeAuthenticationMethodRequest,
  RevokeAuthenticationMethodResponse,
  RevokeCurrentSessionRequest,
  RevokeCurrentSessionResponse,
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
  zCreateMeshSetupBody,
  zCreateMeshSetupResponse2,
  zCreateSessionBody,
  zCreateSessionResponse2,
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
  createCurrentUserApiKey(
    request: CreateApiKeyRequest,
    csrfToken: string,
  ): Promise<CreateApiKeyResponse>;
  createMeshSetup(
    request: CreateMeshSetupRequestWritable,
  ): Promise<CreateMeshSetupResponse>;
  createSession(
    request: CreateSessionRequestWritable,
  ): Promise<CreateSessionResult>;
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
      options.apiKey === undefined ? undefined : `Bearer ${options.apiKey}`,
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
  };

  return {
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
        "/users/current/authentication-methods/api-keys",
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: "POST",
        },
        zCreateCurrentUserApiKeyResponse,
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
          "/users/current/authentication-methods/{method_id}/revocations",
          "method_id",
          path.method_id,
        ),
        {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-CSRF-Token": csrfToken,
          },
          method: "POST",
        },
        zRevokeCurrentUserAuthenticationMethodResponse,
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
