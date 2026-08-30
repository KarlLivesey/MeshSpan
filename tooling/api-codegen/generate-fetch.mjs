// SPDX-License-Identifier: GPL-2.0-only

import { open, readFile, rename, writeFile } from "node:fs/promises";

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
  ApiError,
  CreateMeshSetupRequestWritable,
  CreateMeshSetupResponse,
  CreateSessionRequestWritable,
  CreateSessionResponse,
  CurrentSessionResponse,
  HealthResponse,
  SetupStatusResponse,
} from "./types.gen";
import {
  zApiError,
  zCreateMeshSetupBody,
  zCreateMeshSetupResponse2,
  zCreateSessionBody,
  zCreateSessionResponse2,
  zGetCurrentSessionResponse,
  zGetHealthResponse,
  zGetOpenApiResponse,
  zGetSetupStatusResponse,
} from "./zod.gen";

const MAX_JSON_RESPONSE_BYTES = 65_536;
const SCHEMA_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CSRF_TOKEN_PATTERN = ${regexLiteral(routes.createSession.csrfPattern)};

export type MeshSpanFetchClientOptions = Readonly<{
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
}>;

export type CreateSessionResult = Readonly<{
  csrfToken: string;
  session: CreateSessionResponse;
}>;

export interface MeshSpanFetchClient {
  createMeshSetup(request: CreateMeshSetupRequestWritable): Promise<CreateMeshSetupResponse>;
  createSession(request: CreateSessionRequestWritable): Promise<CreateSessionResult>;
  getCurrentSession(): Promise<CurrentSessionResponse>;
  getHealth(): Promise<HealthResponse>;
  getOpenApi(): Promise<Record<string, unknown>>;
  getSetupStatus(): Promise<SetupStatusResponse>;
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
  fetch: typeof globalThis.fetch;
}

export function createMeshSpanFetchClient(
  options: MeshSpanFetchClientOptions,
): MeshSpanFetchClient {
  const context: RequestContext = {
    apiRoot: normalizeApiRoot(options.baseUrl),
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
  };

  return {
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
  const headers = new Headers(request.headers);
  headers.set("Accept", "application/json");
  const response = await context.fetch(resolveRoute(context.apiRoot, route), {
    ...request,
    credentials: "same-origin",
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
  return new URL(route.replace(/^\\/+/, ""), apiRoot);
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
  rejectOversizedContentLength(response.headers.get("content-length"));
  const bytes = await readBoundedBytes(response.body);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(text) as unknown;
}

function rejectOversizedContentLength(value: string | null): void {
  if (value === null) {
    return;
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError("response has an invalid Content-Length");
  }
  if (length > MAX_JSON_RESPONSE_BYTES) {
    throw new RangeError("response exceeds the JSON byte limit");
  }
}

async function readBoundedBytes(
  body: ReadableStream<Uint8Array> | null,
): Promise<Uint8Array> {
  if (body === null) {
    throw new TypeError("response has no body");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let totalLength = 0;

  for (;;) {
    const result = await reader.read();
    if (result.done) {
      break;
    }
    totalLength += result.value.byteLength;
    if (totalLength > MAX_JSON_RESPONSE_BYTES) {
      await reader.cancel();
      throw new RangeError("response exceeds the JSON byte limit");
    }
    chunks.push(result.value);
  }

  const bytes = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
`;

await writeAtomically(OUTPUT_PATH, source);
const generatedIndex = await readFile(INDEX_PATH, "utf8");
await writeAtomically(
  INDEX_PATH,
  `${generatedIndex}export * from './fetch.gen';\n`,
);

function parseContract(sourceText) {
  const document = JSON.parse(sourceText);
  if (!isRecord(document)) {
    throw new Error("expected the OpenAPI document to be an object");
  }
  if (document.openapi !== "3.1.0") {
    throw new Error("expected an OpenAPI 3.1.0 document");
  }
  const info = requireRecord(document.info, "info");
  const license = requireRecord(info.license, "info.license");
  if (license.identifier !== "GPL-2.0-only") {
    throw new Error("expected the exact GPL-2.0-only identifier");
  }
  requireRecord(document.paths, "paths");
  return document;
}

function readRequiredRoutes(document) {
  const operations = new Map();
  const paths = requireRecord(document.paths, "paths");
  for (const [route, rawPathItem] of Object.entries(paths)) {
    if (!route.startsWith("/") || route.length > 256) {
      throw new Error(`invalid OpenAPI route: ${route}`);
    }
    const pathItem = requireRecord(rawPathItem, `paths.${route}`);
    for (const [method, rawOperation] of Object.entries(pathItem)) {
      if (!/^(?:get|post|put|patch|delete)$/.test(method)) {
        throw new Error(`unsupported OpenAPI path member: ${route} ${method}`);
      }
      const operation = requireRecord(rawOperation, `paths.${route}.${method}`);
      const operationId = operation.operationId;
      if (
        typeof operationId !== "string" ||
        !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(operationId)
      ) {
        throw new Error(
          `invalid operationId for ${method.toUpperCase()} ${route}`,
        );
      }
      if (operations.has(operationId)) {
        throw new Error(`duplicate operationId: ${operationId}`);
      }
      operations.set(operationId, {
        method: method.toUpperCase(),
        operation,
        route,
      });
    }
  }
  return {
    createMeshSetup: requireOperation(operations, "createMeshSetup"),
    createSession: readSessionOperation(
      requireOperation(operations, "createSession"),
    ),
    getHealth: requireOperation(operations, "getHealth"),
    getCurrentSession: requireOperation(operations, "getCurrentSession"),
    getOpenApi: requireOperation(operations, "getOpenApi"),
    getSetupStatus: requireOperation(operations, "getSetupStatus"),
  };
}

function readSessionOperation(operation) {
  const responses = requireRecord(
    operation.operation.responses,
    "createSession.responses",
  );
  const created = requireRecord(
    responses["201"],
    "createSession.responses.201",
  );
  const headers = requireRecord(
    created.headers,
    "createSession.responses.201.headers",
  );
  const csrf = requireRecord(
    headers["MeshSpan-CSRF-Token"],
    "createSession CSRF header",
  );
  const schema = requireRecord(csrf.schema, "createSession CSRF header schema");
  if (typeof schema.pattern !== "string" || schema.pattern.length > 256) {
    throw new Error("createSession CSRF header requires one bounded pattern");
  }
  return { ...operation, csrfPattern: schema.pattern };
}

function regexLiteral(pattern) {
  if (/[\r\n]/u.test(pattern)) {
    throw new Error("regular expression pattern must occupy one line");
  }
  return `/${pattern.replaceAll("/", "\\/")}/u`;
}

function requireOperation(operations, operationId) {
  const operation = operations.get(operationId);
  if (operation === undefined) {
    throw new Error(`missing required operation: ${operationId}`);
  }
  return operation;
}

function requireRecord(value, location) {
  if (!isRecord(value)) {
    throw new Error(`expected ${location} to be an object`);
  }
  return value;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readBoundedUtf8(sourcePath) {
  const handle = await open(sourcePath, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > 1_048_576) {
      throw new Error(
        "OpenAPI input must be a regular file no larger than 1 MiB",
      );
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

async function writeAtomically(destination, contents) {
  const temporary = new URL(`${destination.href}.tmp`);
  await writeFile(temporary, contents, "utf8");
  await rename(temporary, destination);
}
