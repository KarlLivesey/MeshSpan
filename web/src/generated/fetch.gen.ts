// SPDX-License-Identifier: GPL-2.0-only
// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.

import type {
  ApiError,
  CreateSessionRequestWritable,
  CreateSessionResponse,
  HealthResponse,
  SetupStatusResponse,
} from "./types.gen";
import {
  zApiError,
  zCreateSessionBody,
  zCreateSessionResponse2,
  zGetHealthResponse,
  zGetOpenApiResponse,
  zGetSetupStatusResponse,
} from "./zod.gen";

const MAX_JSON_RESPONSE_BYTES = 65_536;
const SCHEMA_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export type MeshSpanFetchClientOptions = Readonly<{
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
}>;

export interface MeshSpanFetchClient {
  createSession(
    request: CreateSessionRequestWritable,
  ): Promise<CreateSessionResponse>;
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
    async createSession(request): Promise<CreateSessionResponse> {
      const body = zCreateSessionBody.parse(request);
      return requestJson(
        context,
        "/sessions",
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
        zCreateSessionResponse2,
      );
    },
    async getHealth(): Promise<HealthResponse> {
      return requestJson(
        context,
        "/health",
        { method: "GET" },
        zGetHealthResponse,
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
  };
}

async function requestJson<T>(
  context: RequestContext,
  route: string,
  request: RequestInit,
  parser: JsonParser<T>,
): Promise<T> {
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

  return parser.parse(value);
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
