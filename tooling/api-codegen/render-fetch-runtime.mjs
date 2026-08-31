// SPDX-License-Identifier: GPL-2.0-only

/** Renders the bounded, authenticated transport shared by native API methods. */
export function renderFetchRuntime() {
  return [
    renderJsonRuntime(),
    renderFileReadRuntime(),
    renderContractRuntime(),
  ].join("\n\n");
}

function renderJsonRuntime() {
  return `async function requestJson<T>(
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
}`;
}

function renderFileReadRuntime() {
  return `async function requestFileRange(
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
}`;
}

function renderContractRuntime() {
  return `function mutationHeaders(
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
  rejectOversizedContentLength(
    response.headers.get("content-length"),
    MAX_JSON_RESPONSE_BYTES,
  );
  const bytes = await readBoundedBytes(response.body, MAX_JSON_RESPONSE_BYTES);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(text) as unknown;
}`;
}
