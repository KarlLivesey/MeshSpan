// SPDX-License-Identifier: GPL-2.0-only

/** Encodes a validated native-API query without accepting repeated fields. */
export function appendQuery(
  route: string,
  query: Readonly<Record<string, string | number | undefined>>,
): string {
  const parameters = new URLSearchParams();
  for (const [name, value] of Object.entries(query)) {
    if (value !== undefined) {
      parameters.set(name, String(value));
    }
  }
  const encoded = parameters.toString();
  return encoded === "" ? route : `${route}?${encoded}`;
}

/** Substitutes one OpenAPI path parameter without permitting route injection. */
export function substitutePathParameter(
  route: string,
  name: string,
  value: string,
): string {
  const placeholder = `{${name}}`;
  if (!route.includes(placeholder)) {
    throw new TypeError("generated route is missing a required path parameter");
  }
  return route.replace(placeholder, encodeURIComponent(value));
}

/** Adds a configured headless credential without exposing it to query strings. */
export function authenticatedHeaders(
  authorization: string | undefined,
  initial?: HeadersInit,
): Headers {
  const headers = new Headers(initial);
  if (authorization !== undefined) {
    headers.set("Authorization", authorization);
  }
  return headers;
}

/** Enforces path semantics which JSON Schema cannot express readably. */
export function validateNamespacePath(value: string): void {
  if (
    value.startsWith("/") ||
    value.endsWith("/") ||
    value
      .split("/")
      .some(
        (component) =>
          component === "" || component === "." || component === "..",
      )
  ) {
    throw new TypeError("request has an invalid MeshSpan namespace path");
  }
}

/** Parses one canonical non-negative integer response header without precision loss. */
export function parseSafeDecimalHeader(value: string | null): number {
  if (value === null || !/^(?:0|[1-9]\d*)$/u.test(value)) {
    throw new TypeError("response has an invalid decimal header");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new TypeError("response has an unsafe decimal header");
  }
  return parsed;
}
