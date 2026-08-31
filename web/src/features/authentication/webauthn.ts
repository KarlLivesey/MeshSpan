// SPDX-License-Identifier: GPL-2.0-only

import type {
  CreatePasskeyChallengeResponse,
  CreatePasskeyRegistrationChallengeResponse,
  CreatePasskeyRegistrationRequestWritable,
  CreateSessionRequestWritable,
} from "../../generated/types.gen";

type PasskeyAuthentication = Extract<
  CreateSessionRequestWritable["authentication"],
  { method: "passkey" }
>;
type PasskeyTransport =
  CreatePasskeyRegistrationRequestWritable["transports"][number];

const MAXIMUM_TRANSPORTS = 6;

/** Returns the browser credential container through a hostile-runtime check. */
export function browserCredentials(): CredentialsContainer {
  const navigatorValue = Reflect.get(globalThis, "navigator") as unknown;
  const navigatorRecord = readRecord(navigatorValue, "browser navigator");
  const credentials = readRecord(
    navigatorRecord["credentials"],
    "browser credential container",
  );
  if (
    typeof credentials["create"] !== "function" ||
    typeof credentials["get"] !== "function"
  ) {
    throw new TypeError("this browser does not expose passkey credentials");
  }
  return credentials as unknown as CredentialsContainer;
}

/** Runs one discoverable passkey assertion and returns bounded API evidence. */
export async function requestPasskeyAssertion(
  challenge: CreatePasskeyChallengeResponse,
  credentials: CredentialsContainer,
): Promise<PasskeyAuthentication> {
  const rawCredential = await credentials.get({
    publicKey: {
      challenge: decodeBase64Url(challenge.challenge),
      rpId: challenge.relying_party_id,
      timeout: challenge.timeout_milliseconds,
      userVerification: challenge.user_verification,
    },
  });
  const credential = readPublicKeyCredential(rawCredential);
  const response = readRecord(credential.response, "passkey response");
  return {
    authenticator_data: encodeBuffer(
      response["authenticatorData"],
      2_048,
      "authenticator data",
    ),
    challenge_id: challenge.challenge_id,
    client_data_json: encodeBuffer(
      response["clientDataJSON"],
      4_096,
      "client data",
    ),
    credential_id: encodeBuffer(credential.rawId, 1_024, "credential ID"),
    method: "passkey",
    signature: encodeBuffer(response["signature"], 1_024, "signature"),
    user_handle:
      response["userHandle"] === null || response["userHandle"] === undefined
        ? null
        : encodeBuffer(response["userHandle"], 1_024, "user handle"),
  };
}

/** Runs one passkey registration and returns bounded API evidence. */
export async function requestPasskeyRegistration(
  challenge: CreatePasskeyRegistrationChallengeResponse,
  label: string,
  operationId: string,
  credentials: CredentialsContainer,
): Promise<CreatePasskeyRegistrationRequestWritable> {
  const rawCredential = await credentials.create({
    publicKey: {
      attestation: challenge.attestation,
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: challenge.resident_key,
        userVerification: challenge.user_verification,
      },
      challenge: decodeBase64Url(challenge.challenge),
      excludeCredentials: challenge.exclude_credentials.map((credential) => ({
        id: decodeBase64Url(credential.id),
        type: credential.type,
      })),
      pubKeyCredParams: challenge.public_key_parameters.map((parameter) => ({
        alg: parameter.algorithm,
        type: parameter.type,
      })),
      rp: {
        id: challenge.relying_party_id,
        name: challenge.relying_party_name,
      },
      timeout: challenge.timeout_milliseconds,
      user: {
        displayName: challenge.user_display_name,
        id: decodeBase64Url(challenge.user_id),
        name: challenge.user_name,
      },
    },
  });
  const credential = readPublicKeyCredential(rawCredential);
  const response = readRecord(credential.response, "passkey response");
  return {
    attestation_object: encodeBuffer(
      response["attestationObject"],
      16_384,
      "attestation object",
    ),
    challenge_id: challenge.challenge_id,
    client_data_json: encodeBuffer(
      response["clientDataJSON"],
      4_096,
      "client data",
    ),
    credential_id: encodeBuffer(credential.rawId, 1_024, "credential ID"),
    label,
    operation_id: operationId,
    transports: readTransports(response),
  };
}

function readPublicKeyCredential(value: Credential | null): {
  rawId: unknown;
  response: unknown;
} {
  const credential = readRecord(value, "passkey credential");
  if (credential["type"] !== "public-key") {
    throw new TypeError("the authenticator returned a non-passkey credential");
  }
  return { rawId: credential["rawId"], response: credential["response"] };
}

function readTransports(
  response: Readonly<Record<string, unknown>>,
): PasskeyTransport[] {
  const getTransports = response["getTransports"];
  if (getTransports === undefined) {
    return [];
  }
  if (typeof getTransports !== "function") {
    throw new TypeError("the authenticator returned invalid transports");
  }
  const values = Reflect.apply(getTransports, response, []) as unknown;
  if (
    !Array.isArray(values) ||
    values.length > MAXIMUM_TRANSPORTS ||
    values.some((value) => !isPasskeyTransport(value))
  ) {
    throw new TypeError("the authenticator returned invalid transports");
  }
  return values as PasskeyTransport[];
}

function isPasskeyTransport(value: unknown): value is PasskeyTransport {
  return (
    value === "ble" ||
    value === "hybrid" ||
    value === "internal" ||
    value === "nfc" ||
    value === "smart-card" ||
    value === "usb"
  );
}

function readRecord(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`the authenticator returned an invalid ${label}`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function encodeBuffer(
  value: unknown,
  maximumBytes: number,
  label: string,
): string {
  const bytes = readBytes(value, maximumBytes, label);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return removeBase64Padding(
    btoa(binary).replaceAll("+", "-").replaceAll("/", "_"),
  );
}

function decodeBase64Url(value: string): ArrayBuffer {
  if (value.length === 0 || value.length > 21_846 || !/^[\w-]+$/u.test(value)) {
    throw new TypeError("the server returned invalid passkey bytes");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(
    value.replaceAll("-", "+").replaceAll("_", "/") + padding,
  );
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBuffer(bytes.buffer, bytes.byteLength, "passkey bytes") !== value) {
    throw new TypeError("the server returned non-canonical passkey bytes");
  }
  return bytes.buffer;
}

function readBytes(
  value: unknown,
  maximumBytes: number,
  label: string,
): Uint8Array {
  let bytes: Uint8Array;
  if (value instanceof ArrayBuffer) {
    bytes = new Uint8Array(value);
  } else if (ArrayBuffer.isView(value)) {
    bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  } else {
    throw new TypeError(`the authenticator returned invalid ${label}`);
  }
  if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes) {
    throw new RangeError(`the authenticator returned oversized ${label}`);
  }
  return bytes;
}

function removeBase64Padding(value: string): string {
  if (value.endsWith("==")) {
    return value.slice(0, -2);
  }
  return value.endsWith("=") ? value.slice(0, -1) : value;
}
