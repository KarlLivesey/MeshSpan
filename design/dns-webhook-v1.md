# DNS automation webhook v1

Status: **implemented contract**.

This optional provider lets MeshSpan automate DNS-01 against a DNS system for which no built-in
adapter exists. It does not weaken the appliance default: RFC 2136 and Cloudflare run directly in
process, and manual DNS remains available. Configuring a webhook explicitly authorises outbound
HTTPS requests to that exact endpoint.

## Transport

- MeshSpan sends `POST` to the configured `https://` URL using its configured TLS trust roots.
- `Authorization: Bearer <configured token>` authenticates every request.
- `Content-Type` is `application/json`; redirects are not followed.
- Connection and whole-request deadlines are finite and configurable within MeshSpan's bounds.
- The token is protected configuration, is never placed in the request JSON or URL, and must not
  be logged by either side.

## Request

The body contains exactly one idempotent record operation:

```json
{
  "action": "publish",
  "name": "_acme-challenge.example.test",
  "ownership": "meshspan-acme:<64 lowercase hexadecimal characters>",
  "value": "unquoted-ACME-TXT-value",
  "version": 1
}
```

`action` is `publish` or `remove`. `name`, `value` and `ownership` form the complete record
identity. The ownership marker is deterministic for the endpoint, record and fenced ACME order,
contains no credential material, and survives daemon restart.

`publish` MUST ensure that exact TXT value exists without creating duplicates. `remove` MUST
remove only that exact owned value and MUST succeed when it is already absent. A changed value or
ownership marker MUST NOT be removed.

## Response

A successful operation returns status `200` and exactly:

```json
{
  "accepted": true,
  "ownership": "meshspan-acme:<the exact request marker>",
  "version": 1
}
```

MeshSpan rejects duplicate or additional JSON members, wrong types, versions or ownership. Status
`401` and `403` are authentication failures. Other statuses, malformed bodies, TLS failures and
timeouts fail closed as unavailable and may be retried by the fenced ACME worker.

The response proves only that the automation endpoint accepted the exact idempotent operation.
MeshSpan separately queries authoritative DNS and does not tell the ACME server to continue until
the exact TXT value is visible there.
