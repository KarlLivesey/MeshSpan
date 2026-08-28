# Identity and access design

Status: **draft for review**.

## Principals and groups

Users and groups share a principal identity. Group membership points from a containing group to a
member principal, so a member may be a user or another group. The graph rejects self-membership and
cycles.

A materialised closure records direct and transitive membership with path count and minimum depth.
It makes access evaluation bounded and preserves diamond-shaped group graphs when one path is
removed. Membership changes update the edge, affected closure and global identity revision in one
transaction.

Disabling a principal invalidates its sessions and removes it from effective access without
destroying audit, ownership or historical references.

## Multiple owners

Ownership is a many-to-many relation:

```text
object_revisions(..., owner_set_id, ...)
object_owners(owner_set_id, owner_principal_id, assigned_by, assigned_at, revision)
```

- An object has one or more owner principals.
- Each owner may be a user or group.
- A user receives effective ownership through direct or transitive membership of an owning group.
- Ownership is stable rather than time-limited. Temporary control uses a permission grant.
- Removing the final active owner requires an atomic transfer.
- Ownership changes are audited and increment the object's authorisation revision.
- Ownership changes create a new immutable owner set and object revision; old
  namespace commits and snapshots retain the prior set.

Folders define a new-child ownership policy: `creator`, `inherit_owners`, or
`creator_and_inherit_owners`. The proposed default is `creator_and_inherit_owners`.

## Permission model

Permissions are allow-only. Absence denies access. A folder may stop
inheriting parent grants, avoiding complicated deny precedence.

One grant names:

```text
subject principal
volume and optional object scope
rights bitset
inheritance: object | descendants | object_and_descendants
optional valid-from instant
optional valid-until instant
optional activation policy
creator and revision
```

Rights are protocol-neutral:

```text
traverse, list, read_data, create_child, write_data, append_data,
rename, delete, read_attributes, write_attributes,
read_permissions, change_permissions, change_owner
```

The UI maps these to reviewed presets such as Read, Contribute, Edit, Manage and Owner. Presets are
not stored as authority; their expanded rights are.

## Activation-required access

A group or individual permission grant may require activation. Structural group
membership remains committed and stable, but an activation-required group
contributes no rights for a user until that user has a current activation for
the group. A grant requiring activation contributes no rights until the current
user has a current activation for that exact grant.

Activation is self-service pre-authorisation, not an approval queue. Its policy
defines the maximum duration, whether a non-blank reason is mandatory and the
minimum recent authentication assurance. The resulting record binds the user,
group or grant, reason, start, expiry, authentication event and creation
operation. It is mesh-wide, revocable and audited. Activation cannot outlive its
source membership, grant, absolute validity window, session or policy limit.
Scheduled and activation-required access may be combined: the schedule controls
when activation is permitted and the activation controls when rights are
actually exercised.

## Access evaluation

For an operation, authority:

1. validates the session and required authentication assurance;
2. verifies the user and contributing groups are active;
3. reads the committed transitive group closure;
4. collects direct and group grants on the volume, object and bounded ancestor chain;
5. applies inheritance, authoritative time windows and required activations;
6. adds rights from every effective owner principal;
7. checks the exact requested right; and
8. issues a bounded capability tied to identity, group, ACL, object and gateway revisions.

A capability expires no later than its session, earliest contributing grant or
activation. It binds the activation revisions it used; revocation or any source
revision change invalidates it. A gateway cannot extend it using its local wall
clock.

During an allowed isolation window, a gateway evaluates ordinary filesystem
rights against one signed committed identity/group/ACL projection and records
that exact revision plus its isolation delegation in the branch operation. It
cannot change users, groups, owners, permissions or roles offline. Delegations
allocate disjoint byte budgets per node/target and expire no later than the
projection's isolation limit. Reconciliation applies current visibility rules
without erasing content validly acknowledged under the recorded revision.

## Authentication methods

One user may enrol multiple independently revocable methods. The common record holds user, kind,
label, state, service scope, creation, expiry and revision. Secret formats remain in typed tables:

| Method | Stored material |
| --- | --- |
| Password | Argon2id verifier and parameters |
| WebAuthn/passkey | credential ID, public key, counter and authenticator metadata |
| TOTP | encrypted secret and algorithm parameters |
| Recovery code | single-use digest and used instant |
| API token | digest, scopes and expiry |
| Client certificate | issuer, fingerprint and expiry |
| SMB credential | encrypted verifier, service scope and generation |

Raw passwords, tokens, recovery codes and session cookies are never stored.

## Two-factor and step-up

Authentication policy is scoped to service and operation class. It specifies allowed factor
classes, minimum factor count, session lifetime and maximum age for privileged step-up.

Administrative changes use recent strong authentication by default. Because ordinary SMB clients
cannot perform an interactive second-factor exchange, the proposal is a separately revocable
SMB-only credential created from a strongly authenticated web/admin session. It cannot administer
the mesh.

## Sessions and throttling

Session authority stores only a token digest, user, factors satisfied, issue/expiry/revocation
instants and identity revision. All gateways validate the same session state.

Authentication attempt buckets are keyed conservatively by user claim, source and service. They
are mesh-wide so changing gateways does not bypass throttling. Errors do not disclose whether a
user or factor exists.

## Tags

Tag definitions are mesh records. Separate join tables attach tags to namespace objects or
principals, covering files, folders, users and groups with valid foreign keys.

Tags are descriptive and searchable only. Tag assignment does not grant access. If attribute-based
access is later required, it receives a separate administrator-owned rule model so users who may
tag content cannot escalate privileges.

## Administration boundary

System administration is separate from implicit data access. Administrators
manage infrastructure and access rules but do not automatically receive file
rights. An authorised administrator can explicitly create inherited global
read, write, manage or recovery grants for another principal or themselves.
Such a grant covers existing and future descendants of its scope and may be
permanent, scheduled or activation-required. Owners cannot prevent authorised
system recovery, but creation, activation and every data operation remain
attributable and audited.
