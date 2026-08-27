# Appliance experience and simplicity budget

Status: draft for review.

MeshSpan's internal design is distributed; its operator experience is a box that
contains files. Internal correctness concepts do not become installation steps,
product tiers or routine repair work.

## Normal lifecycle

The complete ordinary workflow is:

```text
first box: start -> create mesh -> create administrator -> add storage folder

another box: start with join code and storage folder -> appears in mesh

use: create people/shares -> connect by HTTPS or SMB -> store files
```

One self-contained daemon supplies storage, gateway, metadata, voter, repair and
web capabilities as appropriate. The appliance automatically selects roles from
eligible hardware and current topology. A user does not install, place or wire
separate service daemons.

## Complexity that must stay internal

Normal setup and operation must not require users to:

- create storage pools, placement groups, shard maps or coding profiles;
- assign consensus leaders, voters, repair workers or gateway owners;
- calculate quorum, parity width or fault-domain placement;
- install an external database, proxy, certificate service, SMB server,
  orchestrator, message queue or monitoring stack;
- edit generated configuration files on every node;
- run recovery commands after ordinary node, disk, cable or power churn;
- choose between internal histories, shards or returning replicas; or
- understand process roles before saving the first file.

Those records remain available in bounded advanced diagnostics because hiding a
real failure would be unsafe. Diagnostics explain impact and automatic action
first, then expose internal evidence for experts.

## Intent the user may choose

The product asks only for decisions that depend on the user's world:

- which people/groups may access which files;
- which folders on a box MeshSpan may use;
- which real failures the data should survive;
- which named places should hold data and which must confirm a strong save; and
- optional retention, quota and certificate/domain choices.

Plain-language presets are primary. Advanced controls edit the same policy
model; they never open a second configuration path.

## Safe automatic defaults

- One node starts useful and reports that it has no machine redundancy.
- Added folders/nodes become eligible after validation without changing an
  existing acknowledgement promise silently.
- Eventual convergence is the default so a broken link does not stop ordinary
  work.
- Voter count, placement, encoding, repair priority and rebalance are automatic.
- HTTPS works on first start with a clearly scoped local bootstrap identity;
  public ACME or an administrator certificate is an optional later policy.
- Every recommendation includes its consequence in user language before commit.

## One control path

Web, API, CLI flags and headless enrolment invoke the same versioned domain
operations. There is no privileged dashboard database path and no settings file
that silently overrides replicated desired state after enrolment.

Healthy automation is quiet. The dashboard prioritises current user impact and
whether MeshSpan is already fixing it. It asks for action only when intent or a
physical resource is genuinely missing.

## Complexity admission rule

A new visible concept is accepted only when all of these are true:

1. a user must make the decision because MeshSpan cannot derive it safely;
2. a plain default would materially violate user intent;
3. the concept cannot be expressed through an existing people, files, safety,
   place or access control; and
4. its end-to-end setup, failure and removal paths have appliance-level tests.

Supporting a replaceable implementation is not a reason to expose it. Future
connectors and storage engines reuse the same appliance lifecycle and do not add
their own operator control plane.

## Acceptance evidence

An untrained test participant must be able to create a one-node mesh, add a
second node, register several folders, create a user/share and store/retrieve a
file without documentation about consensus, shards or process roles.

Fault tests then unplug and return nodes, targets and links. The participant may
observe plain status but is not asked to repair internal state. Any requested
manual action must identify a missing physical resource, missing user intent or
security decision and must be justified by a stable error code.
