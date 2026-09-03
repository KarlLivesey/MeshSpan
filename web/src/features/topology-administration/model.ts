// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  CreateFaultGroupResponse,
  ListFaultGroupMembershipsResponse,
  ListFaultGroupsResponse,
  ListTopologyNodesResponse,
  ListTopologyTargetsResponse,
  MeshSpanFetchClient,
} from "../../generated";
import { createPagedResource } from "./paged-resource";

export type TopologyAdministrationClient = Pick<
  MeshSpanFetchClient,
  | "createFaultGroup"
  | "beginStorageDrain"
  | "listFaultGroupMemberships"
  | "listFaultGroups"
  | "listStorageDrains"
  | "listNextStorageDrains"
  | "listNextFaultGroupMemberships"
  | "listNextFaultGroups"
  | "listNextTopologyNodes"
  | "listNextTopologyTargets"
  | "listTopologyNodes"
  | "listTopologyTargets"
  | "setFaultGroupMembership"
>;
export type TopologyNode = ListTopologyNodesResponse["nodes"][number];
export type TopologyTarget = ListTopologyTargetsResponse["targets"][number];
export type FaultGroup = ListFaultGroupsResponse["groups"][number];
export type FaultGroupMembership =
  ListFaultGroupMembershipsResponse["memberships"][number];
type DirectoryPhase = "idle" | "loading" | "saving";
export type TopologyDirectory = Readonly<{
  createGroup: (
    className: string,
    groupName: string,
    csrfToken: string,
  ) => Promise<CreateFaultGroupResponse>;
  error: Accessor<string | undefined>;
  groups: Accessor<readonly FaultGroup[]>;
  load: () => Promise<void>;
  loadMoreGroups: () => Promise<void>;
  loadMoreMemberships: () => Promise<void>;
  loadMoreNodes: () => Promise<void>;
  loadMoreTargets: () => Promise<void>;
  memberships: Accessor<readonly FaultGroupMembership[]>;
  nextGroups: Accessor<string | null>;
  nextMemberships: Accessor<string | null>;
  nextNodes: Accessor<string | null>;
  nextTargets: Accessor<string | null>;
  nodes: Accessor<readonly TopologyNode[]>;
  phase: Accessor<DirectoryPhase>;
  setMembership: (
    groupId: string,
    hostId: string,
    present: boolean,
    csrfToken: string,
  ) => Promise<void>;
  targets: Accessor<readonly TopologyTarget[]>;
}>;

export function createTopologyDirectory(
  client: Accessor<TopologyAdministrationClient>,
): TopologyDirectory {
  const resources = createTopologyResources(client);
  const [phase, setPhase] = createSignal<DirectoryPhase>("idle", {
    ownedWrite: true,
  });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const run = createRunner(phase, setPhase, setError);
  return {
    createGroup: async (className, groupName, csrfToken) =>
      run(
        "saving",
        "MeshSpan could not create that shared-failure group.",
        async () =>
          createGroup(client, {
            className,
            csrfToken,
            groupName,
            record: resources.groups.record,
          }),
      ),
    error,
    groups: resources.groups.items,
    load: async () => loadAll(resources, run),
    loadMoreGroups: async () => runMore(run, resources.groups.loadNext),
    loadMoreMemberships: async () =>
      runMore(run, resources.memberships.loadNext),
    loadMoreNodes: async () => runMore(run, resources.nodes.loadNext),
    loadMoreTargets: async () => runMore(run, resources.targets.loadNext),
    memberships: resources.memberships.items,
    nextGroups: resources.groups.nextPageUrl,
    nextMemberships: resources.memberships.nextPageUrl,
    nextNodes: resources.nodes.nextPageUrl,
    nextTargets: resources.targets.nextPageUrl,
    nodes: resources.nodes.items,
    phase,
    setMembership: async (
      groupId: string,
      hostId: string,
      present: boolean,
      csrfToken: string,
    ) =>
      run(
        "saving",
        "MeshSpan could not change that machine membership.",
        async () =>
          setMembership(
            client,
            resources.memberships.items,
            resources.memberships.replace,
            { csrfToken, groupId, hostId, present },
          ),
      ),
    targets: resources.targets.items,
  };
}

function createTopologyResources(
  client: Accessor<TopologyAdministrationClient>,
) {
  return {
    groups: createPagedResource(
      async () => groupPage(await client().listFaultGroups()),
      async (url) => groupPage(await client().listNextFaultGroups(url)),
      (group) => group.group_id,
    ),
    memberships: createPagedResource(
      async () => membershipPage(await client().listFaultGroupMemberships()),
      async (url) =>
        membershipPage(await client().listNextFaultGroupMemberships(url)),
      membershipKey,
    ),
    nodes: createPagedResource(
      async () => nodePage(await client().listTopologyNodes()),
      async (url) => nodePage(await client().listNextTopologyNodes(url)),
      (node) => node.node_id,
    ),
    targets: createPagedResource(
      async () => targetPage(await client().listTopologyTargets()),
      async (url) => targetPage(await client().listNextTopologyTargets(url)),
      (target) => target.target_id,
    ),
  };
}

function createRunner(
  phase: Accessor<DirectoryPhase>,
  setPhase: (value: DirectoryPhase) => void,
  setError: (value: string | undefined) => void,
) {
  return async <Result>(
    nextPhase: DirectoryPhase,
    message: string,
    action: () => Promise<Result>,
  ): Promise<Result> => {
    if (phase() !== "idle") {
      throw new Error("another topology operation is already in progress");
    }
    setPhase(nextPhase);
    setError(undefined);
    try {
      return await action();
    } catch (cause) {
      setError(message);
      throw cause;
    } finally {
      setPhase("idle");
    }
  };
}

async function loadAll(
  resources: ReturnType<typeof createTopologyResources>,
  run: Runner,
): Promise<void> {
  await run(
    "loading",
    "MeshSpan could not read the current mesh topology.",
    async () => {
      await Promise.all([
        resources.nodes.loadInitial(),
        resources.targets.loadInitial(),
        resources.groups.loadInitial(),
        resources.memberships.loadInitial(),
      ]);
    },
  ).catch(() => undefined);
}

async function createGroup(
  client: Accessor<TopologyAdministrationClient>,
  input: Readonly<{
    className: string;
    csrfToken: string;
    groupName: string;
    record: (group: FaultGroup) => void;
  }>,
): Promise<CreateFaultGroupResponse> {
  const response = await client().createFaultGroup(
    {
      class_name: input.className,
      group_name: input.groupName,
      operation_id: crypto.randomUUID(),
    },
    input.csrfToken,
  );
  input.record(response.group);
  return response;
}

type MembershipChange = Readonly<{
  csrfToken: string;
  groupId: string;
  hostId: string;
  present: boolean;
}>;

async function setMembership(
  client: Accessor<TopologyAdministrationClient>,
  current: Accessor<readonly FaultGroupMembership[]>,
  replace: (items: readonly FaultGroupMembership[]) => void,
  change: MembershipChange,
): Promise<void> {
  const response = await client().setFaultGroupMembership(
    {
      groupId: change.groupId,
      hostId: change.hostId,
      request: { operation_id: crypto.randomUUID(), present: change.present },
    },
    change.csrfToken,
  );
  const remaining = current().filter(
    (item) =>
      item.group_id !== change.groupId || item.host_id !== change.hostId,
  );
  replace(
    response.present ? [...remaining, membershipFrom(response)] : remaining,
  );
}

function membershipFrom(
  response: Awaited<
    ReturnType<TopologyAdministrationClient["setFaultGroupMembership"]>
  >,
): FaultGroupMembership {
  return {
    group_id: response.group_id,
    host_id: response.host_id,
    revision: response.revision,
  };
}

type Runner = ReturnType<typeof createRunner>;

async function runMore(run: Runner, load: () => Promise<void>): Promise<void> {
  await run(
    "loading",
    "MeshSpan could not read the next topology page.",
    load,
  ).catch(() => undefined);
}

function nodePage(page: ListTopologyNodesResponse) {
  return { items: page.nodes, nextPageUrl: page.next_page_url };
}
function targetPage(page: ListTopologyTargetsResponse) {
  return { items: page.targets, nextPageUrl: page.next_page_url };
}
function groupPage(page: ListFaultGroupsResponse) {
  return { items: page.groups, nextPageUrl: page.next_page_url };
}
function membershipPage(page: ListFaultGroupMembershipsResponse) {
  return { items: page.memberships, nextPageUrl: page.next_page_url };
}
function membershipKey(value: FaultGroupMembership): string {
  return `${value.host_id}.${value.group_id}`;
}
