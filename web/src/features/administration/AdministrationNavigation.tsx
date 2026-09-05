// SPDX-License-Identifier: GPL-2.0-only

import { For } from "solid-js";
import type { JSX } from "@solidjs/web";

type AdministrationSection =
  | "backups"
  | "certificates"
  | "identities"
  | "operations"
  | "storage-folders"
  | "topology"
  | "volumes";

const SECTIONS: readonly Readonly<{
  href: string;
  id: AdministrationSection;
  label: string;
}>[] = [
  { href: "/admin/identities", id: "identities", label: "People and groups" },
  { href: "/admin/volumes", id: "volumes", label: "Volumes" },
  {
    href: "/admin/storage-folders",
    id: "storage-folders",
    label: "Storage folders",
  },
  { href: "/admin/topology", id: "topology", label: "Mesh topology" },
  {
    href: "/admin/certificates",
    id: "certificates",
    label: "Certificates",
  },
  { href: "/admin/operations", id: "operations", label: "Operations" },
  { href: "/admin/backups", id: "backups", label: "Metadata backups" },
];

export function AdministrationNavigation(
  props: Readonly<{ current: AdministrationSection }>,
): JSX.Element {
  return (
    <nav class="administration-nav" aria-label="Administration sections">
      <For each={SECTIONS}>
        {(section) => (
          <a
            aria-current={section.id === props.current ? "page" : undefined}
            href={section.href}
          >
            {section.label}
          </a>
        )}
      </For>
    </nav>
  );
}
