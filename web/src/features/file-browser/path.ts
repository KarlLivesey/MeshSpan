// SPDX-License-Identifier: GPL-2.0-only

/** Joins one already-selected logical directory and one hostile leaf name. */
export function childPath(directory: string, name: string): string {
  const leaf = name.trim();
  let containsControl = false;
  for (const character of leaf) {
    containsControl ||= character === "\u007f" || isControl(character);
  }
  if (
    leaf.length === 0 ||
    leaf.length > 255 ||
    leaf === "." ||
    leaf === ".." ||
    leaf.includes("/") ||
    containsControl
  ) {
    throw new TypeError("file or folder name is invalid");
  }
  return directory === "" ? leaf : `${directory}/${leaf}`;
}

/** Returns the logical parent without interpreting host filesystem syntax. */
export function parentPath(directory: string): string {
  const separator = directory.lastIndexOf("/");
  return separator < 0 ? "" : directory.slice(0, separator);
}

function isControl(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint < 32;
}
