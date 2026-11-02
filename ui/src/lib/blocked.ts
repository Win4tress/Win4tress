// "Blocked by…" (SPEC §7.9), as the CLI words it.

import type { BlockedConnection } from "./api";

export function blockedByText(by: BlockedConnection["by"]): string {
  switch (by.kind) {
    case "win4tress":
      return by.name;
    case "windows_rule":
      return `Windows Firewall rule “${by.name}”`;
    case "windows_default":
      return "Windows Firewall's default (no rule allowed it)";
    case "other":
      return `Another filter: ${by.name}`;
  }
}
