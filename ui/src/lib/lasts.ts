// How long a decision lasts: for good, or for a while (SPEC §7.2).

import type { Action, Expiry, Lasts } from "./api";

export type HowLong = "always" | "15m" | "1h" | "8h" | "quit" | "restart";

export const HOW_LONG: { value: HowLong; label: string }[] = [
  { value: "always", label: "Always" },
  { value: "15m", label: "For 15 minutes" },
  { value: "1h", label: "For 1 hour" },
  { value: "8h", label: "For 8 hours" },
  { value: "quit", label: "Until it quits" },
  { value: "restart", label: "Until Windows restarts" },
];

/** What the service is asked for; null for good. */
export function lastsOf(h: HowLong): Lasts | null {
  switch (h) {
    case "always":
      return null;
    case "15m":
      return { kind: "minutes", minutes: 15 };
    case "1h":
      return { kind: "minutes", minutes: 60 };
    case "8h":
      return { kind: "minutes", minutes: 8 * 60 };
    case "quit":
      return { kind: "app_quits" };
    case "restart":
      return { kind: "restart" };
  }
}

/** "until 3:45 PM", "until tomorrow 9:00 AM", "until it quits", "until Windows restarts". */
export function untilText(e: Expiry, nowMs = Date.now()): string {
  switch (e.kind) {
    case "app_quits":
      return "until it quits";
    case "restart":
      return "until Windows restarts";
    case "at": {
      const at = new Date(e.ms);
      const time = at.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
      const today = new Date(nowMs).toDateString() === at.toDateString();
      if (today) return `until ${time}`;
      const tomorrow = new Date(nowMs + 24 * 3600 * 1000).toDateString() === at.toDateString();
      return tomorrow
        ? `until tomorrow ${time}`
        : `until ${at.toLocaleDateString([], { day: "numeric", month: "short" })} ${time}`;
    }
  }
}

/** What happens when a temporary rule ends. */
export function thenText(revert: Action | undefined): string {
  return revert === "allow" ? "then allowed again" : revert === "block" ? "then blocked again" : "then removed";
}
