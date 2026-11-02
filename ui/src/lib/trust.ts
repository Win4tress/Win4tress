// What's worth flagging about an app's executable (SPEC §12, trust tier 1).

import type { PathClass, Reputation, Trust } from "./api";

export interface TrustChip {
  label: string;
  tone: "" | "warn" | "bad";
  title: string;
}

/** Flags for an app: an unsigned or broken signature, a download, a user folder
 *  (only when unsigned: signed apps installed per user are common), its own DNS. */
export function trustChips(a: { trust: Trust; path_class?: PathClass; own_dns_ms?: number }): TrustChip[] {
  const chips: TrustChip[] = [];
  const sig = a.trust.signature;
  if (sig === "invalid")
    chips.push({
      label: "Bad signature",
      tone: "bad",
      title: "Its signature doesn't verify: the file was changed after signing, or the certificate isn't trusted.",
    });
  else if (sig === "unsigned")
    chips.push({ label: "Unsigned", tone: "warn", title: "The program isn't signed, so its publisher can't be verified." });
  if (sig !== "signed" && a.path_class === "user_writable")
    chips.push({
      label: "User folder",
      tone: "",
      title: "Runs from a folder any program you run can write to, such as Downloads or AppData.",
    });
  if (a.trust.origin && a.trust.origin.zone >= 3)
    chips.push({
      label: "Downloaded",
      tone: "",
      title: `Downloaded from the internet${a.trust.origin.host_url ? `: ${a.trust.origin.host_url}` : ""}.`,
    });
  if (a.own_dns_ms != null)
    chips.push({
      label: "Own DNS",
      tone: "warn",
      title: "Looks up names itself instead of through Windows, so its lookups don't show in the DNS view.",
    });
  return chips;
}

/** A reputation answer worth a flag: something flagged the file. */
export function reputationChip(r: Reputation | undefined): TrustChip | null {
  if (!r || (r.verdict !== "malicious" && r.verdict !== "suspicious")) return null;
  const count = r.detections != null && r.engines != null ? ` (${r.detections} of ${r.engines} engines)` : "";
  return {
    label: r.verdict === "malicious" ? "Malicious" : "Suspicious",
    tone: r.verdict === "malicious" ? "bad" : "warn",
    title: `${r.source}${count}${r.detail ? `: ${r.detail}` : ""}.`,
  };
}

/** The reputation and trust flags, then "VPN" for a known VPN client (not a
 *  risk: a label) and "Incognito". */
export function appChips(a: {
  trust: Trust;
  path_class?: PathClass;
  own_dns_ms?: number;
  vpn?: boolean;
  reputation?: Reputation;
  incognito?: boolean;
}): TrustChip[] {
  const rep = reputationChip(a.reputation);
  const chips = rep ? [rep, ...trustChips(a)] : trustChips(a);
  if (a.incognito)
    chips.push({ label: "Incognito", tone: "", title: "Its traffic isn't written to history." });
  if (a.vpn)
    chips.push({
      label: "VPN",
      tone: "",
      title: "A VPN client: its traffic is other apps' traffic again, encrypted. Usage can leave it out of totals.",
    });
  return chips;
}

/** For a narrow list cell: the first (most serious) flag, and how many more,
 *  with all of them in the tooltip. */
export function firstChip(chips: TrustChip[]): (TrustChip & { more: number }) | null {
  if (!chips.length) return null;
  return {
    ...chips[0],
    more: chips.length - 1,
    title: chips.map((c) => `${c.label}: ${c.title}`).join("\n"),
  };
}

export const SIGNATURE_TEXT: Record<string, string> = {
  signed: "Signed",
  unsigned: "Not signed",
  invalid: "Signature doesn't verify",
};

export const PATH_CLASS_TEXT: Record<PathClass, string> = {
  windows: "Windows folder",
  program_files: "Program Files (only administrators can change it)",
  user_writable: "A user folder (any program you run can change it)",
  other: "Elsewhere",
};

/** Mark of the Web zones. */
export function zoneText(zone: number): string {
  return ["This computer", "Local network", "Trusted site", "Internet", "Restricted site"][zone] ?? `Zone ${zone}`;
}
