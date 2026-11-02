// An alert in a few words, for places with room for one line (graph markers).

import type { Alert } from "./api";
import { human } from "./format";

export function alertLine(a: Alert): string {
  const app = a.app?.name ?? "An app";
  switch (a.kind) {
    case "app_info_changed":
      return `${app}: ${a.field} changed`;
    case "first_network_activity":
      return `${app} used the network for the first time`;
    case "rdp_connection":
      return `Remote Desktop connection from ${a.remote.name ?? a.remote.ip}`;
    case "monitoring_interrupted":
      return "Monitoring was interrupted";
    case "own_dns":
      return `${app} does its own DNS`;
    case "data_plan":
      return `${a.percent}% of the data plan used (${human(a.used)})`;
    case "firewall_changed":
      return "Firewall rules changed outside win4tress";
    case "system_file_changed":
      return `System file ${a.change}: ${a.path.split("\\").pop()}`;
    case "adapter_added":
      return `New network adapter: ${a.name}`;
    case "dns_servers_changed":
      return `DNS servers changed on ${a.adapter}`;
    case "proxy_changed":
      return `${a.scope === "machine" ? "Machine" : "Your"} proxy settings changed`;
    case "internet_access_changed":
      return a.connected ? "Internet access is back" : "Internet access was lost";
    case "arp_spoofing":
      return `Possible ARP spoofing of the gateway ${a.gateway}`;
    case "wifi_evil_twin":
      return `Possible Wi-Fi evil twin of “${a.ssid}”`;
    case "suspicious_host":
      return `${app} contacted a host on ${a.list}`;
    case "while_away":
      return `While you were away: ${human(a.bytes.recv + a.bytes.sent)}`;
    case "new_device":
      return `New device on the network: ${a.name ?? a.vendor ?? a.ip}`;
    case "reputation":
      return `${app}: ${a.verdict === "malicious" ? "likely malicious" : "flagged"} (${a.source})`;
    case "dns_filter":
      return "DNS filtering set aside; Windows' own DNS put back";
    case "profile_switched":
      return `Switched to the profile ${a.profile}`;
  }
}
