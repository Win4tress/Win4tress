const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** Decimal units, like Windows' network counters: 1 KB = 1000 B. */
export function human(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit++;
  }
  if (unit === 0) return `${Math.round(value)} B`;
  return `${value.toFixed(value < 100 ? 1 : 0)} ${UNITS[unit]}`;
}

export function rate(bytesPerSecond: number): string {
  return `${human(bytesPerSecond)}/s`;
}

const timeFormat = new Intl.DateTimeFormat(undefined, {
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
});

/** Local wall-clock time for a Unix second. */
export function clock(unixSeconds: number): string {
  return timeFormat.format(new Date(unixSeconds * 1000));
}

const dayFormat = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });
const dayTimeFormat = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  hour: "numeric",
  minute: "2-digit",
});

/** A local date, e.g. "25 Oct". */
export function dayLabel(unixSeconds: number): string {
  return dayFormat.format(new Date(unixSeconds * 1000));
}

/** A moment as precisely as a step of `step` seconds needs: the time for
 *  steps under an hour, the date and hour for hours, the date for days. */
export function moment(unixSeconds: number, step: number): string {
  if (step >= 86_400) return dayLabel(unixSeconds);
  if (step >= 3_600) return dayTimeFormat.format(new Date(unixSeconds * 1000));
  return clock(unixSeconds);
}

export function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function duration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

const TRAFFIC_LABELS: Record<string, string> = {
  https: "HTTPS",
  http: "HTTP",
  quic: "QUIC",
  dns: "DNS",
  dot: "DNS over TLS",
  ntp: "NTP",
  mdns: "mDNS",
  llmnr: "LLMNR",
  ssdp: "SSDP",
  netbios: "NetBIOS",
  smb: "SMB",
  rdp: "RDP",
  ssh: "SSH",
  dhcp: "DHCP",
  other: "Other",
};

export function trafficLabel(type: string): string {
  return TRAFFIC_LABELS[type] ?? type;
}

const DNS_TYPES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  64: "SVCB",
  65: "HTTPS",
};

export function dnsType(t: number): string {
  return DNS_TYPES[t] ?? String(t);
}

const DNS_ERRORS: Record<number, string> = {
  9002: "Server failure",
  9003: "No such name",
  9005: "Refused",
  9501: "No records of this type",
  1460: "Timed out",
  1214: "Invalid name",
  123: "Invalid name",
};

/** Windows DNS status codes in plain words. */
export function dnsStatus(status: number): string {
  if (status === 0) return "Answered";
  return DNS_ERRORS[status] ?? `Error ${status}`;
}

/** "ip:port" / "[v6]:port" → [address, port]. */
export function splitEndpoint(endpoint: string): [string, string] {
  const i = endpoint.lastIndexOf(":");
  const host = endpoint.slice(0, i).replace(/^\[|\]$/g, "");
  return [host, endpoint.slice(i + 1)];
}

export function sum(samples: { recv: number; sent: number }[]): { recv: number; sent: number } {
  let recv = 0;
  let sent = 0;
  for (const s of samples) {
    recv += s.recv;
    sent += s.sent;
  }
  return { recv, sent };
}
