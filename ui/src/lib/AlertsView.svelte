<script lang="ts">
  import {
    api,
    errorText,
    events,
    snoozeKey,
    type Alert,
    type AlertKind,
    type AlertsQuery,
    type HostRef,
    type OutsideChange,
    type PopupPrefs,
  } from "./api";
  import AppIcon from "./AppIcon.svelte";
  import { duration, human } from "./format";

  interface Props {
    /** The unread count changed (marked here, or new alerts arrived). */
    onunread: (unread: number) => void;
    /** Show an app in the Apps view. */
    onopenapp: (id: number) => void;
    /** Show the alert settings (Settings). */
    onopensettings?: () => void;
    /** Shown searched for this, e.g. from the search box. */
    search?: string;
  }

  let { onunread, onopenapp, onopensettings, search: searchFor = "" }: Props = $props();

  const PAGE = 200;
  const DAY_MS = 24 * 3600 * 1000;

  type Show = "all" | "unread" | AlertKind;
  const KINDS: { label: string; kinds: { value: AlertKind; label: string }[] }[] = [
    {
      label: "Apps",
      kinds: [
        { value: "app_info_changed", label: "App info changes" },
        { value: "first_network_activity", label: "First network activity" },
        { value: "own_dns", label: "Own DNS" },
        { value: "suspicious_host", label: "Suspicious hosts" },
        { value: "reputation", label: "Reputation" },
      ],
    },
    {
      label: "Network",
      kinds: [
        { value: "new_device", label: "New devices" },
        { value: "adapter_added", label: "Network adapters" },
        { value: "dns_servers_changed", label: "DNS servers" },
        { value: "proxy_changed", label: "Proxy settings" },
        { value: "internet_access_changed", label: "Internet access" },
        { value: "arp_spoofing", label: "ARP spoofing" },
        { value: "wifi_evil_twin", label: "Wi-Fi evil twin" },
      ],
    },
    {
      label: "This PC",
      kinds: [
        { value: "system_file_changed", label: "System files" },
        { value: "rdp_connection", label: "Remote Desktop" },
        { value: "firewall_changed", label: "Firewall changes" },
        { value: "monitoring_interrupted", label: "Monitoring" },
        { value: "data_plan", label: "Data plan" },
        { value: "while_away", label: "While you were away" },
        { value: "dns_filter", label: "DNS filtering" },
        { value: "profile_switched", label: "Profile switched" },
      ],
    },
  ];
  const KIND_LABEL = Object.fromEntries(
    KINDS.flatMap((g) => g.kinds.map((k) => [k.value, k.label])),
  ) as Record<AlertKind, string>;
  type Sort = "date" | "app" | "type";
  const SORTS: { value: Sort; label: string }[] = [
    { value: "date", label: "By date" },
    { value: "app", label: "By app" },
    { value: "type", label: "By type" },
  ];
  type Period = "all" | "today" | "7d" | "30d";
  const PERIODS: { value: Period; label: string }[] = [
    { value: "all", label: "All time" },
    { value: "today", label: "Today" },
    { value: "7d", label: "Last 7 days" },
    { value: "30d", label: "Last 30 days" },
  ];
  const SOURCE: Record<AlertKind, string> = {
    app_info_changed: "App info monitor",
    first_network_activity: "First network activity",
    rdp_connection: "Remote Desktop monitor",
    monitoring_interrupted: "win4tress",
    own_dns: "DNS monitor",
    data_plan: "Data plan",
    firewall_changed: "Firewall monitor",
    system_file_changed: "System file monitor",
    adapter_added: "Network monitor",
    dns_servers_changed: "Network monitor",
    proxy_changed: "Proxy monitor",
    internet_access_changed: "Network monitor",
    arp_spoofing: "ARP monitor",
    wifi_evil_twin: "Wi-Fi monitor",
    suspicious_host: "Threat lists",
    while_away: "While you were away",
    new_device: "Network scanner",
    reputation: "Reputation",
    dns_filter: "DNS filtering",
    profile_switched: "Profiles",
  };

  let show = $state<Show>("all");
  let period = $state<Period>("all");
  let sort = $state<Sort>("date");
  /** Desktop pop-ups: what's snoozed. */
  let prefs = $state.raw<PopupPrefs | null>(null);
  let snoozeError = $state<string | null>(null);

  $effect(() => {
    api.popupPrefs().then(
      (p) => (prefs = p),
      () => {},
    );
  });

  async function toggleSnooze(a: Alert) {
    menuFor = null;
    snoozeError = null;
    const key = snoozeKey(a);
    try {
      prefs = await api.snooze(key, !prefs?.snoozed[key]);
    } catch (e) {
      snoozeError = errorText(e);
    }
  }
  let search = $state("");
  let query = $state(""); // `search`, debounced
  $effect.pre(() => {
    if (searchFor) search = searchFor;
  });
  let alerts = $state.raw<Alert[]>([]);
  let more = $state(false);
  let unread = $state(0);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let menuFor = $state<number | null>(null);
  /** The alert whose changes are being kept, and why that failed. */
  let keeping = $state<number | null>(null);
  let keepError = $state<{ id: number; text: string } | null>(null);

  async function keep(a: Alert) {
    keeping = a.id;
    keepError = null;
    try {
      await api.keepChanges(a.id);
      await load();
    } catch (e) {
      keepError = { id: a.id, text: errorText(e) };
    } finally {
      keeping = null;
    }
  }

  /** Apps whose own DNS was just blocked from here, and why that failed. */
  let dnsBlocked = $state<number[]>([]);
  let dnsError = $state<{ id: number; text: string } | null>(null);

  async function blockOwnDns(a: Alert) {
    if (!a.app) return;
    dnsError = null;
    try {
      await api.setRule(a.app.id, "out", "block", { kind: "dns" });
      dnsBlocked = [...dnsBlocked, a.app.id];
    } catch (e) {
      dnsError = { id: a.id, text: errorText(e) };
    }
  }

  const CHANGE: Record<OutsideChange["kind"], string> = {
    deleted: "deleted",
    disabled: "turned off",
    enabled: "turned on",
    allowed: "switched to allow",
    blocked: "switched to block",
    modified: "had its conditions changed",
    added: "added to win4tress's rules",
  };

  /** e.g. "curl's outgoing block rule was turned off". */
  function changeText(c: OutsideChange): string {
    if (c.direction && c.action) {
      const rule = `${c.name}'s ${c.direction === "in" ? "incoming" : "outgoing"} ${c.action} rule`;
      return c.kind === "added" ? `A copy of ${rule} was added` : `${rule} was ${CHANGE[c.kind]}`;
    }
    return `“${c.name}” was ${CHANGE[c.kind]}`;
  }

  function dateTime(ms: number): string {
    return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }

  function filter(): AlertsQuery {
    const since =
      period === "today"
        ? new Date().setHours(0, 0, 0, 0)
        : period === "7d"
          ? Date.now() - 7 * DAY_MS
          : period === "30d"
            ? Date.now() - 30 * DAY_MS
            : null;
    return {
      kinds: show === "all" || show === "unread" ? [] : [show],
      unread_only: show === "unread",
      since_ms: since,
      query: query || null,
      limit: PAGE,
    };
  }

  async function load() {
    try {
      const r = await api.alerts(filter());
      alerts = r.alerts;
      more = r.more;
      setUnread(r.unread);
      error = null;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function loadOlder() {
    const last = alerts.at(-1);
    if (!last) return;
    try {
      const r = await api.alerts({ ...filter(), before_id: last.id });
      alerts = [...alerts, ...r.alerts];
      more = r.more;
    } catch (e) {
      error = String(e);
    }
  }

  function setUnread(n: number) {
    unread = n;
    onunread(n);
  }

  // Reload when the filters change; typing is debounced.
  $effect(() => {
    const q = search.trim();
    const timer = setTimeout(() => (query = q), 250);
    return () => clearTimeout(timer);
  });
  $effect(() => {
    void show;
    void period;
    void query;
    load();
  });
  // New alerts: reload the first page, so filters and grouping stay right.
  $effect(() => {
    const off = events.onAlerts((_, n) => {
      setUnread(n);
      load();
    });
    return () => {
      off.then((f) => f());
    };
  });

  async function setRead(ids: number[] | null, read: boolean) {
    menuFor = null;
    try {
      setUnread((await api.markRead(ids, read)).unread);
      alerts = alerts.map((a) => (ids === null || ids.includes(a.id) ? { ...a, read } : a));
      if (show === "unread" && read) alerts = alerts.filter((a) => !a.read);
    } catch (e) {
      error = String(e);
    }
  }

  type Group = { key: string; label: string; alerts: Alert[] };
  /** By day, newest first; or by app or type, A to Z, each newest first. */
  const groups = $derived.by(() => {
    const out: Group[] = [];
    if (sort === "date") {
      for (const a of alerts) {
        const d = new Date(a.ts_ms);
        const key = d.toDateString();
        let group = out.at(-1);
        if (group?.key !== key) {
          group = { key, label: dayLabel(d), alerts: [] };
          out.push(group);
        }
        group.alerts.push(a);
      }
      return out;
    }
    const byKey = new Map<string, Group>();
    for (const a of alerts) {
      const key = sort === "app" ? (a.app ? `app:${a.app.id}` : "") : a.kind;
      let group = byKey.get(key);
      if (!group) {
        const label = sort === "app" ? (a.app?.name ?? "Not about an app") : KIND_LABEL[a.kind];
        group = { key, label, alerts: [] };
        byKey.set(key, group);
        out.push(group);
      }
      group.alerts.push(a);
    }
    // Alerts not about an app go last.
    return out.sort((x, y) => Number(x.key === "") - Number(y.key === "") || x.label.localeCompare(y.label));
  });

  function dayLabel(d: Date): string {
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return "Today";
    if (d.toDateString() === new Date(today.getTime() - DAY_MS).toDateString()) return "Yesterday";
    return d.toLocaleDateString(undefined, {
      day: "numeric",
      month: "long",
      year: d.getFullYear() === today.getFullYear() ? undefined : "numeric",
    });
  }

  function time(ms: number): string {
    return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }

  /** The time within a day's group; the date too when grouped otherwise. */
  function when(ms: number): string {
    if (sort === "date") return time(ms);
    return new Date(ms).toLocaleString([], { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" });
  }

  function list(items: string[]): string {
    return items.length ? items.join(", ") : "none";
  }

  function host(h: HostRef): string {
    return h.name ?? h.ip;
  }

  type Part = { text: string; strong?: boolean };
  /** The alert as a sentence, with the names and values in bold. */
  function message(a: Alert): Part[] {
    const app = a.app?.name ?? "An app";
    switch (a.kind) {
      case "app_info_changed":
        switch (a.field) {
          case "signer":
            return [
              { text: app, strong: true },
              { text: " is now signed by " },
              { text: a.to, strong: true },
              { text: ` (was ${a.from}).` },
            ];
          case "signature":
            return [
              { text: app, strong: true },
              { text: ` was ${a.from}; its file is now ` },
              { text: a.to, strong: true },
              { text: "." },
            ];
          case "file":
            return [
              { text: app, strong: true },
              { text: "'s file changed without a version change " },
              { text: `(SHA-256 ${a.from}… → ${a.to}…)` },
              { text: "." },
            ];
          default:
            return [
              { text: app, strong: true },
              { text: ` ${a.field} changed from ` },
              { text: a.from, strong: true },
              { text: " to " },
              { text: a.to, strong: true },
              { text: "." },
            ];
        }
      case "first_network_activity":
        return [
          { text: app, strong: true },
          { text: " used the network for the first time" },
          ...(a.host
            ? [{ text: ", connecting to " }, { text: host(a.host), strong: true }, { text: ` on port ${a.port}` }]
            : []),
          { text: "." },
        ];
      case "rdp_connection":
        return [
          { text: "Remote Desktop connection from " },
          { text: host(a.remote), strong: true },
          {
            text:
              (a.remote.name ? ` (${a.remote.ip})` : "") +
              (a.remote.country.code.length === 2 ? `, ${a.remote.country.name}` : "") +
              ".",
          },
        ];
      case "own_dns":
        return [
          { text: app, strong: true },
          { text: " looks up names itself, through " },
          { text: `${host(a.host)}:${a.port}`, strong: true },
          { text: ", instead of through Windows. Its lookups don't appear in the DNS view." },
        ];
      case "data_plan":
        return [
          { text: `${a.percent}% of your data plan`, strong: true },
          { text: " is used: " },
          { text: `${human(a.used)} of ${human(a.limit)}`, strong: true },
          { text: ` since ${new Date(a.period_start_ms).toLocaleDateString([], { day: "numeric", month: "long" })}.` },
        ];
      case "monitoring_interrupted":
        return [
          { text: "Another program stopped win4tress's traffic monitoring. " },
          { text: "It was restarted within seconds; traffic in between wasn't counted." },
        ];
      case "firewall_changed":
        return [
          { text: "Something other than win4tress changed win4tress's firewall rules. " },
          a.kept_ms != null
            ? { text: "You kept the changes", strong: true }
            : { text: `${a.repaired} ${a.repaired === 1 ? "change was" : "changes were"} put back`, strong: true },
          { text: "." },
        ];
      case "system_file_changed":
        return [
          { text: `A system file was ${a.change}: ` },
          { text: a.path, strong: true },
          { text: ". If you or an installer didn't change it, look at what's in it." },
        ];
      case "adapter_added":
        return [
          { text: "A new network adapter appeared: " },
          { text: a.name, strong: true },
          { text: ` (${a.description}${a.mac ? `, ${a.mac}` : ""}).` },
        ];
      case "dns_servers_changed":
        return [
          { text: "DNS servers on " },
          { text: a.adapter, strong: true },
          { text: " changed from " },
          { text: list(a.from), strong: true },
          { text: " to " },
          { text: list(a.to), strong: true },
          { text: " on the same network. Names may now be answered by someone else." },
        ];
      case "proxy_changed":
        return [
          {
            text: a.scope === "machine" ? "The machine's proxy settings (WinHTTP) changed from " : "Your proxy settings changed from ",
          },
          { text: a.from, strong: true },
          { text: " to " },
          { text: a.to, strong: true },
          { text: "." },
        ];
      case "internet_access_changed":
        return [{ text: a.connected ? "Internet access is back." : "Internet access was lost.", strong: true }];
      case "arp_spoofing":
        return a.also.length
          ? [
              { text: "The gateway " },
              { text: a.gateway, strong: true },
              { text: "'s hardware address " },
              { text: a.mac, strong: true },
              { text: " also answers for " },
              { text: list(a.also), strong: true },
              { text: ". Another device may be posing as the router (ARP spoofing)." },
            ]
          : [
              { text: "The gateway " },
              { text: a.gateway, strong: true },
              { text: " now answers from " },
              { text: a.mac, strong: true },
              { text: a.known.length ? ` instead of ${list(a.known)}` : "" },
              { text: ". A new router does this too; otherwise another device may be posing as it (ARP spoofing)." },
            ];
      case "wifi_evil_twin":
        return a.connected
          ? [
              { text: "You're connected to " },
              { text: a.ssid, strong: true },
              { text: " with " },
              { text: a.seen, strong: true },
              { text: " security, but it had " },
              { text: a.expected, strong: true },
              { text: ". It may be an impostor (evil twin)." },
            ]
          : [
              { text: "A network named " },
              { text: a.ssid, strong: true },
              { text: " with " },
              { text: a.seen, strong: true },
              { text: " security is nearby; yours has " },
              { text: a.expected, strong: true },
              { text: ". Don't connect to it." },
            ];
      case "suspicious_host":
        return [
          { text: app, strong: true },
          { text: " connected to " },
          { text: host(a.host), strong: true },
          { text: ` on port ${a.port}, which is on ` },
          { text: a.list, strong: true },
          { text: "." },
        ];
      case "while_away":
        return [
          { text: `While you were away (${duration(a.to_ms - a.from_ms)}): ` },
          { text: human(a.bytes.recv), strong: true },
          { text: " down and " },
          { text: human(a.bytes.sent), strong: true },
          { text: " up" },
          ...(a.apps.length ? [{ text: ", mostly " }, { text: a.apps.join(", "), strong: true }] : []),
          { text: a.alerts ? `; ${a.alerts} ${a.alerts === 1 ? "alert" : "alerts"}.` : "." },
        ];
      case "new_device":
        return [
          { text: "A new device joined the network: " },
          { text: a.name ?? (a.vendor ? `a ${a.vendor} device` : "an unknown device"), strong: true },
          { text: ` at ${a.ip} (${a.mac}).` },
        ];
      case "reputation":
        return [
          { text: app, strong: true },
          { text: a.verdict === "malicious" ? "'s file is likely malicious: " : "'s file was flagged: " },
          {
            text:
              a.detections != null && a.engines != null
                ? `${a.source}, ${a.detections} of ${a.engines} engines`
                : a.source,
            strong: true,
          },
          { text: a.detail ? ` (${a.detail})` : "" },
          { text: a.blocked ? ". It was blocked both ways." : "." },
        ];
      case "dns_filter":
        return [
          { text: "DNS filtering set aside", strong: true },
          { text: `: ${a.reason}, so Windows' own DNS was put back until it answers again.` },
        ];
      case "profile_switched":
        return [
          { text: "Switched to the firewall profile " },
          { text: a.profile, strong: true },
          { text: a.from ? ` (from ${a.from})` : "" },
          { text: " on " },
          { text: a.network, strong: true },
          { text: "." },
        ];
    }
  }

</script>

<svelte:window
  onclick={() => (menuFor = null)}
  onkeydown={(e) => {
    if (e.key === "Escape") menuFor = null;
  }}
/>

<div class="view">
  <div class="toolbar">
    <select bind:value={show} aria-label="Which alerts">
      <option value="all">All alerts</option>
      <option value="unread">Unread</option>
      {#each KINDS as g (g.label)}
        <optgroup label={g.label}>
          {#each g.kinds as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
        </optgroup>
      {/each}
    </select>
    <select bind:value={period} aria-label="Time range">
      {#each PERIODS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
    </select>
    <select bind:value={sort} aria-label="Sort">
      {#each SORTS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
    </select>
    <span class="muted count">{unread ? `${unread} unread` : "All read"}</span>
    <div class="spacer"></div>
    <button class="button" title="Which alerts win4tress raises, and which pop up" onclick={() => onopensettings?.()}>
      Alert settings
    </button>
    <button class="button" disabled={unread === 0} onclick={() => setRead(null, true)}>Mark all as read</button>
    <input class="search" type="search" placeholder="Search alerts" bind:value={search} aria-label="Search alerts" />
  </div>

  {#if snoozeError}<p class="note keep-error" role="alert">{snoozeError}</p>{/if}

  {#if error}
    <p class="note muted">
      {error.includes("history") ? "Alerts are kept in the history database, which isn't available." : error}
    </p>
  {:else if loading}
    <p class="note muted">Loading…</p>
  {:else if alerts.length === 0}
    <div class="card empty">
      {#if show !== "all" || period !== "all" || query}
        <p>No alerts match.</p>
      {:else}
        <p class="title">No alerts yet</p>
        <p class="muted">
          win4tress lists here when an app changes or uses the network for the first time, an app talks
          to a host on a threat list, the hosts file, DNS servers, proxy or gateway change, a Wi-Fi network
          poses as yours, a new device joins the network, or another program changes win4tress's firewall
          rules. Choose which under Monitors.
        </p>
      {/if}
    </div>
  {:else}
    {#each groups as group (group.key)}
      <section class="day" aria-label={group.label}>
        <h2>{group.label}</h2>
        <ul class="card list">
          {#each group.alerts as a (a.id)}
            <li class="row" class:unread={!a.read}>
              <span class="dot" aria-label={a.read ? undefined : "Unread"}></span>
              <span class="sev {a.severity}" aria-label={a.severity}>{a.severity === "info" ? "i" : a.severity === "critical" ? "!!" : "!"}</span>
              <div class="body">
                <!-- Clicking an unread alert marks it read. -->
                <button
                  class="text"
                  aria-disabled={a.read}
                  onclick={() => {
                    if (!a.read) setRead([a.id], true);
                  }}
                >
                  <span class="message">
                    {#if a.app}<AppIcon name={a.app.name} path={a.app.path} size={18} />{/if}
                    <span>
                      {#each message(a) as part, i (i)}{#if part.strong}<strong>{part.text}</strong>{:else}{part.text}{/if}{/each}
                    </span>
                  </span>
                  {#if a.app && (a.kind === "app_info_changed" || a.kind === "first_network_activity" || a.kind === "suspicious_host" || a.kind === "reputation")}
                    <span class="path muted" title={a.app.path}>{a.app.path}</span>
                  {/if}
                </button>
                {#if a.kind === "firewall_changed" && a.changes?.length}
                  <ul class="changes">
                    {#each a.changes as c, i (i)}
                      <li>
                        {changeText(c)}{#if !c.keepable && a.kept_ms == null}<span class="muted"> · can't be kept</span>{/if}
                      </li>
                    {/each}
                  </ul>
                  {#if a.kept_ms != null}
                    <p class="muted keep-note">Kept instead of win4tress's rules on {dateTime(a.kept_ms)}.</p>
                  {:else if a.changes.some((c) => c.keepable)}
                    <div class="keep">
                      <button class="button primary" disabled={keeping === a.id} onclick={() => keep(a)}>
                        {keeping === a.id ? "Keeping…" : "Keep these changes"}
                      </button>
                      <span class="muted">win4tress put its rules back. Keep the changes instead?</span>
                    </div>
                  {/if}
                  {#if keepError?.id === a.id}<p class="keep-error" role="alert">{keepError.text}</p>{/if}
                {/if}
                {#if a.kind === "own_dns" && a.app}
                  {#if dnsBlocked.includes(a.app.id)}
                    <p class="muted keep-note">Blocked: the app now has to use Windows' DNS.</p>
                  {:else}
                    <div class="keep">
                      <button class="button" onclick={() => blockOwnDns(a)}>Block its own DNS</button>
                      <span class="muted">It then has to look names up through Windows, where win4tress sees them.</span>
                    </div>
                  {/if}
                  {#if dnsError?.id === a.id}<p class="keep-error" role="alert">{dnsError.text}</p>{/if}
                {/if}
              </div>
              <div class="meta muted">
                <div>{SOURCE[a.kind]}</div>
                <div class="num">
                  {#if prefs?.snoozed[snoozeKey(a)]}
                    <span class="chip" title="No pop-ups until {dateTime(prefs.snoozed[snoozeKey(a)])}">Snoozed</span>
                  {/if}
                  {when(a.ts_ms)}
                </div>
              </div>
              <div class="menu-wrap">
                <button
                  class="more"
                  aria-label="More actions"
                  aria-haspopup="menu"
                  aria-expanded={menuFor === a.id}
                  onclick={(e) => {
                    e.stopPropagation();
                    menuFor = menuFor === a.id ? null : a.id;
                  }}>⋯</button
                >
                {#if menuFor === a.id}
                  <div class="menu card" role="menu">
                    <button
                      role="menuitem"
                      onclick={(e) => {
                        e.stopPropagation();
                        setRead([a.id], !a.read);
                      }}>{a.read ? "Mark as unread" : "Mark as read"}</button
                    >
                    <button
                      role="menuitem"
                      onclick={(e) => {
                        e.stopPropagation();
                        toggleSnooze(a);
                      }}
                      >{prefs?.snoozed[snoozeKey(a)] ? "Wake pop-ups" : "Snooze pop-ups for 24 hours"}
                      <span class="muted">· {a.app ? "this app" : "this kind"}</span></button
                    >
                    {#if a.app}
                      {@const id = a.app.id}
                      <button
                        role="menuitem"
                        onclick={(e) => {
                          e.stopPropagation();
                          menuFor = null;
                          onopenapp(id);
                        }}>Show in Apps</button
                      >
                    {/if}
                  </div>
                {/if}
              </div>
            </li>
          {/each}
        </ul>
      </section>
    {/each}
    {#if more}
      <div class="older"><button class="button" onclick={loadOlder}>Show older alerts</button></div>
    {/if}
  {/if}
</div>

<style>
  .view {
    display: grid;
    gap: 14px;
    align-content: start;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .spacer {
    flex: 1;
  }
  select,
  .button,
  .search {
    font: inherit;
    font-size: 13px;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 18px;
    background: var(--surface);
    padding: 6px 14px;
  }
  select {
    cursor: pointer;
  }
  .button {
    cursor: pointer;
  }
  .button:hover:not(:disabled) {
    background: var(--surface-2);
  }
  .button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  /* The view's main action (call to action). */
  .button.primary {
    background: var(--cta);
    color: var(--on-cta);
    border-color: transparent;
    font-weight: 600;
  }
  .button.primary:hover:not(:disabled) {
    background: var(--cta);
    filter: brightness(1.06);
  }
  .search {
    width: 260px;
    background: var(--surface-2);
  }
  .count {
    font-size: 12.5px;
  }
  .note {
    margin: 8px 2px;
  }
  .empty {
    padding: 28px;
    text-align: center;
  }
  .empty p {
    margin: 4px auto;
    max-width: 560px;
  }
  .empty .title {
    font-weight: 600;
  }
  .day h2 {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    margin: 4px 2px 8px;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow: visible;
  }
  .row {
    position: relative;
    display: grid;
    grid-template-columns: 10px 30px minmax(0, 1fr) auto 32px;
    align-items: center;
    gap: 14px;
    padding: 12px 12px 12px 10px;
    border-bottom: 1px solid var(--border);
    cursor: default;
  }
  .row:last-child {
    border-bottom: 0;
  }
  .row.unread {
    background: color-mix(in srgb, var(--highlight) 12%, var(--surface));
  }
  .row:first-child {
    border-radius: var(--radius) var(--radius) 0 0;
  }
  .row:last-child {
    border-radius: 0 0 var(--radius) var(--radius);
  }
  .row:only-child {
    border-radius: var(--radius);
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
  }
  .unread .dot {
    background: var(--alert-warning);
  }
  .sev {
    width: 30px;
    height: 30px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    color: var(--on-status);
    font: 700 16px/1 Georgia, "Times New Roman", serif;
    background: var(--alert-info);
  }
  .sev.warning,
  .sev.critical {
    background: var(--alert-warning);
    font-family: var(--font);
  }
  /* Not by colour alone: a doubled mark and a ring. */
  .sev.critical {
    background: var(--bad);
    outline: 2px solid var(--bad);
    outline-offset: 2px;
    letter-spacing: -1px;
    font-size: 14px;
  }
  .body {
    min-width: 0;
  }
  .text {
    all: unset;
    box-sizing: border-box;
    min-width: 0;
    display: block;
    padding: 2px 4px;
    border-radius: 6px;
  }
  .changes {
    margin: 6px 0 0 4px;
    padding-left: 18px;
    font-size: 13px;
  }
  .changes li {
    margin: 2px 0;
  }
  .keep {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 8px 0 0 4px;
    font-size: 12.5px;
  }
  .keep .button {
    padding: 4px 12px;
  }
  .keep-note {
    margin: 6px 0 0 4px;
    font-size: 12.5px;
  }
  .keep-error {
    margin: 6px 0 0 4px;
    font-size: 12.5px;
    color: var(--bad-text);
  }
  /* Windows high contrast replaces backgrounds: keep the unread dot and the
     severity badge visible with system colours. */
  @media (forced-colors: active) {
    .unread .dot {
      forced-color-adjust: none;
      background: CanvasText;
    }
    .sev {
      border: 1px solid CanvasText;
    }
  }
  .unread .text {
    cursor: pointer;
  }
  .text:focus-visible {
    outline: 2px solid var(--accent-text);
  }
  .message {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13.5px;
  }
  .message strong {
    font-weight: 600;
  }
  .path {
    display: block;
    margin: 2px 0 0 26px;
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    text-align: right;
    font-size: 12.5px;
    white-space: nowrap;
  }
  .meta .chip {
    margin-right: 4px;
  }
  .menu-wrap {
    position: relative;
  }
  .more {
    border: 0;
    background: none;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    cursor: pointer;
    color: var(--text-muted);
    font-size: 16px;
    line-height: 1;
  }
  .more:hover,
  .more[aria-expanded="true"] {
    background: var(--surface-2);
    color: var(--text);
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 5;
    display: grid;
    min-width: 170px;
    white-space: nowrap;
    padding: 4px;
    box-shadow: var(--shadow-popover);
  }
  .menu button {
    border: 0;
    background: none;
    text-align: left;
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
  }
  .menu button:hover {
    background: var(--surface-2);
  }
  .older {
    display: flex;
    justify-content: center;
  }
</style>
