<script lang="ts">
  import { tick } from "svelte";
  import { SvelteSet } from "svelte/reactivity";
  import {
    api,
    errorText,
    type AppRef,
    type AppSummary,
    type BlockedConnection,
    type Direction,
    type KnownApp,
    type Rule,
  } from "./api";
  import AppDetail from "./AppDetail.svelte";
  import AppIcon from "./AppIcon.svelte";
  import { firewall as fw } from "./firewall.svelte";
  import { thenText, untilText } from "./lasts";
  import { blockedByText } from "./blocked";
  import { appChips, firstChip } from "./trust";
  import Flag from "./Flag.svelte";
  import Spark from "./Spark.svelte";
  import { ago, rate, splitEndpoint } from "./format";

  interface Props {
    apps: AppSummary[];
    nowMs: number;
    /** An app to expand and scroll to, e.g. from the Traffic view. */
    selectedId?: number | null;
    /** Show an app on the Firewall screen. */
    onopenfirewall?: (id: number) => void;
  }

  let { apps, nowMs, selectedId = $bindable(null), onopenfirewall }: Props = $props();

  type SortKey = "auto" | "name" | "publisher" | "down" | "up";
  type Group = "active" | "idle" | "blocked";

  let query = $state("");
  let sortKey = $state<SortKey>("auto");
  const expanded = new SvelteSet<number>();
  const collapsed = new SvelteSet<Group>();

  // Firewall: win4tress's rule per app and direction, and what actually
  // happens (the verdict: win4tress, Windows Firewall's own rules or its
  // default). The state is shared and kept fresh (firewall.svelte.ts).
  const DIRECTIONS: Direction[] = ["in", "out"];
  const firewall = $derived(fw.status);
  const verdicts = $derived(fw.verdicts);
  let actionError = $state<string | null>(null);
  /** `${app}:${direction}` being changed. */
  const pending = new SvelteSet<string>();

  /** win4tress's rule per app and direction (setting one replaces the other action). */
  const ours = $derived.by(() => {
    const m = new Map<number, Partial<Record<Direction, Rule>>>();
    for (const r of fw.rules) {
      if (r.scope.kind !== "any") continue;
      m.set(r.app.id, { ...m.get(r.app.id), [r.direction]: r });
    }
    return m;
  });

  const verdictOf = $derived(fw.byApp);

  /** Apps with rules for some hosts, or for their own DNS. */
  const hostRules = $derived(new Set(fw.rules.filter((r) => r.scope.kind !== "any").map((r) => r.app.id)));

  function ourAction(app: number, dir: Direction): "allow" | "block" | null {
    const r = ours.get(app)?.[dir];
    return r?.enabled ? r.action : null;
  }

  /** Where no rule means blocked (outgoing in Ask to Connect), allowing an app takes
   *  an allow rule. Incoming never gets one from a switch: opening an app to the
   *  network is a deliberate action elsewhere. */
  const needsAllow = (dir: Direction) => dir === "out" && (verdicts?.outbound_default_blocks ?? false);

  /** The knob is win4tress's setting: on = not blocked by win4tress (or, where no
   *  rule means blocked, allowed by win4tress). */
  function knobOn(app: number, dir: Direction): boolean {
    const a = ourAction(app, dir);
    return needsAllow(dir) ? a === "allow" : a !== "block";
  }

  /** The track is what happens: allowed, blocked by win4tress, or blocked by Windows. */
  function track(app: number, dir: Direction, on: boolean, busy: boolean): "allowed" | "blocked" | "denied" {
    if (busy) return on ? "allowed" : "blocked"; // the expected result, until the service answers
    const v = verdictOf.get(app)?.[dir];
    if (!v) return on ? "allowed" : "blocked";
    return v.allowed ? "allowed" : v.by === "win4tress" ? "blocked" : "denied";
  }

  /** Apps with a program to name in a rule (not "Unknown"); matches the service. */
  const targetable = (a: AppSummary) => a.path === "System" || a.path.includes("\\");

  /** Flips win4tress's setting in the way the current mode needs. */
  async function toggleRule(app: AppSummary, dir: Direction) {
    const key = `${app.id}:${dir}`;
    if (pending.has(key)) return;
    const rule = ours.get(app.id)?.[dir];
    const action = ourAction(app.id, dir);
    pending.add(key);
    actionError = null;
    try {
      if (needsAllow(dir)) await api.setRule(app.id, dir, action === "allow" ? "block" : "allow");
      else if (rule && action === "block") await api.deleteRule(rule.id);
      else await api.setRule(app.id, dir, "block");
      await fw.refresh();
    } catch (e) {
      actionError = errorText(e);
    } finally {
      pending.delete(key);
    }
  }

  /** What happens now and why, then what a click does. */
  function switchTitle(app: AppSummary, dir: Direction): string {
    const v = verdictOf.get(app.id)?.[dir];
    const what = dir === "in" ? "incoming connections" : "outgoing connections";
    const names = v?.rules?.map((r) => `“${r}”`).join(", ") ?? "";
    let now = "";
    switch (v?.by) {
      case "win4tress":
        now = v.allowed ? "Allowed by a win4tress rule." : "Blocked by win4tress.";
        break;
      case "windows_rule":
        now = `${v.allowed ? "Allowed" : "Blocked"} by Windows Firewall rule ${names}.`;
        break;
      case "firewall_off":
        now = "Allowed: Windows Firewall is off on a network in use.";
        break;
      case "default":
        now = v.allowed
          ? dir === "in"
            ? "Allowed: Windows Firewall allows incoming connections by default on this network."
            : "Allowed."
          : dir === "in"
            ? "Blocked: Windows Firewall blocks incoming connections unless a rule allows them, and none does."
            : "Blocked until allowed: outgoing connections need a rule in this mode.";
        break;
    }
    const action = ourAction(app.id, dir);
    let click: string;
    if (needsAllow(dir)) click = action === "allow" ? "Click to block." : `Click to allow ${what}.`;
    else if (action === "block")
      click =
        dir === "in"
          ? "Click to stop blocking; Windows Firewall's own rules decide then."
          : "Click to stop blocking.";
    else if (v && !v.allowed) click = "Click to block with win4tress too, so a rule added later can't open it.";
    else click = `Click to block ${what}.`;
    const off =
      firewall?.mode === "off" && action === "block" ? " win4tress's rules are Off, so its block doesn't apply now." : "";
    const r = ours.get(app.id)?.[dir];
    const temp = r?.expires ? ` For now: ${untilText(r.expires)}, ${thenText(r.revert)}.` : "";
    return `${now}${temp}${off} ${click}`.trim();
  }

  // Columns drop out as the card narrows: path first (it's in the tooltip and the
  // expanded row), then version, then PID and publisher, then the activity graph.
  // The firewall switches always stay.
  let width = $state(1400);
  const canEnforce = $derived(firewall !== null);
  const room = $derived(width - (canEnforce ? 2 * 58 : 0));
  const show = $derived({
    path: room >= 1300,
    version: room >= 1050,
    pidPublisher: room >= 900,
    activity: room >= 720,
  });
  /** Expand, App, Hosts, Down and Up are always shown, and In and Out with the firewall. */
  const columns = $derived(
    5 +
      Number(show.path) +
      Number(show.version) +
      2 * Number(show.pidPublisher) +
      Number(show.activity) +
      (canEnforce ? 2 : 0),
  );

  /** Traffic in the last minute, or a connection still open. */
  const isActive = (a: AppSummary) => a.recent.recv + a.recent.sent > 0 || a.connections > 0;

  // Apps blocked since the service started (they tried) or by a win4tress rule
  // that have had no traffic, so they aren't above: listed as blocked with
  // their switches, unless they're allowed now.
  let blocks = $state.raw<BlockedConnection[]>([]);
  let known = $state.raw(new Map<number, KnownApp>());
  const askedKnown = new Set<number>();

  $effect(() => {
    const load = () =>
      api
        .blocks(null, null, 1000)
        .then((r) => (blocks = r.blocks))
        .catch(() => {});
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  });

  interface Quiet {
    app: AppRef;
    /** Attempts blocked since the service started, and the last one's time, host and cause. */
    count: number;
    last_ms: number;
    host: string | null;
    by: BlockedConnection["by"] | null;
  }

  const quiet = $derived.by(() => {
    const listed = new Set(apps.map((a) => a.id));
    const m = new Map<number, Quiet>();
    for (const b of blocks) {
      if (listed.has(b.app.id) || !b.app.path.includes("\\")) continue;
      const host = b.name ?? splitEndpoint(b.remote)[0];
      const q = m.get(b.app.id);
      if (!q) m.set(b.app.id, { app: b.app, count: b.count, last_ms: b.last_ms, host, by: b.by });
      else {
        q.count += b.count;
        if (b.last_ms > q.last_ms) Object.assign(q, { last_ms: b.last_ms, host, by: b.by });
      }
    }
    for (const r of fw.rules) {
      if (r.action !== "block" || !r.enabled || r.scope.kind !== "any" || listed.has(r.app.id)) continue;
      if (!m.has(r.app.id)) m.set(r.app.id, { app: r.app, count: 0, last_ms: 0, host: null, by: null });
    }
    // Allowed out now (say, from its switch) and no block rule: not blocked any
    // more. Incoming doesn't count: Windows blocks it for nearly every app.
    for (const id of m.keys()) {
      const ruled = ourAction(id, "in") === "block" || ourAction(id, "out") === "block";
      if (!ruled && verdictOf.get(id)?.out.allowed) m.delete(id);
    }
    return m;
  });

  // Their publisher, version and trust, from every app win4tress knows.
  $effect(() => {
    const missing = [...quiet.keys()].filter((id) => !known.has(id) && !askedKnown.has(id));
    if (!missing.length) return;
    for (const id of missing) askedKnown.add(id);
    api
      .knownApps()
      .then((r) => (known = new Map(r.apps.map((a) => [a.id, a]))))
      .catch(() => {});
  });

  const NONE = { recv: 0, sent: 0 };

  /** A row for an app without traffic since the service started. */
  function quietRow(q: Quiet): AppSummary {
    const k = known.get(q.app.id);
    return {
      id: q.app.id,
      name: k?.name ?? q.app.name,
      path: k?.path ?? q.app.path,
      service: k?.service ?? null,
      company: k?.company ?? null,
      version: k?.version ?? null,
      pids: [],
      first_seen_ms: k?.first_seen_ms ?? q.last_ms,
      last_seen_ms: k?.last_seen_ms ?? q.last_ms,
      total: NONE,
      local: NONE,
      recent: NONE,
      rate: NONE,
      host_count: 0,
      recent_hosts: 0,
      top_host: null,
      connections: 0,
      activity: [],
      trust: k?.trust ?? {},
      path_class: k?.path_class,
      own_dns_ms: k?.own_dns_ms,
      vpn: k?.vpn,
    };
  }

  const blockedRows = $derived([...quiet.values()].map(quietRow));

  function matches(a: AppSummary, q: string): boolean {
    return [a.name, a.path, a.company, a.service, a.version, a.top_host?.name, a.top_host?.ip, ...a.pids.map(String)]
      .concat(quiet.get(a.id)?.host ?? null)
      .some((field) => field?.toLowerCase().includes(q));
  }

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return q ? apps.filter((a) => matches(a, q)) : apps;
  });

  const filteredBlocked = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return q ? blockedRows.filter((a) => matches(a, q)) : blockedRows;
  });

  function quietTitle(q: Quiet | undefined): string {
    if (!q?.count) return "Blocked by a win4tress rule. It hasn't tried to connect since the service started.";
    const times = q.count === 1 ? "once" : `${q.count} times`;
    const by = q.by ? ` By: ${blockedByText(q.by)}.` : "";
    return `Blocked ${times} since the service started, last ${ago(nowMs - q.last_ms)}, connecting to ${q.host}.${by}`;
  }

  function compare(key: SortKey, group: Group): (a: AppSummary, b: AppSummary) => number {
    switch (key) {
      case "name":
        return (a, b) => a.name.localeCompare(b.name);
      case "publisher":
        return (a, b) =>
          (a.company ?? "￿").localeCompare(b.company ?? "￿") || a.name.localeCompare(b.name);
      case "down":
        return (a, b) => b.rate.recv - a.rate.recv || b.recent.recv - a.recent.recv || b.total.recv - a.total.recv;
      case "up":
        return (a, b) => b.rate.sent - a.rate.sent || b.recent.sent - a.recent.sent || b.total.sent - a.total.sent;
      case "auto":
        // Busiest in the last minute (steadier than the current rate), or most
        // recent; blocked ones by their last attempt, then by name.
        if (group === "blocked")
          return (a, b) =>
            (quiet.get(b.id)?.last_ms ?? 0) - (quiet.get(a.id)?.last_ms ?? 0) || a.name.localeCompare(b.name);
        return group === "active"
          ? (a, b) => b.recent.recv + b.recent.sent - (a.recent.recv + a.recent.sent) || a.name.localeCompare(b.name)
          : (a, b) => b.last_seen_ms - a.last_seen_ms;
    }
  }

  const groups = $derived.by(() => {
    const active = filtered.filter(isActive).sort(compare(sortKey, "active"));
    const idle = filtered.filter((a) => !isActive(a)).sort(compare(sortKey, "idle"));
    const blocked = [...filteredBlocked].sort(compare(sortKey, "blocked"));
    return [
      { key: "active" as Group, label: "Active apps", rows: active },
      { key: "idle" as Group, label: "Not active in the last minute", rows: idle },
      { key: "blocked" as Group, label: "Blocked, no traffic", rows: blocked },
    ].filter((g) => g.rows.length > 0);
  });
  const activeCount = $derived(apps.filter(isActive).length);

  // Opened from elsewhere: expand the row and bring it into view.
  $effect(() => {
    const id = selectedId;
    if (id == null) return;
    const app = apps.find((a) => a.id === id);
    const blocked = !app && quiet.has(id);
    if (!app && !blocked) return;
    expanded.add(id);
    collapsed.delete(blocked ? "blocked" : app && isActive(app) ? "active" : "idle");
    query = "";
    selectedId = null;
    tick().then(() => document.getElementById(`app-${id}`)?.scrollIntoView({ block: "nearest" }));
  });

  function toggle(id: number) {
    if (expanded.has(id)) expanded.delete(id);
    else expanded.add(id);
  }

  function toggleGroup(group: Group) {
    if (collapsed.has(group)) collapsed.delete(group);
    else collapsed.add(group);
  }

  function sortBy(key: SortKey) {
    sortKey = sortKey === key ? "auto" : key;
  }

  function sortAttr(key: SortKey) {
    return { "aria-sort": sortKey === key ? ("descending" as const) : ("none" as const) };
  }

  function pidLabel(pids: number[]): string {
    if (pids.length === 0) return "";
    if (pids.length === 1) return String(pids[0]);
    return `${pids.length} processes`;
  }

  function hostTitle(a: AppSummary): string {
    const h = a.top_host;
    if (!h) return "";
    const name = h.name ? `${h.name} (${h.ip})` : h.ip;
    const more = a.recent_hosts > 1 ? `, and ${a.recent_hosts - 1} more in the last minute` : "";
    return `${name} · ${h.country.name}${more}`;
  }
</script>

{#snippet fwSwitch(app: AppSummary, dir: Direction)}
  {#if verdictOf.get(app.id)?.protected}
    <span
      class="lock"
      title="Part of win4tress: it can't be blocked, so win4tress keeps working (Block All still blocks it)."
      aria-label="Part of win4tress: can't be blocked"
    >
      <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>
    </span>
  {:else if targetable(app)}
    {@const busy = pending.has(`${app.id}:${dir}`)}
    {@const on = busy ? !knobOn(app.id, dir) : knobOn(app.id, dir)}
    <button
      class="switch {track(app.id, dir, on, busy)}"
      class:on
      role="switch"
      aria-checked={on}
      aria-label="{dir === 'in' ? 'Incoming' : 'Outgoing'} connections for {app.name}"
      title={fw.monitoringOnly ? `${fw.monitoringOnly} win4tress can only monitor.` : switchTitle(app, dir)}
      disabled={busy || !!fw.monitoringOnly}
      onclick={(e) => {
        e.stopPropagation();
        toggleRule(app, dir);
      }}
      onkeydown={(e) => e.stopPropagation()}
    >
      <span class="knob"></span>
      {#if ours.get(app.id)?.[dir]?.expires}<span class="temp" aria-hidden="true"></span>{/if}
    </button>
  {:else}
    <span class="muted" title="No program is known for this app, so there's nothing to put in a rule.">–</span>
  {/if}
{/snippet}

<section class="card list" bind:clientWidth={width}>
  <div class="card-header">
    <h2 class="card-title">Apps</h2>
    <span class="muted">
      {activeCount} active · {apps.length} since the service started{blockedRows.length
        ? ` · ${blockedRows.length} blocked`
        : ""}
    </span>
    <div class="tools">
      {#if !firewall && fw.unavailable}
        <span class="muted unavailable" title={fw.unavailable}>Firewall controls unavailable</span>
      {/if}
      <input
        class="search"
        type="search"
        placeholder="Search apps, publishers, paths, hosts"
        bind:value={query}
        aria-label="Search apps"
      />
    </div>
  </div>
  {#if fw.monitoringOnly}
    <p class="banner">
      <strong>Monitoring only:</strong> {fw.monitoringOnly} win4tress shows traffic but doesn't change the firewall.
    </p>
  {:else if firewall?.mode === "off"}
    <p class="banner">
      win4tress's firewall is <strong>Off</strong>: your block rules are kept but switched off, and Windows
      Firewall behaves as it did before. Switch back to Click to Block in the Firewall menu at the top to apply them.
    </p>
  {/if}
  {#if actionError}
    <p class="banner error" role="alert">
      {actionError}
      <button class="dismiss" onclick={() => (actionError = null)}>Dismiss</button>
    </p>
  {/if}
  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th class="c-chev"><span class="visually-hidden">Expand</span></th>
          <th class="c-app" class:flex={!show.path} {...sortAttr("name")}>
            <button onclick={() => sortBy("name")}>App</button>
          </th>
          {#if show.pidPublisher}
            <th class="c-pid">PID</th>
            <th class="c-pub" {...sortAttr("publisher")}>
              <button onclick={() => sortBy("publisher")}>Publisher</button>
            </th>
          {/if}
          {#if show.version}<th class="c-ver">Version</th>{/if}
          {#if show.path}<th class="c-path">Path</th>{/if}
          <th class="c-hosts">Hosts</th>
          <th class="c-rate r" {...sortAttr("down")} title="Download rate">
            <button onclick={() => sortBy("down")}><span class="in">▼</span> Down</button>
          </th>
          <th class="c-rate r" {...sortAttr("up")} title="Upload rate">
            <button onclick={() => sortBy("up")}><span class="out">▲</span> Up</button>
          </th>
          {#if show.activity}<th class="c-act">Last minute</th>{/if}
          {#if canEnforce}
            <th
              class="c-fw"
              title="Incoming connections. Teal: allowed. Gray: blocked by Windows Firewall. Coral: blocked by win4tress"
            >
              In
            </th>
            <th
              class="c-fw"
              title="Outgoing connections. Teal: allowed. Gray: blocked by Windows Firewall. Coral: blocked by win4tress"
            >
              Out
            </th>
          {/if}
        </tr>
      </thead>
      {#each groups as group (group.key)}
        <tbody>
          <tr class="group">
            <th colspan={columns} scope="colgroup">
              <button aria-expanded={!collapsed.has(group.key)} onclick={() => toggleGroup(group.key)}>
                <span class="chev" class:open={!collapsed.has(group.key)} aria-hidden="true">›</span>
                {group.label}
                <span class="count">{group.rows.length}</span>
              </button>
            </th>
          </tr>
          {#if !collapsed.has(group.key)}
            {#each group.rows as app (app.id)}
              {@const open = expanded.has(app.id)}
              {@const flag = firstChip([
                ...appChips(app),
                ...(hostRules.has(app.id)
                  ? [{ label: "Host rules", tone: "" as const, title: "win4tress rules for some hosts or its own DNS (see the Firewall tab)." }]
                  : []),
              ])}
              <tr
                id="app-{app.id}"
                class="app"
                class:open
                tabindex="0"
                aria-expanded={open}
                onclick={() => toggle(app.id)}
                onkeydown={(e) => {
                  if (e.target !== e.currentTarget) return;
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    toggle(app.id);
                  }
                }}
              >
                <td class="c-chev"><span class="chev" class:open aria-hidden="true">›</span></td>
                <td class="c-app">
                  <div class="cell" title="{app.name}{app.service ? ` (${app.service})` : ''}&#10;{app.path}">
                    <AppIcon name={app.name} path={app.path} size={20} />
                    <span class="ellipsis name">{app.name}</span>
                    {#if flag}
                      <span class="chip {flag.tone}" title={flag.title}>{flag.label}{flag.more ? ` +${flag.more}` : ""}</span>
                    {/if}
                  </div>
                </td>
                {#if show.pidPublisher}
                  <td class="num muted" title={app.pids.length > 1 ? `PIDs ${app.pids.join(", ")}` : undefined}>
                    {pidLabel(app.pids)}
                  </td>
                  <td><div class="ellipsis" title={app.company ?? undefined}>{app.company ?? "–"}</div></td>
                {/if}
                {#if show.version}<td><div class="ellipsis num muted">{app.version ?? "–"}</div></td>{/if}
                {#if show.path}<td><div class="ellipsis muted" title={app.path}>{app.path}</div></td>{/if}
                <td>
                  {#if group.key === "blocked"}
                    {@const q = quiet.get(app.id)}
                    <div class="cell" title={quietTitle(q)}>
                      <span class="ellipsis muted">
                        {#if q?.count}Blocked {q.count === 1 ? "once" : `${q.count}×`} · {q.host}{:else}Blocked by a rule{/if}
                      </span>
                    </div>
                  {:else if app.top_host}
                    <div class="cell" title={hostTitle(app)}>
                      <Flag code={app.top_host.country.code} size={16} />
                      <span class="ellipsis">{app.top_host.name ?? app.top_host.ip}</span>
                      {#if app.recent_hosts > 1}<span class="more">+{app.recent_hosts - 1} more</span>{/if}
                    </div>
                  {:else if app.connections > 0}
                    <span class="muted">
                      {app.connections}
                      {app.connections === 1 ? "connection" : "connections"} open, quiet
                    </span>
                  {:else}
                    <span class="muted">Last seen {ago(nowMs - app.last_seen_ms)}</span>
                  {/if}
                </td>
                <td class="r num in">{app.rate.recv ? rate(app.rate.recv) : ""}</td>
                <td class="r num out">{app.rate.sent ? rate(app.rate.sent) : ""}</td>
                {#if show.activity}<td><Spark data={app.activity} /></td>{/if}
                {#if canEnforce}
                  {#each DIRECTIONS as dir (dir)}
                    <td class="c-fw">{@render fwSwitch(app, dir)}</td>
                  {/each}
                {/if}
              </tr>
              {#if open}
                <tr class="expanded">
                  <td colspan={columns}><AppDetail {app} {nowMs} {onopenfirewall} /></td>
                </tr>
              {/if}
            {/each}
          {/if}
        </tbody>
      {:else}
        <tbody>
          <tr>
            <td colspan={columns} class="empty muted">
              {query ? `No apps match “${query}”.` : "No app has used the network since the service started."}
            </td>
          </tr>
        </tbody>
      {/each}
    </table>
  </div>
</section>

<style>
  .list {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .tools {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .unavailable {
    font-size: 12.5px;
    cursor: help;
  }
  .banner {
    margin: 0;
    padding: 8px 14px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
    background: color-mix(in srgb, var(--warn) 10%, var(--surface));
  }
  .banner.error {
    display: flex;
    align-items: center;
    gap: 12px;
    background: color-mix(in srgb, var(--bad) 10%, var(--surface));
  }
  .dismiss {
    margin-left: auto;
    font: inherit;
    font-size: 12.5px;
    color: var(--text);
    padding: 3px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    cursor: pointer;
  }
  .c-fw {
    width: 58px;
    text-align: center;
    padding-left: 4px;
    padding-right: 4px;
  }
  .switch {
    all: unset;
    box-sizing: border-box;
    position: relative;
    display: inline-block;
    vertical-align: middle;
    width: 34px;
    height: 18px;
    border-radius: 9px;
    background: var(--accent);
    cursor: pointer;
    transition: background 0.12s;
  }
  .switch .knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--knob);
    box-shadow: 0 1px 2px #00000040;
    transition: left 0.12s;
  }
  /* The knob is win4tress's setting; the track is what happens. */
  .switch.on .knob {
    left: 18px;
  }
  .switch.blocked {
    background: var(--bad);
  }
  /* Blocked by Windows Firewall (its default or a rule), not by win4tress.
     Strong enough for 3:1 against the card and under the knob. */
  .switch.denied {
    background: color-mix(in srgb, var(--text-muted) 70%, var(--surface));
  }
  .switch:disabled {
    cursor: progress;
    opacity: 0.7;
  }
  /* A temporary rule: a small clock on the track's corner. */
  .switch .temp {
    position: absolute;
    top: -4px;
    right: -5px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    border: 1.5px solid var(--surface);
    background:
      linear-gradient(var(--accent-text), var(--accent-text)) 4px 2px / 1.2px 3.5px no-repeat,
      linear-gradient(var(--accent-text), var(--accent-text)) 4px 4.6px / 2.8px 1.2px no-repeat,
      var(--surface-2);
    box-shadow: 0 0 0 1px var(--accent-text) inset;
  }
  .lock {
    display: inline-grid;
    place-items: center;
    width: 34px;
    color: var(--text-muted);
    cursor: help;
  }
  .lock svg {
    width: 15px;
    height: 15px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
  }
  .switch:focus-visible {
    outline: 2px solid var(--accent-text);
    outline-offset: 2px;
  }
  /* Windows high contrast: an outlined track; the knob's side tells win4tress's
     setting, a dashed track "blocked by win4tress", a dotted one "blocked by
     Windows". */
  @media (forced-colors: active) {
    .switch {
      border: 1px solid ButtonText;
    }
    .switch.blocked {
      border-style: dashed;
    }
    .switch.denied {
      border-style: dotted;
    }
    .switch .knob {
      forced-color-adjust: none;
      background: ButtonText;
      top: 1px;
    }
  }
  .search {
    width: 280px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface-2);
    color: var(--text);
    font: inherit;
  }
  .scroll {
    overflow: hidden auto;
    min-height: 0;
    flex: 1;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }
  thead th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface);
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  thead th button {
    all: unset;
    cursor: pointer;
  }
  th[aria-sort="descending"] {
    color: var(--text);
  }
  th[aria-sort="descending"] button::after {
    content: " ↓";
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    font-size: 13px;
  }

  /* Column widths (the header row sets them). The path takes what's left, or
     the app name when the path is hidden. */
  .c-chev {
    width: 30px;
    padding-right: 0;
  }
  .c-app {
    width: 230px;
  }
  .c-app.flex {
    width: auto;
  }
  .c-pid {
    width: 88px;
  }
  .c-pub {
    width: 165px;
  }
  .c-ver {
    width: 120px;
  }
  .c-hosts {
    width: 235px;
  }
  .c-rate {
    width: 90px;
  }
  .c-act {
    width: 118px;
  }

  .group th {
    padding: 0;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    text-align: left;
  }
  .group button {
    all: unset;
    box-sizing: border-box;
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
  }
  .group button:focus-visible {
    outline: 2px solid var(--accent-text);
    outline-offset: -2px;
  }
  .count {
    font-size: 11px;
    padding: 0 6px;
    border-radius: 10px;
    background: var(--surface);
    color: var(--text-muted);
  }
  .chev {
    display: inline-block;
    width: 12px;
    color: var(--text-muted);
    font-size: 15px;
    line-height: 1;
    transition: transform 0.12s;
  }
  .chev.open {
    transform: rotate(90deg);
  }
  tr.app {
    cursor: pointer;
  }
  tr.app:hover,
  tr.app.open {
    background: color-mix(in srgb, var(--surface-2) 70%, transparent);
  }
  tr.app.open td {
    border-bottom-color: transparent;
  }
  tr.app:focus-visible {
    outline: 2px solid var(--accent-text);
    outline-offset: -2px;
  }
  tr.expanded td {
    padding: 0;
    background: color-mix(in srgb, var(--surface-2) 70%, transparent);
  }
  .r {
    text-align: right;
    white-space: nowrap;
  }
  .cell {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-weight: 500;
    /* A flag beside the name never squeezes it out. */
    min-width: 48px;
  }
  .more {
    flex: none;
    font-size: 11px;
    padding: 0 6px;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
  }
  .empty {
    text-align: center;
    padding: 24px;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
</style>
