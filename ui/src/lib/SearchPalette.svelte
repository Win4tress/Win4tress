<script lang="ts" module>
  /** Where a result leads. */
  export type Jump =
    | { to: "app"; id: number; live: boolean }
    | { to: "tab"; tab: "traffic" | "apps" | "firewall" | "connections" | "dns" | "network" | "alerts" | "settings"; search?: string; section?: string };
</script>

<script lang="ts">
  // Search everywhere (Ctrl+K): apps, hosts, DNS names, alerts, devices,
  // profiles, and the places in Settings, from one box. Enter goes there.
  import { tick } from "svelte";
  import { api, type Alert, type AppSummary, type Device, type KnownApp, type NetConnection } from "./api";
  import { alertLine } from "./alerts";
  import AppIcon from "./AppIcon.svelte";
  import { firewall } from "./firewall.svelte";
  import { ago } from "./format";

  interface Props {
    open: boolean;
    /** The apps active in this run, for opening them in Apps rather than Firewall. */
    apps: AppSummary[];
    nowMs: number;
    ongo: (jump: Jump) => void;
  }

  let { open = $bindable(), apps, nowMs, ongo }: Props = $props();

  type Kind = "app" | "host" | "name" | "alert" | "device" | "profile" | "place";
  interface Result {
    key: string;
    kind: Kind;
    label: string;
    detail: string;
    /** Matched against; the label's words count most. */
    text: string;
    app?: { name: string; path: string };
    run: () => void | Promise<unknown>;
  }

  const GROUPS: { kind: Kind; label: string; max: number }[] = [
    { kind: "app", label: "Apps", max: 6 },
    { kind: "host", label: "Hosts connected now", max: 5 },
    { kind: "name", label: "Names looked up (24 hours)", max: 5 },
    { kind: "alert", label: "Alerts", max: 5 },
    { kind: "device", label: "Devices on the network", max: 4 },
    { kind: "profile", label: "Profiles", max: 4 },
    { kind: "place", label: "Places and actions", max: 6 },
  ];

  const PLACES: { label: string; detail: string; words: string; jump?: Jump; run?: () => unknown }[] = [
    { label: "Alerts and notifications", detail: "Settings", words: "monitors pop-ups desktop notifications snooze event log", jump: { to: "tab", tab: "settings", section: "alert-settings" } },
    { label: "Export rules", detail: "Settings · Rules and profiles", words: "backup save file copy another pc", jump: { to: "tab", tab: "settings", section: "transfer" } },
    { label: "Import rules", detail: "Settings · Rules and profiles", words: "restore load file another pc", jump: { to: "tab", tab: "settings", section: "transfer" } },
    { label: "Automatic cleanup", detail: "Settings", words: "uninstalled inactive old rules remove", jump: { to: "tab", tab: "settings", section: "cleanup" } },
    { label: "Reputation lookups", detail: "Settings", words: "virustotal malwarebazaar hash antivirus scan key", jump: { to: "tab", tab: "settings", section: "reputation" } },
    { label: "Incognito", detail: "Settings · Privacy", words: "privacy history private", jump: { to: "tab", tab: "settings", section: "privacy" } },
    { label: "Start when I sign in", detail: "Settings · General", words: "startup autostart tray", jump: { to: "tab", tab: "settings", section: "general" } },
    { label: "About Win4tress", detail: "Settings", words: "version build windows licence license credits copy details", jump: { to: "tab", tab: "settings", section: "about" } },
    { label: "DNS filtering", detail: "DNS", words: "blocklists ads trackers resolver", jump: { to: "tab", tab: "dns" } },
    { label: "Connections and what was blocked", detail: "Connections", words: "blocked attempts dropped firewall open", jump: { to: "tab", tab: "connections" } },
    { label: "Devices on the network", detail: "Network", words: "scan lan devices router", jump: { to: "tab", tab: "network" } },
    { label: "Firewall rules", detail: "Firewall", words: "rules apps block allow bulk", jump: { to: "tab", tab: "firewall" } },
    { label: "Traffic and usage", detail: "Traffic", words: "graph usage data plan map countries", jump: { to: "tab", tab: "traffic" } },
    { label: "Mini viewer", detail: "Opens or closes it", words: "small graph on top overlay", run: () => api.miniToggle() },
  ];

  let query = $state("");
  let active = $state(0);
  let input = $state<HTMLInputElement | null>(null);
  let known = $state.raw<KnownApp[]>([]);
  let connections = $state.raw<NetConnection[]>([]);
  let names = $state.raw<string[]>([]);
  let alerts = $state.raw<Alert[]>([]);
  let devices = $state.raw<Device[]>([]);
  let profiles = $state.raw<string[]>([]);
  let note = $state<string | null>(null);

  // Fresh data each time it opens; whatever fails is left out.
  $effect(() => {
    if (!open) return;
    query = "";
    active = 0;
    note = null;
    tick().then(() => input?.focus());
    const day = 24 * 3600 * 1000;
    api.knownApps().then((r) => (known = r.apps), () => {});
    api.connections().then((r) => (connections = r.connections), () => {});
    api.dnsTop(Date.now() - day, Date.now(), 300).then((r) => (names = r.domains.map((d) => d.name)), () => {});
    api.alerts({ limit: 300 }).then((r) => (alerts = r.alerts), () => {});
    api.devices().then((r) => (devices = r.devices), () => {});
    api.profiles().then((r) => (profiles = r.profiles.map((p) => p.name)), () => {});
  });

  const liveIds = $derived(new Set(apps.map((a) => a.id)));

  function go(jump: Jump) {
    open = false;
    ongo(jump);
  }

  const all = $derived.by((): Result[] => {
    const out: Result[] = [];
    for (const a of known)
      out.push({
        key: `a${a.id}`,
        kind: "app",
        label: a.name,
        detail: [a.company, a.service, a.path].filter(Boolean).join(" · "),
        text: `${a.name} ${a.company ?? ""} ${a.service ?? ""} ${a.path}`,
        app: { name: a.name, path: a.path },
        run: () => go({ to: "app", id: a.id, live: liveIds.has(a.id) }),
      });
    const hosts = new Map<string, Set<string>>();
    for (const c of connections) {
      const host = c.name ?? c.remote.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
      if (!hosts.has(host)) hosts.set(host, new Set());
      hosts.get(host)!.add(c.app.name);
    }
    for (const [host, by] of hosts)
      out.push({
        key: `h${host}`,
        kind: "host",
        label: host,
        detail: [...by].slice(0, 3).join(", "),
        text: `${host} ${[...by].join(" ")}`,
        run: () => go({ to: "tab", tab: "connections", search: host }),
      });
    for (const n of names)
      out.push({
        key: `n${n}`,
        kind: "name",
        label: n,
        detail: "Its lookups in DNS",
        text: n,
        run: () => go({ to: "tab", tab: "dns", search: n }),
      });
    for (const a of alerts) {
      const line = alertLine(a);
      out.push({
        key: `al${a.id}`,
        kind: "alert",
        label: line,
        detail: `${a.severity} · ${ago(nowMs - a.ts_ms)}`,
        text: `${line} ${a.app?.name ?? ""}`,
        run: () => go({ to: "tab", tab: "alerts", search: a.app?.name ?? line }),
      });
    }
    for (const d of devices) {
      const label = d.name ?? d.vendor ?? d.ip;
      out.push({
        key: `d${d.mac}`,
        kind: "device",
        label,
        detail: [d.ip, d.mac, d.vendor !== label ? d.vendor : null].filter(Boolean).join(" · "),
        text: `${d.name ?? ""} ${d.vendor ?? ""} ${d.ip} ${d.mac}`,
        run: () => go({ to: "tab", tab: "network" }),
      });
    }
    for (const p of profiles)
      out.push({
        key: `p${p}`,
        kind: "profile",
        label: `Switch to ${p}`,
        detail: "Firewall profile",
        text: `profile ${p}`,
        run: async () => {
          try {
            await api.switchProfile(p);
            await firewall.refresh();
            open = false;
          } catch (e) {
            note = String(e).replace(/^service error:\s*/i, "").replace(/\s*\(code -?\d+\)$/, "");
          }
        },
      });
    for (const pl of PLACES)
      out.push({
        key: `pl${pl.label}`,
        kind: "place",
        label: pl.label,
        detail: pl.detail,
        text: `${pl.label} ${pl.words}`,
        run: () => {
          if (pl.jump) go(pl.jump);
          else {
            open = false;
            pl.run?.();
          }
        },
      });
    return out;
  });

  /** Higher is better; 0 doesn't match. Every word typed must be found. */
  function score(r: Result, words: string[]): number {
    const label = r.label.toLowerCase();
    const text = r.text.toLowerCase();
    let total = 0;
    for (const w of words) {
      if (label.startsWith(w)) total += 4;
      else if (label.includes(` ${w}`) || label.includes(`.${w}`)) total += 3;
      else if (label.includes(w)) total += 2;
      else if (text.includes(w)) total += 1;
      else return 0;
    }
    return total;
  }

  const groups = $derived.by(() => {
    const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return GROUPS.map((g) => {
      const items = all.filter((r) => r.kind === g.kind);
      const ranked = words.length
        ? items
            .map((r) => ({ r, s: score(r, words) }))
            .filter((x) => x.s > 0)
            .sort((a, b) => b.s - a.s || a.r.label.length - b.r.label.length)
            .map((x) => x.r)
        : // Before typing: places only, as a start.
          g.kind === "place"
          ? items
          : [];
      return { ...g, items: ranked.slice(0, words.length ? g.max : PLACES.length) };
    }).filter((g) => g.items.length);
  });
  const flat = $derived(groups.flatMap((g) => g.items));

  $effect(() => {
    if (active >= flat.length) active = Math.max(0, flat.length - 1);
  });

  function keydown(e: KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      active = flat.length ? (active + 1) % flat.length : 0;
      scrollActive();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      active = flat.length ? (active - 1 + flat.length) % flat.length : 0;
      scrollActive();
    } else if (e.key === "Enter") {
      e.preventDefault();
      flat[active]?.run();
    } else if (e.key === "Escape") {
      e.preventDefault();
      open = false;
    }
  }

  function scrollActive() {
    tick().then(() => document.getElementById(`sr-${active}`)?.scrollIntoView({ block: "nearest" }));
  }

  const GLYPH: Record<Exclude<Kind, "app">, string> = {
    host: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm-9 9h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z",
    name: "M4 6h16M4 12h10M4 18h7",
    alert: "M12 4 3 20h18L12 4Zm0 6v4m0 3v.5",
    device: "M4 5h16v11H4zM9 20h6M12 16v4",
    profile: "M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6l-7-3Z",
    place: "M9 6l6 6-6 6",
  };
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="backdrop" onclick={() => (open = false)}>
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
    <div class="palette card" role="dialog" aria-label="Search" tabindex="-1" onclick={(e) => e.stopPropagation()}>
      <div class="box">
        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></svg>
        <input
          bind:this={input}
          bind:value={query}
          oninput={() => (active = 0)}
          onkeydown={keydown}
          placeholder="Search apps, hosts, alerts, devices, settings…"
          aria-label="Search"
          aria-controls="search-results"
          aria-activedescendant={flat.length ? `sr-${active}` : undefined}
          role="combobox"
          aria-expanded="true"
          spellcheck="false"
        />
        <kbd>Esc</kbd>
      </div>
      {#if note}<p class="error-text note" role="alert">{note}</p>{/if}
      <div class="results" id="search-results" role="listbox" aria-label="Results">
        {#each groups as g (g.kind)}
          <div class="group" role="presentation">{g.label}</div>
          {#each g.items as r (r.key)}
            {@const i = flat.indexOf(r)}
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <div
              id="sr-{i}"
              class="item"
              class:active={i === active}
              role="option"
              aria-selected={i === active}
              tabindex="-1"
              onmousemove={() => (active = i)}
              onclick={() => r.run()}
            >
              <span class="icon">
                {#if r.app}
                  <AppIcon name={r.app.name} path={r.app.path} size={18} />
                {:else}
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d={GLYPH[r.kind as Exclude<Kind, "app">]} /></svg>
                {/if}
              </span>
              <span class="label ellipsis">{r.label}</span>
              <span class="detail muted ellipsis">{r.detail}</span>
            </div>
          {/each}
        {:else}
          <p class="muted empty">{query.trim() ? `Nothing matches “${query.trim()}”.` : "Type to search."}</p>
        {/each}
      </div>
      <p class="hint muted">↑ ↓ to choose · Enter to go there · Ctrl+K opens this anywhere</p>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    background: rgb(0 0 0 / 0.28);
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding-top: 72px;
  }
  .palette {
    width: min(640px, calc(100vw - 32px));
    max-height: min(560px, calc(100vh - 110px));
    display: flex;
    flex-direction: column;
    padding: 0;
    overflow: hidden;
    box-shadow: var(--shadow-popover);
  }
  .box {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
  }
  .box svg {
    width: 18px;
    height: 18px;
    flex: none;
    fill: none;
    stroke: var(--text-muted);
    stroke-width: 2;
    stroke-linecap: round;
  }
  .box input {
    flex: 1;
    min-width: 0;
    border: 0;
    outline: 0;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: 15px;
  }
  kbd {
    font: 11px/1 var(--mono);
    color: var(--text-muted);
    padding: 3px 5px;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .results {
    overflow: auto;
    padding: 4px 6px 6px;
  }
  .group {
    padding: 8px 8px 3px;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-muted);
  }
  .item {
    display: grid;
    grid-template-columns: 22px minmax(0, auto) minmax(0, 1fr);
    align-items: center;
    gap: 10px;
    padding: 6px 8px;
    border-radius: 7px;
    cursor: pointer;
    font-size: 13px;
  }
  .item.active {
    background: color-mix(in srgb, var(--accent) 14%, var(--surface));
  }
  .icon {
    display: grid;
    place-items: center;
  }
  .icon svg {
    width: 16px;
    height: 16px;
    fill: none;
    stroke: var(--text-muted);
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .label {
    max-width: 330px;
  }
  .detail {
    font-size: 12px;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .empty {
    margin: 0;
    padding: 18px 10px;
    text-align: center;
  }
  .note {
    margin: 8px 14px 0;
    font-size: 12.5px;
  }
  .hint {
    margin: 0;
    padding: 7px 14px;
    border-top: 1px solid var(--border);
    font-size: 11.5px;
  }
</style>
