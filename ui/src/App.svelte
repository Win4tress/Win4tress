<script lang="ts">
  import { onMount } from "svelte";
  import { api, events, type AppSummary, type ConnectionState, type Sample, type Status } from "./lib/api";
  import AlertsView from "./lib/AlertsView.svelte";
  import AppsView from "./lib/AppsView.svelte";
  import ConnectionsView from "./lib/ConnectionsView.svelte";
  import Disconnected from "./lib/Disconnected.svelte";
  import DnsView from "./lib/DnsView.svelte";
  import { firewall } from "./lib/firewall.svelte";
  import FirewallMenu from "./lib/FirewallMenu.svelte";
  import FirewallView from "./lib/FirewallView.svelte";
  import Logo from "./lib/Logo.svelte";
  import NetworkView from "./lib/NetworkView.svelte";
  import SearchPalette, { type Jump } from "./lib/SearchPalette.svelte";
  import SettingsView from "./lib/SettingsView.svelte";
  import StatusBanners from "./lib/StatusBanners.svelte";
  import ThemeMenu from "./lib/ThemeMenu.svelte";
  import TrafficView from "./lib/TrafficView.svelte";
  import { duration } from "./lib/format";

  /** Seconds of samples kept: the longest range the Traffic view offers. */
  const LIVE_SECONDS = 600;
  /** Status and the app list, including each app's current rate. */
  const REFRESH_MS = 1000;

  type Tab = "traffic" | "apps" | "firewall" | "connections" | "dns" | "network" | "alerts" | "settings";
  const TABS: Tab[] = ["traffic", "apps", "firewall", "connections", "dns", "network", "alerts", "settings"];
  // The last tab: closing the window frees it, and it reopens where it was.
  let tab = $state<Tab>(savedTab());
  $effect(() => {
    try {
      localStorage.setItem("w4.tab", tab);
    } catch {
      // Not remembered: it opens on Traffic.
    }
  });

  function savedTab(): Tab {
    try {
      const saved = localStorage.getItem("w4.tab");
      return TABS.find((t) => t === saved) ?? "traffic";
    } catch {
      return "traffic";
    }
  }
  let connection = $state<ConnectionState>({ connected: false, reason: null });
  let samples = $state.raw<Sample[]>([]);
  let status = $state.raw<Status | null>(null);
  let apps = $state.raw<AppSummary[]>([]);
  let selectedApp = $state<number | null>(null);
  let firewallApp = $state<number | null>(null);
  let unreadAlerts = $state(0);

  const lost = $derived(
    status ? status.collector.events_lost + status.collector.buffers_lost : 0,
  );
  // The service checks every 10 s and restarts a stopped ETW session.
  const collecting = $derived(status?.collector.running ?? true);
  const activeApps = $derived(
    apps.filter((a) => a.recent.recv + a.recent.sent > 0 || a.connections > 0).length,
  );

  async function refresh() {
    if (!connection.connected) return;
    try {
      const [s, a] = await Promise.all([api.status(), api.apps()]);
      status = s;
      apps = a.apps;
      unreadAlerts = s.unread_alerts ?? 0;
    } catch {
      // Connection events report the state; nothing to do here.
    }
  }

  async function onConnection(state: ConnectionState) {
    connection = state;
    if (!state.connected) return;
    try {
      samples = (await api.live(LIVE_SECONDS)).samples;
    } catch {
      samples = [];
    }
    await refresh();
  }

  function onSamples(batch: Sample[]) {
    const last = samples.at(-1)?.t ?? -Infinity;
    const fresh = batch.filter((s) => s.t > last);
    if (fresh.length) samples = [...samples, ...fresh].slice(-LIVE_SECONDS);
  }

  function openApp(id: number) {
    selectedApp = id;
    tab = "apps";
  }

  function openFirewall(id: number) {
    firewallApp = id;
    tab = "firewall";
  }

  // Search everywhere (Ctrl+K), and the search a result opens a view with.
  let searching = $state(false);
  let jumpSearch = $state<{ tab: Tab; text: string } | null>(null);
  const searchFor = (t: Tab) => (jumpSearch?.tab === t ? jumpSearch.text : "");

  function show(t: Tab) {
    jumpSearch = null;
    tab = t;
  }

  function onJump(j: Jump) {
    jumpSearch = null;
    if (j.to === "app") {
      if (j.live) openApp(j.id);
      else openFirewall(j.id);
      return;
    }
    if (j.search) jumpSearch = { tab: j.tab, text: j.search };
    tab = j.tab;
    if (j.section) scrollTo(j.section);
  }

  /** A section of a view that may still be loading: looked for a few times. */
  function scrollTo(id: string, tries = 20) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ block: "start", behavior: "smooth" });
    else if (tries > 0) setTimeout(() => scrollTo(id, tries - 1), 100);
  }

  // The header in two rows, the tabs under the rest, when one row doesn't fit:
  // the window can be narrower than the tabs and the status pills together,
  // and the pills' text grows ("· 3 waiting").
  let header = $state<HTMLElement>();
  let stacked = $state(false);
  $effect(() => {
    const el = header;
    if (!el) return;
    const fit = () => {
      const css = getComputedStyle(el);
      const parts = [...el.children] as HTMLElement[];
      // Each part is as wide as its content in either layout.
      const need =
        parts.reduce((w, p) => w + p.offsetWidth + parseFloat(getComputedStyle(p).marginRight), 0) +
        parseFloat(css.columnGap) * (parts.length - 1) +
        parseFloat(css.paddingLeft) +
        parseFloat(css.paddingRight);
      stacked = need > el.clientWidth;
    };
    const watch = new ResizeObserver(fit);
    watch.observe(el);
    for (const p of el.children) watch.observe(p);
    return () => watch.disconnect();
  });

  // The firewall's state is shown in the header, so it's kept fresh while connected.
  $effect(() => {
    if (connection.connected) return firewall.watch();
  });

  onMount(() => {
    const unlisten = [
      events.onConnection(onConnection),
      events.onSamples(onSamples),
      events.onAlerts((_, unread) => (unreadAlerts = unread)),
    ];
    api.connection().then(onConnection);
    const timer = setInterval(refresh, REFRESH_MS);
    return () => {
      clearInterval(timer);
      for (const u of unlisten) u.then((off) => off());
    };
  });
</script>

<div class="shell">
  <header bind:this={header} class:stacked>
    <div class="brand"><Logo /> <span>Win4tress</span></div>
    <div class="tabs" role="tablist" aria-label="Views">
      <button role="tab" aria-selected={tab === "traffic"} onclick={() => show("traffic")}>Traffic</button>
      <button role="tab" aria-selected={tab === "apps"} onclick={() => show("apps")}>
        Apps {#if activeApps}<span class="count" title="Active apps">{activeApps}</span>{/if}
      </button>
      <button role="tab" aria-selected={tab === "firewall"} onclick={() => show("firewall")}>Firewall</button>
      <button role="tab" aria-selected={tab === "connections"} onclick={() => show("connections")}>
        Connections
      </button>
      <button role="tab" aria-selected={tab === "dns"} onclick={() => show("dns")}>DNS</button>
      <button role="tab" aria-selected={tab === "network"} onclick={() => show("network")}>Network</button>
      <button role="tab" aria-selected={tab === "alerts"} onclick={() => show("alerts")}>
        Alerts
        {#if unreadAlerts}
          <span class="count unread" title="{unreadAlerts} unread">{unreadAlerts > 99 ? "99+" : unreadAlerts}</span>
        {/if}
      </button>
    </div>
    <div class="end">
      {#if connection.connected}<FirewallMenu nowMs={status?.now_ms ?? Date.now()} />{/if}
      <div
        class="status"
        class:ok={connection.connected && collecting && lost === 0}
        class:warn={connection.connected && (!collecting || lost > 0)}
        title={status
          ? `Service ${status.version}, running ${duration(status.now_ms - status.started_ms)}. ` +
            `${status.collector.events.toLocaleString()} events, ${lost} lost, ` +
            `${status.collector.parse_errors} unreadable` +
            (status.collector.restarts ? `, collector restarted ${status.collector.restarts}×.` : ".")
          : (connection.reason ?? "")}
      >
        <span class="dot"></span>
        {#if !connection.connected}
          Service not running
        {:else if !collecting}
          Not collecting · restarting
        {:else if lost > 0}
          Live · {lost.toLocaleString()} events lost
        {:else}
          Live
        {/if}
      </div>
      {#if connection.connected}
        <button class="icon-btn" aria-label="Search" title="Search everything (Ctrl+K)" onclick={() => (searching = true)}>
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></svg>
        </button>
      {/if}
      <button class="icon-btn" aria-label="Mini viewer" title="Mini viewer: a small live graph on top" onclick={() => api.miniToggle()}>
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <rect x="3" y="5" width="18" height="14" rx="2" />
          <path d="M6 15l3-4 3 2 3-5 3 4" />
        </svg>
      </button>
      <ThemeMenu />
      <button
        class="icon-btn"
        aria-label="Settings"
        title="Settings"
        aria-current={tab === "settings" ? "page" : undefined}
        onclick={() => show("settings")}
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M18.4 10.4 20.7 10.7 20.7 13.3 18.4 13.6 17.7 15.4 19.1 17.2 17.2 19.1 15.4 17.7 13.6 18.4 13.3 20.7 10.7 20.7 10.4 18.4 8.6 17.7 6.8 19.1 4.9 17.2 6.3 15.4 5.6 13.6 3.3 13.3 3.3 10.7 5.6 10.4 6.3 8.6 4.9 6.8 6.8 4.9 8.6 6.3 10.4 5.6 10.7 3.3 13.3 3.3 13.6 5.6 15.4 6.3 17.2 4.9 19.1 6.8 17.7 8.6Z"
          />
          <circle cx="12" cy="12" r="2.6" />
        </svg>
      </button>
    </div>
  </header>

  <main>
    {#if connection.connected}<StatusBanners />{/if}
    {#if !connection.connected}
      <Disconnected reason={connection.reason} />
    {:else if tab === "traffic"}
      <TrafficView {samples} {status} {apps} onopenapp={openApp} />
    {:else if tab === "apps"}
      <AppsView {apps} nowMs={status?.now_ms ?? Date.now()} bind:selectedId={selectedApp} onopenfirewall={openFirewall} />
    {:else if tab === "firewall"}
      <FirewallView nowMs={status?.now_ms ?? Date.now()} bind:selectedId={firewallApp} />
    {:else if tab === "connections"}
      <ConnectionsView nowMs={status?.now_ms ?? Date.now()} search={searchFor("connections")} />
    {:else if tab === "dns"}
      <DnsView onopenapp={openApp} lookup={searchFor("dns")} />
    {:else if tab === "network"}
      <NetworkView nowMs={status?.now_ms ?? Date.now()} />
    {:else if tab === "settings"}
      <SettingsView />
    {:else}
      <AlertsView
        onunread={(n) => (unreadAlerts = n)}
        onopenapp={openApp}
        onopensettings={() => show("settings")}
        search={searchFor("alerts")}
      />
    {/if}
  </main>
</div>

{#if connection.connected}
  <SearchPalette bind:open={searching} {apps} nowMs={status?.now_ms ?? Date.now()} ongo={onJump} />
{/if}

<svelte:window
  onkeydown={(e) => {
    if (e.ctrlKey && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k" && connection.connected) {
      e.preventDefault();
      searching = !searching;
    }
  }}
/>

<style>
  .shell {
    display: grid;
    /* The window's width: nothing in the header or a view widens the page. */
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto 1fr;
    height: 100%;
  }
  header {
    display: grid;
    /* The tabs centred in the window while both sides have room for theirs;
       otherwise they shift over rather than overlap. */
    grid-template-columns: minmax(max-content, 1fr) auto minmax(max-content, 1fr);
    align-items: center;
    gap: 12px;
    padding: 0 20px;
    height: 52px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 9px;
    font: 600 16px/1 var(--font-display);
    letter-spacing: 0.01em;
    margin-right: 12px;
    justify-self: start;
  }
  .tabs {
    display: flex;
    gap: 4px;
    height: 100%;
    align-self: stretch;
  }
  .end {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 12px;
    justify-self: end;
  }
  header.stacked {
    grid-template-columns: auto minmax(0, 1fr);
    grid-template-rows: 48px 40px;
    row-gap: 0;
    height: auto;
  }
  header.stacked .end {
    grid-row: 1;
    grid-column: 2;
  }
  header.stacked .tabs {
    grid-row: 2;
    grid-column: 1 / -1;
    justify-self: center;
    max-width: 100%;
    overflow-x: auto;
  }
  .icon-btn {
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--surface);
    color: var(--text-muted);
    cursor: pointer;
  }
  .icon-btn:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  /* Settings while it's open: no tab is selected then. */
  .icon-btn[aria-current="page"] {
    color: var(--accent-text);
    border-color: var(--accent-text);
  }
  .icon-btn svg {
    width: 17px;
    height: 17px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .tabs button {
    border: 0;
    background: none;
    padding: 0 12px;
    cursor: pointer;
    color: var(--text-muted);
    border-bottom: 2px solid transparent;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .tabs button:hover {
    color: var(--text);
  }
  .tabs button[aria-selected="true"] {
    color: var(--text);
    border-bottom-color: var(--accent-text);
    font-weight: 600;
  }
  .count {
    font-size: 11px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 10px;
    background: var(--surface-2);
    color: var(--text-muted);
  }
  .count.unread {
    background: var(--alert-warning);
    color: var(--on-status);
  }
  .status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
    color: var(--text-muted);
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 20px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--bad);
  }
  .status.ok .dot {
    background: var(--ok);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 25%, transparent);
  }
  .status.warn .dot {
    background: var(--warn);
  }
  /* Windows high contrast replaces backgrounds; the status text says the same. */
  @media (forced-colors: active) {
    .dot {
      forced-color-adjust: none;
      background: CanvasText;
    }
  }
  main {
    padding: 20px;
    overflow: auto;
    min-height: 0;
  }
</style>
