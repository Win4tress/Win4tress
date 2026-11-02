<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    api,
    errorText,
    type AppSummary,
    type BreakdownFilter,
    type HistoryResult,
    type KnownApp,
    type Sample,
    type Severity,
    type Status,
  } from "./api";
  import { alertLine } from "./alerts";
  import AppIcon from "./AppIcon.svelte";
  import Bar from "./Bar.svelte";
  import Breakdown from "./Breakdown.svelte";
  import Graph from "./Graph.svelte";
  import MapView from "./MapView.svelte";
  import UsageView from "./UsageView.svelte";
  import { clock, dayLabel, human, moment, rate, sum, trafficLabel } from "./format";

  interface Props {
    samples: Sample[];
    status: Status | null;
    apps: AppSummary[];
    onopenapp: (id: number) => void;
  }

  let { samples, status, apps, onopenapp }: Props = $props();

  type View = "graph" | "usage" | "map";
  /** Short ranges come per second from memory; longer ones from history, a
   *  step at a time (a minute within 35 days, coarser beyond). */
  const RANGES = [
    { seconds: 60, label: "1 min", step: 1, history: false },
    { seconds: 300, label: "5 min", step: 1, history: false },
    { seconds: 3600, label: "1 h", step: 60, history: true },
    { seconds: 3 * 3600, label: "3 h", step: 60, history: true },
    { seconds: 24 * 3600, label: "24 h", step: 60, history: true },
    { seconds: 7 * 86_400, label: "Week", step: 600, history: true },
    { seconds: 30 * 86_400, label: "Month", step: 3_600, history: true },
  ];
  const HISTORY_REFRESH_MS = 30_000;
  /** Seconds either side of a clicked moment in the live ranges. */
  const MOMENT_HALF = 2;
  const TRAFFIC_TYPES = [
    "https", "http", "quic", "dns", "dot", "ntp", "mdns", "llmnr", "ssdp", "netbios", "smb", "rdp", "ssh", "dhcp", "other",
  ];

  type FilterKind = "all" | "internet" | "local" | "app" | "publisher" | "type" | "country";
  const FILTER_KINDS: { value: FilterKind; label: string }[] = [
    { value: "all", label: "All traffic" },
    { value: "internet", label: "Internet only" },
    { value: "local", label: "Local network only" },
    { value: "app", label: "One app" },
    { value: "publisher", label: "One publisher" },
    { value: "type", label: "One traffic type" },
    { value: "country", label: "One country" },
  ];

  let view = $state<View>(validView(pref("w4.traffic.view", "graph")));

  function validView(v: string): View {
    return v === "usage" || v === "map" ? v : "graph";
  }
  let range = $state(validRange(Number(pref("w4.traffic.range", "300"))));
  /** How many ranges back from now (history ranges). */
  let back = $state(0);
  let paused = $state(false);
  let selection = $state<[number, number] | null>(null);
  let history = $state.raw<HistoryResult | null>(null);
  let filterKind = $state<FilterKind>("all");
  let filterValue = $state("");
  let knownApps = $state.raw<KnownApp[]>([]);
  let countries = $state.raw<{ code: string; name: string }[]>([]);
  let markers = $state.raw<{ t: number; label: string; severity: Severity }[]>([]);
  let graph = $state<Graph | null>(null);
  let note = $state<string | null>(null);

  $effect(() => savePref("w4.traffic.view", view));
  $effect(() => savePref("w4.traffic.range", String(range)));

  const current = $derived(RANGES.find((r) => r.seconds === range) ?? RANGES[1]);
  const isHistory = $derived(current.history);
  const historyEnabled = $derived(status?.history.enabled ?? true);

  const filter = $derived.by((): BreakdownFilter => {
    switch (filterKind) {
      case "internet":
        return { local: false };
      case "local":
        return { local: true };
      case "app":
        return filterValue ? { app: Number(filterValue) } : {};
      case "publisher":
        return filterValue ? { publisher: filterValue } : {};
      case "type":
        return filterValue ? { traffic_type: filterValue } : {};
      case "country":
        return filterValue ? { country: filterValue } : {};
      default:
        return {};
    }
  });

  /** The history range shown: [from, to] Unix seconds. */
  function span(): [number, number] {
    const end = Math.floor(Date.now() / 1000) - back * range;
    return [end - range + 1, end];
  }

  // History ranges: fetch the steps, and refresh while showing the latest.
  $effect(() => {
    if (!isHistory) {
      history = null;
      markers = [];
      return;
    }
    const [step, flt, latest] = [current.step, filter, back === 0];
    void back;
    let cancelled = false;
    const load = () => {
      const [from, to] = span();
      api
        .history(from, to, step, flt)
        .then((h) => {
          if (!cancelled) history = h;
        })
        .catch(() => {
          if (!cancelled) history = { step, samples: [], idle: [] };
        });
      api
        .alerts({ since_ms: from * 1000, limit: 200 })
        .then((r) => {
          if (cancelled) return;
          markers = r.alerts
            .filter((a) => a.ts_ms <= to * 1000)
            .map((a) => ({ t: a.ts_ms / 1000, label: alertLine(a), severity: a.severity }));
        })
        .catch(() => {
          if (!cancelled) markers = [];
        });
    };
    load();
    const timer = latest ? setInterval(load, HISTORY_REFRESH_MS) : undefined;
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  // The choices for the filter's second list.
  $effect(() => {
    if ((filterKind === "app" || filterKind === "publisher") && knownApps.length === 0) {
      api
        .knownApps()
        .then((r) => (knownApps = [...r.apps].sort((a, b) => a.name.localeCompare(b.name))))
        .catch(() => {});
    }
    if (filterKind === "country") {
      const [from, to] = span();
      api
        .breakdown(from, to, {}, 100)
        .then((b) => (countries = b.countries.map((c) => c.country)))
        .catch(() => {});
    }
  });
  const publishers = $derived([...new Set(knownApps.map((a) => a.company).filter((c): c is string => !!c))].sort());
  const filterOptions = $derived.by((): { value: string; label: string }[] => {
    switch (filterKind) {
      case "app":
        return knownApps.map((a) => ({ value: String(a.id), label: a.name }));
      case "publisher":
        return publishers.map((p) => ({ value: p, label: p }));
      case "type":
        return TRAFFIC_TYPES.map((t) => ({ value: t, label: trafficLabel(t) }));
      case "country":
        return countries.map((c) => ({ value: c.code, label: c.name }));
      default:
        return [];
    }
  });

  const step = $derived(isHistory ? (history?.step ?? current.step) : 1);
  /** What the graphs draw: bytes per second (history steps averaged). */
  const shown = $derived(
    isHistory
      ? (history?.samples ?? []).map((s) => ({ t: s.t, recv: s.recv / step, sent: s.sent / step }))
      : samples.slice(-range),
  );
  const shade = $derived<[number, number][]>(
    (history?.idle ?? []).map((i) => [i.start_ms / 1000, i.end_ms / 1000]),
  );
  const latest = $derived(samples.at(-1) ?? null);
  const periodLabel = $derived.by(() => {
    if (!isHistory || back === 0) return `Last ${current.label.toLowerCase()}`;
    const first = history?.samples[0]?.t;
    const last = history?.samples.at(-1)?.t;
    if (first == null || last == null) return "Earlier";
    const label = (t: number) => (range >= 86_400 ? dayLabel(t) : moment(t, 3_600));
    return `${label(first)} – ${label(last + step - 1)}`;
  });

  const inRange = $derived(isHistory ? sum(history?.samples ?? []) : sum(shown));
  const overhead = $derived(
    status
      ? {
          recv: Math.max(0, status.adapter_bytes.recv - status.apps_bytes.recv),
          sent: Math.max(0, status.adapter_bytes.sent - status.apps_bytes.sent),
        }
      : null,
  );
  const active = $derived(
    apps
      .filter((a) => a.recent.recv + a.recent.sent > 0)
      .sort((a, b) => b.recent.recv + b.recent.sent - (a.recent.recv + a.recent.sent))
      .slice(0, 8),
  );
  const activeMax = $derived(Math.max(1, ...active.map((a) => a.recent.recv + a.recent.sent)));

  function setRange(seconds: number) {
    range = seconds;
    back = 0;
    selection = null;
  }

  function pick(t: number) {
    selection = isHistory ? [t, t + step - 1] : [t - MOMENT_HALF, t + MOMENT_HALF];
  }

  function validRange(seconds: number): number {
    return RANGES.some((r) => r.seconds === seconds) ? seconds : 300;
  }

  async function exportPng() {
    const dataUrl = graph?.png();
    if (!dataUrl) return;
    try {
      const path = await invoke<string>("save_png", { dataUrl });
      note = `Saved to ${path}`;
    } catch (e) {
      note = `Couldn't save the picture: ${errorText(e)}`;
    }
    setTimeout(() => (note = null), 8000);
  }

  // Remembered per user; storage can be unavailable, so never let it break the view.
  function pref(key: string, fallback: string): string {
    try {
      return localStorage.getItem(key) ?? fallback;
    } catch {
      return fallback;
    }
  }
  function savePref(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // ignore
    }
  }
</script>

<div class="view" class:fill={view === "usage"}>
  <div class="toolbar">
    <div class="segmented" role="radiogroup" aria-label="View">
      <button role="radio" aria-checked={view === "graph"} onclick={() => (view = "graph")}>Graph</button>
      <button role="radio" aria-checked={view === "usage"} onclick={() => (view = "usage")}>Usage</button>
      <button role="radio" aria-checked={view === "map"} onclick={() => (view = "map")}>Map</button>
    </div>
    <div class="spacer"></div>
    {#if view === "graph"}
      {#if isHistory}
        <div class="paging" aria-label="Move through history">
          <button class="nav" aria-label="Earlier" title="Earlier" onclick={() => (back += 1)}>‹</button>
          <button class="nav" aria-label="Later" title="Later" disabled={back === 0} onclick={() => (back -= 1)}>›</button>
          {#if back > 0}<button class="nav now" onclick={() => (back = 0)}>Now</button>{/if}
        </div>
      {/if}
      <div class="segmented" role="radiogroup" aria-label="Time range">
        {#each RANGES as r (r.seconds)}
          <button
            role="radio"
            aria-checked={range === r.seconds}
            disabled={r.history && !historyEnabled}
            title={r.history && !historyEnabled
              ? "History is off on the service; only the last 10 minutes are kept"
              : undefined}
            onclick={() => setRange(r.seconds)}>{r.label}</button
          >
        {/each}
      </div>
    {/if}
  </div>

  {#if view === "graph"}
    <div class="tiles">
      <div class="tile card">
        <div class="label">Download now</div>
        <div class="value in num">{rate(latest?.recv ?? 0)}</div>
      </div>
      <div class="tile card">
        <div class="label">Upload now</div>
        <div class="value out num">{rate(latest?.sent ?? 0)}</div>
      </div>
      <div class="tile card">
        <div class="label">{periodLabel}{filterKind !== "all" ? " · filtered" : ""}</div>
        <div class="value num">
          <span class="in">▼</span>
          {human(inRange.recv)}
          <span class="out sep">▲</span>
          {human(inRange.sent)}
        </div>
      </div>
      <div class="tile card">
        <div class="label">Since the service started</div>
        {#if status}
          <div class="value num">
            <span class="in">▼</span>
            {human(status.apps_bytes.recv)}
            <span class="out sep">▲</span>
            {human(status.apps_bytes.sent)}
          </div>
          {#if overhead}
            <div
              class="sub muted num"
              title="Packet headers, acknowledgements and other traffic not attributed to an app"
            >
              + {human(overhead.recv + overhead.sent)} protocol overhead &amp; other
            </div>
          {/if}
        {:else}
          <div class="value muted">–</div>
        {/if}
      </div>
    </div>

    <section class="card">
      <div class="card-header">
        <h2 class="card-title">Network activity</h2>
        <span class="muted">
          {periodLabel}{isHistory
            ? ` · ${step >= 3_600 ? "hourly" : step >= 600 ? `${step / 60}-minute` : "per-minute"} averages`
            : ""}
        </span>
        {#if isHistory}
          <select class="filter" bind:value={filterKind} onchange={() => (filterValue = "")} aria-label="Show">
            {#each FILTER_KINDS as k (k.value)}<option value={k.value}>{k.label}</option>{/each}
          </select>
          {#if filterOptions.length}
            <select class="filter" bind:value={filterValue} aria-label="Which">
              <option value="">Choose…</option>
              {#each filterOptions as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
            </select>
          {/if}
        {/if}
        <span class="legend">
          <span class="key in-key"></span>Download
          <span class="key out-key"></span>Upload
          {#if shade.length}<span class="key idle-key"></span>Away{/if}
        </span>
        <button class="pause" aria-pressed={paused} onclick={() => (paused = !paused)}>
          {paused ? "▶ Resume" : "❚❚ Pause"}
        </button>
        <button class="pause" onclick={exportPng} title="Save the graph as a PNG picture">Export PNG</button>
      </div>
      {#if note}<p class="note muted">{note}</p>{/if}
      <Graph
        bind:this={graph}
        samples={shown}
        {paused}
        {selection}
        {step}
        {shade}
        {markers}
        onpick={pick}
        onselect={(from, to) => (selection = [from, to])}
        latestLabel={isHistory ? (back === 0 ? "Latest" : "Last step") : "Now"}
      />
    </section>

    <div class="lower">
      <section class="card">
        <div class="card-header">
          <h2 class="card-title">Most active</h2>
          <span class="muted">last 60 seconds</span>
        </div>
        {#if active.length === 0}
          <p class="empty muted">Nothing has used the network in the last minute.</p>
        {:else}
          <ul class="active">
            {#each active as app (app.id)}
              <li>
                <button class="row" onclick={() => onopenapp(app.id)} title={app.path}>
                  <AppIcon name={app.name} path={app.path} size={24} />
                  <span class="grow">
                    <span class="line">
                      <span class="name">{app.name}</span>
                      <span class="num amounts">
                        <span class="in">▼ {human(app.recent.recv)}</span>
                        <span class="out">▲ {human(app.recent.sent)}</span>
                      </span>
                    </span>
                    <Bar recv={app.recent.recv} sent={app.recent.sent} max={activeMax} />
                  </span>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      {#if selection}
        <section class="card moment">
          <div class="card-header">
            <h2 class="card-title">
              {isHistory ? `${moment(selection[0], step)} – ${moment(selection[1], step)}` : `${clock(selection[0])} – ${clock(selection[1])}`}
            </h2>
            <span class="muted">who was talking</span>
            <button class="close" onclick={() => (selection = null)} aria-label="Close">✕</button>
          </div>
          <div class="moment-body">
            <Breakdown from={selection[0]} to={selection[1]} baseFilter={isHistory ? filter : {}} dense />
          </div>
        </section>
      {:else}
        <section class="card hint">
          <div class="hint-body">
            <div class="hint-icon" aria-hidden="true">⌖</div>
            <p>Click a moment in the graph, or drag across a range, to see which apps and hosts were talking.</p>
          </div>
        </section>
      {/if}
    </div>
  {:else if view === "map"}
    <MapView />
  {:else}
    <UsageView {latest} {historyEnabled} />
  {/if}
</div>

<style>
  .view {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
  }
  /* Usage: the columns scroll and the summary stays pinned at the bottom. */
  .view.fill {
    height: 100%;
    grid-template-rows: auto minmax(0, 1fr);
  }
  /* Grid items default to min-width: auto and would grow to fit wide content. */
  .view > :global(*),
  .lower > :global(*) {
    min-width: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .spacer {
    flex: 1;
  }
  .segmented {
    display: inline-flex;
    padding: 3px;
    gap: 2px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: var(--surface);
  }
  .segmented button {
    border: 0;
    background: none;
    padding: 4px 12px;
    border-radius: 6px;
    cursor: pointer;
    color: var(--text-muted);
    font-size: 13px;
  }
  .segmented button:hover {
    color: var(--text);
  }
  .segmented button:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .segmented button[aria-checked="true"] {
    background: var(--surface-2);
    color: var(--text);
    font-weight: 600;
  }
  .paging {
    display: inline-flex;
    gap: 4px;
  }
  .nav {
    border: 1px solid var(--border);
    background: var(--surface);
    border-radius: 7px;
    min-width: 30px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 14px;
    line-height: 1;
  }
  .nav.now {
    font-size: 12.5px;
  }
  .nav:hover:not(:disabled) {
    background: var(--surface-2);
  }
  .nav:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
  }
  .tile {
    padding: 14px 16px;
  }
  .label {
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 4px;
  }
  .value {
    font: 600 20px/1.2 var(--font-display);
  }
  .value .sep {
    margin-left: 10px;
  }
  .sub {
    font-size: 12px;
    margin-top: 4px;
  }
  .filter {
    font: inherit;
    font-size: 12.5px;
    color: var(--text);
    padding: 3px 6px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
    max-width: 200px;
  }
  .legend {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .key {
    width: 10px;
    height: 10px;
    border-radius: 3px;
    margin-left: 8px;
  }
  .in-key {
    background: var(--in);
  }
  .out-key {
    background: var(--out);
  }
  .idle-key {
    background: color-mix(in srgb, var(--text-muted) 25%, transparent);
  }
  .pause {
    border: 1px solid var(--border);
    background: var(--surface);
    border-radius: 7px;
    padding: 4px 10px;
    cursor: pointer;
    font-size: 12.5px;
    white-space: nowrap;
  }
  .pause:hover,
  .pause[aria-pressed="true"] {
    background: var(--surface-2);
  }
  .note {
    margin: 0 16px 6px;
    font-size: 12.5px;
  }
  .lower {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr);
    gap: 16px;
    align-items: start;
  }
  .active {
    list-style: none;
    margin: 0;
    padding: 0 8px 8px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 7px 8px;
    border: 0;
    border-radius: 8px;
    background: none;
    cursor: pointer;
    text-align: left;
  }
  .row:hover {
    background: var(--surface-2);
  }
  .grow {
    flex: 1;
    min-width: 0;
    display: grid;
    gap: 5px;
  }
  .line {
    display: flex;
    justify-content: space-between;
    gap: 12px;
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .amounts {
    flex: none;
    display: flex;
    gap: 10px;
    font-size: 12.5px;
  }
  .empty {
    padding: 0 16px 14px;
    margin: 0;
  }
  .moment-body {
    padding: 0 8px 12px;
  }
  .close {
    margin-left: auto;
    border: 0;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 6px;
  }
  .close:hover {
    background: var(--surface-2);
  }
  .hint {
    display: grid;
    place-items: center;
    min-height: 160px;
    border-style: dashed;
    box-shadow: none;
    background: transparent;
  }
  .hint-body {
    text-align: center;
    color: var(--text-muted);
    max-width: 300px;
  }
  .hint-icon {
    font-size: 26px;
    color: var(--accent-text);
  }
  @media (max-width: 1050px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .lower {
      grid-template-columns: 1fr;
    }
  }
</style>
