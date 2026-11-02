<script lang="ts">
  import DnsDashboard, { type Range } from "./DnsDashboard.svelte";
  import DnsFilterView from "./DnsFilterView.svelte";
  import DnsLog from "./DnsLog.svelte";

  interface Props {
    onopenapp: (id: number) => void;
    /** A name to show the lookups of, e.g. from the search box. */
    lookup?: string;
  }

  let { onopenapp, lookup = "" }: Props = $props();

  const MIN = 60_000;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  /** History keeps DNS lookups for 30 days. */
  const RANGES: Range[] = [
    { key: "1h", label: "1 h", span: "hour", ms: HOUR, stepMs: MIN, refreshMs: 15_000 },
    { key: "24h", label: "24 h", span: "24 hours", ms: DAY, stepMs: 10 * MIN, refreshMs: 60_000 },
    { key: "7d", label: "7 days", span: "7 days", ms: 7 * DAY, stepMs: HOUR, refreshMs: 120_000 },
    { key: "30d", label: "30 days", span: "30 days", ms: 30 * DAY, stepMs: 6 * HOUR, refreshMs: 300_000 },
  ];

  type View = "dashboard" | "log" | "filtering";
  let view = $state<View>(validView(pref("w4.dns.view", "dashboard")));

  function validView(v: string): View {
    return v === "log" || v === "filtering" ? v : "dashboard";
  }
  let rangeKey = $state(pref("w4.dns.range", "24h"));
  let query = $state("");
  const range = $derived(RANGES.find((r) => r.key === rangeKey) ?? RANGES[1]);

  $effect(() => savePref("w4.dns.view", view));
  $effect(() => savePref("w4.dns.range", rangeKey));

  function showLookups(name: string) {
    query = name;
    view = "log";
  }

  $effect.pre(() => {
    if (lookup) showLookups(lookup);
  });

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

<div class="view" class:fill={view === "log"}>
  <div class="toolbar">
    <div class="segmented" role="radiogroup" aria-label="View">
      <button role="radio" aria-checked={view === "dashboard"} onclick={() => (view = "dashboard")}>Dashboard</button>
      <button role="radio" aria-checked={view === "log"} onclick={() => (view = "log")}>Query log</button>
      <button role="radio" aria-checked={view === "filtering"} onclick={() => (view = "filtering")}>Filtering</button>
    </div>
    <div class="spacer"></div>
    {#if view === "dashboard"}
      <div class="segmented" role="radiogroup" aria-label="Time range">
        {#each RANGES as r (r.key)}
          <button role="radio" aria-checked={rangeKey === r.key} onclick={() => (rangeKey = r.key)}>{r.label}</button>
        {/each}
      </div>
    {/if}
  </div>

  {#if view === "dashboard"}
    <DnsDashboard {range} onquery={showLookups} {onopenapp} />
  {:else if view === "filtering"}
    <DnsFilterView />
  {:else}
    <DnsLog bind:query />
  {/if}
</div>

<style>
  .view {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
  }
  /* The log fills the window and scrolls inside its card. */
  .view.fill {
    height: 100%;
    grid-template-rows: auto minmax(0, 1fr);
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
  .segmented button[aria-checked="true"] {
    background: var(--surface-2);
    color: var(--text);
    font-weight: 600;
  }
</style>
