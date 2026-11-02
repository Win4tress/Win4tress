<script lang="ts">
  // Usage (SPEC §10.2): a day, week or month from history, by app, host,
  // publisher, traffic type and country, for the internet, the local network
  // or both; the data plan; and whether VPN clients count.
  import {
    api,
    errorText,
    type Breakdown as BreakdownData,
    type BreakdownFilter,
    type HistoryResult,
    type Sample,
    type Settings,
  } from "./api";
  import Breakdown from "./Breakdown.svelte";
  import DataPlanCard from "./DataPlanCard.svelte";
  import SummaryBar from "./SummaryBar.svelte";

  interface Props {
    latest: Sample | null;
    historyEnabled: boolean;
  }

  let { latest, historyEnabled }: Props = $props();

  type Period = "day" | "week" | "month";
  type Where = "both" | "internet" | "local";
  const PERIODS: { value: Period; label: string; step: number }[] = [
    { value: "day", label: "Day", step: 300 },
    { value: "week", label: "Week", step: 3_600 },
    { value: "month", label: "Month", step: 3_600 },
  ];
  const WHERE: { value: Where; label: string }[] = [
    { value: "both", label: "Both" },
    { value: "internet", label: "Internet" },
    { value: "local", label: "Local network" },
  ];

  let period = $state<Period>(validPeriod(pref("w4.usage.period", "day")));
  /** A day in the period shown, YYYY-MM-DD (local). */
  let anchor = $state(isoDay(new Date()));
  let where = $state<Where>("both");
  let selection = $state<[number, number] | null>(null);
  let totals = $state.raw<BreakdownData | null>(null);
  let timeline = $state.raw<HistoryResult | null>(null);
  let settings = $state.raw<Settings | null>(null);
  let settingsError = $state<string | null>(null);
  /** Moves the current period's end along with the clock. */
  let tick = $state(0);

  $effect(() => savePref("w4.usage.period", period));
  $effect(() => {
    const timer = setInterval(() => (tick += 1), 60_000);
    return () => clearInterval(timer);
  });
  $effect(() => {
    api
      .settings()
      .then((s) => (settings = s))
      .catch(() => {});
  });

  const step = $derived(PERIODS.find((p) => p.value === period)?.step ?? 300);
  const filter = $derived<BreakdownFilter>(where === "both" ? {} : { local: where === "local" });

  /** Local midnight to local midnight, as [first, last] Unix seconds. */
  const bounds = $derived.by((): [number, number] => {
    const [y, m, d] = anchor.split("-").map(Number);
    let start: Date;
    let end: Date;
    if (period === "day") {
      start = new Date(y, m - 1, d);
      end = new Date(y, m - 1, d + 1);
    } else if (period === "week") {
      // Weeks start on Monday.
      const monday = d - ((new Date(y, m - 1, d).getDay() + 6) % 7);
      start = new Date(y, m - 1, monday);
      end = new Date(y, m - 1, monday + 7);
    } else {
      start = new Date(y, m - 1, 1);
      end = new Date(y, m, 1);
    }
    return [start.getTime() / 1000, end.getTime() / 1000 - 1];
  });
  /** Up to now, for the period that's still going. */
  const range = $derived.by((): [number, number] => {
    void tick;
    return [bounds[0], Math.min(bounds[1], Math.floor(Date.now() / 1000))];
  });
  const current = $derived(bounds[1] >= Date.now() / 1000);

  $effect(() => {
    const [from, to] = range;
    const [s, f] = [step, filter];
    let cancelled = false;
    api
      .history(from, to, s, f)
      .then((h) => {
        if (!cancelled) timeline = h;
      })
      .catch(() => {
        if (!cancelled) timeline = { step: s, samples: [], idle: [] };
      });
    return () => {
      cancelled = true;
    };
  });
  const samples = $derived(
    (timeline?.samples ?? []).map((x) => ({ t: x.t, recv: x.recv / (timeline?.step ?? 1), sent: x.sent / (timeline?.step ?? 1) })),
  );

  function move(by: number) {
    const [y, m, d] = anchor.split("-").map(Number);
    const next =
      period === "day"
        ? new Date(y, m - 1, d + by)
        : period === "week"
          ? new Date(y, m - 1, d + 7 * by)
          : new Date(y, m - 1 + by, Math.min(d, 28));
    anchor = isoDay(next);
    selection = null;
  }

  async function setExcludeVpn(exclude: boolean) {
    if (!settings) return;
    settingsError = null;
    try {
      settings = await api.setSettings({ ...settings, exclude_vpn: exclude });
    } catch (e) {
      settingsError = errorText(e);
    }
  }

  function isoDay(d: Date): string {
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }
  function validPeriod(p: string): Period {
    return p === "week" || p === "month" ? p : "day";
  }
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

<div class="usage-view">
  <!-- One grid row however many of these show, so the breakdown keeps its row. -->
  <div class="head">
    <div class="toolbar">
      <div class="segmented" role="radiogroup" aria-label="Period">
        {#each PERIODS as p (p.value)}
          <button
            role="radio"
            aria-checked={period === p.value}
            onclick={() => {
              period = p.value;
              selection = null;
            }}>{p.label}</button
          >
        {/each}
      </div>
      <div class="paging">
        <button class="nav" aria-label="Earlier" title="Earlier" onclick={() => move(-1)}>‹</button>
        <input
          class="date"
          type="date"
          bind:value={anchor}
          max={isoDay(new Date())}
          aria-label="A day in the period"
          onchange={() => (selection = null)}
        />
        <button class="nav" aria-label="Later" title="Later" disabled={current} onclick={() => move(1)}>›</button>
        {#if !current}
          <button
            class="nav today"
            onclick={() => {
              anchor = isoDay(new Date());
              selection = null;
            }}>Today</button
          >
        {/if}
      </div>
      <div class="segmented" role="radiogroup" aria-label="Which traffic">
        {#each WHERE as w (w.value)}
          <button role="radio" aria-checked={where === w.value} onclick={() => (where = w.value)}>{w.label}</button>
        {/each}
      </div>
      <div class="spacer"></div>
      {#if settings}
        <label
          class="vpn"
          title="VPN clients carry other apps' traffic again, encrypted, so it can be counted twice. Leaving them out counts it once."
        >
          <input type="checkbox" checked={settings.exclude_vpn} onchange={(e) => setExcludeVpn(e.currentTarget.checked)} />
          Leave out VPN clients
        </label>
      {/if}
    </div>
    {#if settingsError}<p class="error-text small">{settingsError}</p>{/if}
    {#if !historyEnabled}
      <p class="muted small">History is off on the service; only the last 10 minutes are kept.</p>
    {/if}

    <DataPlanCard {settings} onsaved={(s) => (settings = s)} />
  </div>

  <section class="card breakdown">
    <Breakdown from={selection?.[0] ?? range[0]} to={selection?.[1] ?? range[1]} baseFilter={filter} ontotals={(b) => (totals = b)} />
  </section>

  <SummaryBar
    {totals}
    {latest}
    {samples}
    {selection}
    onpick={(t) => (selection = [t, t + step - 1])}
    onselect={(from, to) => (selection = [from, to])}
    onclear={() => (selection = null)}
    step={timeline?.step ?? step}
  />
</div>

<style>
  .usage-view {
    height: 100%;
    min-height: 0;
    display: grid;
    grid-template-rows: auto minmax(0, 1fr) auto;
    gap: 12px;
  }
  .head {
    display: grid;
    gap: 10px;
  }
  .usage-view > :global(*) {
    min-width: 0;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
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
  .segmented button[aria-checked="true"] {
    background: var(--surface-2);
    color: var(--text);
    font-weight: 600;
  }
  .paging {
    display: inline-flex;
    align-items: center;
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
  .nav.today {
    font-size: 12.5px;
  }
  .nav:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .date {
    font: inherit;
    font-size: 13px;
    color: var(--text);
    padding: 3px 6px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
    color-scheme: inherit;
  }
  .vpn {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--text-muted);
    cursor: pointer;
  }
  .vpn input {
    accent-color: var(--accent);
  }
  .small {
    font-size: 12.5px;
    margin: 0;
  }
  .breakdown {
    padding: 14px 8px 12px;
    overflow: auto;
    min-height: 0;
  }
</style>
