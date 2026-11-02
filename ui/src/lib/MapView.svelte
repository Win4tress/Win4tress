<script lang="ts">
  // The traffic map (SPEC §10.2, PLAN Phase 6): internet traffic by country
  // for a period, shaded in five steps of one hue on a log scale (a few
  // countries carry most traffic), with the countries as a list beside it.
  // Countries come from DB-IP; shapes from Natural Earth (world-map.json,
  // built by tools/dev/make-world-map.py).
  import { api, errorText, type Bytes, type Country } from "./api";
  import Flag from "./Flag.svelte";
  import { human } from "./format";

  /** world-map.json, loaded with the view (it's 115 KB). */
  type World = { width: number; height: number; countries: { iso: string; name: string; d: string }[] };
  let world = $state.raw<World | null>(null);
  $effect(() => {
    import("./world-map.json").then(
      (m) => (world = m.default as World),
      (e) => (error = `The map couldn't load: ${e}`),
    );
  });

  type Range = "day" | "week" | "month" | "year";
  const RANGES: { value: Range; label: string; days: number }[] = [
    { value: "day", label: "24 hours", days: 1 },
    { value: "week", label: "7 days", days: 7 },
    { value: "month", label: "30 days", days: 30 },
    { value: "year", label: "12 months", days: 365 },
  ];
  const STEPS = 5;

  let range = $state<Range>("week");
  let rows = $state.raw<{ country: Country; bytes: Bytes }[] | null>(null);
  let error = $state<string | null>(null);
  let hover = $state<{ iso: string; x: number; y: number } | null>(null);
  let selected = $state<string | null>(null);

  async function load(r: Range) {
    const days = RANGES.find((x) => x.value === r)?.days ?? 7;
    const to = Math.floor(Date.now() / 1000);
    try {
      const b = await api.breakdown(to - days * 86_400, to, { local: false }, 1);
      if (r === range) {
        rows = b.countries.filter((c) => c.country.code !== "LAN");
        error = null;
      }
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    const r = range;
    rows = null;
    load(r);
    const timer = setInterval(() => load(r), 60_000);
    return () => clearInterval(timer);
  });

  const total = (b: Bytes) => b.recv + b.sent;
  const byCode = $derived(new Map((rows ?? []).map((r) => [r.country.code, r])));
  const sum = $derived((rows ?? []).reduce((s, r) => s + total(r.bytes), 0));
  const onMap = $derived(new Set(world?.countries.map((c) => c.iso) ?? []));

  /** Five geometric steps from the smallest to the largest country total. */
  const thresholds = $derived.by(() => {
    const values = (rows ?? []).map((r) => total(r.bytes)).filter((v) => v > 0);
    if (!values.length) return [];
    const lo = Math.log(Math.min(...values));
    const hi = Math.log(Math.max(...values));
    return Array.from({ length: STEPS - 1 }, (_, i) => Math.exp(lo + ((hi - lo) * (i + 1)) / STEPS));
  });

  function step(bytes: number): number {
    if (bytes <= 0) return 0;
    let s = 1;
    for (const t of thresholds) if (bytes > t) s += 1;
    return s;
  }

  function fill(iso: string): string {
    const r = byCode.get(iso);
    const s = r ? step(total(r.bytes)) : 0;
    return s === 0 ? "var(--seq-none)" : `var(--seq-${s})`;
  }

  const legend = $derived.by(() => {
    if (!thresholds.length) return [];
    const values = (rows ?? []).map((r) => total(r.bytes)).filter((v) => v > 0);
    const bounds = [Math.min(...values), ...thresholds, Math.max(...values)];
    return Array.from({ length: STEPS }, (_, i) => ({ step: i + 1, from: bounds[i], to: bounds[i + 1] }));
  });

  function share(bytes: number): string {
    if (!sum) return "";
    const p = (bytes * 100) / sum;
    return p < 0.1 ? "<0.1%" : `${p.toFixed(p < 10 ? 1 : 0)}%`;
  }

  const hovered = $derived(hover ? byCode.get(hover.iso) : undefined);
  const hoveredName = $derived(
    hover ? (hovered?.country.name ?? world?.countries.find((c) => c.iso === hover?.iso)?.name ?? hover.iso) : "",
  );
  const offMap = $derived((rows ?? []).filter((r) => !onMap.has(r.country.code)).length);
</script>

<div class="map-view">
  <div class="toolbar">
    <div class="segmented" role="radiogroup" aria-label="Period">
      {#each RANGES as r (r.value)}
        <button role="radio" aria-checked={range === r.value} onclick={() => (range = r.value)}>{r.label}</button>
      {/each}
    </div>
    <span class="muted">
      Internet traffic by country{rows ? ` · ${rows.length} ${rows.length === 1 ? "country" : "countries"}` : ""}
    </span>
  </div>

  {#if error}
    <p class="error-text">{error.includes("history") ? "The map needs history, which isn't available." : error}</p>
  {/if}

  <div class="layout">
    <section class="card map-card" aria-label="Map of internet traffic by country">
      {#if !world}<p class="muted pad">Loading the map…</p>{:else}
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <svg
        viewBox="0 0 {world.width} {world.height}"
        role="img"
        aria-label="World map shaded by traffic; the list beside it has the same numbers"
        onmouseleave={() => (hover = null)}
      >
        {#each world.countries as c (c.iso + c.d.length)}
          <!-- Clicking a country selects it; the list beside the map does the same by keyboard. -->
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <path
            d={c.d}
            fill={fill(c.iso)}
            class:selected={selected === c.iso}
            class:hot={hover?.iso === c.iso}
            onmousemove={(e) => {
              const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
              hover = { iso: c.iso, x: e.clientX - box.left, y: e.clientY - box.top };
            }}
            onclick={() => (selected = selected === c.iso ? null : c.iso)}
          />
        {/each}
      </svg>
      {/if}
      {#if hover}
        <div class="tip card" style="left: {hover.x}px; top: {hover.y}px" role="tooltip">
          <div class="tip-name"><Flag code={hover.iso} size={16} /> {hoveredName}</div>
          {#if hovered}
            <div class="num">▼ {human(hovered.bytes.recv)} · ▲ {human(hovered.bytes.sent)}</div>
            <div class="muted num">{share(total(hovered.bytes))} of internet traffic</div>
          {:else}
            <div class="muted">No traffic</div>
          {/if}
        </div>
      {/if}
      {#if legend.length}
        <div class="legend" aria-label="Legend: total traffic per country">
          <span class="muted">Less</span>
          {#each legend as l (l.step)}
            <span class="swatch-wrap" title="{human(l.from)} to {human(l.to)}">
              <span class="swatch" style="background: var(--seq-{l.step})"></span>
              <span class="muted num">{human(l.to)}</span>
            </span>
          {/each}
          <span class="muted">More</span>
          <span class="swatch none" title="No traffic"></span><span class="muted">None</span>
        </div>
      {/if}
    </section>

    <section class="card list-card" aria-label="Countries">
      {#if rows === null}
        <p class="muted pad">Loading…</p>
      {:else if rows.length === 0}
        <p class="muted pad">No internet traffic in this period.</p>
      {:else}
        <ol class="list">
          {#each rows as r (r.country.code)}
            {@const t = total(r.bytes)}
            <li>
              <button
                class="row"
                class:selected={selected === r.country.code}
                onclick={() => (selected = selected === r.country.code ? null : r.country.code)}
              >
                <Flag code={r.country.code} size={18} />
                <span class="name ellipsis" title={r.country.name}>{r.country.name}</span>
                <span class="num amount">{human(t)}</span>
                <span class="num muted pct">{share(t)}</span>
                <span class="bar" style="width: {sum ? (t * 100) / sum : 0}%"></span>
              </button>
            </li>
          {/each}
        </ol>
        {#if offMap}
          <p class="muted small pad">
            {offMap} not on the map (too small at this scale, or not a single country).
          </p>
        {/if}
      {/if}
    </section>
  </div>
  <p class="muted small credit">
    Countries from DB-IP.com (CC BY 4.0); map from Natural Earth (public domain).
  </p>
</div>

<style>
  .map-view {
    display: grid;
    gap: 12px;
    min-height: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 13px;
  }
  .segmented {
    display: flex;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .segmented button {
    border: 0;
    background: var(--surface);
    padding: 4px 12px;
    font: 600 13px/1.3 var(--font-display);
    color: var(--text-muted);
    cursor: pointer;
  }
  .segmented button[aria-checked="true"] {
    background: color-mix(in srgb, var(--accent) 14%, var(--surface));
    color: var(--text);
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: 14px;
    align-items: start;
  }
  @media (max-width: 1000px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .map-card {
    position: relative;
    padding: 12px 12px 10px;
  }
  svg {
    display: block;
    width: 100%;
    height: auto;
  }
  path {
    stroke: var(--surface);
    stroke-width: 0.6;
    stroke-linejoin: round;
    cursor: pointer;
  }
  path.hot {
    stroke: var(--text);
    stroke-width: 1.2;
  }
  path.selected {
    stroke: var(--accent-text);
    stroke-width: 1.6;
  }
  .tip {
    position: absolute;
    transform: translate(12px, 12px);
    padding: 8px 10px;
    font-size: 12.5px;
    pointer-events: none;
    box-shadow: var(--shadow-popover);
    white-space: nowrap;
    z-index: 2;
  }
  .tip-name {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    margin-bottom: 2px;
  }
  .legend {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
    font-size: 12px;
  }
  .swatch-wrap {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .swatch {
    display: inline-block;
    width: 18px;
    height: 10px;
    border-radius: 2px;
  }
  .swatch.none {
    background: var(--seq-none);
    border: 1px solid var(--border);
    margin-left: 8px;
  }
  .list-card {
    max-height: 70vh;
    overflow: hidden auto;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 4px 0;
  }
  .row {
    all: unset;
    box-sizing: border-box;
    position: relative;
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto 48px;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 12px 8px;
    font-size: 13px;
    cursor: pointer;
  }
  .row:hover,
  .row.selected {
    background: var(--surface-2);
  }
  .row:focus-visible {
    outline: 2px solid var(--accent-text);
    outline-offset: -2px;
  }
  .bar {
    position: absolute;
    left: 12px;
    bottom: 3px;
    height: 2px;
    max-width: calc(100% - 24px);
    border-radius: 1px;
    background: var(--seq-3);
  }
  .name {
    min-width: 0;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .amount,
  .pct {
    text-align: right;
  }
  .pad {
    padding: 12px;
    margin: 0;
  }
  .small {
    font-size: 12px;
  }
  .credit {
    margin: 0;
  }
</style>
