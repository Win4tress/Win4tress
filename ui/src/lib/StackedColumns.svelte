<script lang="ts" module>
  export interface Layer {
    label: string;
    /** A CSS color, e.g. "var(--series-1)". */
    color: string;
    values: number[];
  }
</script>

<script lang="ts">
  /** Stacked columns over time. Layers stack bottom-up in the order given; a
   *  2px gap separates segments and the top of each column is rounded. Hover a
   *  column for its numbers. */
  interface Props {
    layers: Layer[];
    /** Start of the first column and the width of each, in ms. */
    startMs: number;
    stepMs: number;
    height?: number;
    /** Name of what's counted, for the readout ("lookups"). */
    unit: string;
  }

  let { layers, startMs, stepMs, height = 190, unit }: Props = $props();

  const PAD = { left: 46, right: 10, top: 10, bottom: 24 };
  const GAP = 2;
  const MAX_BAR = 24;
  const RADIUS = 4;

  let width = $state(0);
  let hover = $state<number | null>(null);

  const n = $derived(Math.max(0, ...layers.map((l) => l.values.length)));
  const totals = $derived(
    Array.from({ length: n }, (_, i) => layers.reduce((sum, l) => sum + (l.values[i] ?? 0), 0)),
  );
  const ticks = $derived(niceTicks(Math.max(1, ...totals)));
  const top = $derived(ticks.at(-1) ?? 1);
  const plotW = $derived(Math.max(0, width - PAD.left - PAD.right));
  const plotH = $derived(height - PAD.top - PAD.bottom);
  const slot = $derived(n ? plotW / n : 0);
  const barW = $derived(Math.max(1, Math.min(MAX_BAR, slot - GAP)));
  const y = (v: number) => PAD.top + plotH - (v / top) * plotH;
  const baseline = $derived(PAD.top + plotH);

  /** 0 and 3–5 round steps covering `max`. */
  function niceTicks(max: number): number[] {
    const raw = max / 4;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
    const count = Math.ceil(max / step);
    return Array.from({ length: count + 1 }, (_, i) => Math.round(i * step * 1000) / 1000);
  }

  type Segment = { x: number; y: number; w: number; h: number; color: string; rounded: boolean };
  const segments = $derived.by(() => {
    const out: Segment[] = [];
    for (let i = 0; i < n; i++) {
      const x = PAD.left + i * slot + (slot - barW) / 2;
      const nonzero = layers.filter((l) => (l.values[i] ?? 0) > 0);
      let base = baseline;
      nonzero.forEach((l, k) => {
        const h = ((l.values[i] ?? 0) / top) * plotH;
        const last = k === nonzero.length - 1;
        // The gap comes out of the lower segment, so the column keeps its height.
        const drawn = Math.max(1, last ? h : h - GAP);
        out.push({ x, y: base - drawn, w: barW, h: drawn, color: l.color, rounded: last });
        base -= h;
      });
    }
    return out;
  });

  /** A rect with rounded top corners only: the data end, square at the baseline. */
  function column(s: Segment): string {
    const r = s.rounded ? Math.min(RADIUS, s.w / 2, s.h) : 0;
    const { x, y: top, w, h } = s;
    return (
      `M${x},${top + h} L${x},${top + r} Q${x},${top} ${x + r},${top} ` +
      `L${x + w - r},${top} Q${x + w},${top} ${x + w},${top + r} L${x + w},${top + h} Z`
    );
  }

  const MIN = 60_000;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  const INTERVALS = [MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY];

  /** Time labels at round local times, about one per 90px. */
  const timeTicks = $derived.by(() => {
    if (!n || !plotW) return [];
    const span = n * stepMs;
    const fit = Math.max(1, Math.floor(plotW / 90));
    const every = INTERVALS.find((iv) => span / iv <= fit) ?? 7 * DAY;
    // Walk whole hours (or minutes, for short intervals) in local time and keep
    // the round ones; walking local hours keeps labels right across DST changes.
    const walk = every >= HOUR ? HOUR : MIN;
    const first = new Date(startMs);
    if (walk === HOUR) first.setMinutes(0, 0, 0);
    else first.setSeconds(0, 0);
    const out: { x: number; label: string }[] = [];
    for (let t = first.getTime(); t <= startMs + span; t += walk) {
      if (t < startMs) continue;
      const d = new Date(t);
      const midnight = d.getHours() === 0 && d.getMinutes() === 0;
      const round =
        every >= DAY
          ? midnight && d.getDate() % (every / DAY) === 0
          : every >= HOUR
            ? d.getMinutes() === 0 && d.getHours() % (every / HOUR) === 0
            : d.getMinutes() % (every / MIN) === 0;
      if (round) {
        out.push({
          x: PAD.left + ((t - startMs) / stepMs) * slot,
          label: midnight && span > DAY ? dayLabel(d) : hm(d),
        });
      }
    }
    return out;
  });

  function hm(d: Date): string {
    return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  function dayLabel(d: Date): string {
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
  function label(v: number): string {
    return v >= 10_000 ? `${Math.round(v / 1000)}k` : v.toLocaleString();
  }

  const readout = $derived.by(() => {
    if (hover == null) return null;
    const from = new Date(startMs + hover * stepMs);
    const to = new Date(startMs + (hover + 1) * stepMs);
    const range =
      stepMs >= DAY || from.toDateString() !== new Date().toDateString()
        ? `${dayLabel(from)} ${hm(from)}–${hm(to)}`
        : `${hm(from)}–${hm(to)}`;
    return { range, total: totals[hover] ?? 0, x: PAD.left + (hover + 0.5) * slot };
  });
</script>

<div class="chart">
  <!-- Legend and readout list layers bottom-up: the first layer is the main one. -->
  <ul class="legend">
    {#each layers as l (l.label)}
      <li><span class="swatch" style:background={l.color}></span>{l.label}</li>
    {/each}
  </ul>
  <div class="plot" bind:clientWidth={width} style:height="{height}px">
    {#if width > 0}
      <svg {width} {height} role="img" aria-label="{unit} over time, stacked by {layers.map((l) => l.label).join(', ')}">
        {#each ticks as t (t)}
          <line class="grid" x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
          <text class="axis" x={PAD.left - 8} y={y(t)} text-anchor="end" dominant-baseline="middle">{label(t)}</text>
        {/each}
        {#if hover != null}
          <rect class="hover" x={PAD.left + hover * slot} y={PAD.top} width={slot} height={plotH} />
        {/if}
        {#each segments as s, i (i)}
          <path d={column(s)} fill={s.color} />
        {/each}
        <line class="base" x1={PAD.left} x2={width - PAD.right} y1={baseline} y2={baseline} />
        {#each timeTicks as t (t.x)}
          <text class="axis" x={t.x} y={height - 6} text-anchor="middle">{t.label}</text>
        {/each}
        <!-- Hit targets: the whole column slot, taller and wider than the bar. -->
        {#each totals as _, i (i)}
          <rect
            class="hit"
            role="presentation"
            x={PAD.left + i * slot}
            y={PAD.top}
            width={slot}
            height={plotH}
            onpointerenter={() => (hover = i)}
            onpointerleave={() => (hover = null)}
          />
        {/each}
      </svg>
      {#if readout && hover != null}
        <div class="tip" style:left="{Math.min(Math.max(readout.x, 90), width - 90)}px">
          <div class="when">{readout.range}</div>
          {#each layers as l (l.label)}
            <div class="row">
              <span class="swatch" style:background={l.color}></span>
              <span class="name">{l.label}</span>
              <span class="num">{(l.values[hover] ?? 0).toLocaleString()}</span>
            </div>
          {/each}
          {#if layers.length > 1}
            <div class="row total"><span class="name">Total {unit}</span><span class="num">{readout.total.toLocaleString()}</span></div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .chart {
    display: grid;
    gap: 6px;
    padding: 0 12px 10px;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 16px;
    margin: 0;
    padding: 0 4px;
    list-style: none;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .legend li {
    display: flex;
    align-items: center;
    gap: 6px;
    max-width: 260px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .swatch {
    flex: none;
    width: 10px;
    height: 10px;
    border-radius: 3px;
  }
  .plot {
    position: relative;
    min-width: 0;
  }
  svg {
    display: block;
  }
  .grid {
    stroke: var(--grid);
    stroke-width: 1;
  }
  .base {
    stroke: var(--border);
    stroke-width: 1;
  }
  .axis {
    fill: var(--text-muted);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
  }
  .hover {
    fill: var(--surface-2);
  }
  .hit {
    fill: transparent;
  }
  .tip {
    position: absolute;
    top: 4px;
    transform: translateX(-50%);
    pointer-events: none;
    min-width: 170px;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    font-size: 12px;
    z-index: 2;
  }
  .when {
    font-weight: 600;
    margin-bottom: 4px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .row .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-muted);
  }
  .row .num {
    font-variant-numeric: tabular-nums;
  }
  .row.total {
    margin-top: 3px;
    padding-top: 3px;
    border-top: 1px solid var(--border);
  }
</style>
