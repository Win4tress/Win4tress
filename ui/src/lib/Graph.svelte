<script lang="ts">
  import { untrack } from "svelte";
  import uPlot from "uplot";
  import "uplot/dist/uPlot.min.css";
  import type { Sample, Severity } from "./api";
  import { clock, dayLabel, moment, rate } from "./format";
  import { theme } from "./theme.svelte";

  interface Props {
    samples: Sample[];
    paused?: boolean;
    /** Highlighted [from, to] Unix seconds. */
    selection?: [number, number] | null;
    /** Click on a moment. */
    onpick?: (t: number) => void;
    /** Drag across a range. */
    onselect?: (from: number, to: number) => void;
    height?: number;
    /** Timeline strip: no readout or rate axis. */
    compact?: boolean;
    /** Readout label for the newest sample when not hovering. */
    latestLabel?: string;
    /** Seconds per sample (for which markers a hovered sample covers). */
    step?: number;
    /** Shaded [from, to] Unix seconds: when nobody used the PC. */
    shade?: [number, number][];
    /** Alerts along the top, at Unix seconds. */
    markers?: { t: number; label: string; severity: Severity }[];
  }

  let {
    samples,
    paused = false,
    selection = null,
    onpick,
    onselect,
    height = 260,
    compact = false,
    latestLabel = "Now",
    step = 1,
    shade = [],
    markers = [],
  }: Props = $props();

  let host: HTMLDivElement;
  let plot: uPlot | null = null;
  /** What's drawn; frozen while paused so clicks match the picture. */
  let shown: Sample[] = [];
  /** Set by a drag so the click that ends it isn't also treated as a pick. */
  let dragged = false;
  let hover = $state<Sample | null>(null);
  const readout = $derived(hover ?? samples.at(-1) ?? null);
  /** Over more than a day, a moment needs its date too. */
  const multiDay = $derived(samples.length > 1 && samples.at(-1)!.t - samples[0].t > 86_400);
  /** Alerts in the hovered sample's time. */
  const hoverMarkers = $derived(hover ? markers.filter((m) => m.t >= hover!.t && m.t < hover!.t + step) : []);

  /** The plot as a PNG data URL (for "Export"). */
  export function png(): string | null {
    return plot ? plot.ctx.canvas.toDataURL("image/png") : null;
  }

  function css(name: string): string {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function toData(s: Sample[]): uPlot.AlignedData {
    return [s.map((x) => x.t), s.map((x) => x.recv), s.map((x) => x.sent)];
  }

  function areaFill(color: string) {
    return (u: uPlot) => {
      const g = u.ctx.createLinearGradient(0, u.bbox.top, 0, u.bbox.top + u.bbox.height);
      g.addColorStop(0, color + "59");
      g.addColorStop(1, color + "05");
      return g;
    };
  }

  function drawSelection(u: uPlot) {
    if (!selection) return;
    const [from, to] = selection;
    const x0 = u.valToPos(from - 0.5, "x", true);
    const x1 = u.valToPos(to + 0.5, "x", true);
    const accent = css("--accent");
    u.ctx.save();
    u.ctx.fillStyle = accent + "1f";
    u.ctx.fillRect(x0, u.bbox.top, x1 - x0, u.bbox.height);
    u.ctx.fillStyle = accent + "99";
    u.ctx.fillRect(x0, u.bbox.top, 1.5 * devicePixelRatio, u.bbox.height);
    u.ctx.fillRect(x1, u.bbox.top, 1.5 * devicePixelRatio, u.bbox.height);
    u.ctx.restore();
  }

  /** Idle time, behind the traffic. */
  function drawShade(u: uPlot) {
    if (!shade.length) return;
    const left = u.bbox.left;
    const right = u.bbox.left + u.bbox.width;
    u.ctx.save();
    u.ctx.fillStyle = css("--text-muted") + "1f";
    for (const [from, to] of shade) {
      const x0 = Math.max(left, u.valToPos(from, "x", true));
      const x1 = Math.min(right, u.valToPos(to, "x", true));
      if (x1 > x0) u.ctx.fillRect(x0, u.bbox.top, x1 - x0, u.bbox.height);
    }
    u.ctx.restore();
  }

  /** A small flag per alert along the top, and a faint line down. */
  function drawMarkers(u: uPlot) {
    if (!markers.length) return;
    const dpr = devicePixelRatio;
    const left = u.bbox.left;
    const right = u.bbox.left + u.bbox.width;
    u.ctx.save();
    for (const m of markers) {
      const x = u.valToPos(m.t, "x", true);
      if (x < left || x > right) continue;
      const color = css(m.severity === "info" ? "--alert-info" : "--alert-warning");
      u.ctx.fillStyle = color + "40";
      u.ctx.fillRect(x - 0.5 * dpr, u.bbox.top, dpr, u.bbox.height);
      u.ctx.fillStyle = color;
      u.ctx.beginPath();
      u.ctx.moveTo(x - 5 * dpr, u.bbox.top);
      u.ctx.lineTo(x + 5 * dpr, u.bbox.top);
      u.ctx.lineTo(x, u.bbox.top + 7 * dpr);
      u.ctx.closePath();
      u.ctx.fill();
    }
    u.ctx.restore();
  }

  function endDrag(u: uPlot) {
    if (u.select.width < 3) return;
    const from = Math.floor(u.posToVal(u.select.left, "x"));
    const to = Math.ceil(u.posToVal(u.select.left + u.select.width, "x"));
    dragged = true;
    u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
    onselect?.(from, to);
  }

  function width() {
    return Math.max(host.clientWidth, 300);
  }

  function create() {
    plot?.destroy();
    const inColor = css("--in");
    const outColor = css("--out");
    const grid = css("--grid");
    const muted = css("--text-muted");
    const font = `${compact ? 11 : 12}px ${css("--font")}`;
    const axis = { stroke: muted, font, grid: { stroke: grid, width: 1 }, ticks: { show: false } };

    plot = new uPlot(
      {
        width: width(),
        height,
        // Right padding leaves room for the last time label, which is centred on its tick.
        padding: compact ? [4, 40, 0, 22] : [10, 40, 0, 0],
        legend: { show: false },
        cursor: {
          drag: { x: !!onselect, y: false, setScale: false },
          points: { size: compact ? 0 : 7 },
        },
        scales: {
          x: { time: true },
          y: { range: (_u, _min, max) => [0, Math.max(max * 1.15, 2000)] },
        },
        axes: [
          {
            ...axis,
            space: compact ? 110 : 90,
            size: compact ? 22 : 50,
            // Times within a day, dates over several.
            values: (u, ticks) => {
              const span = (u.scales.x.max ?? 0) - (u.scales.x.min ?? 0);
              return ticks.map((t) => (span > 2 * 86_400 ? dayLabel(t) : span > 86_400 ? moment(t, 3_600) : clock(t)));
            },
          },
          compact
            ? { show: false }
            : { ...axis, size: 78, values: (_u, ticks) => ticks.map((t) => rate(t)) },
        ],
        series: [
          {},
          { label: "In", stroke: inColor, width: 1.6, fill: areaFill(inColor), points: { show: false } },
          { label: "Out", stroke: outColor, width: 1.6, fill: areaFill(outColor), points: { show: false } },
        ],
        hooks: {
          setCursor: [
            (u) => {
              const i = u.cursor.idx;
              hover = i == null ? null : (shown[i] ?? null);
            },
          ],
          setSelect: [endDrag],
          drawClear: [drawShade],
          draw: [drawSelection, drawMarkers],
        },
      },
      toData(shown),
      host,
    );
    plot.over.addEventListener("click", () => {
      if (dragged) {
        dragged = false;
        return;
      }
      const i = plot?.cursor.idx;
      if (i != null && shown[i]) onpick?.(shown[i].t);
    });
  }

  // Build once; rebuild when the theme changes (canvas colors are baked in).
  $effect(() => {
    void theme.look;
    untrack(create);
    const resize = new ResizeObserver(() => plot?.setSize({ width: width(), height }));
    resize.observe(host);
    return () => {
      resize.disconnect();
      plot?.destroy();
      plot = null;
    };
  });

  $effect(() => {
    const next = samples;
    if (paused) return;
    shown = next;
    plot?.setData(toData(next));
  });

  // Repaint only. A plain redraw() re-applies the committed x range, which on a
  // new plot is still empty and would overwrite the range setData just queued:
  // the graph then stays blank until the next data arrives (30 s for history).
  $effect(() => {
    void selection;
    void shade;
    void markers;
    plot?.redraw(false);
  });
</script>

{#if !compact}
  <div class="readout num" aria-live="off">
    {#if readout}
      <span class="time">{hover ? moment(readout.t, multiDay ? Math.max(step, 3_600) : step) : latestLabel}</span>
      <span class="in">▼ {rate(readout.recv)}</span>
      <span class="out">▲ {rate(readout.sent)}</span>
      {#if hoverMarkers.length}
        <span class="marker" class:info={hoverMarkers[0].severity === "info"}>
          ⚑ {hoverMarkers[0].label}{hoverMarkers.length > 1 ? ` (+${hoverMarkers.length - 1} more)` : ""}
        </span>
      {/if}
    {:else}
      <span class="muted">Waiting for traffic…</span>
    {/if}
  </div>
{/if}
<!-- Padding lives on the wrapper: the plot is sized from `host.clientWidth`, and
     padding there would grow it a little on every resize. -->
<div class="plot-wrap" class:compact>
  <div
    class="plot"
    bind:this={host}
    role="img"
    aria-label="Network traffic over time. Click a moment or drag across a range to see which apps were active."
  ></div>
</div>

<style>
  .readout {
    display: flex;
    gap: 16px;
    align-items: baseline;
    padding: 0 16px 6px;
    min-height: 22px;
    font-size: 13px;
  }
  .time {
    color: var(--text-muted);
    min-width: 72px;
  }
  .marker {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--bad-text);
  }
  .marker.info {
    color: var(--text-muted);
  }
  .plot-wrap {
    padding: 0 4px 8px;
  }
  .plot-wrap.compact {
    padding: 0;
  }
  /* uPlot's root is `width: min-content`; clip it so it can never widen the page. */
  .plot {
    width: 100%;
    min-width: 0;
    overflow: hidden;
    cursor: crosshair;
  }
  .plot :global(.u-over) {
    cursor: crosshair;
  }
  .plot :global(.u-select) {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
  }
</style>
