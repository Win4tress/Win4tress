<script lang="ts">
  /** A tiny download/upload area graph for a table row. Each row is scaled to
   *  its own peak: it shows the shape of an app's activity, not its size. */
  interface Props {
    /** [recv, sent] per step, oldest first. */
    data: [number, number][];
    width?: number;
    height?: number;
  }

  let { data, width = 96, height = 22 }: Props = $props();

  const peak = $derived(Math.max(1, ...data.map(([r, s]) => Math.max(r, s))));

  function area(series: 0 | 1): string {
    const n = data.length;
    if (n < 2) return "";
    const top = 1; // keep the stroke inside the box
    const y = (v: number) => (height - top - ((height - 2 * top) * v) / peak).toFixed(1);
    const x = (i: number) => ((width * i) / (n - 1)).toFixed(1);
    const line = data.map((d, i) => `${x(i)},${y(d[series])}`).join(" L");
    return `M0,${height} L${line} L${width},${height} Z`;
  }
</script>

{#if data.length > 1}
  <svg {width} {height} viewBox="0 0 {width} {height}" aria-hidden="true">
    <path class="in" d={area(0)} />
    <path class="out" d={area(1)} />
  </svg>
{/if}

<style>
  svg {
    display: block;
    overflow: visible;
  }
  path {
    stroke-width: 1.2;
    stroke-linejoin: round;
    vector-effect: non-scaling-stroke;
  }
  .in {
    fill: color-mix(in srgb, var(--in) 30%, transparent);
    stroke: var(--in);
  }
  .out {
    fill: color-mix(in srgb, var(--out) 30%, transparent);
    stroke: var(--out);
  }
</style>
