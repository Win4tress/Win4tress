<script lang="ts">
  import type { Breakdown, Sample } from "./api";
  import Graph from "./Graph.svelte";
  import { human, moment, rate } from "./format";

  interface Props {
    totals: Breakdown | null;
    latest: Sample | null;
    samples: Sample[];
    selection: [number, number] | null;
    onpick: (t: number) => void;
    onselect: (from: number, to: number) => void;
    onclear: () => void;
    /** Seconds per sample, for how precisely to name the selection. */
    step?: number;
  }

  let { totals, latest, samples, selection, onpick, onselect, onclear, step = 60 }: Props = $props();

  const total = $derived(totals?.total ?? { recv: 0, sent: 0 });
  const internet = $derived((totals?.internet.recv ?? 0) + (totals?.internet.sent ?? 0));
  const local = $derived((totals?.local.recv ?? 0) + (totals?.local.sent ?? 0));
  const splitMax = $derived(Math.max(1, internet, local));
</script>

<section class="card summary">
  <div class="totals">
    <div class="dir">
      <span class="arrow in" aria-hidden="true">▼</span>
      <div>
        <div class="big num">{human(total.recv)}</div>
        <div class="muted small num">Downloaded · {rate(latest?.recv ?? 0)} now</div>
      </div>
    </div>
    <div class="dir">
      <span class="arrow out" aria-hidden="true">▲</span>
      <div>
        <div class="big num">{human(total.sent)}</div>
        <div class="muted small num">Uploaded · {rate(latest?.sent ?? 0)} now</div>
      </div>
    </div>
    <div class="split">
      <div class="split-row">
        <span class="muted">Internet</span>
        <span class="track"><span class="fill internet" style:width="{(internet / splitMax) * 100}%"></span></span>
        <span class="num">{human(internet)}</span>
      </div>
      <div class="split-row">
        <span class="muted">Local network</span>
        <span class="track"><span class="fill local" style:width="{(local / splitMax) * 100}%"></span></span>
        <span class="num">{human(local)}</span>
      </div>
    </div>
  </div>

  <div class="timeline">
    <Graph
      {samples}
      compact
      height={64}
      {selection}
      {onselect}
      {onpick}
    />
    <div class="hint muted">
      {#if selection}
        Showing {moment(selection[0], step)} – {moment(selection[1], step)}
        <button onclick={onclear}>Show the whole range</button>
      {:else}
        Drag across the timeline to look at part of the range.
      {/if}
    </div>
  </div>
</section>

<style>
  .summary {
    padding: 14px 16px 10px;
    display: grid;
    gap: 10px;
  }
  .totals {
    display: grid;
    grid-template-columns: auto auto minmax(0, 1fr);
    gap: 32px;
    align-items: center;
  }
  .dir {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .arrow {
    font-size: 18px;
  }
  .big {
    font: 600 20px/1.2 var(--font-display);
  }
  .small {
    font-size: 12px;
  }
  .split {
    display: grid;
    gap: 6px;
  }
  .split-row {
    display: grid;
    grid-template-columns: 100px minmax(0, 1fr) 80px;
    gap: 10px;
    align-items: center;
    font-size: 12.5px;
  }
  .split-row .num {
    text-align: right;
  }
  .track {
    height: 5px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .fill {
    display: block;
    height: 100%;
  }
  .fill.internet {
    background: var(--in);
  }
  .fill.local {
    background: var(--ok);
  }
  .hint {
    font-size: 12px;
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .hint button {
    border: 0;
    background: none;
    color: var(--accent-text);
    cursor: pointer;
    padding: 0;
    font-size: 12px;
    text-decoration: underline;
  }
</style>
