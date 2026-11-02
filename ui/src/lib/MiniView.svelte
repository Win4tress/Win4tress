<script lang="ts">
  // The mini viewer window (SPEC §10.2): the live rates and the last minute
  // as a small graph, always on top. Drag it anywhere; × closes it. Its
  // background is as solid as the user set it in Settings.
  import { listen } from "@tauri-apps/api/event";
  import { api, events, type MiniPrefs, type Sample } from "./api";
  import { rate } from "./format";
  import Spark from "./Spark.svelte";

  const SECONDS = 60;

  let samples = $state.raw<Sample[]>([]);
  let opacity = $state(85);
  let connected = $state(true);

  $effect(() => {
    api.miniPrefs().then(
      (p) => (opacity = p.opacity),
      () => {},
    );
    api.live(SECONDS).then(
      (r) => (samples = r.samples),
      () => {},
    );
    const unlisten = [
      events.onSamples((batch) => {
        const last = samples.at(-1)?.t ?? -Infinity;
        const fresh = batch.filter((s) => s.t > last);
        if (fresh.length) samples = [...samples, ...fresh].slice(-SECONDS);
        connected = true;
      }),
      events.onConnection((c) => (connected = c.connected)),
      listen<MiniPrefs>("w4://mini-prefs", (e) => (opacity = e.payload.opacity)),
    ];
    return () => {
      for (const u of unlisten) u.then((off) => off());
    };
  });

  const now = $derived(samples.at(-1));
  const data = $derived(samples.map((s) => [s.recv, s.sent] as [number, number]));
</script>

<div class="mini" style="--opacity: {opacity}%" data-tauri-drag-region>
  <div class="top" data-tauri-drag-region>
    <span class="rate in" data-tauri-drag-region title="Download">▼ {now ? rate(now.recv) : "–"}</span>
    <span class="rate out" data-tauri-drag-region title="Upload">▲ {now ? rate(now.sent) : "–"}</span>
    <button class="close" aria-label="Close the mini viewer" onclick={() => api.miniToggle()}>×</button>
  </div>
  {#if !connected}
    <p class="muted" data-tauri-drag-region>Service not running</p>
  {:else}
    <div class="graph" data-tauri-drag-region>
      <Spark {data} width={276} height={58} />
    </div>
  {/if}
</div>

<style>
  .mini {
    box-sizing: border-box;
    height: 100vh;
    padding: 8px 10px 6px;
    border-radius: 10px;
    border: 1px solid color-mix(in srgb, var(--border) var(--opacity), transparent);
    background: color-mix(in srgb, var(--surface) var(--opacity), transparent);
    color: var(--text);
    overflow: hidden;
    user-select: none;
    cursor: move;
  }
  .top {
    display: flex;
    align-items: center;
    gap: 12px;
    font: 600 13px/1.2 var(--font-display);
    font-variant-numeric: tabular-nums;
  }
  .rate.in {
    color: var(--in);
  }
  .rate.out {
    color: var(--out);
  }
  .close {
    margin-left: auto;
    border: 0;
    background: none;
    color: var(--text-muted);
    font-size: 16px;
    line-height: 1;
    padding: 0 2px;
    cursor: pointer;
  }
  .close:hover {
    color: var(--text);
  }
  .graph {
    margin-top: 8px;
  }
  p {
    margin: 14px 0 0;
    font-size: 12.5px;
  }
</style>
