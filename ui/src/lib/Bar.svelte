<script lang="ts">
  /** Stacked in/out bar, scaled against `max`. */
  let { recv, sent, max }: { recv: number; sent: number; max: number } = $props();
  const inPct = $derived(max > 0 ? (recv / max) * 100 : 0);
  const outPct = $derived(max > 0 ? (sent / max) * 100 : 0);
</script>

<span class="bar" aria-hidden="true">
  <span class="seg in" style:width="{inPct}%"></span>
  <span class="seg out" style:width="{outPct}%"></span>
</span>

<style>
  .bar {
    display: flex;
    height: 4px;
    border-radius: 2px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .seg {
    height: 100%;
  }
  .seg.in {
    background: var(--in);
  }
  .seg.out {
    background: var(--out);
  }
</style>
