<script lang="ts">
  import * as flags from "country-flag-icons/string/3x2";

  /** Country flag; a network glyph for the local network, a globe when unknown. */
  let { code, size = 18 }: { code: string; size?: number } = $props();

  const svg = $derived((flags as Record<string, string>)[code] ?? null);
</script>

<span class="flag" style:width="{size}px" style:height="{Math.round((size * 2) / 3)}px" aria-hidden="true">
  {#if svg}
    <!-- Static SVG from the country-flag-icons package (MIT). -->
    {@html svg}
  {:else if code === "LAN"}
    <svg class="glyph" viewBox="0 0 24 16">
      <rect x="9" y="1" width="6" height="4" rx="1" />
      <rect x="2" y="11" width="6" height="4" rx="1" />
      <rect x="16" y="11" width="6" height="4" rx="1" />
      <path d="M12 5v3M5 11V8h14v3" />
    </svg>
  {:else}
    <svg class="glyph" viewBox="0 0 24 16">
      <circle cx="12" cy="8" r="6.5" />
      <path d="M5.5 8h13M12 1.5c-2.4 2-2.4 11 0 13M12 1.5c2.4 2 2.4 11 0 13" />
    </svg>
  {/if}
</span>

<style>
  .flag {
    display: inline-grid;
    flex: none;
    border-radius: 2px;
    overflow: hidden;
    color: var(--text-muted);
  }
  .flag :global(svg) {
    width: 100%;
    height: 100%;
    display: block;
  }
  .glyph rect {
    fill: currentColor;
  }
  .glyph path,
  .glyph circle {
    fill: none;
    stroke: currentColor;
    stroke-width: 1.4;
  }
</style>
