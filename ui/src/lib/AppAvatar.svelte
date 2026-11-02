<script lang="ts">
  let { name, size = 28 }: { name: string; size?: number } = $props();

  const initials = $derived(
    name
      .replace(/\.exe$/i, "")
      .split(/[\s._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]!.toUpperCase())
      .join("") || "?",
  );

  // Stable hue per name, so an app keeps its color between views.
  const hue = $derived([...name].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7));
</script>

<span
  class="avatar"
  style:width="{size}px"
  style:height="{size}px"
  style:font-size="{Math.round(size * 0.4)}px"
  style:--hue={hue}
  aria-hidden="true">{initials}</span
>

<style>
  .avatar {
    display: inline-grid;
    place-items: center;
    flex: none;
    border-radius: 8px;
    font-weight: 600;
    background: hsl(var(--hue) 55% 45% / 0.16);
    color: hsl(var(--hue) 60% 38%);
  }
  :global(:root[data-theme="dark"]) .avatar {
    background: hsl(var(--hue) 60% 60% / 0.16);
    color: hsl(var(--hue) 70% 72%);
  }
</style>
