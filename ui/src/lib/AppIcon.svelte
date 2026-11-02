<script lang="ts">
  import { appIcon } from "./api";
  import AppAvatar from "./AppAvatar.svelte";

  /** The executable's own icon, falling back to a lettered avatar. */
  let { name, path, size = 28 }: { name: string; path: string; size?: number } = $props();

  let url = $state<string | null>(null);

  $effect(() => {
    const p = path;
    let cancelled = false;
    url = null;
    appIcon(p).then((u) => {
      if (!cancelled) url = u;
    });
    return () => {
      cancelled = true;
    };
  });
</script>

{#if url}
  <img src={url} alt="" width={size} height={size} style:width="{size}px" style:height="{size}px" />
{:else}
  <AppAvatar {name} {size} />
{/if}

<style>
  img {
    flex: none;
    object-fit: contain;
  }
</style>
