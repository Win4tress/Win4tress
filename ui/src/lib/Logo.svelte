<script lang="ts">
  // The win4tress emblem (assets/logo/emblem.svg, copied here by tools/dev/make-logo.py).
  import emblem from "./logo/emblem.svg";

  let { size = 22 }: { size?: number } = $props();
</script>

<img src={emblem} width={size} height={size} alt="" aria-hidden="true" />

<style>
  img {
    display: block;
    flex: none;
  }
</style>
