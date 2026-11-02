<script lang="ts">
  // Firewall states that change what every view means, above every view: Block
  // All, and Windows Firewall off on a network in use.
  import { api, errorText } from "./api";
  import { firewall } from "./firewall.svelte";

  let busy = $state(false);
  let error = $state<string | null>(null);

  const status = $derived(firewall.status);
  const blockAll = $derived(status?.block_all ?? null);
  const activeOff = $derived(status?.state?.profiles.filter((p) => p.active && !p.firewall_on) ?? []);

  async function run(action: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await action();
      await firewall.refresh();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function until(ms: number): string {
    return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
</script>

{#if blockAll}
  <div class="banner bad" role="status">
    <span>
      <strong>Block All is on.</strong>
      All traffic is blocked{blockAll.until_ms ? ` until ${until(blockAll.until_ms)}` : " until you turn it off"}.
    </span>
    <button class="btn small" disabled={busy} onclick={() => run(() => api.blockAll(false))}>Stop blocking</button>
  </div>
{/if}
{#if activeOff.length && !status?.monitoring_only}
  <div class="banner warn" role="status">
    <span>
      <strong>Windows Firewall is off</strong> on the
      {activeOff.map((p) => p.name).join(" and ")}
      {activeOff.length === 1 ? "network" : "networks"} in use: nothing is blocked there, win4tress's rules included.
    </span>
    <button class="btn small" disabled={busy} onclick={() => run(() => api.turnOn())}>Turn it on</button>
  </div>
{/if}
{#if error && (blockAll || activeOff.length)}
  <p class="error-text err" role="alert">{error}</p>
{/if}

<style>
  .banner {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 8px 14px;
    margin-bottom: 12px;
    border-radius: var(--radius);
    font-size: 13px;
  }
  .banner span {
    flex: 1;
  }
  .bad {
    background: var(--bad);
    color: var(--on-status);
  }
  .warn {
    background: color-mix(in srgb, var(--alert-info) 22%, var(--surface));
    border: 1px solid var(--alert-info);
  }
  .err {
    margin: -6px 2px 12px;
    font-size: 12.5px;
  }
  @media (forced-colors: active) {
    .banner {
      border: 1px solid CanvasText;
    }
  }
</style>
