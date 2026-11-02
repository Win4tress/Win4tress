<script lang="ts">
  import { api, type DnsEntry } from "./api";
  import AppIcon from "./AppIcon.svelte";
  import { clock, dnsStatus, dnsType } from "./format";

  /** Every DNS lookup, newest first, by the app that made it. */
  interface Props {
    /** Name filter; the dashboard sets it when a domain is picked. */
    query?: string;
  }

  let { query = $bindable("") }: Props = $props();

  const REFRESH_MS = 2000;

  let entries = $state.raw<DnsEntry[]>([]);
  let error = $state<string | null>(null);
  let failedOnly = $state(false);

  // The search runs on the service, so it reaches past the newest 1000 entries.
  $effect(() => {
    const q = query.trim();
    let cancelled = false;
    const load = () =>
      api
        .dnsLog(1000, q)
        .then((r) => {
          if (cancelled) return;
          entries = r.entries;
          error = null;
        })
        .catch((e) => {
          if (!cancelled) error = String(e);
        });
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  const shown = $derived(failedOnly ? entries.filter((e) => e.status !== 0) : entries);

  function result(e: DnsEntry): string {
    if (e.blocked_by) return `Blocked: ${e.blocked_by}`;
    if (e.status !== 0) return dnsStatus(e.status);
    return e.addrs.length ? e.addrs.join(", ") : "No addresses";
  }
</script>

<section class="card pane">
  <div class="card-header">
    <h2 class="card-title">Query log</h2>
    <span class="muted">newest first, by the app that asked</span>
    <label class="toggle"><input type="checkbox" bind:checked={failedOnly} /> Failed only</label>
    <input class="search" type="search" placeholder="Search names" bind:value={query} aria-label="Search DNS names" />
  </div>
  {#if error}<p class="error">{error}</p>{/if}
  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th class="app">App</th>
          <th>Type</th>
          <th class="fill">Name</th>
          <th class="fill">Result</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as e, i (e.ts_ms + e.name + e.query_type + i)}
          <tr class:failed={e.status !== 0} class:blocked={!!e.blocked_by}>
            <td class="muted nowrap num">{clock(e.ts_ms / 1000)}</td>
            <td class="app">
              <div class="cell">
                <AppIcon name={e.app.name} path={e.app.path} size={18} />
                <span class="ellipsis" title={e.app.name}>{e.app.name}</span>
              </div>
            </td>
            <td class="muted">{dnsType(e.query_type)}</td>
            <td class="fill"><span class="ellipsis block" title={e.name}>{e.name}</span></td>
            <td class="fill">
              <span class="ellipsis block result" title={result(e)}>{result(e)}</span>
            </td>
          </tr>
        {:else}
          <tr><td colspan="5" class="empty muted">No lookups{query ? ` matching “${query}”` : " yet"}.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .toggle {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--text-muted);
  }
  .search {
    width: 240px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface-2);
    color: var(--text);
    font: inherit;
  }
  .scroll {
    overflow: hidden auto;
    min-height: 0;
    flex: 1;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th {
    position: sticky;
    top: 0;
    background: var(--surface);
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .app {
    width: 200px;
    max-width: 200px;
  }
  .fill {
    width: 50%;
    max-width: 0;
  }
  .cell {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .block {
    display: block;
  }
  .nowrap {
    white-space: nowrap;
  }
  tr.blocked .result {
    color: var(--bad-text);
    font-weight: 600;
  }
  tr.failed .result {
    color: var(--bad-text);
  }
  .empty {
    text-align: center;
    padding: 24px;
  }
  .error {
    color: var(--bad-text);
    padding: 0 16px;
  }
</style>
