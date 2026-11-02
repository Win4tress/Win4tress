<script lang="ts">
  // The Network screen (SPEC §10.2): devices on the local network, from the
  // scanner (private networks with a gateway only) and the ARP table, with
  // their maker from the IEEE registry. Marking a device known sets it apart
  // from ones nobody has looked at.
  import { api, errorText, type Device, type DevicesResult, type Settings } from "./api";
  import { ago } from "./format";

  interface Props {
    nowMs: number;
  }

  let { nowMs }: Props = $props();

  const REFRESH_MS = 10_000;
  /** While a scan runs. */
  const SCANNING_MS = 1_500;
  const DAY_MS = 24 * 3600 * 1000;

  type Filter = "all" | "unknown";
  let filter = $state<Filter>("all");
  let query = $state("");
  let result = $state.raw<DevicesResult | null>(null);
  let settings = $state.raw<Settings | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function load() {
    try {
      result = await api.devices();
      error = null;
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    load();
    api.settings().then(
      (s) => (settings = s),
      () => {},
    );
  });
  $effect(() => {
    const timer = setInterval(load, result?.scanning ? SCANNING_MS : REFRESH_MS);
    return () => clearInterval(timer);
  });

  async function scan() {
    busy = true;
    error = null;
    try {
      result = await api.scan();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function setAutomatic(on: boolean) {
    if (!settings) return;
    error = null;
    try {
      settings = await api.setSettings({ ...settings, scanner: on });
    } catch (e) {
      error = errorText(e);
    }
  }

  async function setKnown(d: Device, known: boolean) {
    error = null;
    try {
      result = await api.setDeviceKnown(d.mac, known);
    } catch (e) {
      error = errorText(e);
    }
  }

  function maker(d: Device): string {
    if (d.vendor) return d.vendor;
    return d.randomized ? "Private address" : "Unknown maker";
  }

  function title(d: Device): string {
    return d.name ?? d.vendor ?? (d.randomized ? "Device with a private address" : "Unknown device");
  }

  const devices = $derived(result?.devices ?? []);
  const unknown = $derived(devices.filter((d) => !d.known).length);
  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return devices.filter(
      (d) =>
        (filter === "all" || !d.known) &&
        (!q || [d.name, d.vendor, d.ip, d.mac].some((f) => f?.toLowerCase().includes(q))),
    );
  });
  const scanning = $derived(busy || (result?.scanning ?? false));
</script>

<section class="card view">
  <div class="card-header">
    <div class="seg" role="radiogroup" aria-label="Show">
      <button role="radio" aria-checked={filter === "all"} onclick={() => (filter = "all")}>All</button>
      <button role="radio" aria-checked={filter === "unknown"} onclick={() => (filter = "unknown")}>
        Unknown{#if unknown}<span class="count">{unknown}</span>{/if}
      </button>
    </div>
    <span class="muted summary">
      {#if result}
        {result.networks.length ? result.networks.join(", ") : "No private network to scan"} · last scan
        {result.last_scan_ms != null ? ago(nowMs - result.last_scan_ms) : "never"}
      {/if}
    </span>
    <div class="spacer"></div>
    {#if settings}
      <label class="toggle">
        <input type="checkbox" checked={settings.scanner} onchange={(e) => setAutomatic(e.currentTarget.checked)} />
        Scan every half hour and alert on new devices
      </label>
    {/if}
    <button class="btn primary" disabled={scanning || !result?.networks.length} onclick={scan}>
      {scanning ? "Scanning…" : "Scan now"}
    </button>
    <input class="search" type="search" placeholder="Search names, makers, addresses" bind:value={query} aria-label="Search devices" />
  </div>
  {#if error}<p class="error-text msg" role="alert">{error}</p>{/if}
  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th class="fill">Device</th>
          <th>Address</th>
          <th>Hardware address</th>
          <th class="fill">Maker</th>
          <th class="r">First seen</th>
          <th class="r">Last seen</th>
          <th class="c">Known</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as d (d.mac)}
          <tr class:unknown={!d.known}>
            <td class="fill">
              <div class="cell">
                <span class="ellipsis" title={title(d)}>{title(d)}</span>
                {#if !d.known && nowMs - d.first_seen_ms < DAY_MS}<span class="chip warn">New</span>{/if}
              </div>
            </td>
            <td class="num nowrap">{d.ip}</td>
            <td class="num nowrap muted">{d.mac}</td>
            <td class="fill">
              <div class="cell">
                <span class="ellipsis" class:muted={!d.vendor} title={maker(d)}>{maker(d)}</span>
                {#if d.randomized}
                  <span class="chip" title="Phones and laptops pick a random hardware address per network, so the maker can't be told">Random</span>
                {/if}
              </div>
            </td>
            <td class="r muted">{ago(nowMs - d.first_seen_ms)}</td>
            <td class="r muted">{ago(nowMs - d.last_seen_ms)}</td>
            <td class="c">
              <input
                type="checkbox"
                checked={d.known}
                aria-label="I know {title(d)}"
                onchange={(e) => setKnown(d, e.currentTarget.checked)}
              />
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="7" class="empty muted">
              {#if query || filter === "unknown"}
                No devices match.
              {:else if scanning}
                Scanning…
              {:else}
                No devices seen yet. “Scan now” asks each address on your private network for its hardware
                address; public networks (cafés, airports) aren't scanned.
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .view {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .seg {
    display: flex;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .seg button {
    display: flex;
    align-items: center;
    gap: 6px;
    border: 0;
    background: var(--surface);
    padding: 4px 12px;
    font: 600 13px/1.3 var(--font-display);
    color: var(--text-muted);
    cursor: pointer;
  }
  .seg button[aria-checked="true"] {
    background: color-mix(in srgb, var(--accent) 14%, var(--surface));
    color: var(--text);
  }
  .count {
    font-size: 11px;
    padding: 0 6px;
    border-radius: 8px;
    background: var(--surface-2);
    color: var(--text);
  }
  .summary {
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
  .spacer {
    flex: 1;
  }
  .toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--text-muted);
    white-space: nowrap;
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
  .msg {
    margin: 0;
    padding: 0 16px 8px;
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
    z-index: 1;
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
    padding: 7px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  tr.unknown td:first-child {
    box-shadow: inset 3px 0 0 var(--alert-info);
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
  .nowrap {
    white-space: nowrap;
  }
  .r {
    text-align: right;
    white-space: nowrap;
  }
  .c {
    text-align: center;
  }
  .empty {
    text-align: center;
    padding: 24px;
  }
</style>
