<script lang="ts">
  import { api, errorText, type BlockedConnection, type NetConnection } from "./api";
  import AppIcon from "./AppIcon.svelte";
  import { blockedByText } from "./blocked";
  import Flag from "./Flag.svelte";
  import { ago, duration, human, splitEndpoint, trafficLabel } from "./format";

  let { nowMs, search = "" }: { nowMs: number; /** Shown filtered by this, e.g. from search. */ search?: string } =
    $props();

  const REFRESH_MS = 2000;

  let list = $state.raw<NetConnection[]>([]);
  let error = $state<string | null>(null);
  let query = $state("");
  // A search from elsewhere (the search box) replaces what's typed here.
  $effect.pre(() => {
    if (search) query = search;
  });
  /** Connections being ended, by key; and what came of the last one. */
  let ending = $state(new Set<string>());
  let endNote = $state<string | null>(null);

  /** Windows can end IPv4 TCP connections only. */
  const closable = (c: NetConnection) =>
    c.state === "open" && c.protocol === "tcp" && !c.remote.startsWith("[") && !c.local.startsWith("[");

  async function end(c: NetConnection) {
    const key = c.local + c.remote;
    ending.add(key);
    ending = new Set(ending);
    endNote = null;
    try {
      const r = await api.closeConnections(null, [[c.local, c.remote]]);
      if (r.closed === 0) endNote = r.error ? `Couldn't end it: ${r.error}` : "It had already ended.";
    } catch (e) {
      endNote = errorText(e);
    } finally {
      ending.delete(key);
      ending = new Set(ending);
    }
  }
  let showClosed = $state(true);

  // Blocked attempts (SPEC §7.9): since the service started, or from history.
  type Show = "connections" | "blocked";
  type Range = "live" | "day" | "month";
  const RANGES: { value: Range; label: string; ms: number | null }[] = [
    { value: "live", label: "Since the service started", ms: null },
    { value: "day", label: "Last 24 hours", ms: 24 * 3600 * 1000 },
    { value: "month", label: "Last 30 days", ms: 30 * 24 * 3600 * 1000 },
  ];
  const BLOCKED_REFRESH_MS = 5000;
  let show = $state<Show>("connections");
  let range = $state<Range>("live");
  let blocked = $state.raw<BlockedConnection[]>([]);
  let blockedError = $state<string | null>(null);

  $effect(() => {
    if (show !== "blocked") return;
    const ms = RANGES.find((r) => r.value === range)?.ms ?? null;
    let cancelled = false;
    const load = () =>
      api
        .blocks(null, ms === null ? null : Date.now() - ms, 500)
        .then((r) => {
          if (cancelled) return;
          blocked = r.blocks;
          blockedError = null;
        })
        .catch((e) => {
          if (!cancelled) blockedError = errorText(e);
        });
    load();
    const timer = setInterval(load, BLOCKED_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  const shownBlocked = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return blocked;
    return blocked.filter((b) =>
      [b.app.name, b.name ?? "", b.remote, blockedByText(b.by)].some((f) => f.toLowerCase().includes(q)),
    );
  });

  $effect(() => {
    let cancelled = false;
    const load = () =>
      api
        .connections()
        .then((r) => {
          if (cancelled) return;
          list = r.connections;
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

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return list.filter(
      (c) =>
        (showClosed || c.state === "open") &&
        (!q ||
          c.app.name.toLowerCase().includes(q) ||
          (c.name ?? "").toLowerCase().includes(q) ||
          (c.owner?.name ?? "").toLowerCase().includes(q) ||
          c.remote.toLowerCase().includes(q) ||
          c.local.endsWith(`:${q}`)),
    );
  });
  const openCount = $derived(list.filter((c) => c.state === "open").length);

  function direction(c: NetConnection): string {
    if (c.inbound === true) return "In";
    if (c.inbound === false) return "Out";
    return "–";
  }
</script>

<section class="card view">
  <div class="card-header">
    <div class="seg" role="radiogroup" aria-label="Show">
      <button role="radio" aria-checked={show === "connections"} onclick={() => (show = "connections")}>Connections</button>
      <button role="radio" aria-checked={show === "blocked"} onclick={() => (show = "blocked")}>Blocked</button>
    </div>
    {#if show === "connections"}
      <span class="muted">{openCount} open · {list.length - openCount} closed in the last minute</span>
      <label class="toggle"><input type="checkbox" bind:checked={showClosed} /> Show closed</label>
    {:else}
      <span class="muted">{blocked.length} blocked {blocked.length === 1 ? "address" : "addresses"}</span>
      <select class="range" bind:value={range} aria-label="Time range">
        {#each RANGES as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
      </select>
    {/if}
    <input
      class="search"
      type="search"
      placeholder="Search apps, hosts, addresses, ports"
      bind:value={query}
      aria-label="Search connections"
    />
  </div>
  {#if show === "blocked"}
    {#if blockedError}<p class="error">{blockedError}</p>{/if}
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th class="third">App</th>
            <th class="third">Remote</th>
            <th>Dir</th>
            <th class="third">Blocked by</th>
            <th class="r">Attempts</th>
            <th class="r">Last attempt</th>
          </tr>
        </thead>
        <tbody>
          {#each shownBlocked as b, i (i)}
            {@const [address, port] = splitEndpoint(b.remote)}
            <tr>
              <td class="third">
                <div class="cell">
                  <AppIcon name={b.app.name} path={b.app.path} size={18} />
                  <span class="ellipsis" title={b.app.path}>{b.app.name}</span>
                </div>
              </td>
              <td class="third">
                <div class="cell" title={b.remote}>
                  <span class="ellipsis">{b.name ?? address}</span>
                  <span class="muted port">:{port}</span>
                </div>
              </td>
              <td class="muted">{b.inbound ? "In" : "Out"}</td>
              <td class="third"><div class="ellipsis" title={b.by.name}>{blockedByText(b.by)}</div></td>
              <td class="r num muted">{b.count.toLocaleString()}</td>
              <td class="r muted nowrap">{ago(nowMs - b.last_ms)}</td>
            </tr>
          {:else}
            <tr>
              <td colspan="6" class="empty muted">
                {query ? `No blocked attempts match “${query}”.` : "Nothing blocked."}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
  {#if error}<p class="error">{error}</p>{/if}
  {#if endNote}<p class="error" role="alert">{endNote}</p>{/if}
  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th class="fill">App</th>
          <th class="fill">Remote</th>
          <th>Type</th>
          <th>Dir</th>
          <th class="r">Down</th>
          <th class="r">Up</th>
          <th class="r">Duration</th>
          <th class="r">Last activity</th>
          <th class="c-end"><span class="visually-hidden">End</span></th>
        </tr>
      </thead>
      <tbody>
        {#each shown as c (c.pid + c.protocol + c.local + c.remote)}
          {@const [address, port] = splitEndpoint(c.remote)}
          <tr class:closed={c.state === "closed"}>
            <td class="fill">
              <div class="cell">
                <AppIcon name={c.app.name} path={c.app.path} size={18} />
                <span class="ellipsis" title="{c.app.name} (PID {c.pid})">{c.app.name}</span>
              </div>
            </td>
            <td class="fill">
              <div
                class="cell"
                title="{c.name ?? address} · {c.country.name}{c.owner
                  ? ` · ${c.owner.name} (AS${c.owner.asn})`
                  : ''} · local {c.local}"
              >
                <Flag code={c.country.code} size={16} />
                <span class="ellipsis">{c.name ?? address}</span>
                <span class="muted port">:{port}</span>
              </div>
            </td>
            <td class="muted nowrap">{c.protocol.toUpperCase()} · {trafficLabel(c.traffic_type)}</td>
            <td class="muted">{direction(c)}</td>
            <td class="r num in">{human(c.bytes.recv)}</td>
            <td class="r num out">{human(c.bytes.sent)}</td>
            <td class="r muted nowrap">{duration(c.last_seen_ms - c.first_seen_ms)}</td>
            <td class="r muted nowrap">
              {c.state === "closed" ? "closed " : ""}{ago(nowMs - c.last_seen_ms)}
            </td>
            <td class="c-end">
              {#if closable(c)}
                <button
                  class="end"
                  disabled={ending.has(c.local + c.remote)}
                  title="End this connection now (both ends get a reset)"
                  aria-label="End {c.app.name}'s connection to {c.name ?? address}"
                  onclick={() => end(c)}
                >
                  <svg viewBox="0 0 10 10" width="9" height="9" aria-hidden="true">
                    <path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
                  </svg>
                </button>
              {/if}
            </td>
          </tr>
        {:else}
          <tr><td colspan="9" class="empty muted">No connections{query ? ` match “${query}”` : ""}.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
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
  .range {
    margin-left: auto;
    font: inherit;
    font-size: 13px;
    color: var(--text);
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
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
    width: 280px;
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
  .fill {
    width: 50%;
    max-width: 0;
  }
  /* The blocked list has three text columns. */
  .third {
    width: 33%;
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
  .port {
    flex: none;
  }
  .nowrap {
    white-space: nowrap;
  }
  /* Amounts and times: the two text columns give way instead. */
  .r {
    text-align: right;
    white-space: nowrap;
  }
  tr.closed td {
    opacity: 0.55;
  }
  .c-end {
    width: 28px;
    padding: 0 6px 0 0;
    text-align: right;
  }
  .end {
    display: inline-grid;
    place-items: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: 6px;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
    visibility: hidden;
  }
  tr:hover .end,
  .end:focus-visible {
    visibility: visible;
  }
  .end:hover {
    border-color: var(--border);
    color: var(--bad-text);
  }
  .end:disabled {
    cursor: progress;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
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
