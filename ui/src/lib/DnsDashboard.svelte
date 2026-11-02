<script lang="ts" module>
  export interface Range {
    key: string;
    label: string;
    /** Completes "over the last …". */
    span: string;
    ms: number;
    stepMs: number;
    refreshMs: number;
  }
</script>

<script lang="ts">
  import { api, type DnsStats, type DomainCount } from "./api";
  import BarList, { type Row } from "./BarList.svelte";
  import { dnsStatus, dnsType } from "./format";
  import StackedColumns, { type Layer } from "./StackedColumns.svelte";

  /** DNS at a glance. Counts come from history. */
  interface Props {
    range: Range;
    /** Show the query log filtered to a name. */
    onquery: (name: string) => void;
    onopenapp: (id: number) => void;
  }

  let { range, onquery, onopenapp }: Props = $props();

  /** Query types and outcomes beyond this many fold into "Other". */
  const SHOWN = 6;
  const TYPE_NOTES: Record<number, string> = {
    1: "IPv4 address",
    28: "IPv6 address",
    65: "HTTPS service info",
    12: "reverse lookup",
    5: "alias",
    33: "service location",
    16: "text",
    15: "mail server",
  };

  let stats = $state.raw<DnsStats | null>(null);
  let error = $state<string | null>(null);

  $effect(() => {
    const r = range;
    let cancelled = false;
    stats = null;
    error = null;
    const load = () => {
      const now = Date.now();
      api
        .dnsStats(now - r.ms, now, r.stepMs)
        .then((s) => {
          if (!cancelled) {
            stats = s;
            error = null;
          }
        })
        .catch((e) => {
          if (!cancelled) error = String(e);
        });
    };
    load();
    const timer = setInterval(load, r.refreshMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  const outcomeLayers = $derived<Layer[]>(
    stats
      ? [
          { label: "Answered", color: "var(--series-1)", values: stats.timeline.map((t) => t[0]) },
          { label: "Failed", color: "var(--series-2)", values: stats.timeline.map((t) => t[1]) },
        ]
      : [],
  );
  // The busiest app sits on the baseline, "Other" on top.
  const appLayers = $derived<Layer[]>(
    stats
      ? [
          ...stats.app_timeline.map((a, i) => ({
            label: a.app.name,
            color: `var(--series-${i + 1})`,
            values: a.counts,
          })),
          ...(stats.other_timeline.some((v) => v > 0)
            ? [{ label: "Other apps", color: "var(--series-other)", values: stats.other_timeline }]
            : []),
        ]
      : [],
  );

  function fold<T>(items: T[], count: (t: T) => number, row: (t: T) => Row): Row[] {
    const rows = items.slice(0, SHOWN).map(row);
    const rest = items.slice(SHOWN).reduce((s, t) => s + count(t), 0);
    return rest ? [...rows, { key: "other", label: "Other", count: rest }] : rows;
  }
  const typeRows = $derived(
    fold(
      stats?.query_types ?? [],
      (t) => t.count,
      (t) => ({
        key: String(t.query_type),
        label: TYPE_NOTES[t.query_type] ? `${dnsType(t.query_type)} · ${TYPE_NOTES[t.query_type]}` : dnsType(t.query_type),
        count: t.count,
      }),
    ),
  );
  const resultRows = $derived(
    fold(
      stats?.results ?? [],
      (r) => r.count,
      (r) => ({ key: String(r.status), label: dnsStatus(r.status), count: r.count }),
    ),
  );

  function percent(part: number, whole: number): string {
    if (!whole) return "0%";
    const p = (100 * part) / whole;
    return p >= 10 || p === 0 ? `${Math.round(p)}%` : `${p.toFixed(1)}%`;
  }
  function maxOf(list: DomainCount[], key: "queries" | "failed"): number {
    return Math.max(1, ...list.map((d) => d[key]));
  }
</script>

{#snippet domains(list: DomainCount[], key: "queries" | "failed", empty: string)}
  {@const max = maxOf(list, key)}
  <table class="top">
    <thead>
      <tr>
        <th class="name">Domain</th>
        {#if key === "failed"}<th class="r">Failed</th>{/if}
        <th class="r">Lookups</th>
        <th class="freq-col">Frequency</th>
      </tr>
    </thead>
    <tbody>
      {#each list as d (d.name)}
        <tr>
          <td class="name">
            <button class="link" title="Show lookups of {d.name}" onclick={() => onquery(d.name)}>{d.name}</button>
          </td>
          {#if key === "failed"}<td class="r num">{d.failed.toLocaleString()}</td>{/if}
          <td class="r num" class:muted={key === "failed"}>{d.queries.toLocaleString()}</td>
          <td class="freq-col" title="{percent(d.queries, stats?.lookups ?? 0)} of all lookups">
            <span class="freq"><span style:width="{(d[key] / max) * 100}%"></span></span>
          </td>
        </tr>
      {:else}
        <tr><td colspan="4" class="empty muted">{empty}</td></tr>
      {/each}
    </tbody>
  </table>
{/snippet}

{#if error}
  <p class="note muted">
    {error.includes("history") ? "The DNS dashboard reads from the history database, which isn't available. The query log still works." : error}
  </p>
{:else if !stats}
  <p class="note muted">Loading…</p>
{:else}
  <div class="dash">
    <div class="tiles">
      <div class="tile card">
        <div class="label">Lookups</div>
        <div class="value num">{stats.lookups.toLocaleString()}</div>
        <div class="sub muted">by {stats.apps} {stats.apps === 1 ? "app" : "apps"}</div>
      </div>
      <div class="tile card">
        <div class="label">Failed lookups</div>
        <div class="value num">{stats.failed.toLocaleString()}</div>
        <div class="sub muted">no answer, or the name doesn't exist</div>
      </div>
      <div class="tile card">
        <div class="label">Percent failed</div>
        <div class="value num">{percent(stats.failed, stats.lookups)}</div>
        <div class="sub muted">of all lookups</div>
      </div>
      <div class="tile card">
        <div class="label">Domains</div>
        <div class="value num">{stats.domains.toLocaleString()}</div>
        <div class="sub muted">different names looked up</div>
      </div>
    </div>

    <section class="card">
      <div class="card-header">
        <h2 class="card-title">Lookups over the last {range.span}</h2>
      </div>
      <StackedColumns layers={outcomeLayers} startMs={stats.start_ms} stepMs={stats.step_ms} unit="lookups" />
    </section>

    <section class="card">
      <div class="card-header">
        <h2 class="card-title">Lookups by app over the last {range.span}</h2>
      </div>
      <StackedColumns layers={appLayers} startMs={stats.start_ms} stepMs={stats.step_ms} unit="lookups" />
    </section>

    <div class="trio">
      <section class="card">
        <div class="card-header"><h2 class="card-title">Query types</h2></div>
        <BarList rows={typeRows} total={stats.lookups} empty="No lookups in this range." />
      </section>
      <section class="card">
        <div class="card-header"><h2 class="card-title">Results</h2></div>
        <BarList rows={resultRows} total={stats.lookups} empty="No lookups in this range." />
      </section>
      <section class="card">
        <div class="card-header"><h2 class="card-title">Top apps</h2></div>
        <BarList
          rows={stats.top_apps.slice(0, SHOWN).map((a) => ({
            key: String(a.app.id),
            label: a.app.name,
            count: a.lookups,
            note: a.failed ? `${a.failed.toLocaleString()} failed` : undefined,
            app: a.app,
          }))}
          total={stats.lookups}
          onpick={(r) => onopenapp(Number(r.key))}
          empty="No lookups in this range."
        />
      </section>
    </div>

    <div class="pair">
      <section class="card">
        <div class="card-header"><h2 class="card-title">Top domains</h2></div>
        {@render domains(stats.top_domains, "queries", "No lookups in this range.")}
      </section>
      <section class="card">
        <div class="card-header"><h2 class="card-title">Top failed domains</h2></div>
        {@render domains(stats.top_failed, "failed", "No failed lookups in this range.")}
      </section>
    </div>

    <p class="footnote muted">
      Counts lookups made through Windows' DNS Client. Apps that resolve names themselves, such as a
      browser using secure DNS (DNS over HTTPS), don't appear here. win4tress's own reverse lookups are
      left out.
    </p>
  </div>
{/if}

<style>
  .dash {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
  }
  .note {
    margin: 8px 2px;
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
  }
  .tile {
    padding: 14px 16px;
  }
  .label {
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 4px;
  }
  .value {
    font: 600 24px/1.2 var(--font-display);
  }
  .sub {
    font-size: 12px;
    margin-top: 2px;
  }
  .trio {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    align-items: start;
  }
  .pair {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
    align-items: start;
  }
  .top {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    margin-bottom: 6px;
  }
  .top th {
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 6px 12px;
    border-bottom: 1px solid var(--border);
  }
  .top td {
    padding: 6px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .top tr:last-child td {
    border-bottom: 0;
  }
  .top .r {
    text-align: right;
    width: 76px;
  }
  .top th.r {
    text-align: right;
  }
  .freq-col {
    width: 26%;
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .link {
    all: unset;
    cursor: pointer;
    color: var(--accent-text);
  }
  .link:hover {
    text-decoration: underline;
  }
  .link:focus-visible {
    outline: 2px solid var(--accent-text);
  }
  .freq {
    display: block;
    height: 6px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .freq span {
    display: block;
    height: 100%;
    border-radius: 3px;
    background: var(--series-1);
  }
  .empty {
    text-align: center;
    padding: 16px;
  }
  .footnote {
    margin: 0 2px;
    font-size: 12px;
  }
  @media (max-width: 1050px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .trio,
    .pair {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
