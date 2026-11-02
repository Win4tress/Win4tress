<script lang="ts">
  // The Firewall screen (SPEC §10.2): every app win4tress knows, with what
  // happens to its connections, filters, bulk changes (previewed first), and
  // one app's rules beside the list.
  import { SvelteSet } from "svelte/reactivity";
  import { api, errorText, type Direction, type KnownApp, type RuleChange, type Verdict } from "./api";
  import AppFirewall from "./AppFirewall.svelte";
  import AppIcon from "./AppIcon.svelte";
  import { firewall as fw } from "./firewall.svelte";
  import { ago } from "./format";
  import { appChips, firstChip, reputationChip, trustChips } from "./trust";

  interface Props {
    nowMs: number;
    /** The app whose rules are shown beside the list. */
    selectedId?: number | null;
  }

  let { nowMs, selectedId = $bindable(null) }: Props = $props();

  const APPS_REFRESH_MS = 15_000;

  type Filter = "all" | "blocked" | "allowed" | "host_rules" | "flagged";
  const FILTERS: { value: Filter; label: string }[] = [
    { value: "all", label: "All" },
    { value: "blocked", label: "Blocked by win4tress" },
    { value: "allowed", label: "Can connect out" },
    { value: "host_rules", label: "Host rules" },
    { value: "flagged", label: "Flagged" },
  ];

  let apps = $state.raw<KnownApp[]>([]);
  let loadError = $state<string | null>(null);
  let loading = $state(true);
  let filter = $state<Filter>("all");
  let query = $state("");
  let sort = $state<"name" | "recent">("recent");
  const checked = new SvelteSet<number>();

  /** A bulk change being previewed, and its outcome. */
  type Bulk = { title: string; changes: RuleChange[]; lines: string[]; skipped: string[]; removes: number };
  let preview = $state<Bulk | null>(null);
  let applying = $state(false);
  let result = $state<{ applied: number; failed: string[] } | null>(null);
  let bulkError = $state<string | null>(null);

  async function loadApps() {
    try {
      apps = (await api.knownApps()).apps;
      loadError = null;
    } catch (e) {
      loadError = errorText(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    loadApps();
    const timer = setInterval(loadApps, APPS_REFRESH_MS);
    return () => clearInterval(timer);
  });

  const targetable = (a: KnownApp) => a.path === "System" || a.path.includes("\\");
  const isProtected = (a: KnownApp) => fw.byApp.get(a.id)?.protected ?? false;
  const rulesOf = (a: KnownApp) => fw.rulesByApp.get(a.id) ?? [];

  function blockedByUs(a: KnownApp): boolean {
    const v = fw.byApp.get(a.id);
    return !!v && ((!v.in.allowed && v.in.by === "win4tress") || (!v.out.allowed && v.out.by === "win4tress"));
  }

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const list = apps.filter((a) => {
      if (q && ![a.name, a.path, a.company, a.service].some((f) => f?.toLowerCase().includes(q))) return false;
      switch (filter) {
        case "all":
          return true;
        case "blocked":
          return blockedByUs(a);
        case "allowed":
          return fw.byApp.get(a.id)?.out.allowed ?? false;
        case "host_rules":
          return rulesOf(a).some((r) => r.scope.kind !== "any");
        case "flagged":
          return trustChips(a).length > 0 || reputationChip(a.reputation) !== null;
      }
    });
    return list.sort(
      sort === "name" ? (a, b) => a.name.localeCompare(b.name) : (a, b) => b.last_seen_ms - a.last_seen_ms,
    );
  });

  const selected = $derived(apps.find((a) => a.id === selectedId) ?? null);
  const checkedApps = $derived(apps.filter((a) => checked.has(a.id)));
  const allShownChecked = $derived(shown.length > 0 && shown.every((a) => checked.has(a.id)));
  const readOnly = $derived(!fw.status || !!fw.monitoringOnly);

  function toggleAll() {
    if (allShownChecked) for (const a of shown) checked.delete(a.id);
    else for (const a of shown) checked.add(a.id);
  }

  /** The apps a change can apply to, and why the others are left out. */
  function partition(list: KnownApp[], forBlock: boolean) {
    const ok: KnownApp[] = [];
    const skipped: string[] = [];
    for (const a of list) {
      if (!targetable(a)) skipped.push(`${a.name}: no program is known`);
      else if (forBlock && isProtected(a)) skipped.push(`${a.name}: part of win4tress`);
      else ok.push(a);
    }
    return { ok, skipped };
  }

  function block(direction: Direction) {
    const { ok, skipped } = partition(checkedApps, true);
    const what = direction === "in" ? "incoming" : "outgoing";
    preview = {
      title: `Block ${what} connections`,
      changes: ok.map((a) => ({ op: "set", app: a.id, direction, action: "block" })),
      lines: ok.map((a) => `${a.name}: block all ${what} connections`),
      skipped,
      removes: 0,
    };
  }

  function unblock() {
    const changes: RuleChange[] = [];
    const lines: string[] = [];
    for (const a of checkedApps)
      for (const r of rulesOf(a))
        if (r.action === "block" && r.scope.kind === "any") {
          changes.push({ op: "delete", id: r.id });
          lines.push(`${a.name}: stop blocking ${r.direction === "in" ? "incoming" : "outgoing"} connections`);
        }
    preview = { title: "Stop blocking", changes, lines, skipped: [], removes: changes.length };
  }

  function removeAll() {
    const changes: RuleChange[] = [];
    const lines: string[] = [];
    for (const a of checkedApps) {
      const rules = rulesOf(a);
      if (!rules.length) continue;
      for (const r of rules) changes.push({ op: "delete", id: r.id });
      lines.push(`${a.name}: remove ${rules.length} ${rules.length === 1 ? "rule" : "rules"}`);
    }
    preview = { title: "Remove win4tress's rules", changes, lines, skipped: [], removes: changes.length };
  }

  async function apply() {
    if (!preview) return;
    applying = true;
    bulkError = null;
    try {
      result = await api.applyRules(preview.changes);
      preview = null;
      if (result.failed.length === 0) checked.clear();
      await fw.refresh();
    } catch (e) {
      bulkError = errorText(e);
    } finally {
      applying = false;
    }
  }

  function cell(v: Verdict | undefined): { text: string; tone: "" | "bad" | "denied" } {
    if (!v) return { text: "–", tone: "" };
    if (v.allowed) return { text: "Allowed", tone: "" };
    return v.by === "win4tress" ? { text: "Blocked", tone: "bad" } : { text: "Blocked by Windows", tone: "denied" };
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === "Escape" && preview && !applying) preview = null;
  }}
/>

<div class="layout" class:with-detail={selected}>
  <section class="card list">
    <div class="card-header">
      <h2 class="card-title">Firewall</h2>
      <span class="muted">{apps.length} apps known</span>
      <div class="tools">
        <select bind:value={sort} aria-label="Sort">
          <option value="recent">Recently used</option>
          <option value="name">Name</option>
        </select>
        <input class="search" type="search" placeholder="Search apps, publishers, paths" bind:value={query} aria-label="Search apps" />
      </div>
    </div>
    <div class="filters" role="radiogroup" aria-label="Show">
      {#each FILTERS as f (f.value)}
        <button role="radio" aria-checked={filter === f.value} onclick={() => (filter = f.value)}>{f.label}</button>
      {/each}
    </div>

    {#if checked.size > 0}
      <div class="bulk" role="toolbar" aria-label="Change the checked apps">
        <strong>{checked.size} checked</strong>
        <button class="btn small" disabled={readOnly} onclick={() => block("out")}>Block outgoing</button>
        <button class="btn small" disabled={readOnly} onclick={() => block("in")}>Block incoming</button>
        <button class="btn small" disabled={readOnly} onclick={unblock}>Stop blocking</button>
        <button class="btn small" disabled={readOnly} onclick={removeAll}>Remove rules</button>
        <button class="link" onclick={() => checked.clear()}>Clear</button>
      </div>
    {/if}
    {#if result}
      <p class="result" role="status">
        Made {result.applied} {result.applied === 1 ? "change" : "changes"}.
        {#if result.failed.length}
          <span class="error-text">{result.failed.length} failed:</span>
          {result.failed.join("; ")}
        {/if}
        <button class="link" onclick={() => (result = null)}>Dismiss</button>
      </p>
    {/if}

    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th class="c-check">
              <input type="checkbox" checked={allShownChecked} onchange={toggleAll} aria-label="Check all shown apps" />
            </th>
            <th class="c-app">App</th>
            <th class="c-pub">Publisher</th>
            <th class="c-v">Out</th>
            <th class="c-v">In</th>
            <th class="c-rules r">Rules</th>
            <th class="c-seen r">Last used</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as a (a.id)}
            {@const v = fw.byApp.get(a.id)}
            {@const out = cell(v?.out)}
            {@const inn = cell(v?.in)}
            {@const flag = firstChip(appChips(a))}
            <tr
              class:selected={selectedId === a.id}
              onclick={() => (selectedId = selectedId === a.id ? null : a.id)}
            >
              <td class="c-check">
                <input
                  type="checkbox"
                  checked={checked.has(a.id)}
                  aria-label="Check {a.name}"
                  onclick={(e) => e.stopPropagation()}
                  onchange={() => (checked.has(a.id) ? checked.delete(a.id) : checked.add(a.id))}
                />
              </td>
              <td>
                <div class="cell" title={a.path}>
                  <AppIcon name={a.name} path={a.path} size={18} />
                  <!-- The row is clickable too; this is its keyboard and screen-reader way in. -->
                  <button
                    class="ellipsis name"
                    aria-label="Show {a.name}'s rules"
                    aria-pressed={selectedId === a.id}
                    onclick={(e) => {
                      e.stopPropagation();
                      selectedId = selectedId === a.id ? null : a.id;
                    }}>{a.name}</button
                  >
                  {#if v?.protected}<span class="chip" title="Part of win4tress: it can't be blocked.">win4tress</span>{/if}
                  {#if flag}
                    <span class="chip {flag.tone}" title={flag.title}>{flag.label}{flag.more ? ` +${flag.more}` : ""}</span>
                  {/if}
                </div>
              </td>
              <td><div class="ellipsis muted">{a.company ?? "–"}</div></td>
              <td class="c-v"><span class="v {out.tone}">{out.text}</span></td>
              <td class="c-v"><span class="v {inn.tone}">{inn.text}</span></td>
              <td class="r num muted">{rulesOf(a).length || ""}</td>
              <td class="r muted nowrap">{ago(nowMs - a.last_seen_ms)}</td>
            </tr>
          {:else}
            <tr>
              <td colspan="7" class="empty muted">
                {#if loading}Loading…{:else if loadError}{loadError.includes("history")
                    ? "The Firewall screen needs the history database, which isn't available."
                    : loadError}{:else}No apps match.{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  {#if selected}
    <aside class="card detail" aria-label="{selected.name} firewall">
      <div class="card-header">
        <AppIcon name={selected.name} path={selected.path} size={22} />
        <h2 class="card-title ellipsis">{selected.name}</h2>
        <button class="close" aria-label="Close" onclick={() => (selectedId = null)}>×</button>
      </div>
      <div class="detail-body">
        {#if selected.company || selected.version}
          <p class="muted sub">{[selected.company, selected.version].filter(Boolean).join(" · ")}</p>
        {/if}
        <AppFirewall app={selected} {nowMs} />
      </div>
    </aside>
  {/if}
</div>

{#if preview}
  <div class="backdrop" role="presentation" onclick={() => !applying && (preview = null)}>
    <div
      class="dialog card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="preview-title"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
    >
      <h2 id="preview-title" class="card-title">{preview.title}</h2>
      {#if preview.changes.length === 0}
        <p class="muted">Nothing to change for the checked apps.</p>
      {:else}
        <p>
          {preview.changes.length}
          {preview.changes.length === 1 ? "change" : "changes"}, applied to Windows Firewall together:
        </p>
        <ul class="lines">
          {#each preview.lines as l, i (i)}<li>{l}</li>{/each}
        </ul>
        {#if preview.removes}
          <p class="note">
            This removes {preview.removes} win4tress {preview.removes === 1 ? "rule" : "rules"}. Windows Firewall's own
            rules then decide for those apps.
          </p>
        {/if}
      {/if}
      {#if preview.skipped.length}
        <p class="muted small">Left out: {preview.skipped.join("; ")}.</p>
      {/if}
      {#if bulkError}<p class="error-text" role="alert">{bulkError}</p>{/if}
      <div class="actions">
        <button class="btn" disabled={applying} onclick={() => (preview = null)}>Cancel</button>
        {#if preview.changes.length}
          <button class="btn {preview.removes ? 'danger' : 'primary'}" disabled={applying} onclick={apply}>
            {applying ? "Applying…" : `Apply ${preview.changes.length} ${preview.changes.length === 1 ? "change" : "changes"}`}
          </button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
    height: 100%;
    min-height: 0;
  }
  .layout.with-detail {
    grid-template-columns: minmax(0, 1fr) 440px;
  }
  .list,
  .detail {
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .tools {
    margin-left: auto;
    display: flex;
    gap: 10px;
  }
  select,
  .search {
    font: inherit;
    font-size: 13px;
    color: var(--text);
    padding: 5px 8px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
  }
  .search {
    width: 240px;
    background: var(--surface-2);
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 0 16px 10px;
  }
  .filters button {
    font-size: 12.5px;
    padding: 3px 11px;
    border: 1px solid var(--border);
    border-radius: 14px;
    background: var(--surface);
    cursor: pointer;
  }
  .filters button[aria-checked="true"] {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, var(--surface));
    font-weight: 600;
  }
  .bulk,
  .result {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin: 0;
    padding: 8px 16px;
    border-top: 1px solid var(--border);
    background: color-mix(in srgb, var(--accent) 8%, var(--surface));
    font-size: 13px;
  }
  .link {
    border: 0;
    background: none;
    color: var(--accent-text);
    cursor: pointer;
    font-size: 12.5px;
    text-decoration: underline;
  }
  .scroll {
    overflow: hidden auto;
    flex: 1;
    min-height: 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }
  thead th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface);
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 8px 10px;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  tbody tr {
    cursor: pointer;
  }
  tbody tr:hover,
  tbody tr.selected {
    background: color-mix(in srgb, var(--surface-2) 70%, transparent);
  }
  tbody tr.selected {
    box-shadow: inset 3px 0 0 var(--accent);
  }
  /* Shares of the width, not pixels: with the detail panel open, an auto
     column for the app was squeezed to almost nothing. */
  .c-check {
    width: 5%;
    padding-right: 0;
  }
  .c-app {
    width: 31%;
  }
  input[type="checkbox"] {
    accent-color: var(--accent);
    cursor: pointer;
  }
  .c-pub {
    width: 18%;
  }
  .c-v {
    width: 14%;
  }
  .c-rules {
    width: 7%;
  }
  .c-seen {
    width: 11%;
  }
  .r {
    text-align: right;
  }
  .nowrap {
    white-space: nowrap;
  }
  .cell {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    overflow: hidden;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  /* A button that reads as text; `all: unset` clears .ellipsis too, so it's restated. */
  .name {
    all: unset;
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 500;
    cursor: pointer;
    min-width: 48px;
  }
  .name:focus-visible {
    outline: 2px solid var(--accent-text);
    outline-offset: 1px;
  }
  .v {
    font-size: 12.5px;
  }
  .v.bad {
    color: var(--bad-text);
    font-weight: 600;
  }
  .v.denied {
    color: var(--text-muted);
  }
  .empty {
    text-align: center;
    padding: 24px;
  }
  .detail .card-header {
    border-bottom: 1px solid var(--border);
  }
  .detail-body {
    overflow: auto;
    padding: 4px 16px 12px;
    min-height: 0;
  }
  .sub {
    margin: 8px 0 0;
    font-size: 12.5px;
  }
  .close {
    margin-left: auto;
    border: 0;
    background: none;
    font-size: 20px;
    line-height: 1;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 6px;
  }
  .close:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: grid;
    place-items: center;
    background: #00000059;
  }
  .dialog {
    width: min(520px, calc(100vw - 32px));
    max-height: calc(100vh - 64px);
    overflow: auto;
    padding: 18px 20px;
    box-shadow: var(--shadow-popover);
    font-size: 13.5px;
  }
  .lines {
    max-height: 260px;
    overflow: auto;
    margin: 6px 0;
    padding-left: 20px;
    font-size: 13px;
  }
  .note {
    padding: 7px 10px;
    border-radius: 7px;
    background: color-mix(in srgb, var(--alert-info) 18%, var(--surface));
  }
  .small {
    font-size: 12px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 14px;
  }
  @media (max-width: 1100px) {
    .layout.with-detail {
      grid-template-columns: minmax(0, 1fr);
      grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
    }
  }
</style>
