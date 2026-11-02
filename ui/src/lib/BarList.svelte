<script lang="ts" module>
  export interface Row {
    key: string;
    label: string;
    count: number;
    /** Extra muted text after the label, e.g. "12 failed". */
    note?: string;
    /** An app whose icon goes before the label. */
    app?: { name: string; path: string };
  }
</script>

<script lang="ts">
  import AppIcon from "./AppIcon.svelte";

  /** Ranked rows with a count, its share, and a bar scaled to the largest row.
   *  One hue for every bar: these show magnitude, not identity. */
  interface Props {
    rows: Row[];
    /** What the shares are of; defaults to the rows' sum. */
    total?: number;
    onpick?: (row: Row) => void;
    empty?: string;
  }

  let { rows, total, onpick, empty = "Nothing yet." }: Props = $props();

  const max = $derived(Math.max(1, ...rows.map((r) => r.count)));
  const sum = $derived(total ?? rows.reduce((s, r) => s + r.count, 0));

  function share(count: number): string {
    if (!sum) return "";
    const p = (100 * count) / sum;
    return p >= 10 ? `${Math.round(p)}%` : p >= 0.1 ? `${p.toFixed(1)}%` : "<0.1%";
  }
</script>

<ul class="list">
  {#each rows as r (r.key)}
    <li>
      <svelte:element
        this={onpick ? "button" : "div"}
        class="row"
        class:pick={onpick}
        role={onpick ? undefined : "group"}
        onclick={onpick ? () => onpick(r) : undefined}
      >
        <span class="line">
          {#if r.app}<AppIcon name={r.app.name} path={r.app.path} size={18} />{/if}
          <span class="label" title={r.label}>{r.label}</span>
          {#if r.note}<span class="note muted">{r.note}</span>{/if}
          <span class="num count">{r.count.toLocaleString()}</span>
          <span class="num muted share">{share(r.count)}</span>
        </span>
        <span class="bar"><span style:width="{(r.count / max) * 100}%"></span></span>
      </svelte:element>
    </li>
  {:else}
    <li class="empty muted">{empty}</li>
  {/each}
</ul>

<style>
  .list {
    list-style: none;
    margin: 0;
    padding: 0 8px 10px;
  }
  .row {
    display: grid;
    gap: 3px;
    width: 100%;
    padding: 6px 8px;
    border: 0;
    border-radius: 7px;
    background: none;
    text-align: left;
    font: inherit;
  }
  .row.pick {
    cursor: pointer;
  }
  .row.pick:hover {
    background: var(--surface-2);
  }
  .line {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    font-size: 13px;
  }
  .label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .count {
    flex: none;
  }
  .share {
    flex: none;
    width: 44px;
    text-align: right;
    font-size: 12px;
  }
  .note {
    flex: none;
    font-size: 11.5px;
  }
  .bar {
    height: 4px;
    border-radius: 2px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 2px;
    background: var(--series-1);
  }
  .empty {
    padding: 16px 8px;
    font-size: 13px;
  }
</style>
