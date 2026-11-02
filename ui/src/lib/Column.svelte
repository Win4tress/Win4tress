<script lang="ts" generics="T">
  import type { Snippet } from "svelte";
  import Bar from "./Bar.svelte";
  import { human } from "./format";
  import type { Row } from "./rows";

  interface Props {
    title: string;
    rows: Row<T>[];
    /** Rows left out by the service's limit. */
    more?: number;
    /** Key of the row the other columns are filtered by. */
    active?: string | null;
    icon: Snippet<[T]>;
    /** Optional small marker after the amount. */
    trailing?: Snippet<[T]>;
    onpick: (row: Row<T>) => void;
    footer?: Snippet;
  }

  let { title, rows, more = 0, active = null, icon, trailing, onpick, footer }: Props = $props();

  const max = $derived(Math.max(1, ...rows.map((r) => r.bytes.recv + r.bytes.sent)));
</script>

<section class="column">
  <h3>{title}</h3>
  {#if rows.length === 0}
    <p class="empty muted">Nothing in this range.</p>
  {:else}
    <ul>
      {#each rows as row (row.key)}
        <li>
          <button
            class:active={row.key === active}
            aria-pressed={row.key === active}
            title={row.title ?? row.label}
            onclick={() => onpick(row)}
          >
            <span class="icon">{@render icon(row.item)}</span>
            <span class="body">
              <span class="line">
                <span class="label">{row.label}</span>
                <span
                  class="amount num"
                  title="Download {human(row.bytes.recv)} · Upload {human(row.bytes.sent)}"
                  >{human(row.bytes.recv + row.bytes.sent)}</span
                >
                {#if trailing}<span class="trailing">{@render trailing(row.item)}</span>{/if}
              </span>
              <Bar recv={row.bytes.recv} sent={row.bytes.sent} {max} />
            </span>
          </button>
        </li>
      {/each}
    </ul>
    {#if more > 0}
      <p class="more muted">+{more} more</p>
    {/if}
  {/if}
  {#if footer}
    <div class="footer muted">{@render footer()}</div>
  {/if}
</section>

<style>
  .column {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  h3 {
    font: 600 13px/1.3 var(--font-display);
    margin: 0 0 6px;
    padding: 0 8px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  /* Compact rows: 11 px text, a row every 23 px. */
  button {
    display: flex;
    align-items: center;
    gap: 7px;
    width: 100%;
    padding: 2px 8px;
    border: 0;
    border-radius: 5px;
    background: none;
    text-align: left;
    cursor: pointer;
  }
  button:hover {
    background: var(--surface-2);
  }
  button.active {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }
  .icon {
    display: inline-grid;
    place-items: center;
    width: 16px;
    flex: none;
  }
  .body {
    flex: 1;
    min-width: 0;
    display: grid;
    /* minmax(0, ...) and min-width: 0 below let long labels truncate instead of
       pushing the amount past the end of the bar. */
    grid-template-columns: minmax(0, 1fr);
    gap: 2px;
  }
  .body > :global(.bar) {
    height: 3px;
  }
  .line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    min-width: 0;
    font-size: 11px;
    line-height: 14px;
  }
  .label {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .amount {
    flex: none;
    margin-left: auto;
  }
  .trailing {
    flex: none;
    display: inline-grid;
    place-items: center;
    height: 14px;
  }
  .empty,
  .more {
    padding: 3px 8px;
    margin: 0;
    font-size: 11px;
  }
  .footer {
    margin-top: auto;
    padding: 10px 8px 0;
    font-size: 11.5px;
  }
</style>
