<script lang="ts">
  import { api, type Breakdown, type BreakdownFilter } from "./api";
  import AppIcon from "./AppIcon.svelte";
  import Column from "./Column.svelte";
  import Flag from "./Flag.svelte";
  import { trafficLabel } from "./format";

  interface Props {
    /** First and last Unix second, inclusive. */
    from: number;
    to: number;
    /** Two columns instead of five, for side panels. */
    dense?: boolean;
    /** Applies to everything, under the chips the user picks. */
    baseFilter?: BreakdownFilter;
    ontotals?: (b: Breakdown) => void;
  }

  let { from, to, dense = false, baseFilter = {}, ontotals }: Props = $props();

  type FilterKey = keyof BreakdownFilter;
  interface Chip {
    key: FilterKey;
    value: string | number;
    label: string;
  }

  let chips = $state<Chip[]>([]);
  let data = $state.raw<Breakdown | null>(null);
  let error = $state<string | null>(null);

  const filter = $derived({
    ...baseFilter,
    ...(Object.fromEntries(chips.map((c) => [c.key, c.value])) as BreakdownFilter),
  });

  // Re-query whenever the range or filter changes. While live, the range moves
  // every second as samples arrive, which keeps the columns current.
  $effect(() => {
    const [f, t, flt] = [from, to, filter];
    let cancelled = false;
    api
      .breakdown(f, t, flt)
      .then((b) => {
        if (cancelled) return;
        data = b;
        error = null;
        ontotals?.(b);
      })
      .catch((e) => {
        if (!cancelled) error = String(e);
      });
    return () => {
      cancelled = true;
    };
  });

  function toggle(key: FilterKey, value: string | number, label: string) {
    const current = chips.find((c) => c.key === key);
    const rest = chips.filter((c) => c.key !== key);
    chips = current?.value === value ? rest : [...rest, { key, value, label }];
  }

  function activeKey(key: FilterKey): string | null {
    const chip = chips.find((c) => c.key === key);
    return chip ? String(chip.value) : null;
  }

  const appRows = $derived(
    (data?.apps ?? []).map((a) => ({
      key: String(a.app.id),
      label: a.app.name,
      title: `${a.app.name}\n${a.app.path}`,
      bytes: a.bytes,
      item: a,
    })),
  );
  // A machine can appear under several addresses (IPv4 and IPv6) with the same
  // name; show the address when names repeat so the rows can be told apart.
  const repeatedNames = $derived.by(() => {
    const seen = new Map<string, number>();
    for (const h of data?.hosts ?? []) if (h.name) seen.set(h.name, (seen.get(h.name) ?? 0) + 1);
    return new Set([...seen].filter(([, n]) => n > 1).map(([name]) => name));
  });
  const hostRows = $derived(
    (data?.hosts ?? []).map((h) => ({
      key: h.ip,
      label: h.name ? (repeatedNames.has(h.name) ? `${h.name} (${h.ip})` : h.name) : h.ip,
      title:
        `${h.name ? `${h.name} · ` : ""}${h.ip}\n${h.country.name}\n` +
        (h.app_count > 1 ? `${h.top_app.name} and ${h.app_count - 1} more` : h.top_app.name),
      bytes: h.bytes,
      item: h,
    })),
  );
  const typeRows = $derived(
    (data?.traffic_types ?? []).map((t) => ({
      key: t.traffic_type,
      label: trafficLabel(t.traffic_type),
      bytes: t.bytes,
      item: t,
    })),
  );
  const publisherRows = $derived(
    (data?.publishers ?? []).map((p) => ({
      key: p.name,
      label: p.name,
      title: `${p.name}
${p.apps} ${p.apps === 1 ? "app" : "apps"}`,
      bytes: p.bytes,
      item: p,
    })),
  );
  const countryRows = $derived(
    (data?.countries ?? []).map((c) => ({
      key: c.country.code,
      label: c.country.name,
      bytes: c.bytes,
      item: c,
    })),
  );
</script>

<div class="breakdown">
  {#if chips.length}
    <div class="chips">
      <span class="muted">Only</span>
      {#each chips as chip (chip.key)}
        <button class="chip" onclick={() => toggle(chip.key, chip.value, chip.label)}>
          {chip.label} <span aria-hidden="true">✕</span><span class="sr">remove filter</span>
        </button>
      {/each}
      <button class="clear" onclick={() => (chips = [])}>Clear</button>
    </div>
  {/if}
  {#if error}
    <p class="error">{error}</p>
  {/if}

  <div class="cols" class:dense>
    <Column
      title="Apps"
      rows={appRows}
      more={data?.apps_more ?? 0}
      active={activeKey("app")}
      onpick={(r) => toggle("app", r.item.app.id, r.item.app.name)}
    >
      {#snippet icon(a)}<AppIcon name={a.app.name} path={a.app.path} size={16} />{/snippet}
    </Column>

    <Column
      title="Hosts"
      rows={hostRows}
      more={data?.hosts_more ?? 0}
      active={activeKey("host")}
      onpick={(r) => toggle("host", r.item.ip, r.item.name ?? r.item.ip)}
    >
      {#snippet icon(h)}<Flag code={h.country.code} size={16} />{/snippet}
      {#snippet trailing(h)}<AppIcon name={h.top_app.name} path={h.top_app.path} size={14} />{/snippet}
    </Column>

    <Column
      title="Publishers"
      rows={publisherRows}
      active={activeKey("publisher")}
      onpick={(r) => toggle("publisher", r.item.name, r.item.name)}
    >
      {#snippet icon(p)}<span class="initial" aria-hidden="true">{p.name.charAt(0)}</span>{/snippet}
    </Column>

    <Column
      title="Traffic type"
      rows={typeRows}
      active={activeKey("traffic_type")}
      onpick={(r) => toggle("traffic_type", r.item.traffic_type, trafficLabel(r.item.traffic_type))}
    >
      {#snippet icon(t)}<span class="type-dot" data-type={t.traffic_type}></span>{/snippet}
    </Column>

    <Column
      title="Countries"
      rows={countryRows}
      active={activeKey("country")}
      onpick={(r) => toggle("country", r.item.country.code, r.item.country.name)}
    >
      {#snippet icon(c)}<Flag code={c.country.code} size={16} />{/snippet}
      {#snippet footer()}IP geolocation by DB-IP.com{/snippet}
    </Column>
  </div>
</div>

<style>
  .breakdown {
    display: grid;
    gap: 10px;
    min-width: 0;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding: 0 8px;
    font-size: 12.5px;
  }
  .chip {
    border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border-radius: 14px;
    padding: 2px 9px;
    cursor: pointer;
    font-size: 12.5px;
  }
  .clear {
    border: 0;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
    text-decoration: underline;
    font-size: 12.5px;
  }
  .error {
    color: var(--bad-text);
    padding: 0 8px;
    margin: 0;
  }
  .cols {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 8px 16px;
  }
  .cols.dense {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    row-gap: 18px;
  }
  .initial {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    display: grid;
    place-items: center;
    font-size: 10px;
    font-weight: 700;
    color: var(--text-muted);
    background: var(--surface-2);
  }
  .type-dot {
    width: 9px;
    height: 9px;
    border-radius: 3px;
    background: var(--text-muted);
    opacity: 0.55;
  }
  .type-dot[data-type="https"],
  .type-dot[data-type="quic"] {
    background: var(--in);
    opacity: 1;
  }
  .type-dot[data-type="rdp"],
  .type-dot[data-type="smb"],
  .type-dot[data-type="ssh"] {
    background: var(--out);
    opacity: 1;
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }
  @media (max-width: 1300px) {
    .cols {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      row-gap: 18px;
    }
  }
  @media (max-width: 1000px) {
    .cols {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      row-gap: 18px;
    }
  }
</style>
