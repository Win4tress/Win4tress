<script lang="ts">
  // The card (SPEC §7.4): what wants an answer, one at a time, in a small
  // window above the taskbar. Ask to Connect's blocked connections: Allow or
  // Block, for the whole app or (under Details) only this host, for good or
  // for a while. In Click to Block, new apps' first connections: Block (which
  // also ends its connections), or OK. The window follows the card's height
  // and closes when nothing is left.
  import { onMount } from "svelte";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import {
    api,
    appProduct,
    errorText,
    events,
    type Alert,
    type DecisionScope,
    type KnownApp,
    type Prompt,
  } from "./api";
  import AppIcon from "./AppIcon.svelte";
  import Flag from "./Flag.svelte";
  import Logo from "./Logo.svelte";
  import { ago } from "./format";
  import { HOW_LONG, lastsOf, type HowLong } from "./lasts";
  import { appOrigin } from "./origin";
  import { trustChips } from "./trust";

  type NewApp = Extract<Alert, { kind: "first_network_activity" }>;
  type Item = { key: string; prompt: Prompt; notice?: never } | { key: string; notice: NewApp; prompt?: never };

  /** A new app's card goes after 6 s as the one showing (not counting while
   *  the pointer is on it); the alert stays in the list. */
  const NOTICE_MS = 6_000;
  /** Off the card, the new app showing gets at least this much more. */
  const AFTER_POINTER_MS = 3_000;

  let prompts = $state.raw<Prompt[]>([]);
  let notices = $state.raw<Alert[]>([]);
  let loaded = $state(false);
  /** The item shown, by key; the first one when it's gone. */
  let currentKey = $state<string | null>(null);
  let details = $state(false);
  let scope = $state<DecisionScope>("app");
  let howLong = $state<HowLong>("always");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let nowMs = $state(Date.now());
  /** New apps' details (company, signature), from the service's app list. */
  let apps = $state.raw(new Map<number, KnownApp>());
  let root: HTMLElement;
  let hovered = false;
  /** The new app showing, whose time is counting. */
  let timed: number | null = null;
  /** When its clock last started; null while it's stopped. */
  let shownAt: number | null = null;
  /** New apps' time as the one showing, up to their clock's last stop. */
  const seen = new Map<number, number>();
  const asked = new Set<number>();

  const items: Item[] = $derived([
    ...prompts.map((p) => ({ key: `p${p.id}`, prompt: p })),
    ...notices
      .filter((a): a is NewApp => a.kind === "first_network_activity")
      .map((a) => ({ key: `n${a.id}`, notice: a })),
  ]);
  const index = $derived(Math.max(0, items.findIndex((i) => i.key === currentKey)));
  const current = $derived(items[index] ?? null);

  /** The product the program showing is part of, from its file (see `appOrigin`). */
  let product = $state<string | null>(null);
  $effect(() => {
    const path = current?.prompt?.app.path ?? current?.notice?.app?.path;
    product = null;
    if (!path) return;
    let stale = false;
    appProduct(path).then((p) => {
      if (!stale) product = p;
    });
    return () => {
      stale = true;
    };
  });

  // Another item: its own choices, from the start.
  let shownKey: string | null = null;
  $effect.pre(() => {
    const key = current?.key ?? null;
    if (key !== shownKey) {
      shownKey = key;
      details = false;
      scope = "app";
      howLong = "always";
      error = null;
      stopClock();
      timed = current?.notice?.id ?? null;
      startClock();
    }
  });

  $effect(() => {
    if (loaded && items.length === 0) close();
  });

  $effect(() => {
    const missing = notices.some((a) => a.app && !apps.has(a.app.id) && !asked.has(a.app.id));
    if (!missing) return;
    for (const a of notices) if (a.app) asked.add(a.app.id);
    api
      .knownApps()
      .then((r) => (apps = new Map(r.apps.map((a) => [a.id, a]))))
      .catch(() => {});
  });

  onMount(() => {
    Promise.all([api.prompts(), api.cardNotices()])
      .then(([p, n]) => {
        prompts = p.prompts;
        notices = n;
      })
      .catch((e) => (error = errorText(e)))
      .finally(() => (loaded = true));
    const offs = [events.onPrompts((p) => (prompts = p)), events.onNotices((n) => (notices = n))];
    const fit = new ResizeObserver(() => api.cardFit(Math.ceil(root.getBoundingClientRect().height)));
    fit.observe(root);
    const timer = setInterval(tick, 500);
    return () => {
      for (const off of offs) off.then((f) => f());
      fit.disconnect();
      clearInterval(timer);
    };
  });

  function stopClock() {
    if (timed != null && shownAt != null) seen.set(timed, (seen.get(timed) ?? 0) + Date.now() - shownAt);
    shownAt = null;
  }

  function startClock() {
    if (timed != null && !hovered) shownAt = Date.now();
  }

  function tick() {
    nowMs = Date.now();
    if (busy || timed == null || shownAt == null) return;
    if ((seen.get(timed) ?? 0) + nowMs - shownAt >= NOTICE_MS) api.cardDismiss(timed);
  }

  function entered() {
    hovered = true;
    stopClock();
  }

  function left() {
    hovered = false;
    if (timed != null) seen.set(timed, Math.min(seen.get(timed) ?? 0, NOTICE_MS - AFTER_POINTER_MS));
    startClock();
  }

  function close() {
    getCurrentWindow().close();
  }

  function go(step: number) {
    currentKey = items[(index + step + items.length) % items.length]?.key ?? null;
  }

  async function act(f: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await f();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function decide(p: Prompt, decision: "allow" | "block" | "later") {
    return act(async () => {
      await api.decide(p.id, decision, scope, decision === "later" || scope === "host" ? null : lastsOf(howLong));
      // "Later" keeps it in the list: on to the next one, if any.
      if (decision === "later") {
        if (items.length > 1) go(1);
        else close();
      }
    });
  }

  /** Blocks it and ends what it has open: blocking doesn't cut connections
   *  already made. */
  function blockApp(a: NewApp) {
    return act(async () => {
      if (a.app) {
        await api.setRule(a.app.id, "out", "block", { kind: "any" }, lastsOf(howLong));
        await api.closeConnections(a.app.id).catch(() => {});
      }
      await api.cardDismiss(a.id);
    });
  }

  function time(ms: number): string {
    return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && close()} />

{#snippet howLongSelect(hostOnly: boolean)}
  <select
    class="how-long"
    bind:value={howLong}
    disabled={busy || hostOnly}
    aria-label="How long"
    title={hostOnly ? "A decision for one host is for good" : "How long the decision lasts; then it goes back"}
  >
    {#each HOW_LONG as h (h.value)}<option value={h.value}>{h.label}</option>{/each}
  </select>
{/snippet}

<main bind:this={root} onpointerenter={entered} onpointerleave={left}>
  <div class="top">
    <Logo size={14} />
    <span class="caption">{current?.notice ? "First network activity" : "Ask to Connect"}</span>
    {#if items.length > 1}
      <nav aria-label="Others waiting">
        <button class="step" onclick={() => go(-1)} aria-label="Previous">‹</button>
        <span class="num">{index + 1} of {items.length}</span>
        <button class="step" onclick={() => go(1)} aria-label="Next">›</button>
      </nav>
    {/if}
    <button class="x" onclick={close} aria-label="Close" title="Close (Esc)">
      <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
        <path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" />
      </svg>
    </button>
  </div>

  {#if current?.prompt}
    {@const p = current.prompt}
    {@const host = p.remote.name ?? p.remote.ip}
    {@const chips = trustChips(p)}
    {@const origin = appOrigin(p.app.name, p.app.path, product, p.path_class)}
    <div class="who">
      <AppIcon name={p.app.name} path={p.app.path} size={32} />
      <div class="names">
        <h1 title={p.app.path}>{p.app.name}</h1>
        <p class="muted">{[p.company, `first seen ${ago(nowMs - p.first_seen_ms)}`].filter(Boolean).join(" · ")}</p>
        {#if origin}<p class="origin" title={p.app.path}>{origin}</p>{/if}
      </div>
    </div>
    <p class="muted lead">wants to connect to</p>
    <p class="host">
      <Flag code={p.remote.country.code} size={16} />
      <span class="where"><strong title={host}>{host}</strong><span class="muted">:{p.port}</span></span>
    </p>
    {#if chips.length}
      <div class="chips">
        {#each chips as c (c.label)}<span class="chip {c.tone}" title={c.title}>{c.label}</span>{/each}
      </div>
    {/if}

    {#if details}
      <div class="details">
        <p class="path mono" title={p.app.path}>{p.app.path}</p>
        <p class="muted">
          {[p.remote.name ? p.remote.ip : null, p.remote.country.name, p.owner?.name].filter(Boolean).join(" · ")}
        </p>
        <p class="muted">
          Blocked {p.attempts === 1 ? "once" : `${p.attempts} times`} since {time(p.first_ms)}.
          {#if p.state === "pending"}Waiting for your decision.{/if}
        </p>
        <fieldset>
          <legend class="muted">Apply to</legend>
          <label><input type="radio" bind:group={scope} value="app" /> Every connection of this app</label>
          <label><input type="radio" bind:group={scope} value="host" /> Only <span class="mono">{host}</span></label>
        </fieldset>
      </div>
    {/if}

    {#if error}<p class="error-text" role="alert">{error}</p>{/if}
    <div class="actions">
      <button class="btn danger" disabled={busy} onclick={() => decide(p, "block")}>Block</button>
      <button class="btn primary" disabled={busy} onclick={() => decide(p, "allow")}>Allow</button>
      {@render howLongSelect(scope === "host")}
      {#if details}
        <button class="link" disabled={busy} onclick={() => decide(p, "later")}>Decide later</button>
      {:else}
        <button class="link" onclick={() => (details = true)}>Details</button>
      {/if}
    </div>
  {:else if current?.notice}
    {@const a = current.notice}
    {@const known = a.app ? apps.get(a.app.id) : undefined}
    {@const chips = known ? trustChips(known) : []}
    {@const origin = known ? appOrigin(known.name, known.path, product, known.path_class) : null}
    <div class="who">
      <AppIcon name={a.app?.name ?? "?"} path={a.app?.path ?? ""} size={32} />
      <div class="names">
        <h1 title={a.app?.path}>{a.app?.name}</h1>
        <p class="muted">{[known?.company, ago(nowMs - a.ts_ms)].filter(Boolean).join(" · ")}</p>
        {#if origin}<p class="origin" title={known?.path}>{origin}</p>{/if}
      </div>
    </div>
    {#if a.host}
      {@const host = a.host.name ?? a.host.ip}
      <p class="muted lead">connected to</p>
      <p class="host">
        <Flag code={a.host.country.code} size={16} />
        <span class="where"><strong title={host}>{host}</strong><span class="muted">:{a.port}</span></span>
      </p>
    {:else}
      <p class="muted lead">used the network for the first time</p>
    {/if}
    {#if chips.length}
      <div class="chips">
        {#each chips as c (c.label)}<span class="chip {c.tone}" title={c.title}>{c.label}</span>{/each}
      </div>
    {/if}

    {#if error}<p class="error-text" role="alert">{error}</p>{/if}
    <div class="actions">
      <button
        class="btn danger"
        disabled={busy}
        title="Block its connections and end the ones it has open"
        onclick={() => blockApp(a)}
      >
        Block
      </button>
      <button class="btn" disabled={busy} onclick={() => api.cardDismiss(a.id)}>OK</button>
      {@render howLongSelect(false)}
    </div>
  {:else if error}
    <p class="error-text" role="alert">{error}</p>
  {/if}
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 14px 14px;
    font-size: 13px;
  }
  p {
    margin: 0;
  }
  .top {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: 22px;
    color: var(--text-muted);
    font-size: 12px;
  }
  .caption {
    flex: 1;
    min-width: 0;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  nav {
    display: flex;
    align-items: center;
    gap: 2px;
  }
  .step,
  .x {
    display: grid;
    place-items: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 0;
    border-radius: 5px;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
  }
  .step {
    font-size: 16px;
    line-height: 1;
  }
  .step:hover,
  .x:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .who {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .names {
    min-width: 0;
  }
  h1 {
    margin: 0;
    font: 600 15px/1.25 var(--font-display);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .names .origin {
    color: var(--text);
  }
  .names p {
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .lead {
    margin-bottom: -6px;
    font-size: 12px;
  }
  .host {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    font-size: 14px;
  }
  .where {
    display: flex;
    min-width: 0;
  }
  .where strong {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .details {
    display: grid;
    gap: 5px;
    padding-top: 8px;
    border-top: 1px solid var(--border);
    font-size: 12.5px;
  }
  .path {
    padding: 3px 7px;
    background: var(--surface-2);
    border-radius: 6px;
    font-size: 11.5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  fieldset {
    display: grid;
    gap: 3px;
    margin: 2px 0 0;
    padding: 0;
    border: 0;
  }
  legend {
    padding: 0;
    margin-bottom: 2px;
  }
  fieldset label {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    cursor: pointer;
  }
  fieldset .mono {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  input[type="radio"] {
    margin: 0;
    accent-color: var(--accent);
  }
  .error-text {
    font-size: 12.5px;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 4px;
  }
  .actions .btn {
    flex: 1;
    min-width: 0;
    padding: 6px 10px;
  }
  .how-long {
    flex: none;
    width: 118px;
    font: inherit;
    font-size: 12.5px;
    color: var(--text);
    padding: 5px 4px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
  }
  .link {
    margin-left: 4px;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent-text);
    cursor: pointer;
    text-decoration: underline;
    font-size: 12.5px;
  }
</style>
