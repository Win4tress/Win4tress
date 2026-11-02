<script lang="ts">
  import { api, errorText, type AppSummary, type HostsResult } from "./api";
  import { firewall as fw } from "./firewall.svelte";
  import Flag from "./Flag.svelte";
  import { ago, human, trafficLabel } from "./format";
  import { HOW_LONG, lastsOf, thenText, untilText, type HowLong } from "./lasts";
  import { SIGNATURE_TEXT } from "./trust";

  /** An app's expanded row: totals and every host it talked to, each of which
   *  can be blocked on its own; blocking or allowing it for a while, and
   *  ending its connections. */
  interface Props {
    app: AppSummary;
    nowMs: number;
    /** Show the app on the Firewall screen. */
    onopenfirewall?: (id: number) => void;
  }

  let { app, nowMs, onopenfirewall }: Props = $props();

  const REFRESH_MS = 3000;
  let hosts = $state.raw<HostsResult | null>(null);
  let failed = $state(false);

  $effect(() => {
    const id = app.id;
    let cancelled = false;
    const load = () =>
      api
        .hosts(id)
        .then((r) => {
          if (!cancelled) {
            hosts = r;
            failed = false;
          }
        })
        .catch(() => {
          if (!cancelled) failed = true;
        });
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  // Per-host blocks live in one rule: the app's outgoing block for some hosts.
  const blockedHosts = $derived.by(() => {
    const scope = fw.rule(app.id, "out", "block", "hosts")?.scope;
    return new Set(scope?.kind === "hosts" ? scope.hosts : []);
  });
  const canBlock = $derived(
    !!fw.status && !fw.monitoringOnly && !fw.byApp.get(app.id)?.protected && (app.path === "System" || app.path.includes("\\")),
  );
  let hostBusy = $state<string | null>(null);
  let hostError = $state<string | null>(null);
  let note = $state<string | null>(null);

  /** Its outgoing rule for the whole app, if it's temporary. */
  const temporary = $derived.by(() => {
    const r = fw.rules.find((r) => r.app.id === app.id && r.direction === "out" && r.scope.kind === "any");
    return r?.expires ? r : null;
  });
  const outAllowed = $derived(fw.byApp.get(app.id)?.out.allowed ?? true);
  const FOR_A_WHILE = HOW_LONG.filter((h) => h.value !== "always");

  /** Blocks (or allows, if it's blocked now) its outgoing connections for a while. */
  async function forAWhile(e: Event & { currentTarget: HTMLSelectElement }) {
    const chosen = e.currentTarget.value as HowLong | "";
    e.currentTarget.value = "";
    if (!chosen) return;
    hostBusy = "*";
    hostError = null;
    note = null;
    try {
      await api.setRule(app.id, "out", outAllowed ? "block" : "allow", { kind: "any" }, lastsOf(chosen));
      if (outAllowed) await api.closeConnections(app.id).catch(() => {});
      await fw.refresh();
    } catch (err) {
      hostError = errorText(err);
    } finally {
      hostBusy = null;
    }
  }

  /** Ends its open TCP connections (IPv4: Windows can't end IPv6 ones). */
  async function disconnect() {
    hostBusy = "*";
    hostError = null;
    note = null;
    try {
      const r = await api.closeConnections(app.id);
      note =
        `Ended ${r.closed} ${r.closed === 1 ? "connection" : "connections"}.` +
        (r.not_closable ? ` ${r.not_closable} IPv6 ${r.not_closable === 1 ? "one stays" : "ones stay"} open: Windows can only end IPv4 connections.` : "") +
        (r.error ? ` Some couldn't be ended: ${r.error}` : "");
    } catch (err) {
      hostError = errorText(err);
    } finally {
      hostBusy = null;
    }
  }

  /** A name covers every address this app looked up for it. */
  async function toggleHost(host: string) {
    const next = new Set(blockedHosts);
    if (next.has(host)) next.delete(host);
    else next.add(host);
    const rule = fw.rule(app.id, "out", "block", "hosts");
    hostBusy = host;
    hostError = null;
    try {
      if (next.size) await api.setRule(app.id, "out", "block", { kind: "hosts", hosts: [...next] });
      else if (rule) await api.deleteRule(rule.id);
      await fw.refresh();
    } catch (e) {
      hostError = errorText(e);
    } finally {
      hostBusy = null;
    }
  }

  function portsLabel(ports: number[]): string {
    const shown = ports.slice(0, 3).join(", ");
    const more = ports.length > 3 ? ` +${ports.length - 3}` : "";
    return `${ports.length === 1 ? "port" : "ports"} ${shown}${more}`;
  }
</script>

<div class="detail">
  <dl class="facts">
    <div>
      <dt>Since the service started</dt>
      <dd class="num"><span class="in">▼ {human(app.total.recv)}</span> <span class="out">▲ {human(app.total.sent)}</span></dd>
    </div>
    <div><dt>Local network</dt><dd class="num">{human(app.local.recv + app.local.sent)}</dd></div>
    <div><dt>Open connections</dt><dd class="num">{app.connections}</dd></div>
    <div><dt>First seen</dt><dd>{ago(nowMs - app.first_seen_ms)}</dd></div>
    {#if app.service}
      <div><dt>Windows service</dt><dd class="mono">{app.service}</dd></div>
    {/if}
    {#if app.pids.length > 1}
      <div><dt>Processes</dt><dd class="num">{app.pids.join(", ")}</dd></div>
    {/if}
    {#if app.trust.signature}
      <div>
        <dt>Signature</dt>
        <dd class:bad={app.trust.signature !== "signed"}>
          {app.trust.signer && app.trust.signature === "signed" ? app.trust.signer : SIGNATURE_TEXT[app.trust.signature]}
        </dd>
      </div>
    {/if}
    {#if temporary?.expires}
      <div>
        <dt>Outgoing</dt>
        <dd>{temporary.action === "block" ? "Blocked" : "Allowed"} {untilText(temporary.expires, nowMs)}, {thenText(temporary.revert)}</dd>
      </div>
    {/if}
    <div class="fw-link">
      {#if canBlock}
        <select
          class="btn small"
          aria-label={outAllowed ? "Block for a while" : "Allow for a while"}
          disabled={hostBusy !== null}
          onchange={forAWhile}
        >
          <option value="">{outAllowed ? "Block for…" : "Allow for…"}</option>
          {#each FOR_A_WHILE as h (h.value)}<option value={h.value}>{h.label}</option>{/each}
        </select>
        {#if app.connections > 0}
          <button
            class="btn small"
            disabled={hostBusy !== null}
            title="End its open connections now (blocking doesn't end connections already made)"
            onclick={disconnect}>Disconnect</button
          >
        {/if}
      {/if}
      {#if onopenfirewall}
        <button class="btn small" onclick={() => onopenfirewall(app.id)}>Firewall rules…</button>
      {/if}
    </div>
  </dl>
  <div class="path mono" title={app.path}>{app.path}</div>
  {#if hostError}<p class="error-text" role="alert">{hostError}</p>{/if}
  {#if note}<p class="muted" role="status">{note}</p>{/if}

  {#if failed && !hosts}
    <p class="muted">Couldn't load hosts.</p>
  {:else if !hosts}
    <p class="muted">Loading hosts…</p>
  {:else}
    <table class="hosts">
      <thead>
        <tr>
          <th class="fill">Host · {hosts.hosts.length}</th>
          <th>Network</th>
          <th>Type</th>
          <th class="r">Down</th>
          <th class="r">Up</th>
          <th class="r">Last seen</th>
          {#if canBlock}<th class="c-block"><span class="visually-hidden">Block</span></th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each hosts.hosts as h (h.ip)}
          {@const key = h.name ?? h.ip}
          {@const blocked = blockedHosts.has(key)}
          <tr class:blocked>
            <td class="fill">
              <div class="host" title="{h.name ?? h.ip} · {h.country.name} · {portsLabel(h.ports)}">
                <Flag code={h.country.code} size={16} />
                <span class="ellipsis">{h.name ?? h.ip}</span>
                {#if h.name}<span class="muted mono small ellipsis">{h.ip}</span>{/if}
              </div>
            </td>
            <td class="muted ellipsis net" title={h.owner ? `AS${h.owner.asn}` : undefined}>
              {h.owner?.name ?? (h.locality === "local" ? "Local network" : "–")}
            </td>
            <td class="muted nowrap">{trafficLabel(h.traffic_type)}</td>
            <td class="r num in">{human(h.total.recv)}</td>
            <td class="r num out">{human(h.total.sent)}</td>
            <td class="r muted nowrap">{ago(nowMs - h.last_seen_ms)}</td>
            {#if canBlock}
              <td class="c-block">
                <button
                  class="btn small"
                  class:danger={!blocked}
                  disabled={hostBusy !== null}
                  title={blocked
                    ? `Stop blocking ${key} for ${app.name}`
                    : `Block ${app.name}'s outgoing connections to ${key}${h.name ? " (every address it looked up for this name)" : ""}`}
                  onclick={() => toggleHost(key)}>{blocked ? "Unblock" : "Block"}</button
                >
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .detail {
    padding: 4px 16px 14px 44px;
    display: grid;
    gap: 10px;
  }
  .facts {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 28px;
    margin: 0;
  }
  dt {
    font-size: 11.5px;
    color: var(--text-muted);
  }
  dd {
    margin: 0;
    font-weight: 600;
  }
  .path {
    max-width: 1100px;
    padding: 5px 8px;
    background: var(--surface-2);
    border-radius: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
  }
  .hosts {
    width: 100%;
    max-width: 1100px;
    border-collapse: collapse;
    table-layout: fixed;
  }
  .hosts th {
    text-align: left;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .hosts td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    font-size: 12.5px;
  }
  .hosts tr:last-child td {
    border-bottom: 0;
  }
  .fill {
    width: 40%;
  }
  .c-block {
    width: 86px;
    text-align: right;
  }
  .c-block .btn {
    visibility: hidden;
  }
  tr:hover .c-block .btn,
  tr.blocked .c-block .btn,
  .c-block .btn:focus-visible {
    visibility: visible;
  }
  tr.blocked td:first-child {
    text-decoration: line-through;
    text-decoration-color: var(--bad);
  }
  dd.bad {
    color: var(--bad-text);
  }
  .fw-link {
    align-self: center;
    display: flex;
    gap: 6px;
  }
  select.btn {
    width: auto;
    font: inherit;
    font-size: 12px;
    cursor: pointer;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  .net {
    width: 22%;
  }
  .r,
  .hosts th.r {
    text-align: right;
    white-space: nowrap;
  }
  .nowrap {
    white-space: nowrap;
  }
  .host {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .small {
    font-size: 11.5px;
  }
  p {
    margin: 0;
    font-size: 12.5px;
  }
</style>
