<script lang="ts">
  // One app's firewall: what happens to its connections and why, win4tress's
  // rules for it (whole app, for good or for a while, some hosts, "allow
  // only", its own DNS), Windows Firewall's rules that name it, its trust
  // facts, and what was blocked.
  import {
    api,
    errorText,
    type Action,
    type BlockedConnection,
    type Direction,
    type PathClass,
    type Rule,
    type Scope,
    type Trust,
    type Verdict,
    type WindowsRuleInfo,
  } from "./api";
  import AppReputation from "./AppReputation.svelte";
  import { blockedByText } from "./blocked";
  import { firewall as fw } from "./firewall.svelte";
  import { ago } from "./format";
  import { HOW_LONG, lastsOf, thenText, untilText, type HowLong } from "./lasts";
  import { PATH_CLASS_TEXT, SIGNATURE_TEXT, zoneText } from "./trust";

  interface Props {
    app: { id: number; name: string; path: string; trust: Trust; path_class?: PathClass; own_dns_ms?: number };
    nowMs: number;
  }

  let { app, nowMs }: Props = $props();

  const DAY_MS = 24 * 3600 * 1000;
  const REFRESH_MS = 10_000;

  let windowsRules = $state.raw<WindowsRuleInfo[] | null>(null);
  let blocks = $state.raw<BlockedConnection[] | null>(null);
  /** Names this app looked up recently, offered when adding hosts. */
  let knownHosts = $state.raw<string[]>([]);
  let busy = $state(false);
  let error = $state<string | null>(null);

  type AddKind = "block_hosts" | "allow_only" | "allow_in" | "own_dns" | "block_for" | "allow_for";
  let addKind = $state<AddKind>("block_hosts");
  let addDirection = $state<Direction>("out");
  /** For "block for a while" and "allow for a while". */
  let addFor = $state<Exclude<HowLong, "always">>("1h");
  const FOR_A_WHILE = HOW_LONG.filter((h) => h.value !== "always");
  const timed = $derived(addKind === "block_for" || addKind === "allow_for");
  let addHosts = $state("");
  /** "Allow incoming" asks first. */
  let confirmAllowIn = $state(false);

  const rules = $derived(fw.rulesByApp.get(app.id) ?? []);
  const verdict = $derived(fw.byApp.get(app.id));
  const isProtected = $derived(verdict?.protected ?? false);
  const targetable = $derived(app.path === "System" || app.path.includes("\\"));
  const canChange = $derived(!!fw.status && !fw.monitoringOnly && targetable);
  const dnsBlocked = $derived(rules.some((r) => r.scope.kind === "dns"));

  $effect(() => {
    const id = app.id;
    let cancelled = false;
    const load = async () => {
      const [w, b] = await Promise.allSettled([api.appRules(id), api.blocks(id, Date.now() - 30 * DAY_MS, 50)]);
      if (cancelled) return;
      windowsRules = w.status === "fulfilled" ? w.value.rules : [];
      blocks = b.status === "fulfilled" ? b.value.blocks : [];
    };
    windowsRules = null;
    blocks = null;
    knownHosts = [];
    load();
    api
      .hosts(id)
      .then((r) => {
        if (!cancelled) knownHosts = [...new Set(r.hosts.map((h) => h.name ?? h.ip))];
      })
      .catch(() => {});
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  function parseHosts(text: string): string[] {
    return text
      .split(/[\s,;]+/)
      .map((h) => h.trim())
      .filter(Boolean);
  }

  async function run(action: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await action();
      await fw.refresh();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  /** The same kind of rule takes the union of its hosts: one rule per kind (SPEC §7.2). */
  function withHosts(direction: Direction, action: Action, kind: "hosts" | "except", add: string[]): Scope {
    const scope = fw.rule(app.id, direction, action, kind)?.scope;
    const old = scope?.kind === "hosts" || scope?.kind === "except" ? scope.hosts : [];
    return { kind, hosts: [...new Set([...old, ...add])] };
  }

  function add() {
    const hosts = parseHosts(addHosts);
    switch (addKind) {
      case "block_hosts":
        if (!hosts.length) return void (error = "Name at least one host.");
        return run(async () => {
          await api.setRule(app.id, addDirection, "block", withHosts(addDirection, "block", "hosts", hosts));
          addHosts = "";
        });
      case "allow_only":
        if (!hosts.length) return void (error = "Name at least one host.");
        return run(async () => {
          await api.setRule(app.id, addDirection, "block", withHosts(addDirection, "block", "except", hosts));
          addHosts = "";
        });
      case "allow_in":
        confirmAllowIn = true;
        return;
      case "own_dns":
        // The option goes once it's blocked.
        return run(async () => {
          await api.setRule(app.id, "out", "block", { kind: "dns" });
          addKind = "block_hosts";
        });
      case "block_for":
      case "allow_for":
        return run(() =>
          api.setRule(app.id, addDirection, addKind === "block_for" ? "block" : "allow", { kind: "any" }, lastsOf(addFor)),
        );
    }
  }

  function allowIncoming() {
    const hosts = parseHosts(addHosts);
    confirmAllowIn = false;
    run(async () => {
      await api.setRule(app.id, "in", "allow", hosts.length ? withHosts("in", "allow", "hosts", hosts) : { kind: "any" });
      addHosts = "";
    });
  }

  /** Takes one host out of a rule; the last one takes the rule with it. */
  function removeHost(r: Rule, host: string) {
    if (r.scope.kind !== "hosts" && r.scope.kind !== "except") return;
    const kind = r.scope.kind;
    const rest = r.scope.hosts.filter((h) => h !== host);
    run(() => (rest.length ? api.setRule(app.id, r.direction, r.action, { kind, hosts: rest }) : api.deleteRule(r.id)));
  }

  function ruleText(r: Rule): string {
    const dir = r.direction === "in" ? "incoming" : "outgoing";
    const toFrom = r.direction === "in" ? "from" : "to";
    const verb = r.action === "block" ? "Blocks" : "Allows";
    switch (r.scope.kind) {
      case "any":
        return `${verb} all ${dir} connections`;
      case "hosts":
        return `${verb} ${dir} connections ${toFrom}`;
      case "except":
        return `Allows ${dir} connections only ${toFrom} these hosts, and blocks the rest`;
      case "dns":
        return "Blocks its own DNS: ports 53 and 853, and DNS-over-HTTPS servers";
    }
  }

  function verdictText(v: Verdict | undefined, dir: Direction): string {
    if (!v) return "Unknown";
    const state = v.allowed ? "Allowed" : "Blocked";
    switch (v.by) {
      case "win4tress":
        return `${state} by win4tress`;
      case "windows_rule":
        return `${state} by Windows Firewall rule ${v.rules?.map((r) => `“${r}”`).join(", ") ?? ""}`;
      case "firewall_off":
        return "Allowed: Windows Firewall is off on a network in use";
      case "default":
        return v.allowed
          ? `Allowed (Windows Firewall's default for ${dir === "in" ? "incoming" : "outgoing"})`
          : dir === "in"
            ? "Blocked: no rule allows incoming connections"
            : "Blocked: outgoing connections need a rule";
    }
  }

  function when(ms: number): string {
    return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }
</script>

<div class="fw">
  {#if error}<p class="error-text" role="alert">{error}</p>{/if}

  <section>
    <h3>What happens now</h3>
    <dl class="verdicts">
      <div>
        <dt>Outgoing</dt>
        <dd class:blocked={verdict && !verdict.out.allowed}>{verdictText(verdict?.out, "out")}</dd>
      </div>
      <div>
        <dt>Incoming</dt>
        <dd class:blocked={verdict && !verdict.in.allowed}>{verdictText(verdict?.in, "in")}</dd>
      </div>
    </dl>
    <p class="muted small">For the app as a whole: rules for some hosts, ports or addresses aren't weighed here.</p>
    {#if isProtected}
      <p class="note">
        Part of win4tress: it can't be blocked, so win4tress keeps working. Block All still blocks it.
      </p>
    {:else if !targetable}
      <p class="note">No program is known for this app, so there's nothing to put in a rule.</p>
    {/if}
  </section>

  <section>
    <h3>win4tress rules · {rules.length}</h3>
    {#if rules.length === 0}
      <p class="muted small">None. Use the switches in Apps, or add a rule below.</p>
    {:else}
      <ul class="rules">
        {#each rules as r (r.id)}
          <li>
            <div class="rule-text">
              <span class="chip" class:bad={r.action === "block"}>{r.action === "block" ? "Block" : "Allow"}</span>
              <span>
                {ruleText(r)}{#if !r.enabled}<span class="muted"> (off)</span>{/if}
                {#if r.expires}<span class="until">{untilText(r.expires, nowMs)}, {thenText(r.revert)}</span>{/if}
                {#if r.scope.kind === "hosts" || r.scope.kind === "except"}
                  <span class="hosts">
                    {#each r.scope.hosts as h (h)}
                      <span class="host">
                        {h}
                        {#if canChange}
                          <button class="x" aria-label="Remove {h}" disabled={busy} onclick={() => removeHost(r, h)}>×</button>
                        {/if}
                      </span>
                    {/each}
                  </span>
                {/if}
              </span>
            </div>
            <span class="muted small nowrap">{ago(nowMs - r.updated_ms)}</span>
            {#if canChange}
              <button
                class="btn small"
                disabled={busy}
                title={r.enabled ? "Keep the rule but switch it off (profiles remember which rules are on)" : "Switch the rule back on"}
                onclick={() => run(() => api.enableRule(r.id, !r.enabled))}>{r.enabled ? "Turn off" : "Turn on"}</button
              >
              <button class="btn small" disabled={busy} onclick={() => run(() => api.deleteRule(r.id))}>Remove</button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  {#if canChange && !isProtected}
    <section>
      <h3>Add a rule</h3>
      <div class="add">
        <select bind:value={addKind} aria-label="Kind of rule" onchange={() => (confirmAllowIn = false)}>
          <option value="block_hosts">Block some hosts</option>
          <option value="allow_only">Allow only some hosts</option>
          <option value="allow_in">Allow incoming connections…</option>
          {#if !dnsBlocked}<option value="own_dns">Block its own DNS</option>{/if}
          <option value="block_for">Block for a while</option>
          <option value="allow_for">Allow for a while</option>
        </select>
        {#if addKind === "block_hosts" || addKind === "allow_only" || timed}
          <select bind:value={addDirection} aria-label="Direction">
            <option value="out">Outgoing</option>
            <option value="in">Incoming</option>
          </select>
        {/if}
        {#if timed}
          <select bind:value={addFor} aria-label="How long">
            {#each FOR_A_WHILE as h (h.value)}<option value={h.value}>{h.label}</option>{/each}
          </select>
        {/if}
      </div>
      {#if timed}
        <p class="muted small">
          All of its {addDirection === "in" ? "incoming" : "outgoing"} connections. Then it goes back to what it was: its
          rule now, or none.
        </p>
      {:else if addKind !== "own_dns"}
        <input
          class="hosts-input"
          list="hosts-{app.id}"
          placeholder={addKind === "allow_in"
            ? "From any address, or only from: 192.168.1.0/24, nas.local"
            : "example.com, *.example.com, 203.0.113.7, 10.0.0.0/8"}
          bind:value={addHosts}
          aria-label="Hosts"
        />
        <datalist id="hosts-{app.id}">
          {#each knownHosts as h (h)}<option value={h}></option>{/each}
        </datalist>
        <p class="muted small">
          Addresses, ranges (a-b), networks (a/n) or names. A name covers the addresses this app looked up for it;
          *.example.com includes its subdomains.
          {#if addKind === "allow_only"}Everything else is blocked, except this PC itself.{/if}
        </p>
      {:else}
        <p class="muted small">
          It then has to look names up through Windows, where win4tress sees them. Blocks ports 53 and 853 and known
          DNS-over-HTTPS servers.
        </p>
      {/if}
      {#if confirmAllowIn}
        {@const hosts = parseHosts(addHosts)}
        {@const replaces = fw.rule(app.id, "in", "block", hosts.length ? "hosts" : "any")}
        <div class="note warn" role="alert">
          <p>
            This lets other computers connect to <strong>{app.name}</strong>
            {hosts.length ? `from ${hosts.join(", ")}` : "from any address on the networks you use"}. Only do this for
            apps that need it, such as a game server, a media server or file sharing.
            {#if replaces}It replaces win4tress's incoming block rule for {hosts.length ? "those hosts" : "this app"}.{/if}
          </p>
          <div class="row">
            <button class="btn danger" disabled={busy} onclick={allowIncoming}>Allow incoming connections</button>
            <button class="btn" onclick={() => (confirmAllowIn = false)}>Cancel</button>
          </div>
        </div>
      {:else}
        <button class="btn primary" disabled={busy} onclick={add}>
          {addKind === "allow_in"
            ? "Allow incoming…"
            : addKind === "own_dns"
              ? "Block its own DNS"
              : addKind === "block_for"
                ? "Block"
                : addKind === "allow_for"
                  ? "Allow"
                  : "Add"}
        </button>
      {/if}
    </section>
  {/if}

  <section>
    <h3>Windows Firewall rules for this app{windowsRules ? ` · ${windowsRules.length}` : ""}</h3>
    {#if windowsRules === null}
      <p class="muted small">Loading…</p>
    {:else if windowsRules.length === 0}
      <p class="muted small">None outside win4tress name this program.</p>
    {:else}
      <ul class="win-rules">
        {#each windowsRules as w, i (i)}
          <li class:inactive={!w.active}>
            <span class="chip" class:bad={w.action === "block"}>{w.action === "block" ? "Block" : "Allow"}</span>
            <span class="ellipsis" title={w.name}>{w.name}</span>
            <span class="muted small nowrap">{w.direction === "in" ? "Incoming" : "Outgoing"} · {w.profiles}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section>
    <h3>Program</h3>
    <dl class="facts">
      <div><dt>Signature</dt><dd>{app.trust.signature ? SIGNATURE_TEXT[app.trust.signature] : "Not checked yet"}</dd></div>
      {#if app.trust.signer}<div><dt>Signed by</dt><dd>{app.trust.signer}</dd></div>{/if}
      {#if app.path_class}<div><dt>Location</dt><dd>{PATH_CLASS_TEXT[app.path_class]}</dd></div>{/if}
      {#if app.trust.origin}
        <div>
          <dt>Downloaded</dt>
          <dd>
            {zoneText(app.trust.origin.zone)}{#if app.trust.origin.host_url}: <span class="mono url">{app.trust.origin.host_url}</span>{/if}
          </dd>
        </div>
      {/if}
      {#if app.own_dns_ms != null}<div><dt>Own DNS</dt><dd>Seen {when(app.own_dns_ms)}</dd></div>{/if}
      {#if app.trust.sha256}<div><dt>SHA-256</dt><dd class="mono hash">{app.trust.sha256}</dd></div>{/if}
    </dl>
    <div class="path mono" title={app.path}>{app.path}</div>
  </section>

  <AppReputation {app} {nowMs} />

  <section>
    <h3>Blocked in the last 30 days{blocks?.length ? ` · ${blocks.length}` : ""}</h3>
    {#if blocks === null}
      <p class="muted small">Loading…</p>
    {:else if blocks.length === 0}
      <p class="muted small">Nothing blocked.</p>
    {:else}
      <table class="blocks">
        <tbody>
          {#each blocks as b, i (i)}
            <tr>
              <td class="ellipsis" title={b.remote}>
                <span class={b.inbound ? "in" : "out"}>{b.inbound ? "▼" : "▲"}</span>
                {b.name ?? b.remote}{#if b.name}<span class="muted mono small"> {b.remote}</span>{/if}
              </td>
              <td class="ellipsis muted" title={b.by.name}>{blockedByText(b.by)}</td>
              <td class="r num muted nowrap">{b.count}×</td>
              <td class="r muted nowrap">{ago(nowMs - b.last_ms)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>

<style>
  .fw {
    display: grid;
    /* The panel's width, not its widest line: the one-line path would
       otherwise widen every section and scroll the panel sideways. */
    grid-template-columns: minmax(0, 1fr);
    gap: 0;
    font-size: 13px;
  }
  section {
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }
  section:last-child {
    border-bottom: 0;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
  }
  p {
    margin: 6px 0;
  }
  .small {
    font-size: 12px;
  }
  .nowrap {
    white-space: nowrap;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .note {
    padding: 7px 10px;
    border-radius: 7px;
    background: var(--surface-2);
  }
  .note.warn {
    background: color-mix(in srgb, var(--alert-info) 18%, var(--surface));
  }
  .note p {
    margin: 0 0 8px;
  }
  .verdicts {
    display: grid;
    gap: 4px;
    margin: 0;
  }
  .verdicts div {
    display: grid;
    grid-template-columns: 74px 1fr;
    gap: 8px;
  }
  dt {
    color: var(--text-muted);
  }
  dd {
    margin: 0;
  }
  .verdicts dd {
    font-weight: 600;
  }
  .verdicts dd.blocked {
    color: var(--bad-text);
  }
  .rules,
  .win-rules {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 6px;
  }
  .rules li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto auto;
    align-items: start;
    gap: 10px;
  }
  .rule-text {
    display: flex;
    gap: 8px;
    align-items: baseline;
  }
  .hosts {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 4px;
  }
  .until {
    display: block;
    margin-top: 2px;
    font-size: 12px;
    color: var(--accent-text);
  }
  .host {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    font-family: var(--mono);
    font-size: 12px;
    padding: 0 4px 0 7px;
    border-radius: 10px;
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .x {
    border: 0;
    background: none;
    cursor: pointer;
    color: var(--text-muted);
    padding: 0 3px;
    font-size: 13px;
    line-height: 1;
  }
  .x:hover {
    color: var(--bad-text);
  }
  .win-rules li {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    gap: 8px;
    align-items: center;
  }
  .win-rules li.inactive {
    opacity: 0.6;
  }
  .add {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 8px;
  }
  .add select {
    min-width: 0;
  }
  select,
  .hosts-input {
    font: inherit;
    font-size: 13px;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
    padding: 5px 8px;
  }
  .hosts-input {
    width: 100%;
    font-family: var(--mono);
    font-size: 12.5px;
  }
  .row {
    display: flex;
    gap: 8px;
  }
  .facts {
    display: grid;
    gap: 4px;
    margin: 0 0 8px;
  }
  .facts div {
    display: grid;
    grid-template-columns: 90px minmax(0, 1fr);
    gap: 8px;
  }
  .hash,
  .url {
    word-break: break-all;
    font-size: 11.5px;
  }
  .path {
    padding: 5px 8px;
    background: var(--surface-2);
    border-radius: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
  }
  .blocks {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }
  .blocks td {
    padding: 4px 6px 4px 0;
    border-bottom: 1px solid var(--border);
    font-size: 12.5px;
  }
  .blocks td:first-child {
    width: 46%;
  }
  .blocks tr:last-child td {
    border-bottom: 0;
  }
  .r {
    text-align: right;
  }
</style>
