<script lang="ts">
  // DNS filtering (SPEC §13): on or off, how it's going, the blocklists to
  // choose (each with its licence), your own rules, where lookups go, and
  // pausing. The service runs the resolver and puts Windows' DNS back if it
  // stops answering.
  import { api, errorText, type DnsFilterStatus, type DnsSettings, type Settings } from "./api";
  import { ago } from "./format";

  const PRESETS: { label: string; url: string | null }[] = [
    { label: "Your network's DNS servers", url: null },
    { label: "Cloudflare (DNS over HTTPS)", url: "https://cloudflare-dns.com/dns-query" },
    { label: "Quad9 (DNS over HTTPS, blocks malware)", url: "https://dns.quad9.net/dns-query" },
    { label: "Google (DNS over HTTPS)", url: "https://dns.google/dns-query" },
  ];
  const PAUSES: { label: string; minutes: number }[] = [
    { label: "5 minutes", minutes: 5 },
    { label: "1 hour", minutes: 60 },
  ];

  let status = $state.raw<DnsFilterStatus | null>(null);
  let settings = $state.raw<Settings | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let nowMs = $state(Date.now());
  // Rule editors: one name or pattern per line.
  let allowText = $state("");
  let denyText = $state("");
  let regexText = $state("");
  let localText = $state("");
  let customUrl = $state("");
  let rulesDirty = $state(false);

  async function load() {
    try {
      const [st, se] = await Promise.all([api.dnsFilter(), api.settings()]);
      status = st;
      if (!rulesDirty) fillEditors(se.dns);
      settings = se;
      error = null;
    } catch (e) {
      error = errorText(e);
    }
    nowMs = Date.now();
  }

  function fillEditors(d: DnsSettings) {
    allowText = d.allow.join("\n");
    denyText = d.deny.join("\n");
    regexText = d.regex.join("\n");
    localText = d.local_records.map((r) => `${r.name} ${r.addrs.join(" ")}`).join("\n");
  }

  $effect(() => {
    load();
    const timer = setInterval(load, 3_000);
    return () => clearInterval(timer);
  });

  async function save(change: (d: DnsSettings) => DnsSettings) {
    if (!settings) return;
    busy = true;
    error = null;
    try {
      settings = await api.setSettings({ ...settings, dns: change(settings.dns) });
      status = await api.dnsFilter();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const lines = (text: string) =>
    text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));

  // Enough to name the bad line; the service checks properly.
  const looksLikeIp = (a: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a) || /^[0-9a-f:.]*:[0-9a-f:.]*$/i.test(a);

  function saveRules() {
    const local_records = lines(localText).map((l) => {
      const [name, ...addrs] = l.split(/\s+/);
      return { name, addrs };
    });
    const bad = local_records.find((r) => !r.addrs.length || !r.addrs.every(looksLikeIp));
    if (bad) {
      error = `Local name ${bad.name}: give it one or more IP addresses after the name.`;
      return;
    }
    save((d) => ({ ...d, allow: lines(allowText), deny: lines(denyText), regex: lines(regexText), local_records })).then(
      () => (rulesDirty = false),
    );
  }

  function toggleList(id: string, on: boolean) {
    save((d) => ({ ...d, lists: on ? [...d.lists.filter((l) => l !== id), id] : d.lists.filter((l) => l !== id) }));
  }

  function addCustom() {
    const url = customUrl.trim();
    if (!url) return;
    if (settings?.dns.custom_lists.some((c) => c.url === url)) {
      error = "That list is already one of yours.";
      return;
    }
    const name = url.replace(/^https:\/\//, "").split("/")[0];
    save((d) => ({ ...d, custom_lists: [...d.custom_lists, { name, url, regex: false }] })).then(() => (customUrl = ""));
  }

  function removeCustom(index: number) {
    save((d) => ({ ...d, custom_lists: d.custom_lists.filter((_, i) => i !== index) }));
  }

  async function act(f: () => Promise<DnsFilterStatus>) {
    busy = true;
    error = null;
    try {
      status = await f();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const d = $derived(settings?.dns ?? null);
  const preset = $derived(
    d?.upstream.kind === "doh" ? (PRESETS.find((p) => p.url === (d.upstream as { url: string }).url) ?? null) : PRESETS[0],
  );
  const STATE_TEXT: Record<string, string> = {
    off: "Off",
    starting: "Starting",
    on: "On",
    passing: "On, not blocking",
    failed: "Stopped",
  };
  const share = $derived(status && status.queries ? Math.round((status.blocked * 100) / status.queries) : 0);

  function when(ms: number | null): string {
    return ms ? ago(nowMs - ms) : "never";
  }
</script>

<div class="filter">
  {#if error}<p class="error-text msg" role="alert">{error}</p>{/if}
  {#if !status || !d}
    {#if !error}<p class="muted msg">Loading…</p>{/if}
  {:else}
    <section class="card head">
      <label class="switch">
        <input
          type="checkbox"
          checked={d.enabled}
          disabled={busy}
          onchange={(e) => save((x) => ({ ...x, enabled: e.currentTarget.checked }))}
        />
        <span class="title">DNS filtering</span>
      </label>
      <span class="state {status.state ?? 'off'}">{STATE_TEXT[status.state ?? "off"]}</span>
      {#if status.message}<span class="muted">{status.message}</span>{/if}
      <div class="spacer"></div>
      {#if d.enabled}
        {#if status.paused_until_ms}
          <span class="muted">Paused until {new Date(status.paused_until_ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</span>
          <button class="btn small" disabled={busy} onclick={() => act(() => api.dnsPause(null))}>Resume</button>
        {:else}
          <span class="muted">Pause</span>
          {#each PAUSES as p (p.minutes)}
            <button class="btn small" disabled={busy} onclick={() => act(() => api.dnsPause(p.minutes))}>{p.label}</button>
          {/each}
        {/if}
      {/if}
    </section>

    {#if !d.enabled}
      <section class="card about">
        <p>
          With DNS filtering on, Windows asks win4tress's own resolver on this PC for every name. It answers
          names on the blocklists you choose with nothing (0.0.0.0), and asks your network's DNS servers, or
          a DNS-over-HTTPS service you choose, for the rest. Lists are downloaded from their makers, never
          bundled. If the resolver stops answering, Windows' own DNS is back within 2 seconds.
        </p>
      </section>
    {:else}
      <div class="tiles">
        <div class="tile card"><div class="label">Lookups</div><div class="value num">{status.queries.toLocaleString()}</div></div>
        <div class="tile card"><div class="label">Blocked</div><div class="value num">{status.blocked.toLocaleString()} <span class="muted small">{share}%</span></div></div>
        <div class="tile card"><div class="label">From the cache</div><div class="value num">{status.cached.toLocaleString()}</div></div>
        <div class="tile card"><div class="label">Domains on your lists</div><div class="value num">{status.blocked_domains.toLocaleString()}</div></div>
      </div>
    {/if}

    <div class="grid">
      <section class="card">
        <h3>Blocklists</h3>
        <ul class="lists">
          {#each status.lists.filter((l) => !l.custom) as l (l.id)}
            <li>
              <label class="check">
                <input type="checkbox" checked={l.enabled} disabled={busy} onchange={(e) => toggleList(l.id, e.currentTarget.checked)} />
                <span>
                  <span class="label">{l.name}</span>
                  <span class="muted desc">{l.description}</span>
                  <span class="muted meta">
                    <button class="link" onclick={() => api.openLink(l.licence_url)}>{l.licence}</button> ·
                    <button class="link" onclick={() => api.openLink(l.homepage)}>homepage</button>
                    {#if l.entries != null} · {l.entries.toLocaleString()} entries{/if}
                    {#if l.enabled} · downloaded {when(l.updated_ms)}{/if}
                    {#if l.error}<span class="error-text"> · {l.error}</span>{/if}
                  </span>
                </span>
              </label>
            </li>
          {/each}
          {#each d.custom_lists as c, i (c.url)}
            {@const st = status.lists.find((l) => l.custom && l.url === c.url)}
            <li>
              <span class="custom">
                <span class="label">{c.name}</span>
                <span class="muted desc">{c.url}</span>
                <span class="muted meta">
                  {#if st?.entries != null}{st.entries.toLocaleString()} entries · {/if}downloaded {when(st?.updated_ms ?? null)}
                  {#if st?.error}<span class="error-text"> · {st.error}</span>{/if}
                </span>
              </span>
              <button class="btn small" disabled={busy} onclick={() => removeCustom(i)}>Remove</button>
            </li>
          {/each}
        </ul>
        <div class="row">
          <input class="text" placeholder="https://… a list of your own (hosts, domains or Adblock)" bind:value={customUrl} aria-label="Your own list's address" />
          <button class="btn small" disabled={busy || !customUrl.trim().startsWith("https://")} onclick={addCustom}>Add</button>
        </div>
        <div class="row">
          <button class="btn small" disabled={busy || !d.enabled} onclick={() => act(() => api.dnsUpdate())}>Update now</button>
          <span class="muted small">Checked daily, not on metered connections; unchanged lists aren't downloaded again.</span>
        </div>
      </section>

      <section class="card">
        <h3>Your rules</h3>
        <div class="rules">
          <label>
            <span class="label">Always allow</span>
            <textarea rows="4" placeholder="example.com" bind:value={allowText} oninput={() => (rulesDirty = true)}></textarea>
          </label>
          <label>
            <span class="label">Always block</span>
            <textarea rows="4" placeholder="ads.example.com" bind:value={denyText} oninput={() => (rulesDirty = true)}></textarea>
          </label>
          <label>
            <span class="label">Block by pattern (regex)</span>
            <textarea rows="3" placeholder="^ad[0-9]+\." bind:value={regexText} oninput={() => (rulesDirty = true)}></textarea>
          </label>
          <label>
            <span class="label">Local names (name address…)</span>
            <textarea rows="3" placeholder="nas.home 192.168.1.20" bind:value={localText} oninput={() => (rulesDirty = true)}></textarea>
          </label>
        </div>
        <p class="muted small">One per line; a domain covers its subdomains. Allow wins over everything else.</p>
        <div class="row">
          <button class="btn small primary" disabled={busy || !rulesDirty} onclick={saveRules}>Save rules</button>
          {#if rulesDirty}<button class="btn small" disabled={busy} onclick={() => { rulesDirty = false; if (d) fillEditors(d); }}>Undo</button>{/if}
        </div>

        <h3>Lookups go to</h3>
        <select
          aria-label="Where lookups go"
          disabled={busy}
          value={preset?.label ?? "custom"}
          onchange={(e) => {
            const p = PRESETS.find((x) => x.label === e.currentTarget.value);
            if (p) save((x) => ({ ...x, upstream: p.url ? { kind: "doh", url: p.url } : { kind: "system" } }));
          }}
        >
          {#each PRESETS as p (p.label)}<option value={p.label}>{p.label}</option>{/each}
          {#if !preset}<option value="custom">{d.upstream.kind === "doh" ? d.upstream.url : "Custom"}</option>{/if}
        </select>
        <p class="muted small">
          {#if d.upstream.kind === "doh"}
            Names on your network (and the service's own name) still go to your network's DNS servers.
          {:else if status.system_servers.length}
            Now: {status.system_servers.join(", ")}.
          {/if}
        </p>
        <label class="check">
          <input type="checkbox" checked={d.nxdomain} disabled={busy} onchange={(e) => save((x) => ({ ...x, nxdomain: e.currentTarget.checked }))} />
          <span>Answer blocked names with "no such name" instead of 0.0.0.0</span>
        </label>
        <label class="check">
          <input
            type="checkbox"
            checked={d.observe === "on"}
            disabled={busy}
            onchange={(e) => save((x) => ({ ...x, observe: e.currentTarget.checked ? "on" : "auto" }))}
          />
          <span>Only observe: note what would be blocked, block nothing{status.upstream_blocks ? " (your network's DNS already blocks, so win4tress only observes)" : ""}</span>
        </label>
      </section>
    </div>

    {#if d.enabled && status.top_blocked.length}
      <section class="card">
        <h3>Most blocked</h3>
        <ol class="top">
          {#each status.top_blocked.slice(0, 12) as [name, n] (name)}
            <li><span class="ellipsis" title={name}>{name}</span><span class="num muted">{n.toLocaleString()}</span></li>
          {/each}
        </ol>
      </section>
    {/if}
    {#if status.problems.length || status.restores}
      <section class="card">
        <h3>Problems</h3>
        {#each status.problems as p, i (i)}<p class="small">{p}</p>{/each}
        {#if status.restores}<p class="small">The watchdog put Windows' own DNS back {status.restores} {status.restores === 1 ? "time" : "times"} since the service started.</p>{/if}
      </section>
    {/if}
  {/if}
</div>

<style>
  .filter {
    display: grid;
    gap: 14px;
  }
  .msg {
    margin: 0;
  }
  .card {
    padding: 14px 16px;
  }
  .head {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }
  .switch {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }
  .title {
    font: 600 15px/1.3 var(--font-display);
  }
  .state {
    font-size: 12px;
    font-weight: 600;
    padding: 1px 8px;
    border-radius: 10px;
    border: 1px solid var(--border);
  }
  .state.on {
    background: color-mix(in srgb, var(--accent) 20%, var(--surface));
  }
  .state.failed {
    background: var(--bad);
    color: var(--on-status);
    border-color: transparent;
  }
  .spacer {
    flex: 1;
  }
  .about p {
    margin: 0;
    max-width: 760px;
    font-size: 13.5px;
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
  }
  .tile .label {
    font-size: 12px;
    color: var(--text-muted);
  }
  .tile .value {
    font: 600 22px/1.3 var(--font-display);
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
    gap: 14px;
    align-items: start;
  }
  @media (max-width: 1000px) {
    .grid,
    .tiles {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  h3 {
    margin: 0 0 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  h3:not(:first-child) {
    margin-top: 16px;
  }
  .lists {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .lists li {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
  }
  .lists li:last-child {
    border-bottom: 0;
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 13px;
    cursor: pointer;
    margin: 4px 0;
  }
  .check input {
    margin-top: 3px;
    flex: none;
  }
  .custom {
    flex: 1;
    min-width: 0;
  }
  .label {
    display: block;
    font-weight: 600;
    font-size: 13px;
  }
  .desc,
  .meta {
    display: block;
    font-size: 12.5px;
    overflow-wrap: anywhere;
  }
  .link {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent-text);
    font: inherit;
    cursor: pointer;
    text-decoration: underline;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 10px;
  }
  .text {
    flex: 1;
    min-width: 0;
    font: inherit;
    font-size: 13px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface-2);
    color: var(--text);
  }
  .rules {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  textarea {
    width: 100%;
    font: 12.5px/1.4 var(--mono);
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface-2);
    color: var(--text);
    resize: vertical;
  }
  select {
    font: inherit;
    font-size: 13px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
    color: var(--text);
    max-width: 100%;
  }
  .small {
    font-size: 12.5px;
  }
  p.small {
    margin: 6px 0 0;
  }
  .top {
    margin: 0;
    padding: 0;
    list-style: none;
    columns: 2;
    column-gap: 24px;
  }
  .top li {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-size: 13px;
    padding: 2px 0;
    break-inside: avoid;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
