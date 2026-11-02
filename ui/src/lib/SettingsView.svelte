<script lang="ts">
  // Settings (SPEC §10.2): alerts and notifications, starting at sign-in,
  // incognito, reputation lookups and their keys, automatic cleanup of rules,
  // exporting and importing rules, the mini viewer, and About. Changes go to the
  // service at once; with "Require elevation" on they ask through UAC.
  import {
    api,
    errorText,
    type CleanupResult,
    type ImportResult,
    type KnownApp,
    type MiniPrefs,
    type ReputationStatus,
    type RulesExport,
    type Settings,
  } from "./api";
  import About from "./About.svelte";
  import AlertSettings from "./AlertSettings.svelte";
  import AppIcon from "./AppIcon.svelte";

  let settings = $state.raw<Settings | null>(null);
  let status = $state.raw<ReputationStatus | null>(null);
  let cleanup = $state.raw<CleanupResult | null>(null);
  let apps = $state.raw<KnownApp[]>([]);
  let mini = $state.raw<MiniPrefs | null>(null);
  let startAtSignIn = $state<boolean | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let vtKey = $state("");
  let abuseKey = $state("");

  async function load() {
    try {
      const [s, r, c, a] = await Promise.all([
        api.settings(),
        api.reputationStatus(),
        api.cleanup(),
        api.knownApps(),
      ]);
      settings = s;
      status = r;
      cleanup = c;
      apps = a.apps;
      error = null;
    } catch (e) {
      error = errorText(e);
    }
    api.miniPrefs().then(
      (p) => (mini = p),
      () => {},
    );
    api.autostart().then(
      (on) => (startAtSignIn = on),
      () => {},
    );
  }

  $effect(() => {
    load();
    const timer = setInterval(() => {
      api.reputationStatus().then(
        (r) => (status = r),
        () => {},
      );
    }, 10_000);
    return () => clearInterval(timer);
  });

  async function save(change: (s: Settings) => Settings) {
    if (!settings) return;
    busy = true;
    error = null;
    try {
      settings = await api.setSettings(change(settings));
      [status, cleanup] = await Promise.all([api.reputationStatus(), api.cleanup()]);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function setKey(service: "virus_total" | "abuse_ch", key: string | null) {
    busy = true;
    error = null;
    try {
      status = await api.setKey(service, key);
      if (service === "virus_total") vtKey = "";
      else abuseKey = "";
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function runCleanup() {
    busy = true;
    error = null;
    try {
      cleanup = await api.runCleanup();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function setStartAtSignIn(on: boolean) {
    error = null;
    try {
      startAtSignIn = await api.setAutostart(on);
    } catch (e) {
      error = errorText(e);
      startAtSignIn = await api.autostart().catch(() => null);
    }
  }

  async function setOpacity(percent: number) {
    try {
      mini = await api.miniSetOpacity(percent);
    } catch (e) {
      error = errorText(e);
    }
  }

  // Rules, profiles and DNS filtering to and from a file (SPEC §7.2).
  let saved = $state<string | null>(null);
  let incoming = $state.raw<{ file: RulesExport; preview: ImportResult } | null>(null);
  let imported = $state.raw<ImportResult | null>(null);

  async function exportRules() {
    busy = true;
    error = null;
    saved = null;
    try {
      const file = await api.exportRules();
      const day = new Date().toISOString().slice(0, 10);
      const path = await api.saveFile(`win4tress-rules-${day}.json`, JSON.stringify(file, null, 2) + "\n");
      if (path)
        saved = `Saved ${count(file.rules.length, "rule", "rules")}, ${count(file.profiles.length, "profile", "profiles")} and DNS filtering's settings to ${path}.`;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function pickImport() {
    busy = true;
    error = null;
    imported = null;
    incoming = null;
    try {
      const text = await api.openFile();
      if (text == null) return;
      let file: RulesExport;
      try {
        file = JSON.parse(text);
      } catch {
        throw new Error("That file isn't a win4tress rules file.");
      }
      incoming = { file, preview: await api.importRules(file, true) };
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function confirmImport() {
    if (!incoming) return;
    busy = true;
    error = null;
    try {
      imported = await api.importRules(incoming.file, false);
      incoming = null;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function count(n: number, one: string, many: string): string {
    return `${n} ${n === 1 ? one : many}`;
  }

  const byId = $derived(new Map(apps.map((a) => [a.id, a])));
  const due = $derived(cleanup?.items.filter((i) => i.due).length ?? 0);

  function date(ms: number): string {
    return new Date(ms).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
  }

  function clampNumber(value: string, min: number, max: number, fallback: number): number {
    const n = Math.round(Number(value));
    return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
  }
</script>

<div class="view">
  {#if error}<p class="error-text msg" role="alert">{error}</p>{/if}
  {#if !settings}
    {#if !error}<p class="muted msg">Loading…</p>{/if}
  {:else}
    {@const s = settings}
    <section class="card" id="alert-settings" aria-labelledby="alerts">
      <h2 id="alerts">Alerts and notifications</h2>
      <AlertSettings settings={s} {busy} {save} />
    </section>

    <section class="card" aria-labelledby="general">
      <h2 id="general">General</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={startAtSignIn ?? false}
          disabled={startAtSignIn === null}
          onchange={(e) => setStartAtSignIn(e.currentTarget.checked)}
        />
        <span>
          <span class="label">Start Win4tress when I sign in</span>
          <span class="muted desc">
            In the tray, without its window. The protection itself starts with Windows either way.
          </span>
        </span>
      </label>
    </section>

    <section class="card" aria-labelledby="privacy">
      <h2 id="privacy">Privacy</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={s.incognito}
          disabled={busy}
          onchange={(e) => save((x) => ({ ...x, incognito: e.currentTarget.checked }))}
        />
        <span>
          <span class="label">Incognito</span>
          <span class="muted desc">
            Write no traffic or DNS lookups to history. The live view still shows the last 10 minutes; blocking
            and alerts carry on. Usage and the data plan don't count what isn't written.
          </span>
        </span>
      </label>
      <h3>Incognito apps</h3>
      {#if s.incognito_apps.length === 0}
        <p class="muted note">None. Make an app incognito from its details on the Firewall screen.</p>
      {:else}
        <ul class="list">
          {#each s.incognito_apps as id (id)}
            {@const a = byId.get(id)}
            <li>
              {#if a}<AppIcon name={a.name} path={a.path} size={18} />{/if}
              <span class="grow ellipsis" title={a?.path}>{a?.name ?? `App ${id}`}</span>
              <button
                class="btn small"
                disabled={busy}
                onclick={() => save((x) => ({ ...x, incognito_apps: x.incognito_apps.filter((i) => i !== id) }))}
                >Remove</button
              >
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="card" aria-labelledby="mini">
      <h2 id="mini">Mini viewer</h2>
      <p class="muted note">A small live graph that stays on top. Drag it anywhere; it opens where you left it.</p>
      <div class="row">
        <button class="btn small" onclick={() => api.miniToggle()}>Open or close the mini viewer</button>
      </div>
      {#if mini}
        <label class="inline">
          Background
          <input
            type="range"
            min="20"
            max="100"
            step="5"
            value={mini.opacity}
            oninput={(e) => setOpacity(Number(e.currentTarget.value))}
            aria-label="Mini viewer background opacity"
          />
          <span class="num">{mini.opacity}%</span>
        </label>
      {/if}
    </section>

    <section class="card" aria-labelledby="reputation">
      <h2 id="reputation">Reputation</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={s.reputation.enabled}
          disabled={busy}
          onchange={(e) => save((x) => ({ ...x, reputation: { ...x.reputation, enabled: e.currentTarget.checked } }))}
        />
        <span>
          <span class="label">Look up apps' files</span>
          <span class="muted desc">
            Sends each app's SHA-256 hash (not the file) to CIRCL hashlookup, which knows many good files, and to
            VirusTotal with your key. Apps using the network go first.
          </span>
        </span>
      </label>

      <h3>VirusTotal</h3>
      <div class="key">
        {#if status?.virustotal_key}
          <span class="chip">Key saved</span>
          <button class="btn small" disabled={busy} onclick={() => setKey("virus_total", null)}>Remove</button>
        {:else}
          <input
            type="password"
            placeholder="Your API key (64 characters)"
            autocomplete="off"
            bind:value={vtKey}
            aria-label="VirusTotal API key"
          />
          <button class="btn small primary" disabled={busy || !vtKey.trim()} onclick={() => setKey("virus_total", vtKey)}
            >Save</button
          >
          <button class="link" onclick={() => api.openLink("https://www.virustotal.com/gui/join-us")}>Get a free key</button>
        {/if}
      </div>
      <p class="muted note">
        The free key allows 4 lookups a minute and 500 a day. It's stored encrypted and never shown again.
      </p>

      <h3>MalwareBazaar</h3>
      <label class="check">
        <input
          type="checkbox"
          checked={s.reputation.malwarebazaar}
          disabled={busy}
          onchange={(e) =>
            save((x) => ({ ...x, reputation: { ...x.reputation, malwarebazaar: e.currentTarget.checked } }))}
        />
        <span>Also ask abuse.ch MalwareBazaar, which knows malware samples (needs an abuse.ch key)</span>
      </label>
      <div class="key">
        {#if status?.abuse_ch_key}
          <span class="chip">Key saved</span>
          <button class="btn small" disabled={busy} onclick={() => setKey("abuse_ch", null)}>Remove</button>
        {:else}
          <input
            type="password"
            placeholder="Your abuse.ch Auth-Key"
            autocomplete="off"
            bind:value={abuseKey}
            aria-label="abuse.ch Auth-Key"
          />
          <button class="btn small primary" disabled={busy || !abuseKey.trim()} onclick={() => setKey("abuse_ch", abuseKey)}
            >Save</button
          >
          <button class="link" onclick={() => api.openLink("https://auth.abuse.ch/")}>Get a free key</button>
        {/if}
      </div>

      <h3>When files are flagged</h3>
      <label class="inline">
        Alert when
        <input
          class="num-input"
          type="number"
          min="1"
          max="100"
          value={s.reputation.alert_at}
          disabled={busy}
          onchange={(e) =>
            save((x) => ({
              ...x,
              reputation: { ...x.reputation, alert_at: clampNumber(e.currentTarget.value, 1, 100, 3) },
            }))}
        />
        engines flag a file
      </label>
      <label class="check">
        <input
          type="checkbox"
          checked={s.reputation.auto_block}
          disabled={busy}
          onchange={(e) => save((x) => ({ ...x, reputation: { ...x.reputation, auto_block: e.currentTarget.checked } }))}
        />
        <span class="inline">
          Block the app both ways when
          <input
            class="num-input"
            type="number"
            min="1"
            max="100"
            value={s.reputation.block_at}
            disabled={busy || !s.reputation.auto_block}
            onchange={(e) =>
              save((x) => ({
                ...x,
                reputation: { ...x.reputation, block_at: clampNumber(e.currentTarget.value, 1, 100, 5) },
              }))}
          />
          engines flag it, or MalwareBazaar or your antivirus finds it
        </span>
      </label>
      {#if status}
        <p class="muted note">
          {status.checked.toLocaleString()}
          {status.checked === 1 ? "file" : "files"} answered{status.enabled ? `, ${status.queued} waiting` : ""} ·
          VirusTotal today: {status.virustotal_today} of 500{status.last_error ? ` · Last problem: ${status.last_error}` : ""}
        </p>
      {/if}
    </section>

    <section class="card" aria-labelledby="cleanup">
      <h2 id="cleanup">Automatic cleanup</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={s.cleanup.uninstalled}
          disabled={busy}
          onchange={(e) => save((x) => ({ ...x, cleanup: { ...x.cleanup, uninstalled: e.currentTarget.checked } }))}
        />
        <span>Remove the rules of apps whose program has been gone for 7 days</span>
      </label>
      <label class="check">
        <input
          type="checkbox"
          checked={s.cleanup.inactive_days != null}
          disabled={busy}
          onchange={(e) =>
            save((x) => ({ ...x, cleanup: { ...x.cleanup, inactive_days: e.currentTarget.checked ? 30 : null } }))}
        />
        <span class="inline">
          Remove the rules of apps that haven't used the network, or tried to, for
          <input
            class="num-input"
            type="number"
            min="1"
            max="3650"
            value={s.cleanup.inactive_days ?? 30}
            disabled={busy || s.cleanup.inactive_days == null}
            onchange={(e) =>
              save((x) => ({
                ...x,
                cleanup: { ...x.cleanup, inactive_days: clampNumber(e.currentTarget.value, 1, 3650, 30) },
              }))}
          />
          days
        </span>
      </label>
      <p class="muted note">
        An app whose rules were removed is new again if it comes back. Every removal is in the rules' history.
      </p>
      {#if cleanup && cleanup.items.length}
        <ul class="list">
          {#each cleanup.items as i (i.app.id)}
            <li>
              <AppIcon name={i.app.name} path={i.app.path} size={18} />
              <span class="grow ellipsis" title={i.app.path}>{i.app.name}</span>
              <span class="muted small">
                {i.reason === "uninstalled" ? `gone since ${date(i.since_ms)}` : `last active ${date(i.since_ms)}`} ·
                {i.rules}
                {i.rules === 1 ? "rule" : "rules"}
              </span>
              <span class="chip" class:warn={i.due}>{i.due ? "Due" : "Not yet"}</span>
            </li>
          {/each}
        </ul>
      {/if}
      <div class="row">
        <button class="btn small" disabled={busy || due === 0} onclick={runCleanup}>Clean up now</button>
        <span class="muted small">
          {#if cleanup?.removed}{cleanup.removed} {cleanup.removed === 1 ? "rule" : "rules"} removed.{/if}
          {cleanup?.items.length ? "" : "Nothing to clean up."}
          {cleanup?.last_run_ms ? `Last checked ${new Date(cleanup.last_run_ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.` : ""}
        </span>
      </div>
    </section>

    <section class="card" aria-labelledby="transfer">
      <h2 id="transfer">Rules and profiles</h2>
      <p class="muted note">
        Save every win4tress rule and profile, and DNS filtering's settings, to a file, to set up another PC the
        same way or keep a copy. A temporary rule is saved as what it goes back to.
      </p>
      <div class="row">
        <button class="btn small" disabled={busy} onclick={exportRules}>Export…</button>
        <button class="btn small" disabled={busy} onclick={pickImport}>Import…</button>
      </div>
      {#if saved}<p class="muted small" role="status">{saved}</p>{/if}
      {#if incoming}
        {@const f = incoming.file}
        {@const p = incoming.preview}
        <div class="preview">
          <p>
            <strong
              >{count(f.rules.length, "rule", "rules")}{f.dns ? ", " : " and "}{count(
                f.profiles.length,
                "profile",
                "profiles",
              )}{f.dns ? " and DNS filtering's settings" : ""}</strong
            >
            from {f.computer || "another PC"}, saved {date(f.exported_ms)}.
          </p>
          <p class="small">
            Adds {count(p.added, "rule", "rules")} and replaces {p.replaced} for the same app and kind; {p.unchanged}
            already {p.unchanged === 1 ? "is" : "are"} as in the file.
            {#if p.profiles.length}Profiles: {p.profiles.join(", ")}.{/if}
            {#if p.dns}
              Replaces this PC's DNS filtering settings with the file's (filtering {f.dns?.enabled ? "on" : "off"}).
            {/if}
            The mode stays as it is.
          </p>
          {#if p.missing_apps.length}
            <p class="muted small">Not on this PC (their rules apply once installed): {p.missing_apps.join(", ")}.</p>
          {/if}
          {#each p.failed as fail (fail)}<p class="error-text small">Not imported: {fail}</p>{/each}
          <div class="row">
            <button class="btn small primary" disabled={busy} onclick={confirmImport}>Import</button>
            <button class="btn small" disabled={busy} onclick={() => (incoming = null)}>Cancel</button>
          </div>
        </div>
      {/if}
      {#if imported}
        <p class="small" role="status">
          Imported: {count(imported.added, "rule", "rules")} added, {imported.replaced} replaced{imported.profiles.length
            ? `; profiles ${imported.profiles.join(", ")}`
            : ""}{imported.dns ? "; DNS filtering's settings" : ""}. Applied right away.
        </p>
        {#each imported.failed as fail (fail)}<p class="error-text small">Not imported: {fail}</p>{/each}
      {/if}
    </section>

    <section class="card" aria-labelledby="about">
      <h2 id="about">About</h2>
      <About />
    </section>
  {/if}
</div>

<style>
  /* Up to three columns at least 420 px wide, each card whole: a short card
     sits under the one above it rather than below the tallest in its row. */
  .view {
    columns: 3 420px;
    column-gap: 14px;
  }
  .card {
    padding: 14px 16px 16px;
    min-width: 0;
    break-inside: avoid;
    margin-bottom: 14px;
  }
  h2 {
    margin: 0 0 10px;
    font: 600 15px/1.3 var(--font-display);
  }
  h3 {
    margin: 14px 0 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .msg {
    column-span: all;
    margin: 0 0 14px;
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 13px;
    margin: 6px 0;
    cursor: pointer;
  }
  .check > input {
    margin-top: 3px;
    flex: none;
  }
  .label {
    display: block;
    font-weight: 600;
  }
  .desc {
    display: block;
    font-size: 12.5px;
  }
  .inline {
    display: inline-flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    font-size: 13px;
  }
  .num-input {
    width: 64px;
    font: inherit;
    font-size: 13px;
    padding: 2px 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--text);
  }
  .key {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .key input {
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
  .link {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent-text);
    font: inherit;
    font-size: 12.5px;
    cursor: pointer;
    text-decoration: underline;
    white-space: nowrap;
  }
  .note {
    margin: 6px 0 0;
    font-size: 12.5px;
  }
  .list {
    list-style: none;
    margin: 8px 0 0;
    padding: 0;
  }
  .list li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .list li:last-child {
    border-bottom: 0;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .small {
    font-size: 12.5px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
  }
  .num {
    font-variant-numeric: tabular-nums;
  }
  .preview {
    margin-top: 10px;
    padding: 8px 12px 10px;
    border-radius: 8px;
    background: var(--surface-2);
    font-size: 13px;
  }
  .preview p {
    margin: 4px 0;
  }
</style>
