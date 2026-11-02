<script lang="ts">
  // Alerts and notifications (SPEC §11), as a list and a detail pane: the
  // monitors in a list, and the chosen one's settings beside it (whether it
  // alerts, its desktop notifications, its level, and what only it has: the
  // new-app card, the threat lists). Then what applies to every monitor.
  import {
    api,
    errorText,
    type MonitorState,
    type PopupDesktop,
    type PopupLevel,
    type PopupPrefs,
    type Settings,
    type Severity,
    type ThreatStatus,
  } from "./api";

  interface Props {
    settings: Settings;
    busy: boolean;
    /** Saves a change to the service's settings (the page's own). */
    save: (change: (s: Settings) => Settings) => Promise<void>;
  }

  let { settings, busy, save }: Props = $props();

  let monitors = $state.raw<MonitorState[]>([]);
  let threats = $state.raw<ThreatStatus | null>(null);
  let prefs = $state.raw<PopupPrefs | null>(null);
  let selected = $state("first_network_activity");
  let error = $state<string | null>(null);

  // The monitors' state follows the settings, changed here or elsewhere.
  $effect(() => {
    void settings;
    api.monitors().then(
      (m) => {
        monitors = m.monitors;
        threats = m.threats;
      },
      (e) => (error = errorText(e)),
    );
  });

  $effect(() => {
    api.popupPrefs().then(
      (p) => (prefs = p),
      (e) => (error = errorText(e)),
    );
  });

  const current = $derived(monitors.find((m) => m.kind === selected) ?? monitors[0] ?? null);

  const SEVERITY: Record<Severity, string> = { info: "Info", warning: "Warning", critical: "Critical" };
  const LEVELS: { value: PopupLevel; label: string }[] = [
    { value: "off", label: "Off" },
    { value: "warnings", label: "Warnings and critical" },
    { value: "all", label: "All alerts" },
  ];

  /** Its alerts' level; null where it depends on what changed. */
  const severityOf = (m: MonitorState) => m.severity ?? m.default_severity;

  function desktopOf(m: MonitorState): PopupDesktop {
    const own = prefs?.desktop[m.kind];
    if (own) return own;
    return prefs?.level === "off" ? "off" : prefs?.level === "all" ? "all" : "important";
  }

  /** Its alerts pop up (some of them, for a monitor whose level varies). */
  function popsUp(m: MonitorState): boolean {
    const d = desktopOf(m);
    return d === "all" || (d === "important" && severityOf(m) !== "info");
  }

  async function change<T>(f: () => Promise<T>): Promise<T | undefined> {
    error = null;
    try {
      return await f();
    } catch (e) {
      error = errorText(e);
    }
  }

  async function setDesktop(m: MonitorState, d: PopupDesktop) {
    prefs = (await change(() => api.setPopupKind(m.kind, d))) ?? prefs;
  }

  async function setAll(level: PopupLevel) {
    prefs = (await change(() => api.setPopupLevel(level))) ?? prefs;
  }

  async function setNewAppCards(on: boolean) {
    prefs = (await change(() => api.setNewAppCards(on))) ?? prefs;
  }

  async function wakeAll() {
    for (const key of Object.keys(prefs?.snoozed ?? {})) prefs = (await change(() => api.snooze(key, false))) ?? prefs;
  }

  function setMonitor(m: MonitorState, next: { enabled?: boolean; severity?: Severity | null }) {
    const now = { enabled: m.enabled, severity: m.severity };
    return save((s) => ({ ...s, monitors: { ...s.monitors, [m.kind]: { ...now, ...next } } }));
  }

  const snoozed = $derived(prefs ? Object.keys(prefs.snoozed).length : 0);

  function dateTime(ms: number): string {
    return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }
</script>

{#snippet bell(on: boolean)}
  <svg class="bell" class:on viewBox="0 0 24 24" aria-hidden="true">
    <path d="M6 17V11a6 6 0 0 1 12 0v6l1.5 2h-15L6 17zM10 21h4" />
    {#if !on}<path d="M4 4l16 16" />{/if}
  </svg>
{/snippet}

{#if error}<p class="error-text note" role="alert">{error}</p>{/if}
{#if !prefs || !current}
  {#if !error}<p class="muted note">Loading…</p>{/if}
{:else}
  <div class="fit">
    <div class="panes">
      <ul class="monitors" aria-label="Monitors">
        {#each monitors as m (m.kind)}
          <li>
            <button
              class:selected={m.kind === current.kind}
              class:off={!m.enabled}
              aria-current={m.kind === current.kind}
              onclick={() => (selected = m.kind)}
            >
              <span class="name">{m.label}</span>
              <span title={m.enabled && popsUp(m) ? "Desktop notifications on" : "No desktop notifications"}>
                {@render bell(m.enabled && popsUp(m))}
              </span>
              <span class="state" class:on={m.enabled}>{m.enabled ? "On" : "Off"}</span>
            </button>
          </li>
        {/each}
      </ul>

      <div class="detail" aria-live="polite">
        <h3>{current.label}</h3>
        <p class="muted desc">{current.description}.</p>

        <label class="check">
          <input
            type="checkbox"
            checked={current.enabled}
            disabled={busy}
            onchange={(e) => setMonitor(current, { enabled: e.currentTarget.checked })}
          />
          <span>Alert me when this happens</span>
        </label>

        {#if severityOf(current) === null}
          <label class="field">
            <span>Desktop notifications</span>
            <select
              value={desktopOf(current)}
              disabled={!current.enabled}
              onchange={(e) => setDesktop(current, e.currentTarget.value as PopupDesktop)}
            >
              <option value="off">Off</option>
              <option value="important">Warnings and critical only</option>
              <option value="all">Every alert</option>
            </select>
          </label>
          <p class="muted hint">Its alerts' level depends on what happened (an update is info; a new signer, a warning).</p>
        {:else}
          <label class="check">
            <input
              type="checkbox"
              checked={popsUp(current)}
              disabled={!current.enabled}
              onchange={(e) => setDesktop(current, e.currentTarget.checked ? "all" : "off")}
            />
            <span>Show a desktop notification</span>
          </label>
        {/if}

        <label class="field">
          <span>Alert level</span>
          <select
            disabled={busy || !current.enabled}
            value={current.severity ?? ""}
            onchange={(e) => setMonitor(current, { severity: (e.currentTarget.value || null) as Severity | null })}
          >
            <option value="">
              {current.default_severity ? `${SEVERITY[current.default_severity]} (default)` : "Varies (default)"}
            </option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        {#if current.kind === "first_network_activity"}
          <label class="check">
            <input
              type="checkbox"
              checked={prefs.new_app_cards}
              onchange={(e) => setNewAppCards(e.currentTarget.checked)}
            />
            <span>
              In Click to Block, show a card with <strong>Block</strong> instead
              <span class="muted hint">
                Above the taskbar; it doesn't take the keyboard and waits while a game or video is full screen.
              </span>
            </span>
          </label>
        {:else if current.kind === "suspicious_host"}
          <label class="check">
            <input
              type="checkbox"
              checked={settings.threat_feeds}
              disabled={busy}
              onchange={(e) => save((s) => ({ ...s, threat_feeds: e.currentTarget.checked }))}
            />
            <span>Download abuse.ch Feodo Tracker's botnet list daily (not on metered connections)</span>
          </label>
          {#if threats}
            <p class="muted hint">
              {#if !settings.threat_feeds}
                Not downloading.
              {:else if threats.feodo_updated_ms != null}
                {threats.feodo.toLocaleString()} addresses, updated {dateTime(threats.feodo_updated_ms)}{threats.feodo_error
                  ? `; the last update failed: ${threats.feodo_error}`
                  : "."}
              {:else if threats.feodo_error}
                Not downloaded: {threats.feodo_error}
              {:else}
                Not downloaded yet.
              {/if}
            </p>
            <p class="muted hint">
              Your own list: {threats.local}
              {threats.local === 1 ? "entry" : "entries"} in <span class="path">{threats.local_path}</span> (one address or
              name per line).
            </p>
          {/if}
        {/if}
      </div>
    </div>
  </div>

  <div class="all">
    <div class="row">
      <span>Desktop notifications for every monitor:</span>
      {#each LEVELS as l (l.value)}
        <button class="btn small" title="Sets every monitor, replacing their own choices" onclick={() => setAll(l.value)}>
          {l.label}
        </button>
      {/each}
    </div>
    <p class="muted hint">
      None while Win4tress is the window in front. Snooze an app or a kind of alert for 24 hours from an alert's ⋯ menu.
      {#if snoozed}
        {snoozed} snoozed. <button class="link" onclick={wakeAll}>Wake all</button>
      {/if}
    </p>
    <label class="check">
      <input
        type="checkbox"
        checked={settings.event_log}
        disabled={busy}
        onchange={(e) => save((s) => ({ ...s, event_log: e.currentTarget.checked }))}
      />
      <span>Copy alerts to the Windows Event Log (Application, source “win4tress”)</span>
    </label>
  </div>
{/if}

<style>
  /* Side by side while the card is wide enough, by the card's width, not the
     window's: Settings puts it in one of up to three columns. */
  .fit {
    container-type: inline-size;
  }
  .panes {
    display: grid;
    grid-template-columns: minmax(220px, 300px) minmax(0, 1fr);
    gap: 20px;
  }
  @container (max-width: 520px) {
    .panes {
      grid-template-columns: minmax(0, 1fr);
      gap: 14px;
    }
    .monitors {
      max-height: 260px;
    }
  }
  .monitors {
    list-style: none;
    margin: 0;
    padding: 4px;
    max-height: 420px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .monitors button {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 8px;
    border: 0;
    border-radius: 6px;
    background: none;
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }
  .monitors button:hover {
    background: var(--surface-2);
  }
  .monitors button.selected {
    background: color-mix(in srgb, var(--accent) 14%, var(--surface));
  }
  .monitors button.off .name {
    color: var(--text-muted);
  }
  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .bell {
    display: block;
    width: 15px;
    height: 15px;
    fill: none;
    stroke: var(--text-muted);
    stroke-width: 1.7;
    stroke-linecap: round;
    stroke-linejoin: round;
    opacity: 0.55;
  }
  .bell.on {
    stroke: var(--accent-text);
    opacity: 1;
  }
  .state {
    flex: none;
    min-width: 30px;
    padding: 0 5px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    line-height: 16px;
    text-align: center;
    color: var(--text-muted);
    border: 1px solid var(--border);
  }
  .state.on {
    color: var(--on-status);
    background: var(--ok);
    border-color: transparent;
  }
  .detail {
    min-width: 0;
  }
  h3 {
    margin: 2px 0 2px;
    font: 600 15px/1.3 var(--font-display);
  }
  .desc {
    margin: 0 0 10px;
    font-size: 13px;
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin: 8px 0;
    font-size: 13px;
    cursor: pointer;
  }
  .check > input {
    flex: none;
    margin-top: 3px;
  }
  .field {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 10px 0;
    font-size: 13px;
  }
  select {
    font: inherit;
    font-size: 12.5px;
    color: var(--text);
    padding: 3px 6px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface);
  }
  .hint {
    display: block;
    margin: 2px 0 0;
    font-size: 12.5px;
  }
  .path {
    word-break: break-all;
  }
  .all {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
  }
  .row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    font-size: 13px;
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
  .note {
    margin: 6px 0 0;
    font-size: 12.5px;
  }
</style>
