<script lang="ts">
  // The firewall's state in the header, and its switches: the mode, profiles
  // (and the networks they're switched to on), Block All, turning Windows
  // Firewall on, and "Require elevation" (SPEC §7.1, §7.5, §7.6, §7.7, §4.3).
  import {
    api,
    errorCode,
    errorText,
    REMOTE_SESSION,
    type KnownApp,
    type Mode,
    type NetworkCategory,
    type NetworkInfo,
    type NetworkMatch,
    type Profile,
    type ProfilesResult,
    type RuleChange,
  } from "./api";
  import { firewall } from "./firewall.svelte";
  import { ago, duration } from "./format";
  import { trustChips } from "./trust";

  interface Props {
    nowMs: number;
  }

  let { nowMs }: Props = $props();

  const BLOCK_ALL_FOR: { minutes: number | null; label: string }[] = [
    { minutes: 15, label: "15 minutes" },
    { minutes: 60, label: "1 hour" },
    { minutes: null, label: "Until I turn it off" },
  ];

  let open = $state(false);
  let busy = $state<string | null>(null);
  let error = $state<string | null>(null);
  /** Block All was refused over Remote Desktop: asking first. */
  let remoteConfirm = $state<{ minutes: number | null } | null>(null);

  // Turning Ask to Connect on: the apps used lately that have no rule, offered
  // for allowing first so they keep working (SPEC §7.4 "Learning mode").
  const RECENT_DAYS = 7;
  let learning = $state<{ apps: KnownApp[]; checked: Set<number> } | null>(null);

  async function startAsk() {
    busy = "mode";
    error = null;
    try {
      const since = Date.now() - RECENT_DAYS * 24 * 3600 * 1000;
      const known = (await api.knownApps()).apps;
      const apps = known
        .filter((a) => a.net_first_seen_ms != null && a.last_seen_ms >= since)
        .filter((a) => a.path === "System" || a.path.includes("\\"))
        .filter((a) => !firewall.byApp.get(a.id)?.protected)
        .filter((a) => !firewall.rule(a.id, "out", "allow", "any") && !firewall.rule(a.id, "out", "block", "any"))
        .sort((a, b) => a.name.localeCompare(b.name));
      // Flagged apps (unsigned, downloaded, …) are left for a prompt.
      learning = { apps, checked: new Set(apps.filter((a) => trustChips(a).length === 0).map((a) => a.id)) };
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = null;
    }
  }

  function toggleLearn(id: number) {
    if (!learning) return;
    const checked = new Set(learning.checked);
    if (checked.has(id)) checked.delete(id);
    else checked.add(id);
    learning = { ...learning, checked };
  }

  function turnOnAsk(allow: boolean) {
    const changes: RuleChange[] = allow
      ? [...(learning?.checked ?? [])].map((app) => ({ op: "set", app, direction: "out", action: "allow" }))
      : [];
    learning = null;
    run("mode", async () => {
      if (changes.length) {
        const r = await api.applyRules(changes);
        if (r.failed.length) throw new Error(`${r.failed.length} couldn't be allowed: ${r.failed.join("; ")}`);
      }
      await api.setMode("ask_to_connect");
    });
  }

  const waiting = $derived(firewall.prompts.length);

  const status = $derived(firewall.status);
  const blockAll = $derived(status?.block_all ?? null);
  const profilesOff = $derived(status?.state?.profiles.filter((p) => !p.firewall_on) ?? []);
  const activeOff = $derived(profilesOff.filter((p) => p.active));

  const pill = $derived.by((): { text: string; tone: "ok" | "warn" | "bad" | "idle" } => {
    if (!status) return { text: "Firewall unavailable", tone: "idle" };
    if (blockAll)
      return {
        text: blockAll.until_ms ? `Block All · ${duration(blockAll.until_ms - nowMs)} left` : "Block All",
        tone: "bad",
      };
    if (status.monitoring_only) return { text: "Monitoring only", tone: "warn" };
    if (activeOff.length) return { text: "Windows Firewall off", tone: "bad" };
    if (status.mode === "off") return { text: "Firewall Off", tone: "idle" };
    const name = status.mode === "ask_to_connect" ? "Ask to Connect" : "Click to Block";
    if (status.last_error || !status.in_sync) return { text: `${name} · not in sync`, tone: "warn" };
    if (waiting) return { text: `${name} · ${waiting} waiting`, tone: "warn" };
    return { text: name, tone: "ok" };
  });

  function profileName(name: string): string {
    return name.charAt(0).toUpperCase() + name.slice(1);
  }

  function until(ms: number): string {
    return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }

  async function run(what: string, action: () => Promise<unknown>) {
    busy = what;
    error = null;
    try {
      await action();
      await firewall.refresh();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = null;
    }
  }

  function setMode(mode: Mode) {
    learning = null;
    if (mode === status?.mode) return;
    if (mode === "ask_to_connect") startAsk();
    else run("mode", () => api.setMode(mode));
  }

  // Profiles: named snapshots of the mode, the rules on and DNS filtering;
  // switching to one turns every other rule off.
  let profiles = $state.raw<ProfilesResult | null>(null);
  let newName = $state("");
  let deleting = $state<string | null>(null);
  const MODE_NAME: Record<Mode, string> = {
    off: "Off",
    click_to_block: "Click to Block",
    ask_to_connect: "Ask to Connect",
  };

  // What a profile is compared with: re-read on opening and whenever the mode or
  // a rule's on/off changes, here, elsewhere in the app or from the CLI, so
  // "changed" and Save changes keep up. DNS filtering changes in its own view,
  // with the menu closed.
  const compared = $derived(
    `${status?.mode}|${firewall.rules.map((r) => `${r.id}:${r.enabled}:${r.action}:${JSON.stringify(r.scope)}`).join(",")}`,
  );

  $effect(() => {
    if (!open) return;
    compared;
    let current = true;
    api.profiles().then(
      (p) => current && (profiles = p),
      () => current && (profiles = null),
    );
    return () => (current = false);
  });

  function isActive(name: string): boolean {
    return profiles?.active?.toLowerCase() === name.toLowerCase();
  }

  function saveProfile() {
    const name = newName.trim();
    run("profile", async () => {
      profiles = await api.saveProfile(name);
      newName = "";
    });
  }

  function switchProfile(name: string) {
    deleting = null;
    run("profile", async () => {
      profiles = await api.switchProfile(name);
    });
  }

  // The active profile, as things are now; saving over it keeps its networks.
  function saveChanges(name: string) {
    deleting = null;
    run("profile", async () => {
      profiles = await api.saveProfile(name);
    });
  }

  // Switching by network: the profile being given networks, and the networks
  // Windows knows (connected first).
  const CATEGORY_TEXT: Record<NetworkCategory, string> = {
    public: "Public",
    private: "Private",
    domain: "Domain",
  };
  let editing = $state<{ name: string; ids: Set<string>; kinds: Set<NetworkCategory> } | null>(null);
  let known = $state.raw<NetworkInfo[]>([]);

  function networksText(p: Profile): string {
    return p.networks
      .map((m) => (m.kind === "network" ? `“${m.name}”` : `any ${m.category} network`))
      .join(", ");
  }

  async function editNetworks(p: Profile) {
    deleting = null;
    if (editing?.name === p.name) {
      editing = null;
      return;
    }
    editing = {
      name: p.name,
      ids: new Set(p.networks.flatMap((m) => (m.kind === "network" ? [m.id.toLowerCase()] : []))),
      kinds: new Set(p.networks.flatMap((m) => (m.kind === "category" ? [m.category] : []))),
    };
    try {
      known = (await api.networks()).networks;
    } catch (e) {
      error = errorText(e);
    }
  }

  function toggleIn<T>(set: Set<T>, value: T): Set<T> {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  }

  function saveNetworks() {
    if (!editing) return;
    const { name, ids, kinds } = editing;
    const networks: NetworkMatch[] = [
      ...known.filter((n) => ids.has(n.id.toLowerCase())).map((n) => ({ kind: "network" as const, id: n.id, name: n.name })),
      // Chosen before but not known any more: kept as they were.
      ...(profiles?.profiles.find((p) => p.name === name)?.networks ?? []).filter(
        (m) => m.kind === "network" && ids.has(m.id.toLowerCase()) && !known.some((n) => n.id.toLowerCase() === m.id.toLowerCase()),
      ),
      ...[...kinds].map((category) => ({ kind: "category" as const, category })),
    ];
    editing = null;
    run("profile", async () => {
      profiles = await api.setProfileNetworks(name, networks);
    });
  }

  function deleteProfile(name: string) {
    if (deleting !== name) {
      deleting = name;
      return;
    }
    deleting = null;
    run("profile", async () => {
      profiles = await api.deleteProfile(name);
    });
  }

  async function startBlockAll(minutes: number | null, confirmRemote = false) {
    remoteConfirm = null;
    busy = "block_all";
    error = null;
    try {
      await api.blockAll(true, minutes, confirmRemote);
      await firewall.refresh();
    } catch (e) {
      if (errorCode(e) === REMOTE_SESSION) remoteConfirm = { minutes };
      else error = errorText(e);
    } finally {
      busy = null;
    }
  }
</script>

<svelte:window
  onclick={() => (open = false)}
  onkeydown={(e) => {
    if (e.key === "Escape") open = false;
  }}
/>

<div class="wrap">
  <button
    class="pill {pill.tone}"
    aria-haspopup="dialog"
    aria-expanded={open}
    title={status?.monitoring_only ?? firewall.unavailable ?? "Firewall"}
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}
  >
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6l-7-3Z" /></svg>
    {pill.text}
  </button>

  {#if open}
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
    <div class="panel card" role="dialog" aria-label="Firewall" tabindex="-1" onclick={(e) => e.stopPropagation()}>
      {#if !status}
        <p class="muted">Firewall controls are unavailable{firewall.unavailable ? `: ${firewall.unavailable}` : "."}</p>
      {:else}
        {#if status.monitoring_only}
          <p class="note warn">
            <strong>Monitoring only.</strong>
            {status.monitoring_only} win4tress shows traffic but doesn't change the firewall.
          </p>
        {/if}

        <section>
          <h3>Windows Firewall</h3>
          <ul class="profiles">
            {#each status.state?.profiles ?? [] as p (p.name)}
              <li>
                <span class="dot" class:on={p.firewall_on}></span>
                <span>{profileName(p.name)}{p.active ? " (in use)" : ""}</span>
                <span class="muted">{p.firewall_on ? "On" : "Off"}</span>
                {#if !p.firewall_on}
                  <button
                    class="btn small"
                    disabled={busy !== null || !!status.monitoring_only}
                    onclick={() => run("turn_on", () => api.turnOn(p.name))}>Turn on</button
                  >
                {/if}
              </li>
            {/each}
          </ul>
          {#if profilesOff.length}
            <p class="muted small">
              With Windows Firewall off on a network, nothing is blocked there, win4tress's rules included.
            </p>
          {/if}
        </section>

        <section>
          <h3>Mode</h3>
          <div class="modes" role="radiogroup" aria-label="Mode">
            <button
              role="radio"
              aria-checked={status.mode === "click_to_block"}
              disabled={busy !== null || !!status.monitoring_only}
              onclick={() => setMode("click_to_block")}
            >
              <strong>Click to Block</strong>
              <span class="muted">Everything is allowed unless you block it.</span>
            </button>
            <button
              role="radio"
              aria-checked={status.mode === "ask_to_connect"}
              disabled={busy !== null || !!status.monitoring_only || status.environment.outbound_default_forced_by.length > 0}
              title={status.environment.outbound_default_forced_by.length
                ? `Unavailable: ${status.environment.outbound_default_forced_by.join(" and ")} sets what happens to outgoing connections.`
                : undefined}
              onclick={() => setMode("ask_to_connect")}
            >
              <strong>Ask to Connect</strong>
              <span class="muted">Apps without a rule are blocked until you decide. Windows' own services keep working.</span>
            </button>
            <button
              role="radio"
              aria-checked={status.mode === "off"}
              disabled={busy !== null || !!status.monitoring_only}
              onclick={() => setMode("off")}
            >
              <strong>Off</strong>
              <span class="muted">Your rules are kept but switched off; Windows Firewall works as before.</span>
            </button>
          </div>
          {#if learning}
            <div class="learn">
              {#if learning.apps.length}
                <p>
                  These apps used the network in the last {RECENT_DAYS} days and have no rule. Allow them now, so
                  they keep working without asking?
                </p>
                <ul>
                  {#each learning.apps as a (a.id)}
                    {@const flags = trustChips(a)}
                    <li>
                      <label>
                        <input type="checkbox" checked={learning.checked.has(a.id)} onchange={() => toggleLearn(a.id)} />
                        <span class="ellipsis" title={a.path}>{a.name}</span>
                        {#if flags.length}<span class="chip {flags[0].tone}" title={flags.map((f) => f.title).join("\n")}>{flags[0].label}</span>{/if}
                      </label>
                    </li>
                  {/each}
                </ul>
                <div class="row">
                  <button class="btn small primary" disabled={busy !== null} onclick={() => turnOnAsk(true)}>
                    Allow {learning.checked.size} and turn on
                  </button>
                  <button class="btn small" disabled={busy !== null} onclick={() => turnOnAsk(false)}>Turn on</button>
                  <button class="btn small" onclick={() => (learning = null)}>Cancel</button>
                </div>
              {:else}
                <p>Every app used lately already has a rule. Apps without one will be asked about.</p>
                <div class="row">
                  <button class="btn small primary" disabled={busy !== null} onclick={() => turnOnAsk(false)}>Turn on</button>
                  <button class="btn small" onclick={() => (learning = null)}>Cancel</button>
                </div>
              {/if}
            </div>
          {/if}
          {#if waiting}
            <p class="small">
              {waiting} {waiting === 1 ? "connection is" : "connections are"} waiting for your decision.
              <button class="link" onclick={() => api.showCard()}>Show</button>
            </p>
          {/if}
        </section>

        <section>
          <h3>Profiles</h3>
          {#if profiles?.profiles.length}
            <ul class="plist">
              {#each profiles.profiles as p (p.name)}
                {@const active = isActive(p.name)}
                <li>
                  <span class="pname">
                    <strong>{p.name}</strong>
                    {#if active}<span class="chip">{profiles.changed ? "Active, changed" : "Active"}</span>{/if}
                    <span class="muted small block facts">
                      <span>{MODE_NAME[p.mode]}</span>
                      <span>{p.rules} {p.rules === 1 ? "rule" : "rules"} on</span>
                      {#if p.dns_filtering != null}<span>DNS filtering {p.dns_filtering ? "on" : "off"}</span>{/if}
                    </span>
                    {#if p.networks.length}
                      <span class="muted small block ellipsis" title={networksText(p)}>On {networksText(p)}</span>
                    {/if}
                  </span>
                  <button
                    class="link"
                    disabled={busy !== null}
                    aria-expanded={editing?.name === p.name}
                    title="Switch to it by itself on networks you choose"
                    onclick={() => editNetworks(p)}>Networks</button
                  >
                  <button
                    class="btn small"
                    disabled={busy !== null || (active && !profiles.changed) || !!status.monitoring_only}
                    title={active ? "Put the profile's mode, rules and DNS filtering back" : `Switch to ${p.name}`}
                    onclick={() => switchProfile(p.name)}>{active ? "Restore" : "Switch"}</button
                  >
                  <button class="link" disabled={busy !== null} onclick={() => deleteProfile(p.name)}
                    >{deleting === p.name ? "Really delete?" : "Delete"}</button
                  >
                </li>
                <!-- Also for a profile saved before profiles held DNS filtering. -->
                {#if active && (profiles.changed || p.dns_filtering == null)}
                  <li class="unsaved">
                    <span class="small">
                      {profiles.changed
                        ? `The mode, rules or DNS filtering have changed since ${p.name} was saved.`
                        : `${p.name} doesn't hold DNS filtering yet: save it to add the current settings.`}
                    </span>
                    <button
                      class="btn small primary"
                      disabled={busy !== null}
                      title="Keep the mode, rules and DNS filtering as they are now in {p.name}"
                      onclick={() => saveChanges(p.name)}>Save changes</button
                    >
                  </li>
                {/if}
                {#if editing?.name === p.name}
                  {@const ed = editing}
                  <li class="nets">
                    <p class="small">Switch to {p.name} by itself when this PC joins:</p>
                    <ul>
                      {#each known as n (n.id)}
                        <li>
                          <label>
                            <input
                              type="checkbox"
                              checked={ed.ids.has(n.id.toLowerCase())}
                              onchange={() => (editing = { ...ed, ids: toggleIn(ed.ids, n.id.toLowerCase()) })}
                            />
                            <span class="ellipsis" title={n.id}>{n.name}</span>
                            <span class="muted small">{CATEGORY_TEXT[n.category]}{n.connected ? " · connected" : ""}</span>
                          </label>
                        </li>
                      {:else}
                        <li class="muted small">Windows doesn't remember any networks yet.</li>
                      {/each}
                      {#each ["public", "private", "domain"] as const as c (c)}
                        <li>
                          <label>
                            <input
                              type="checkbox"
                              checked={ed.kinds.has(c)}
                              onchange={() => (editing = { ...ed, kinds: toggleIn(ed.kinds, c) })}
                            />
                            <span>Any {c} network</span>
                          </label>
                        </li>
                      {/each}
                    </ul>
                    <p class="muted small">
                      A network chosen by name wins over one chosen by kind. Switching by hand stays until the PC
                      joins another network.
                    </p>
                    <div class="row">
                      <button class="btn small primary" disabled={busy !== null} onclick={saveNetworks}>Save</button>
                      <button class="btn small" onclick={() => (editing = null)}>Cancel</button>
                    </div>
                  </li>
                {/if}
              {/each}
            </ul>
            {#if profiles.last_auto}
              <p class="muted small">
                Switched to {profiles.last_auto.profile} by itself on {profiles.last_auto.network},
                {ago(nowMs - profiles.last_auto.at_ms)}.
              </p>
            {/if}
          {:else}
            <p class="muted small">
              Save the mode, every app's switches and DNS filtering as a profile, such as Home or Travel, and switch
              between them. Block an app in one and not another to block it only some of the time.
            </p>
          {/if}
          <div class="row">
            <input class="pinput" placeholder="Profile name" maxlength="40" bind:value={newName} aria-label="Profile name" />
            <button class="btn small" disabled={busy !== null || !newName.trim()} onclick={saveProfile}>
              {profiles?.profiles.some((p) => p.name.toLowerCase() === newName.trim().toLowerCase())
                ? "Replace"
                : "Save current"}
            </button>
          </div>
        </section>

        <section>
          <h3>Block All</h3>
          {#if blockAll}
            <p class="note bad">
              All traffic is blocked{blockAll.until_ms ? ` until ${until(blockAll.until_ms)}` : " until you turn it off"},
              win4tress included.
            </p>
            <button
              class="btn primary"
              disabled={busy !== null}
              onclick={() => run("block_all", () => api.blockAll(false))}>Stop blocking</button
            >
          {:else if remoteConfirm}
            <p class="note bad" role="alert">
              You're connected over Remote Desktop. Block All disconnects you, and you can't reconnect
              {remoteConfirm.minutes
                ? `for ${remoteConfirm.minutes} minutes`
                : "until someone at this PC turns it off"}.
            </p>
            <div class="row">
              <button
                class="btn danger"
                disabled={busy !== null}
                onclick={() => startBlockAll(remoteConfirm?.minutes ?? null, true)}>Block anyway</button
              >
              <button class="btn" onclick={() => (remoteConfirm = null)}>Cancel</button>
            </div>
          {:else}
            <p class="muted small">Cuts this PC off the network, in and out. Local traffic on this PC still works.</p>
            <div class="row">
              {#each BLOCK_ALL_FOR as o (o.label)}
                <button
                  class="btn small"
                  disabled={busy !== null || !!status.monitoring_only}
                  onclick={() => startBlockAll(o.minutes)}>{o.label}</button
                >
              {/each}
            </div>
          {/if}
        </section>

        <section>
          <label class="check">
            <input
              type="checkbox"
              checked={status.require_elevation}
              disabled={busy !== null}
              onchange={(e) => {
                const on = e.currentTarget.checked;
                e.currentTarget.checked = !on; // until the change is made
                run("elevation", () => api.setRequireElevation(on));
              }}
            />
            <span>
              <strong>Require elevation</strong>
              <span class="muted small block">
                Changes need an administrator's approval (a UAC prompt) each time, so a program running as you
                can't change the firewall through win4tress.
              </span>
            </span>
          </label>
        </section>

        {#if error}<p class="error-text small" role="alert">{error}</p>{/if}
        {#if busy === "elevation"}<p class="muted small">Waiting for the UAC prompt…</p>{/if}

        <p class="footer muted small">
          {status.rules} win4tress {status.rules === 1 ? "rule" : "rules"} in Windows Firewall
          {#if status.last_check_ms}· checked {ago(nowMs - status.last_check_ms)}{/if}
          · {status.live_events ? "changes seen as they happen" : "changes checked every minute"}
          {#if status.last_error}<br /><span class="error-text">{status.last_error}</span>{/if}
        </p>
      {/if}
    </div>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
  }
  .pill {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12.5px;
    padding: 4px 12px 4px 9px;
    border: 1px solid var(--border);
    border-radius: 20px;
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    white-space: nowrap;
  }
  .pill:hover,
  .pill[aria-expanded="true"] {
    background: var(--surface-2);
  }
  .pill svg {
    width: 15px;
    height: 15px;
    fill: var(--accent);
    stroke: none;
  }
  .pill.idle svg {
    fill: var(--text-muted);
  }
  .pill.warn svg {
    fill: var(--alert-info);
  }
  .pill.bad {
    background: var(--bad);
    color: var(--on-status);
    border-color: transparent;
    font-weight: 600;
  }
  .pill.bad svg {
    fill: var(--on-status);
  }
  @media (forced-colors: active) {
    .pill svg {
      fill: CanvasText;
    }
  }
  .panel {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 20;
    width: 420px;
    padding: 6px 16px 12px;
    box-shadow: var(--shadow-popover);
    font-size: 13px;
  }
  section {
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
  }
  h3 {
    margin: 0 0 6px;
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
  .block {
    display: block;
  }
  .note {
    padding: 7px 10px;
    border-radius: 7px;
  }
  .note.warn {
    background: color-mix(in srgb, var(--alert-info) 18%, var(--surface));
  }
  .note.bad {
    background: color-mix(in srgb, var(--bad) 16%, var(--surface));
  }
  .profiles {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .profiles li {
    display: grid;
    grid-template-columns: 10px 1fr auto auto;
    align-items: center;
    gap: 8px;
    min-height: 26px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--bad);
  }
  .dot.on {
    background: var(--ok);
  }
  @media (forced-colors: active) {
    .dot {
      forced-color-adjust: none;
      background: CanvasText;
    }
  }
  .modes {
    display: grid;
    gap: 6px;
  }
  .modes button {
    display: grid;
    gap: 1px;
    text-align: left;
    padding: 7px 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    cursor: pointer;
    font-size: 13px;
  }
  .modes button[aria-checked="true"] {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 10%, var(--surface));
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .modes button:disabled {
    cursor: default;
    opacity: 0.6;
  }
  .modes span {
    font-size: 12px;
  }
  .plist {
    list-style: none;
    margin: 0 0 8px;
    padding: 0;
  }
  .plist li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 0;
  }
  .pname {
    flex: 1;
    min-width: 0;
  }
  .pname .chip {
    margin-left: 6px;
  }
  /* Broken between its parts rather than cut off. */
  .facts > span {
    white-space: nowrap;
  }
  .facts > span:not(:last-child)::after {
    content: " ·";
  }
  .plist li.unsaved {
    margin-bottom: 4px;
    padding: 6px 6px 6px 10px;
    border-radius: 8px;
    background: var(--surface-2);
  }
  .unsaved span {
    flex: 1;
    min-width: 0;
  }
  .plist li.nets {
    display: block;
    padding: 6px 10px 8px;
    border-radius: 8px;
    background: var(--surface-2);
  }
  .nets ul {
    list-style: none;
    margin: 4px 0;
    padding: 0;
    max-height: 190px;
    overflow: auto;
  }
  .nets label {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 2px 0;
    min-width: 0;
    cursor: pointer;
  }
  .nets label .ellipsis {
    flex: 1;
    min-width: 0;
  }
  .nets input {
    accent-color: var(--accent);
  }
  .pinput {
    flex: 1;
    min-width: 0;
    font: inherit;
    font-size: 13px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--surface-2);
    color: var(--text);
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .check {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    cursor: pointer;
  }
  .check input {
    margin-top: 3px;
    accent-color: var(--accent);
  }
  .footer {
    margin: 10px 0 0;
  }
  .learn {
    margin-top: 8px;
    padding: 8px 10px;
    border-radius: 8px;
    background: var(--surface-2);
  }
  .learn ul {
    list-style: none;
    margin: 6px 0 8px;
    padding: 0;
    max-height: 180px;
    overflow: auto;
  }
  .learn label {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 2px 0;
    cursor: pointer;
    min-width: 0;
  }
  .learn input {
    accent-color: var(--accent);
  }
  .ellipsis {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .link {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent-text);
    text-decoration: underline;
    cursor: pointer;
    font-size: inherit;
  }
</style>
