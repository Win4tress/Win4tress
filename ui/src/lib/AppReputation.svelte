<script lang="ts">
  // An app's reputation (SPEC §12 tiers 2 and 3): what CIRCL, VirusTotal,
  // MalwareBazaar and the installed antivirus said about its file; looking it
  // up now, scanning it, or uploading it to VirusTotal (asked first). And
  // whether its traffic is kept out of history (incognito, SPEC §8.4).
  import { api, errorText, type AppReputation, type Reputation, type Settings, type Trust } from "./api";
  import { ago } from "./format";

  interface Props {
    app: { id: number; name: string; path: string; trust: Trust };
    nowMs: number;
  }

  let { app, nowMs }: Props = $props();

  let rep = $state.raw<AppReputation | null>(null);
  let settings = $state.raw<Settings | null>(null);
  let vtKey = $state(false);
  let busy = $state<"check" | "scan" | "upload" | "incognito" | null>(null);
  let error = $state<string | null>(null);
  let note = $state<string | null>(null);
  let confirmUpload = $state(false);

  const hasFile = $derived(app.path.includes("\\"));

  async function load(id: number) {
    try {
      const [r, s, st] = await Promise.all([api.appReputation(id), api.settings(), api.reputationStatus()]);
      if (id !== app.id) return;
      rep = r;
      settings = s;
      vtKey = st.virustotal_key;
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    const id = app.id;
    rep = null;
    error = null;
    note = null;
    confirmUpload = false;
    load(id);
    const timer = setInterval(() => load(id), 15_000);
    return () => clearInterval(timer);
  });

  async function act(what: "check" | "scan" | "upload", f: () => Promise<void>) {
    busy = what;
    error = null;
    note = null;
    try {
      await f();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = null;
    }
  }

  const check = () =>
    act("check", async () => {
      rep = await api.checkNow(app.id);
      note = "Looking it up; answers appear here in a few seconds.";
      setTimeout(() => load(app.id), 5_000);
    });
  const scan = () =>
    act("scan", async () => {
      rep = await api.avScan(app.id);
    });
  const upload = () =>
    act("upload", async () => {
      confirmUpload = false;
      const r = await api.vtUpload(app.id);
      note = "Uploaded. VirusTotal's analysis takes a few minutes; win4tress fetches the result.";
      link = r.link;
    });
  let link = $state<string | null>(null);

  const incognito = $derived(settings?.incognito_apps.includes(app.id) ?? false);

  async function setIncognito(on: boolean) {
    if (!settings) return;
    busy = "incognito";
    error = null;
    try {
      const others = settings.incognito_apps.filter((i) => i !== app.id);
      settings = await api.setSettings({ ...settings, incognito_apps: on ? [...others, app.id] : others });
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = null;
    }
  }

  const VERDICT: Record<Reputation["verdict"], string> = {
    unknown: "Not known",
    known_good: "Known good",
    clean: "Clean",
    suspicious: "Suspicious",
    malicious: "Malicious",
  };

  function result(r: Reputation): string {
    const parts = [VERDICT[r.verdict]];
    if (r.detections != null && r.engines != null) parts.push(`${r.detections} of ${r.engines} engines`);
    if (r.detail) parts.push(r.detail);
    return parts.join(" · ");
  }
</script>

<section>
  <h3>Reputation</h3>
  {#if !hasFile}
    <p class="muted small">This app has no program file to look up.</p>
  {:else}
    {#if rep && rep.results.length}
      <ul class="answers">
        {#each rep.results as r (r.source)}
          <li>
            <span class="tone {r.verdict}" aria-hidden="true"></span>
            <span class="source">{r.source}</span>
            <span class="result">{result(r)}</span>
            <span class="muted small when">{ago(nowMs - r.checked_ms)}</span>
            {#if r.link}
              <button class="link" onclick={() => r.link && api.openLink(r.link)}>Details</button>
            {/if}
          </li>
        {/each}
      </ul>
    {:else if rep}
      <p class="muted small">
        Not looked up yet{settings && !settings.reputation.enabled ? ": lookups are off (Settings, Reputation)" : ""}.
      </p>
    {/if}
    <div class="actions">
      <button
        class="btn small"
        disabled={busy !== null || !settings?.reputation.enabled}
        title={settings?.reputation.enabled ? "Ask CIRCL and VirusTotal now" : "Turn lookups on in Settings first"}
        onclick={check}>{busy === "check" ? "Looking up…" : "Look up now"}</button
      >
      <button class="btn small" disabled={busy !== null} onclick={scan}
        >{busy === "scan" ? "Scanning…" : "Scan with antivirus"}</button
      >
      <button
        class="btn small"
        disabled={busy !== null || !vtKey}
        title={vtKey ? "Send the file itself to VirusTotal" : "Set a VirusTotal key in Settings first"}
        onclick={() => (confirmUpload = true)}>{busy === "upload" ? "Uploading…" : "Upload to VirusTotal…"}</button
      >
    </div>
    {#if confirmUpload}
      <div class="confirm" role="alertdialog" aria-label="Upload to VirusTotal?">
        <p>
          <strong>Upload {app.name}'s file to VirusTotal?</strong> The file itself is sent. Anyone with VirusTotal
          access, including companies that pay for it, can download it. Don't upload a program you built or one that
          holds anything private.
        </p>
        <div class="actions">
          <button class="btn small danger" onclick={upload}>Upload</button>
          <button class="btn small" onclick={() => (confirmUpload = false)}>Cancel</button>
        </div>
      </div>
    {/if}
    {#if note}
      <p class="muted small">
        {note}{#if link}
          <button class="link" onclick={() => link && api.openLink(link)}>Open its page</button>{/if}
      </p>
    {/if}
  {/if}
  {#if error}<p class="error-text small" role="alert">{error}</p>{/if}

  <label class="check">
    <input
      type="checkbox"
      checked={incognito}
      disabled={busy !== null || !settings}
      onchange={(e) => setIncognito(e.currentTarget.checked)}
    />
    <span>
      <strong>Incognito</strong>
      <span class="muted small block">Keep this app's traffic and lookups out of history. Blocking and alerts carry on.</span>
    </span>
  </label>
</section>

<style>
  section {
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }
  h3 {
    margin: 0 0 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
  }
  .answers {
    list-style: none;
    margin: 0 0 8px;
    padding: 0;
  }
  .answers li {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 3px 0;
    font-size: 13px;
  }
  .tone {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    align-self: center;
  }
  .tone.known_good,
  .tone.clean {
    background: var(--accent);
  }
  .tone.suspicious {
    background: var(--alert-info);
  }
  .tone.malicious {
    background: var(--bad);
  }
  .source {
    font-weight: 600;
    white-space: nowrap;
  }
  .result {
    flex: 1;
    min-width: 0;
  }
  .when {
    white-space: nowrap;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .confirm {
    margin-top: 10px;
    padding: 10px 12px;
    border: 1px solid var(--bad);
    border-radius: 8px;
    font-size: 13px;
  }
  .confirm p {
    margin: 0 0 8px;
  }
  .small {
    font-size: 12.5px;
  }
  .block {
    display: block;
  }
  p.small {
    margin: 8px 0 0;
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-top: 12px;
    font-size: 13px;
    cursor: pointer;
  }
  .check input {
    margin-top: 3px;
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
  }
</style>
