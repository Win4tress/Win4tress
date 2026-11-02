<script lang="ts">
  // Settings → About: the app's version, the service's (they can differ when
  // an upgrade didn't finish, or the service runs from a console), Windows', a
  // copy of all three for bug reports, the licence, and credits for the data
  // the app shows (DB-IP's licence asks for its credit here).
  import { api, errorText, type AboutInfo, type Status } from "./api";
  import { duration } from "./format";
  import Logo from "./Logo.svelte";

  let about = $state.raw<AboutInfo | null>(null);
  let service = $state.raw<Status | null>(null);
  let serviceDown = $state(false);
  let copied = $state<string | null>(null);

  $effect(() => {
    api.about().then((a) => (about = a), () => {});
    api.status().then(
      (s) => (service = s),
      () => (serviceDown = true),
    );
  });

  const mismatch = $derived(!!about && !!service && service.version !== about.version);

  function serviceLine(): string {
    if (serviceDown) return "Service not running";
    if (!service) return "";
    return `Service ${service.version}, running ${duration(service.now_ms - service.started_ms)}`;
  }

  async function copy() {
    const text = [`Win4tress ${about?.version ?? "?"}`, serviceLine(), about?.windows ?? ""].filter(Boolean).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      copied = "Copied.";
    } catch (e) {
      copied = `Couldn't copy: ${errorText(e)}`;
    }
    setTimeout(() => (copied = null), 2500);
  }

  const credits: [string, string, string, string?][] = [
    ["IP locations and network owners", "DB-IP", "https://db-ip.com", "CC BY 4.0"],
    ["Botnet servers", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/"],
    ["Device makers", "IEEE Registration Authority", "https://standards.ieee.org/products-programs/regauth/"],
    ["World map", "Natural Earth", "https://www.naturalearthdata.com/", "public domain"],
    ["Country flags", "country-flag-icons", "https://gitlab.com/catamphetamine/country-flag-icons", "MIT licence"],
  ];
</script>

<div class="head">
  <Logo size={40} />
  <div>
    <div class="name">Win4tress {about?.version ?? ""}</div>
    <div class="muted small">Network monitor and firewall for Windows 11</div>
  </div>
</div>

<dl>
  <dt>Service</dt>
  <dd class:warn-text={mismatch || serviceDown}>
    {#if serviceDown}
      Not running
    {:else if service}
      {service.version}{#if mismatch}: not the app's version. Reinstall win4tress to bring them in line.{:else}, running
        {duration(service.now_ms - service.started_ms)}{/if}
    {/if}
  </dd>
  <dt>Windows</dt>
  <dd>{about?.windows ?? ""}</dd>
  <dt>Licence</dt>
  <dd>Open source, under the MIT or Apache 2.0 licence</dd>
</dl>

<div class="row">
  <button class="btn small" disabled={!about} onclick={copy}>Copy details</button>
  {#if copied}<span class="muted small" role="status">{copied}</span>{/if}
</div>

<h3>Credits</h3>
<ul>
  {#each credits as [what, name, url, licence] (name)}
    <li>
      <span class="muted">{what}:</span>
      <button class="link" onclick={() => api.openLink(url)}>{name}</button>{#if licence === "CC BY 4.0"}, licensed
        <button class="link" onclick={() => api.openLink("https://creativecommons.org/licenses/by/4.0/")}
          >CC BY 4.0</button
        >{:else if licence}, {licence}{/if}
    </li>
  {/each}
</ul>

<style>
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .name {
    font: 600 16px/1.3 var(--font-display);
  }
  .small {
    font-size: 12.5px;
  }
  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 4px 14px;
    margin: 14px 0 0;
    font-size: 13px;
  }
  dt {
    color: var(--text-muted);
  }
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .warn-text {
    color: var(--warn);
  }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 12px;
  }
  h3 {
    margin: 16px 0 6px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    font-size: 12.5px;
    display: grid;
    gap: 4px;
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
</style>
