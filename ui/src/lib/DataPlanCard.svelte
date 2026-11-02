<script lang="ts">
  // The data plan (SPEC §10.2): how much of this period's limit is used, and
  // setting it up. Alerts come from the service as thresholds pass.
  import { api, errorText, type PlanStatus, type Settings } from "./api";
  import { human } from "./format";

  interface Props {
    settings: Settings | null;
    onsaved: (s: Settings) => void;
  }

  let { settings, onsaved }: Props = $props();

  const REFRESH_MS = 60_000;
  const GB = 1e9;

  let status = $state.raw<PlanStatus | null>(null);
  let editing = $state(false);
  let limitGb = $state(50);
  let resetDay = $state(1);
  let meteredOnly = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function load() {
    try {
      status = await api.planStatus();
    } catch {
      status = null;
    }
  }

  $effect(() => {
    void settings;
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  });

  function edit() {
    const plan = settings?.data_plan;
    limitGb = plan ? Math.round((plan.limit_bytes / GB) * 10) / 10 : 50;
    resetDay = plan?.reset_day ?? 1;
    meteredOnly = plan?.metered_only ?? false;
    error = null;
    editing = true;
  }

  async function save(remove = false) {
    if (!settings) return;
    busy = true;
    error = null;
    try {
      const next: Settings = {
        ...settings,
        data_plan: remove
          ? null
          : {
              limit_bytes: Math.round(limitGb * GB),
              reset_day: resetDay,
              warn_at: settings.data_plan?.warn_at ?? [75, 90, 100],
              metered_only: meteredOnly,
            },
      };
      onsaved(await api.setSettings(next));
      editing = false;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function day(ms: number): string {
    return new Date(ms).toLocaleDateString([], { day: "numeric", month: "short" });
  }

  const used = $derived(status ? status.used.recv + status.used.sent : 0);
  const tone = $derived(!status ? "" : status.percent >= 100 ? "bad" : status.percent >= 75 ? "warn" : "ok");
</script>

{#if editing}
  <section class="card plan">
    <div class="form">
      <label>
        Limit
        <input type="number" min="0.1" step="0.1" bind:value={limitGb} /> GB a month
      </label>
      <label>
        Starts on day
        <select bind:value={resetDay}>
          {#each Array.from({ length: 28 }, (_, i) => i + 1) as d (d)}<option value={d}>{d}</option>{/each}
        </select>
        of the month
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={meteredOnly} /> Count only while on a metered connection
      </label>
      <div class="actions">
        <button class="btn small primary" disabled={busy || !(limitGb > 0)} onclick={() => save()}>Save</button>
        {#if settings?.data_plan}
          <button class="btn small" disabled={busy} onclick={() => save(true)}>Remove the plan</button>
        {/if}
        <button class="btn small" onclick={() => (editing = false)}>Cancel</button>
      </div>
    </div>
    <p class="muted small">
      Alerts at 75%, 90% and 100%. Downloads and uploads both count; the local network doesn't.
    </p>
    {#if error}<p class="error-text small">{error}</p>{/if}
  </section>
{:else if status}
  <section class="card plan">
    <div class="row">
      <strong>Data plan</strong>
      <span class="num">{human(used)} of {human(status.plan.limit_bytes)}</span>
      <span class="pct {tone}">{status.percent.toFixed(0)}%</span>
      <span class="muted small">
        since {day(status.period_start_ms)}, resets {day(status.period_end_ms)}{status.plan.metered_only
          ? " · metered connections only"
          : ""}{status.metered ? " · this connection is metered" : ""}
      </span>
      <button class="link" onclick={edit}>Change</button>
    </div>
    <div class="track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.min(100, Math.round(status.percent))}>
      <span class="fill {tone}" style:width="{Math.min(100, status.percent)}%"></span>
    </div>
  </section>
{:else if settings}
  <p class="muted small none">
    No data plan. <button class="link" onclick={edit}>Set one up</button> to see how much of it is used and get alerts.
  </p>
{/if}

<style>
  .plan {
    padding: 10px 14px;
    display: grid;
    gap: 8px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 10px;
    font-size: 13px;
  }
  .pct {
    font-weight: 600;
  }
  .pct.warn {
    color: var(--warn);
  }
  .pct.bad {
    color: var(--bad-text);
  }
  .track {
    height: 6px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .fill {
    display: block;
    height: 100%;
    background: var(--ok);
  }
  .fill.warn {
    background: var(--alert-info);
  }
  .fill.bad {
    background: var(--bad);
  }
  .form {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    font-size: 13px;
  }
  .form label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  input[type="number"] {
    width: 80px;
  }
  input[type="number"],
  select {
    font: inherit;
    font-size: 13px;
    color: var(--text);
    padding: 3px 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
  }
  .check input {
    accent-color: var(--accent);
  }
  .actions {
    display: flex;
    gap: 6px;
  }
  .small {
    font-size: 12.5px;
    margin: 0;
  }
  .none {
    padding: 0 2px;
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
  .row .link {
    margin-left: auto;
  }
</style>
