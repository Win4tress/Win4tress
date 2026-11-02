<script lang="ts">
  // Theme picker in the header, until Settings exists (SPEC §10.2).
  import { theme, type Palette, type ThemeChoice } from "./theme.svelte";

  const PALETTES: { value: Palette; label: string }[] = [
    { value: "win4tress", label: "Win4tress" },
    { value: "indigo", label: "Indigo" },
  ];
  const CHOICES: { value: ThemeChoice; label: string }[] = [
    { value: "system", label: "Match Windows" },
    { value: "light", label: "Light" },
    { value: "dark", label: "Dark" },
  ];
  let open = $state(false);
  const current = $derived(
    [PALETTES.find((p) => p.value === theme.palette), CHOICES.find((c) => c.value === theme.choice)]
      .map((x) => x?.label ?? "")
      .join(", "),
  );
</script>

<svelte:window
  onclick={() => (open = false)}
  onkeydown={(e) => {
    if (e.key === "Escape") open = false;
  }}
/>

<div class="wrap">
  <button
    class="toggle"
    aria-label="Theme: {current}"
    title="Theme: {current}"
    aria-haspopup="menu"
    aria-expanded={open}
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}
  >
    {#if theme.resolved === "dark"}
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" /></svg>
    {:else}
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
      </svg>
    {/if}
  </button>
  {#if open}
    <div class="menu card" role="menu" aria-label="Theme">
      <div role="group" aria-labelledby="theme-colours">
        <div class="heading" id="theme-colours">Colours</div>
        {#each PALETTES as p (p.value)}
          <button
            role="menuitemradio"
            aria-checked={theme.palette === p.value}
            onclick={(e) => {
              e.stopPropagation();
              theme.setPalette(p.value);
              open = false;
            }}
          >
            <span class="check" aria-hidden="true">{theme.palette === p.value ? "✓" : ""}</span>
            {p.label}
          </button>
        {/each}
      </div>
      <div class="rule" role="separator"></div>
      <div role="group" aria-labelledby="theme-brightness">
        <div class="heading" id="theme-brightness">Light or dark</div>
        {#each CHOICES as c (c.value)}
          <button
            role="menuitemradio"
            aria-checked={theme.choice === c.value}
            onclick={(e) => {
              e.stopPropagation();
              theme.set(c.value);
              open = false;
            }}
          >
            <span class="check" aria-hidden="true">{theme.choice === c.value ? "✓" : ""}</span>
            {c.label}
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
  }
  .toggle {
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--surface);
    color: var(--text-muted);
    cursor: pointer;
  }
  .toggle:hover,
  .toggle[aria-expanded="true"] {
    background: var(--surface-2);
    color: var(--text);
  }
  svg {
    width: 17px;
    height: 17px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 20;
    display: grid;
    min-width: 170px;
    padding: 4px;
    box-shadow: var(--shadow-popover);
  }
  .menu [role="group"] {
    display: grid;
  }
  .heading {
    padding: 6px 10px 2px;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-muted);
  }
  .rule {
    height: 1px;
    margin: 4px 6px;
    background: var(--border);
  }
  .menu button {
    display: flex;
    align-items: center;
    gap: 6px;
    border: 0;
    background: none;
    text-align: left;
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
  }
  .menu button:hover {
    background: var(--surface-2);
  }
  .check {
    width: 14px;
    color: var(--accent-text);
    font-weight: 700;
  }
</style>
