<script lang="ts">
  import Logo from "./Logo.svelte";

  let { reason }: { reason: string | null } = $props();
</script>

<div class="wrap">
  <div class="card box">
    <Logo size={44} />
    <h1>Waiting for the win4tress service</h1>
    <p>
      win4tress needs its background service to see network traffic. This window connects on its
      own as soon as the service is running.
    </p>
    <ul>
      <li>
        To try it, run this in an <strong>elevated</strong> terminal in the project folder:
        <code>target\release\win4tress-svc.exe console</code>
      </li>
      <li>Or install it as a Windows service: <code>win4tress-svc.exe install</code></li>
    </ul>
    {#if reason}
      <p class="reason muted">Last attempt: {reason}</p>
    {/if}
    <p class="retry muted"><span class="dot"></span> Retrying every 2 seconds</p>
  </div>
</div>

<style>
  .wrap {
    display: grid;
    place-items: center;
    height: 100%;
  }
  .box {
    max-width: 560px;
    padding: 28px 32px;
  }
  h1 {
    font: 600 20px/1.3 var(--font-display);
    margin: 14px 0 8px;
  }
  p,
  li {
    color: var(--text);
  }
  ul {
    padding-left: 18px;
    display: grid;
    gap: 8px;
  }
  code {
    display: inline-block;
    font-family: var(--mono);
    font-size: 12.5px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 1px 6px;
    margin-top: 4px;
  }
  .reason {
    font-size: 12.5px;
  }
  .retry {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
    margin-bottom: 0;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--warn);
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse {
    50% {
      opacity: 0.25;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .dot {
      animation: none;
    }
  }
</style>
