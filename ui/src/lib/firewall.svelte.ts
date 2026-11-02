// Firewall state shared by the header, the Apps view and the Firewall view:
// the status, win4tress's rules and every known app's verdicts. Rules can also
// change from the CLI or other programs, so it's re-read now and then, and
// right after a change made here.

import {
  api,
  errorText,
  events,
  type Direction,
  type FirewallStatus,
  type Prompt,
  type Rule,
  type Verdict,
  type VerdictsResult,
} from "./api";

const REFRESH_MS = 5000;

class Firewall {
  status = $state.raw<FirewallStatus | null>(null);
  rules = $state.raw<Rule[]>([]);
  verdicts = $state.raw<VerdictsResult | null>(null);
  /** Why there are no firewall controls (no history, or no access to Windows Firewall). */
  unavailable = $state<string | null>(null);
  /** Ask to Connect's prompts, kept current by the service's notifications. */
  prompts = $state.raw<Prompt[]>([]);

  /** Per app: its verdicts and whether it's one of win4tress's own programs. */
  readonly byApp = $derived.by(() => {
    const m = new Map<number, { in: Verdict; out: Verdict; protected: boolean }>();
    for (const a of this.verdicts?.apps ?? [])
      m.set(a.app, { in: a.inbound, out: a.outbound, protected: a.protected ?? false });
    return m;
  });

  /** win4tress's rules per app. */
  readonly rulesByApp = $derived.by(() => {
    const m = new Map<number, Rule[]>();
    for (const r of this.rules) m.set(r.app.id, [...(m.get(r.app.id) ?? []), r]);
    return m;
  });

  /** Changes are refused: another firewall is in charge, or local rules are ignored. */
  readonly monitoringOnly = $derived(this.status?.monitoring_only ?? null);

  #users = 0;
  #timer: ReturnType<typeof setInterval> | null = null;
  #unlisten: Promise<() => void> | null = null;
  /** The latest load; an older one answering late is dropped. */
  #seq = 0;

  async refresh(): Promise<void> {
    const seq = ++this.#seq;
    try {
      const [s, r, v, p] = await Promise.all([
        api.firewall(),
        api.rules(),
        api.verdicts(true),
        api.prompts().catch(() => ({ prompts: [] })),
      ]);
      if (seq !== this.#seq) return;
      this.status = s;
      this.rules = r.rules;
      this.verdicts = v;
      this.prompts = p.prompts;
      this.unavailable = null;
    } catch (e) {
      if (seq !== this.#seq) return;
      this.status = null;
      this.unavailable = errorText(e);
    }
  }

  /** Keeps the state fresh while something shows it; call the result to stop. */
  watch(): () => void {
    if (this.#users++ === 0) {
      this.refresh();
      this.#timer = setInterval(() => this.refresh(), REFRESH_MS);
      this.#unlisten = events.onPrompts((p) => (this.prompts = p));
    }
    return () => {
      if (--this.#users === 0 && this.#timer) {
        clearInterval(this.#timer);
        this.#timer = null;
        this.#unlisten?.then((off) => off());
        this.#unlisten = null;
      }
    };
  }

  /** The app's rule for a direction, action and scope kind (one each, SPEC §7.2). */
  rule(app: number, direction: Direction, action: "allow" | "block", kind: string): Rule | undefined {
    return this.rulesByApp
      .get(app)
      ?.find((r) => r.direction === direction && r.action === action && r.scope.kind === kind);
  }
}

export const firewall = new Firewall();
