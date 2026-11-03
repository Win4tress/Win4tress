# win4tress: Implementation Plan

**Status:** Draft v0.1 · 2026-10-25
**Companion:** [SPEC.md](SPEC.md) (what we're building and why)

---

## Principles

1. **Prove the risky parts first.** Phase 0 tests decide technical approaches before product code depends on them.
2. **Every phase ends with something usable** and has written exit criteria. The next phase starts only when those criteria are met.
3. **Test destructive features in a VM.** Firewall and DNS work happens in a Hyper-V VM with checkpoints, never first on the dev machine.
4. **Desired state + reconcile.** Our database is the truth; Windows Firewall is a projection of it.
5. **Release work runs alongside, not at the end.** Signing, installer, updater and docs are tracked in the [release track](#release-track).

## Milestones

| Milestone | Contents | Audience |
|---|---|---|
| **Alpha** | Phases 0–2 + release track R1 | Our own daily use |
| **Private beta** | Phases 3–4 + R2 (signed installer, updater) | Invited testers |
| **v1.0** | Phase 5 + R3 | Public |
| **v1.1** | Phase 6 (profiles, incognito, reputation, mini viewer, map) | Public |
| **v1.2** | Phase 7 (DNS filtering module) | Public |
| **v2 candidates** | WFP backend, auto-switching profiles by network, Windows Server, webcam/mic monitor, remote monitoring (mutual TLS) | — |

## Repository layout

```
win4tress/
├─ Cargo.toml                 # workspace
├─ crates/
│  ├─ w4-core/                # shared types: counters, events, locality, traffic types, rules, trust
│  ├─ w4-sys/                 # Win32 helpers: process images, device paths, version info, signatures, hashes, Mark of the Web
│  ├─ w4-etw/                 # ETW sessions + Kernel-Network / Kernel-Process / DNS-Client / WFP drop decoders
│  ├─ w4-monitor/             # in-memory traffic model: live buckets, apps, hosts, names, blocks, alerts
│  ├─ w4-ipc/                 # JSON-RPC protocol types + named-pipe server/client
│  ├─ w4-enforce/             # Phase 2: EnforcementBackend trait + Windows Firewall (COM) backend, verdicts, WFP filter → rule mapping, environment, event log
│  ├─ w4-store/               # Phase 1/4: SQLite schema, migrations, rollups, retention
│  ├─ w4-monitors/            # Phase 5: security monitors (one module each), LAN scanner, maker lookup
│  └─ w4-dns/                 # Phase 7: blocklist compiler, matcher, forwarder
├─ bins/
│  ├─ win4tress-svc/
│  ├─ win4tress-dns/
│  └─ win4tress-cli/
├─ ui/                        # Tauri 2 app (src-tauri/ + web front-end)
├─ installer/                 # WiX
├─ data/                      # curated lists: baseline services, abused system tools, traffic types
├─ tools/                     # spikes, benchmarks, test-trace recorders
└─ docs/
```

---

## Phase 0: Spikes

Each spike is throwaway code in `tools/spikes/`. Spikes 0.1–0.6 must pass before Phase 1. Spikes 0.7–0.8 must pass before Phase 7 but can run in parallel.

| # | Spike | Pass criteria | If it fails |
|---|---|---|---|
| **0.1** | **ETW collector in Rust** (do this first) | Inbound payload ≥ 95% of `GetIfTable2` bytes minus estimated headers over 24 h. 50 MB download **and** upload credited ≥ 99% to `curl.exe`. Sustained full-rate download: lost events measured and small, CPU low. Process killed outright → leftover session cleaned up and collection resumes within 2 s. Flat memory over 72 h. Attribution correct over IPv4 and IPv6, using the process ID from the event data | Switch `ferrisetw` → raw `windows` API. Last resort: a small .NET `TraceEvent` collector process feeding the service over the pipe |
| 0.2 | Windows Firewall rules from Rust (COM) | Create/update/delete rules with program, service, package and address-list conditions. Rule group works. Measure time per change and per batch | Use the `NetSecurity` WMI classes instead of COM |
| 0.3 | Named IP lists (dynamic keyword addresses) without Defender | With automatic resolution off, they work when Defender Network Protection is off or Defender is replaced by a third-party antivirus | Use inline address lists in the rules (already the design baseline) |
| 0.4 | WFP block notifications → Windows Firewall rule | Each block notification maps to the Windows Firewall rule that caused it, **including the default outbound block**. Latency from block to notification < 250 ms | Ask to Connect falls back to Security-log auditing (event 5157). Investigate further |
| 0.5 | Environment detection | Third-party firewall detected through Security Center (test with a trial of a consumer antivirus suite). Local-merge policy and forced outbound default detected | Manual setting plus documentation |
| 0.6 | UI ↔ service IPC | Tauri app talks to the service over an access-controlled pipe. Authorization check by caller token works (admin / standard / elevated). 1 Hz live stream drawn in uPlot | — |
| 0.7 | Local resolver failover | Resolver on loopback; adapter DNS switched with `SetInterfaceDnsSettings`. Resolver killed → original DNS restored within 2 s. Sleep/resume and Wi-Fi switch survive | Use the Name Resolution Policy Table (NRPT) to route lookups, or postpone Phase 7 |
| 0.8 | Blocklist compile/memory-map benchmark | HaGeZi Pro or OISD Big: ≤ 50 MB RAM with 1M domains, start ≤ 200 ms, added delay at the 99th percentile ≤ 2 ms | Adjust the data structure (e.g. a trie of domain labels) |

**Exit:** spikes 0.1–0.6 pass. Findings are written into SPEC.md (any changed decisions noted in §5 / §7).

**Status:**

| Spike | State |
|---|---|
| 0.1 | Partly passed 2026-10-25: accuracy, attribution, crash recovery, zero lost events. 24 h, 72 h, upload and IPv6 still to do. See [results](spikes/0.1-etw-collector.md) |
| 0.2 | Passed 2026-10-25: program, service, package and address-list rules; updates, deletes and the rule group work; changes apply at once; 4–11 ms per add, ~10 ms per delete. See [results](spikes/0.2-firewall-com.md) |
| 0.3 | Partly passed 2026-10-25: with Network Protection off, keyword addresses work (an update takes effect within 0.2 s). But COM reads a keyword rule's addresses as `*`, so using them would need a second (WMI) API. **Inline address lists stay.** Third-party antivirus case needs the test VM. See [results](spikes/0.3-dynamic-keywords.md) |
| 0.4 | Passed 2026-10-25: every block maps to its rule (filter name = rule name), **including the default outbound block**. Latency met by real-time ETW (`Microsoft-Windows-WFP` event 1001) in its own session: ~0.13 s from attempt to callback. Net events arrive in ~1 s batches. See [results](spikes/0.4-wfp-block-notifications.md) |
| 0.5 | Partly passed 2026-10-25: Security Center products and health, per-profile firewall state, modify state and the Group Policy/MDM keys all read correctly, without elevation. Third-party firewall and Group Policy cases need the test VM. See [results](spikes/0.5-environment-detection.md) |
| 0.6 | Not run as a spike; the IPC pipe, caller-token authorization and the uPlot live graph were built and verified in Phases 1–2 |
| 0.7 | Passed 2026-10-26 (sleep/resume and Wi-Fi switch not testable in the VM): routed in 75–160 ms; resolver killed → lookups working again in 1.7 s. **NRPT chosen over changing adapters' DNS.** See [results](spikes/0.7-resolver-failover.md) |
| 0.8 | Passed 2026-10-26: 1M domains in a 9.5 MB memory-mapped file, 0.2 ms to the first answer, 1.8–2.6 µs at p99. See [results](spikes/0.8-blocklist-matcher.md) |

## Phase 1: Monitor (read-only), size L

**Goal:** a useful network monitor that changes nothing on the system.

- [x] Service skeleton: Windows service (install/uninstall, restart on failure), console mode, `tracing` logs, cleanup of leftover ETW sessions
- [x] ETW collector made production-ready: `w4-etw` with event-data PIDs, 250 ms flush, UDP orientation fix, health counters; a watchdog restarts the session within 10 s if something outside stops it (health reports `running` and `restarts`); console runs on their own pipe get their own session name; regression test that replays a recorded `.etl` (`tools/dev/record-trace.ps1`); property tests on the decoder in place of fuzzing
- [x] App identity: path-based apps, Store package captured, PID reuse via Kernel-Process start events, System, friendly names and publishers from version info, protocol-overhead total, `svchost` split by hosted service. `ProcessSequenceNumber` is decoded but not needed: network events carry only the PID, and start events already handle reuse
- [x] Hostnames and classification: names from each app's DNS-Client lookups, reverse-DNS fallback, traffic types (with local-port fallback), local/internet, this PC's own addresses ignored, DB-IP country and network owner (ASN) (`w4-geo`)
- [x] Store: 1 s in-memory live buckets (10 min) by event timestamp; SQLite (`w4-store`) with per-minute app×host traffic kept 48 h, DNS lookups kept 30 days, and the app table so IDs survive restarts
- [x] IPC protocol v1: read methods + live sample stream over an access-controlled pipe; caller PID recorded (authorization in Phase 2)
- [x] UI:
  - shell, disconnected screen, light/dark, close to tray with the current rate in the tooltip
  - **Traffic**: Graph | Usage views; 1/5 min live and 1/3/24 h from history; click or drag on the graph for a breakdown; most active
  - **Usage**: Apps / Hosts / Traffic type / Countries columns with cross-filtering, pinned totals strip with WAN/LAN split and drag-select timeline
  - **Apps**: a table (PID, publisher, file version, path, busiest current host with "+N more", live down/up rates, last-minute graph), grouped into active and not active, sortable; rows expand to totals and every host with its network owner. Columns drop out as the window narrows. The service has a manifest declaring Windows 10/11 support; without it, Windows reports its own files as version 6.2
  - **Connections**: open and recently closed TCP connections and UDP flows; one-off UDP lookups (DNS, mDNS, LLMNR, NetBIOS, SSDP) expire after 15 s
  - **DNS**: a dashboard (1 h / 24 h / 7 / 30 days from history): lookups, failed, percent failed and domains; stacked columns of answered vs failed and of lookups by app; query types, results and top apps; top domains and top failed domains, which open the query log. Failed lookups stand in for "blocked" until Phase 7. A full-width query log by app with failures is the second view
  - real executable icons, country flags; status shows when the collector is restarting
- [x] CLI: `status [--json]`, `apps`, `hosts`, `connections`, `dns [--top]`, `watch`

**Status 2026-10-25:** all Phase 1 features are built. Verified on the dev PC: an outside `logman stop` is recovered in 5 s with no lost events; two console instances run side by side; history survives a restart; working set is about 23 MB. The exit tests below have not been run yet.

**Built early (2026-10-25):** the alert framework and the **Alerts** tab, because they need nothing from the firewall. Alerts are raised by the monitor, kept a year in history (`alerts` table, schema 4), pushed to the app as they happen, and listed by day with read/unread, type and time filters and search; `win4tress alerts` lists them too. Monitors so far: app info changed (version and publisher), first network activity, RDP connection, and monitoring interrupted. The items below in Phases 2, 3 and 5 say what's left of each.

**Exit:**

- [ ] 72 h test in the VM within the §16 targets, with accuracy within 5% (`tools/dev/soak.ps1` collects the numbers).
- [ ] The UI reflects new traffic within 1 s. Today it's about 1.5–2.25 s: a second is published once it has closed plus a 1 s allowance for late ETW events (`CLOSE_LAG_MS`). Measure how late events really arrive before shortening it, or relax the target. Spike 0.4 found that with per-CPU buffers, ETW delivers a quiet provider's events about twice the flush timer late (~0.5 s at 250 ms). One set of buffers halves that, and a shorter flush cuts it further.
- [ ] A cold install on a clean VM works.

## Phase 2: Firewall (Click to Block, Block All), size L

**Goal:** per-app control with full safety rails.

**Started 2026-10-25.** Foundations built and verified end to end on the dev PC (block, outside disable and outside delete both put back within the 60 s check with an alert, allow, delete): the `w4-enforce` crate, rules and audit in history, the reconcile loop, IPC change methods with caller checks, CLI `firewall` / `block` / `allow` / `delete-rule`, uninstall cleanup.

**Also verified end to end, same day:**
- Blocking from the Apps table switch.
- Mode Off and back.
- Outside disable and delete put back ~1.2 s after Windows logged them, then kept from the alert (UI and CLI).
- Reset is refused without elevation, works elevated, and works with the service stopped. Nothing was left behind.

**The rest of Phase 2's features, built and verified end to end the same evening** (a test copy of curl, made unsigned and marked as downloaded):
- A host rule by address blocked that address only; "allow only" blocked everything else (loopback stayed open); a host rule by name covered the IPv4 and IPv6 addresses the app had looked up.
- DNS over HTTPS to 1.1.1.1 raised "App uses its own DNS"; blocking it stopped that and left other traffic alone.
- Each blocked attempt was listed with the rule that blocked it.
- Trust read as unsigned, user folder, downloaded from its URL (zone 3), with its SHA-256. Windows Firewall's rule naming the app was listed.
- With "Require elevation" on, unelevated changes were refused (code -32006); off again, they worked. `rules.apply` made batches.
- Tamper detection now compares with what win4tress last wrote. The first run raised a false alert for win4tress's own new rules at startup; the second raised none.
- Block All, live over Remote Desktop (agreed beforehand): the CLI warned and changed nothing when the answer was no; with `--yes`, internet traffic was blocked while loopback still connected, blocked attempts were attributed to "win4tress: Block All", the app showed a red status and banner, and the internet was back 60.6 s after a 1-minute Block All started. The session dropped and reconnected as expected.
  - Found on the way: a failed filter lookup was cached for good, so 1,314 drops of the RDP connection read "a filter removed since". Failed lookups are now retried after 5 s and say "a filter that couldn't be looked up (#id)".
  - While blocked, the Traffic view still showed upload: the ETW send events come before WFP drops the packets. To look at with the Phase 1 accuracy work.
- Turning Windows Firewall on wasn't run, since it's on here. Monitoring-only needs the VM with a third-party firewall. The service-restart case of a timed Block All wasn't run.

- [x] `EnforcementBackend` trait + COM backend on its own thread (`w4-enforce`); desired-state `rules` table and `rule_audit` (schema 6–7, ids never reused); reconcile loop at start, after every change and every 60 s; pure plan with property tests. Console runs use their own rule group
- [x] Mode "Off": the group is switched off in one call and the rules are kept; switching back turns them on. Stored in history, audited, shown in `firewall.status`; `win4tress mode`, and the header's Firewall menu. Ask to Connect (Phase 3) is a separate item
- [x] Rule naming and grouping; protected components (the service, app and CLI get outgoing allow rules; blocking them is refused; a lock in the app); saving and restoring original profile settings: history keeps the first snapshot and reset and uninstall put it back. Nothing takes a snapshot yet, because nothing in win4tress changes a profile default until Ask to Connect (Phase 3), which will take it first
- [x] **Firewall** screen.
  - In/Out switches in the Apps table. The knob is win4tress's setting; the track shows what actually happens (teal allowed, gray blocked by Windows, coral blocked by win4tress), from per-app verdicts that include Windows Firewall's own rules (`firewall.verdicts`, `win4tress why`). A click blocks, or removes the block. Where no rule means blocked (outgoing in Ask to Connect) it sets an allow rule; that branch is untested until Phase 3. A switch never adds an incoming allow rule.
  - A **Firewall** tab: every app from history (`apps.all`) with its verdicts and rule count; search; filters (all, blocked by win4tress, can connect out, host rules, flagged); checkboxes and a bulk bar (block outgoing or incoming, stop blocking, remove rules) → preview → one `rules.apply`, with removals called out.
  - The app's detail: win4tress's rules with their hosts (each removable), adding host rules and "allow only", **Allow incoming connections…** (confirmed, says what it replaces), the own-DNS block, Windows Firewall's rules naming the app (`firewall.app_rules`), trust facts and 30 days of blocks. The Apps table's expanded row has a **Block** button per host and a link to it.
- [x] Per-host rules: block-hosts; allow-only-hosts via complement address lists (loopback left open); names resolve to the addresses this app received, refreshed within 5 s of new answers; `win4tress block --hosts / --allow-only`
- [x] **Block All** with durations (15 min, 1 h, until off), RDP warning (refused over Remote Desktop unless confirmed) and automatic revert, also across a service restart; `win4tress block-all`. Verified live 2026-10-25 (above)
- [x] Firewall on/off; `win4tress-cli reset` (elevated): removes our rules, restores the saved defaults. Uninstall already removes the `win4tress` group's rules (stored rules stay in history). `win4tress reset` deletes every stored rule (audited), empties the group and returns to Click to Block; with the service stopped it works on the group and database directly. Turning Windows Firewall on for a profile: the Firewall menu, a banner, `win4tress firewall-on` (not run on the dev PC, where it's on)
- [x] Environment detection + status header + monitoring-only mode: the header's firewall status opens the Firewall menu (profiles with **Turn on**, mode, Block All, Require elevation); with a third-party firewall in charge or local rules ignored by policy, changes are refused and the app explains why. **To verify in the VM** with a third-party firewall and Group Policy
- [x] Tamper detection (event channel + 60 s diff) → "Firewall changed outside win4tress" alert with Restore/Accept. The firewall event log wakes a check 0.5 s after an outside change: put back ~1.2 s after Windows logs it (was up to 60 s). Changes are restored at once. The alert lists what changed per rule; **Keep these changes** (UI, or `win4tress keep-changes`) adopts deletes, on/off and allow/block. Profile defaults join the diff with Ask to Connect, which is the first thing to change them
- [x] "Blocked by …" from WFP block notifications: a dedicated real-time ETW session (`Microsoft-Windows-WFP` event 1001, 50 ms flush), filter ID resolved to the rule as each event arrives (spike 0.4). Drops are counted per app, address, port and cause, kept 30 days; the Connections screen's **Blocked** list, the Firewall detail, `win4tress blocked`
- [x] Trust tier 1 (signature with catalog fallback, signer, SHA-256, path class, Mark of the Web, first seen) + **App info changed** alert for version, publisher, signer and same-version file changes; a signed app turned unsigned is critical. Badges in the Apps and Firewall lists
- [x] "App uses its own DNS" detection + one-click per-app block (ports 53/853 and known DoH servers), from the alert, the Firewall detail or `win4tress block --own-dns`
- [x] IPC authorization enforced; "Require elevation" hardening option. The caller's token is read by impersonation; rule changes need Administrators membership (elevation not required) and are audited with the user SID and process ID. With the option on, changes need elevation; the app retries them through an elevated helper (UAC). The option itself needs elevation, on or off

**Exit:**

- Rules survive reboot.
- Uninstall test leaves zero `win4tress` rules and restores the original profile settings.
- Tampered rules are detected and restored.
- Monitoring-only mode verified with a third-party antivirus installed.
- **Alpha:** daily use starts.

## Phase 3: Ask to Connect, size M

**Built 2026-10-25, and verified end to end on the dev PC** (details below the list).

- [x] Switch the outbound default with save/restore: blocked on every profile once the baseline rules are in; the original settings saved first (once) and put back on leaving the mode, before the baseline rules go; a default changed from outside is put back with an alert; unavailable when policy sets the outbound default
- [x] Baseline allow-list (`data/baseline-services.txt`, 26 services and programs, matched by service SID) created up front; automatic allow on first block for Microsoft-signed programs in the Windows folder (and the kernel), **except** commonly abused tools (`data/abused-system-tools.txt`, 32 names), which prompt. Drops carry the process ID, so an svchost drop is told apart by service
- [x] Learning mode: pre-allow apps seen in the last 7 days. The Firewall menu lists them when Ask to Connect is chosen (flagged ones unticked); `win4tress mode ask-to-connect --allow-recent`
- [x] Pipeline from block notification to prompt: one prompt per app at a time, 5 shown per minute (the rest wait), 60 s then pending, `prompts.changed` notifications; `win4tress prompts`, `win4tress decide <id> allow|block|later [--host]`
- [x] Prompt window with trust signals; Allow / Block / Decide later; scope whole app or this host. A small window on top, shown when a new prompt opens; "N waiting" in the header and the tray tooltip. **Since 2026-10-28 the card** (SPEC §7.4): in the corner above the taskbar, never taking the keyboard, waiting out full-screen apps; also offers **Block** for new apps in Click to Block
- [x] **First network activity** alert (built early): an app's first traffic ever, after a 1-hour learning period from the first run; apps with traffic in history count as known

**Verified end to end (2026-10-25, console service, profile defaults recorded and put back by the test):**
- Turning it on with recent apps allowed: 39 apps allowed, 26 baseline rules, outbound default Block on all three profiles.
- A never-seen program in a user folder was blocked, prompted within ~2 s, and was allowed from the prompt window's **Allow**.
- nslookup (Microsoft-signed, in System32) was allowed without asking on its first block; finger.exe (Microsoft-signed, but on the abused list) prompted and was blocked with `decide`.
- The Public profile's outbound default set to Allow from outside was put back in 1.8 s, with an alert.
- Back to Click to Block: the original defaults restored, baseline rules removed, prompts cleared. Nothing left behind.
- Not yet: the week-long VM run below. The case of no app connected to answer: prompts go pending, and since 2026-10-28 the card shows them when the app connects (not yet checked live in Ask to Connect).

**The card, checked live (2026-10-28, installed service, a test copy of the app, Click to Block):** a renamed copy of curl.exe connecting out got the card within seconds, in the corner (15 px from the work area's right and bottom edges at 125%), on top and not activated. **Block** made an outgoing block rule and closed the card; the program's next connection failed (rule then deleted). **OK** closed it; unanswered, it closed itself after 65 s. Two new apps at once: the first went after 63 s, then the second showed for its own full minute (it doesn't count down while waiting behind another). With the card closed, the test copy had no WebView2 processes left. A real new app (Microsoft Defender's service, after an update) came up in the same card with its icon and publisher. Not checked live: Ask to Connect's prompts in the card (layout checked with mock data), and waiting out a full-screen app.

**DNS counts stuck at 0, installed (found 2026-10-28):** filtering worked (`ebay.com` on the user's deny list and `pagead2.googlesyndication.com` answered `0.0.0.0` over UDP, TCP and through Windows), but the Filtering view and `dns-filter` showed 0 lookups and the log was empty. `\\.\pipe\win4tress-dns` didn't exist: the resolver, running as LocalService, had only "create instance" on its pipe, and opening the next instance also takes read and write, so after the service's first poll the pipe server ended. Console runs never showed it (the resolver has the console's account there). Fixed: LocalService gets `GRGW`; the IPC server retries the next instance instead of ending; the service reports an unreadable resolver as a problem. A test opens the next instance with only the resolver's rights (with the old entry: "Access is denied").

**Five additions (2026-10-29, 0.1.7):** temporary rules (for a time, until the app quits, until Windows restarts, going back to what they replaced), profiles switched by the network the PC joins, export and import of rules and profiles, ending an app's connections, and search everywhere (Ctrl+K) (SPEC §7.2, §7.6, §10.2). Checked by tests: the store's temporary rules (standing in, going back, never shortening a rule for good, a toggle making them permanent), profile networks kept on saving, the choice of profile (named over kind, online networks only), boot time, Network List Manager, `--for` parsing, and ending a TCP connection (refused unelevated; elevated, the client gets a reset). Checked through the service's own request handling, with a stand-in for Windows Firewall: a temporary allow going back to the block in Windows Firewall when its time is up, audited as the service's; a rule until its program quits ending when a real program exits; the restart rule carrying Windows' boot time; the refusals; an export imported on a fresh store (dry run first, a rule of the same kind replaced, the profile pointing at the new rule ids, a second import changing nothing); and a profile switched by itself for this PC's real connected network, a switch by hand standing until the networks change. Checked in headless Edge with mock data, light and dark: the card's How long, an app's Block for…/Disconnect and the switches' clock, the firewall detail's temporary rules, the profile networks editor, Settings → Rules and profiles with an import preview, Connections' ×, and search. **Not checked live yet** (the run against a console service was stopped at its UAC prompt): the rules in real Windows Firewall, Disconnect resetting a real connection through the service, the run loop waking for a program quitting, the app's Save and Open dialogs, and search in the real window.

**Blocked apps, found (2026-10-28):** in Ask to Connect, Acrobat's web helper (AcroCEF.exe) was blocked from its first attempt, so it never had traffic and was missing from the Apps tab, and `win4tress why AcroCEF` answered "no app matches". Now the Apps tab lists such apps under **Blocked, no traffic** with their attempts and switches (checked live: "Adobe AcroCEF · Blocked 2× · geo2.adobe.com", header "· 1 blocked"), and the CLI's lookups fall back to every known app (`why AcroCEF`: outgoing blocked by a win4tress rule). The card names what a helper belongs to: AcroCEF's file says only "Adobe AcroCEF", so it's its install folder, "in Adobe\Acrobat DC" (14 path cases checked).

**Exit:**

- A clean Windows 11 VM runs a week of normal use in Ask to Connect. Windows Update, Store, Defender updates, activation and time sync all work **with no prompts**.
- Prompts appear within 1 s.

## Phase 4: History & usage, size M

**Built 2026-10-25, and checked live against a console service** (details below the list).

- [x] Full rollup tiers and retention jobs (SPEC §9.1); size budget checked against a synthetic year of data. Schema 9: per minute and app (35 days), per hour, app and host (2 years), per local day by one dimension (kept), DNS day counts after 30 days, idle spans. Every flush writes every tier, so they agree; queries pick the finest tier that covers the range and the filter. A year of busy use is 158 MB (budget 500 MB). `cargo test -p w4-store --release synthetic_year -- --ignored --nocapture`
- [x] Graph ranges 3 h / 24 h / week / month; alert markers; idle shading; pause; PNG export (to Pictures\win4tress). The **timeline scrubber** is, for now, stepping back and forward a range at a time (‹ › Now); a draggable overview strip is a follow-up
- [x] Filters: apps / traffic types / publishers / countries, and internet or local network only
- [x] **Usage** screen: day/week/month (weeks from Monday), calendar (a date picker and ‹ ›), breakdowns by app, host, publisher, traffic type and country, local/external filter
- [x] Data plan: monthly limit, reset day (1–28), warning thresholds (75/90/100%), metered awareness (shows a metered connection; can count only metered traffic) → bandwidth alert. `win4tress plan`
- [x] VPN clients labelled (`data/vpn-clients.txt`); "exclude from totals" for the graph, usage and the live view. `win4tress exclude-vpn on|off`

**Checked live (2026-10-25):** 7 days at 10-minute steps, 30 days hourly and 30 days by day gave the same totals; since local midnight two days back, usage and graph totals were equal for all traffic, internet only and local only; a 1 kB data plan raised its 100% alert within a minute; leaving out VPN clients took exactly Tailscale's bytes off the totals; Export PNG wrote the file. Idle shading needs the app running to report input, and wasn't seen live (no 10-minute absence during the test); it's unit-tested.

**Exit:**

- Month view ≤ 500 ms with a year of data. **Met:** 63 ms for the graph, 189 ms for usage, on a synthetic year.
- Usage totals match graph totals. **Met:** equal live and in tests.
- **Private beta** (requires R2).

## Phase 5: Security monitors, alerts, network scanner, size L

**Built 2026-10-25, and checked live against a console service** (details below the list; as built: SPEC §10.2 Network, §11).

- [x] Monitor framework: one module per monitor in `w4-monitors` (pure checks over what Windows reports, memory kept in history), an on/off switch and a severity per alert kind, trigger tests (`docs/monitor-tests.md`)
- [x] Monitors: system files, adapters, DNS servers, proxy (the user's through the app, and machine-wide), internet access (off by default), ARP spoofing, Wi-Fi evil twin, suspicious hosts, while you were away. RDP was already done (inbound accept on port 3389, once per address per 12 h)
- [x] Suspicious hosts: abuse.ch **Feodo Tracker** daily (not on metered connections), and the user's own list. URLhaus and ThreatFox need an abuse.ch Auth-Key since 2025 (anonymous downloads answer 410): a follow-up, with the user's key
- [x] **Alerts** screen: sort by date, app or type; kinds grouped in the filter; a **Monitors** panel; desktop pop-ups (warnings and critical by default) with **snooze 24 h** per app or kind; copy to the **Windows Event Log** (source "win4tress", an event id per kind); critical alerts marked by shape as well as colour
- [x] **Network** screen: scanner (private networks with a gateway only), maker from the IEEE registry (`tools/dev/fetch-oui.ps1`), known/unknown devices, automatic scans every half hour with the new-device alert. CLI: `scan`, `devices`, `scanner`, `monitors`, `monitor`

**Checked live (2026-10-25), two runs in the VM:** a file created in `drivers\etc` alerted, and its deletion was dropped while the monitor was off; the machine proxy set and restored alerted both times, at the chosen severity (critical); `curl` and PowerShell reaching a name on the own list alerted (a list saved with Notepad's byte-order mark read right after a fix); "While you were away" summed up a 40-minute absence (bytes, three busiest apps, 10 alerts); the Event Log got every alert with its id and level; the scan of 192.168.1.0/24 found 10 devices with names and makers in 21 s; a desktop pop-up appeared with the window minimized. Bugs found and fixed on the way: the CLI didn't wait for a scan it started (the scan showed as running only once its thread did), name lookups ran one at a time (39 s for 9 devices), and the own list counted a byte-order mark as a name. The settings changed for the test were put back.

**Not triggered live** (no safe way in this VM; unit-tested, procedures in `docs/monitor-tests.md`): new adapter, DNS servers, internet access, ARP spoofing, Wi-Fi evil twin (the VM has no Wi-Fi), new device (needs a device joining after the first scan).

**Exit:**

- Each monitor has a reproducible trigger test in the VM. **Written** (`docs/monitor-tests.md`); five of the twelve were triggered live (system files, machine proxy, suspicious host, while you were away, Remote Desktop), the others need a second machine, Wi-Fi, a device joining or a network change.
- False-positive review passed: evil twin on mesh Wi-Fi, ARP during DHCP renewal, adapter changes from VPN connect/disconnect. **Covered by unit tests** (same name and security on many access points; incomplete and unreachable ARP entries; adapters seen before); a real mesh network and a VPN reconnect are still to try.
- **v1.0** (requires R3).

## Phase 6: Polish (v1.1), size M

**Built 2026-10-26** (as built: SPEC §7.6, §7.10, §8.4, §10.2, §12).

- [x] Profiles (manual switching), with a per-rule on/off switch so profiles can differ; automatic cleanup (uninstalled apps on, inactive apps off; blocked attempts count as activity)
- [x] Incognito: global and per app
- [x] Reputation tier 2: CIRCL → VirusTotal hash lookup with the user's key (DPAPI-encrypted), MalwareBazaar optional (abuse.ch key), cache, prioritised queue within VirusTotal's free limits
- [x] Reputation tier 3: scan with installed antivirus (`IOfficeAntiVirus`, what `IAttachmentExecute` calls, without its Mark-of-the-Web side effect), VirusTotal upload with warning; optional auto-block threshold; "Reputation" alert
- [x] Mini viewer; geo map view (Natural Earth, Equal Earth projection, one-hue log scale); a Settings tab. Themes done early (2026-10-25): light and dark from the swatch board, "Match Windows" / Light / Dark in the header, title bar included, basic Windows high-contrast support. Left: moving the picker to Settings
- [x] Switching profiles by network (2026-10-29, SPEC §7.6)
- [x] Exact profiles (2026-10-30, 0.1.14, SPEC §7.6): each rule on held in full, every other rule off while a profile is active, so the Apps tab's switches are saved and put back. Checked by tests: the store putting rules back as saved (made again after a delete, set back after allow ↔ block, others turned off not deleted), each Apps tab change counting as changed, baseline, reputation and temporary rules left alone, cleanup taking an app out of profiles, and schema 13 profiles converted; through the service's request handling, the Apps tab's unblock and block saved as two profiles and switched between, checked in the stand-in Windows Firewall; and an export carrying profiles' rules in full to another PC. Not checked live yet.
- [x] DNS filtering in profiles and in the rules export (2026-10-30, 0.1.13, SPEC §7.2, §7.6). Checked by tests: the store saving it without a pause, "changed" by any DNS setting but not a pause, and a profile from before holding none; through the service's request handling, switching putting DNS filtering back with this PC's pause kept, a profile whose blocklist is gone refused before anything changes, and an export carrying it to another PC (dry run first, the profile holding it, a second import changing nothing). Checked in headless Edge with mock data: the Firewall menu's profiles and Save changes, and the import preview. Not checked live yet.
- [x] Indigo themes, light and dark (2026-11-01, 0.1.15, SPEC §10.3): after the Skote admin template's palette, picked under Colours in the header's theme menu, with Match Windows / Light / Dark as before. Text colours checked at 4.5:1 or more on each surface; chart and map palettes run through the palette validator (the map's near-zero step recedes toward the surface, as in the win4tress ramps). Checked in the headless Edge mock (Traffic, Apps, Firewall, Settings, the menu); not checked live yet.
- [x] Settings as a gear button at the right end of the header, after the theme button, instead of a tab; Indigo dark the default theme until the user picks one (2026-11-01, 0.1.16, SPEC §10.2, §10.3). Checked in the headless Edge mock; not checked live yet.
- [x] New emblem (2026-11-02, 0.1.17, SPEC §10.3): the user's teal and amber design, redrawn as an SVG on its isometric grid (`assets/logo/emblem.svg`). The app shows the SVG; `make-logo.py` draws every icon size from it, with no light ring. Icon sizes checked at 16-64 px on light and dark; not checked live yet.
- [x] About in Settings (2026-11-02, 0.1.18, SPEC §10.2): the app's version, the service's (a warning when they differ), Windows' edition and build from the registry, **Copy details**, the licence, and the data credits as links; also in Ctrl+K search. Checked in the headless Edge mock; not checked live yet.
- [x] Local names with DNS filtering on (2026-11-02, 0.1.20, SPEC §13): a one-label or `.local` name the network's DNS doesn't know is looked for on the local network (LLMNR, mDNS). Before, filtering's routing rule made Windows give up on names like `\\garrserver`. Tested against a server on the dev network: `w4-sys` and resolver tests, and a resolver on a spare port (found in under 50 ms; an unknown name still NXDOMAIN after about 1.3 s); not checked live with the installed service yet. Also: a network Windows lists as connected but reports as not connected (Tailscale signed out, its adapter up) no longer counts as connected for switching profiles.
- [x] One-label names with DNS filtering on (2026-11-03, 0.1.22, SPEC §13): `\\garrserver` still failed on two PCs with 0.1.21; the query log showed Windows' own `ERROR_INVALID_NAME` and the resolver never saw the lookup. With the routing rule's `.` namespace Windows treats a one-label name as a DNS name, refuses it, and doesn't try LLMNR, mDNS or NetBIOS, so the 0.1.20 and 0.1.21 fixes in the resolver never ran for such names (0.1.20 seemed to work because filtering was off, or SMB reused a connection made while it was; a wake drops that connection). The rule now lists every public top-level domain instead (IANA's list, bundled in `w4-sys`). Spike on the dev VM with the rule cut to `.com .net .org`: `\\garrserver` 192.168.1.226 and `garrserver.local` resolved by Windows itself, a `.com` name still through the resolver, a `.co.uk` one not; restored after. Not yet checked with the full list: Windows accepting about 1,450 namespaces in one rule is what installing 0.1.22 tests. To do: refresh the list with the blocklist updates, so a new top-level domain is filtered without a new version.
- [x] Local names after sleep (2026-11-03, 0.1.21, SPEC §13): a PC that woke from sleep couldn't reach LAN names until the service was stopped (which flushes Windows' DNS cache). Not the cause after all (see 0.1.22), but real, and fixed: Windows reports no internet for a while after a wake, which puts the resolver in pass-through, and pass-through never looked on the local network; an NXDOMAIN given before the network was up could stay in Windows' cache for up to 15 minutes; the resolver kept it 60 s itself, ahead of the local-network search, and a failed search 30 s. Now pass-through searches too, a name nothing has gets an NXDOMAIN kept 5 s and not cached, and a config change clears the searches. Reproduced with a resolver on a spare port in pass-through (`\\garrserver` NXDOMAIN before, found after); resolver live tests pass in both modes. Not yet seen through a real sleep, and the logs from the PC that slept haven't been read yet.
- [x] Unblock from the DNS query log (2026-11-03, 0.1.23, SPEC §13): a blocked row has **Unblock**, which puts the name on the allow list (a deny rule for exactly it goes) and then shows "allowed now". The service stops labelling later lookups of it blocked, and empties Windows' DNS cache 1.5 s after any allow, deny or regex change, so the blocked 0.0.0.0 Windows kept for a minute doesn't outlast it.
- [x] New-app card for 6 s (2026-11-03, 0.1.23, SPEC §7.4): Click to Block's card for a new app goes after 6 s as the item showing, not a minute; off the card it gets at least 3 s more (was 10 s). Ask to Connect's prompts still wait for an answer. Alert pop-ups are Windows notifications, whose time on screen is Windows' own setting (Accessibility → Visual effects → Dismiss notifications after; 5 s at the least), not the app's.
- [ ] Not done: the rest of the Settings screen (units, language, data location)

**Checked live (2026-10-26), against a console service in the VM:** with curl incognito, its 29 KB showed in the live view and nothing in history, while other apps' history grew; Defender scanned curl's file through `IOfficeAntiVirus` (clean, 0.5 s); a malformed VirusTotal key was refused; a copy of curl that got a rule and was deleted showed in cleanup as gone ("not yet", due after 7 days); profile "Travel" turned a curl block rule on in Windows Firewall (curl failed to connect) and "Home" turned it off (curl got through); the mini viewer's window opened from the header button of a test window (but see the correction below). Test rules and profiles were removed and settings put back. Found and fixed on the way: CLI commands documented as taking an app ID only matched names (`block 164` failed). Not checked live: hash lookups (they would send every app's hash out; unit-tested against CIRCL's real answers and VirusTotal's and MalwareBazaar's documented ones), uploads (need a VirusTotal key), and the mini viewer's look on screen (screen capture isn't available to the test tools; checked in a rendered mock-up).

**Correction (2026-10-26):** the mini viewer didn't work. Its window opened but its page stayed `about:blank`: on Windows, a window opened from a synchronous Tauri command never loads its page (wry#583). The transparent window then showed nothing, and the black capture hid it. `mini_toggle` and `show_prompts` (which can open the Ask to Connect window) are now async. Checked through WebView2's DevTools port: the page loads with live rates and graph and an 85%-opaque card; it closes with × and opens again.

## Phase 7: DNS filtering module (v1.2), size L

Requires spikes 0.7 and 0.8.

- [x] `win4tress-dns`: UDP/TCP forwarder on loopback, started and watched by the service, as LocalService when installed; DNS messages hand-written and property-tested (SPEC §20 #9)
- [x] Blocklist catalogue (licence shown per list), downloads that skip unchanged lists (ETag), compiler, memory-mapped matcher with parent-name lookups, regex rules (capped)
- [x] Allow/deny/regex rules, pause, CNAME inspection, local records, stats, query log (the resolver's, and Windows' DNS log by app labelled "Blocked: …")
- [x] Encrypted upstream: DoH with a connection that closes when idle. DoT dropped (SPEC §20 #10)
- [x] Routing by an NRPT rule rather than adapters' DNS (spike 0.7); watchdog removes it within 2 s; turning off, `reset`, the service stopping and uninstall remove it too
- [x] Captive portals, split DNS, VPN DNS, router-provided IPv6 DNS, port-53 conflicts; an ad-blocking DNS server upstream detected → observe-only; Firefox canary domain
- [x] ~~Per-host firewall rules match hostnames exactly when the module is on~~: not possible, since Windows' DNS Client asks for every app (SPEC §20 #11)
- [x] App: DNS → Filtering, blocked labels in the query log, the "DNS filtering set aside" alert; CLI `dns-filter`, `dns-lists`, `dns-allow`, `dns-deny`, `dns-pause`, `dns-upstream`, `dns-log`

**Exit:** resource targets met (SPEC §16), and the failover test matrix passes:

- resolver killed
- sleep/resume
- Wi-Fi switch
- VPN connect/disconnect
- hotel/café sign-in page
- uninstall while active

**Checked live (2026-10-26), against a console service in the VM:**

- **Routing.** Turned on, the service downloaded HaGeZi Normal (170,463 domains, 4.2 s) and routed Windows' lookups to the resolver. Windows applied the registry rule: the effective policy showed `.` → `127.0.0.1;::1`. Tailscale's own NRPT rules kept winning.
- **Answers through Windows' DNS client.** Listed names got `0.0.0.0` and `::`, the Firefox canary NXDOMAIN, a local record its address, other names their real addresses.
- **Your rules from the CLI.** Deny, allow (over a listed name), pause and resume all took effect.
- **DoH.** With Cloudflare as upstream, the resolver held an HTTPS connection to Cloudflare and answered through it.
- **Labels.** Windows' DNS log labelled the blocked lookups "HaGeZi Normal: g.doubleclick.net".
- **Watchdog.** Resolver killed: rule removed after 1.71 s, lookups working 1.80 s after the kill, the alert raised, filtering back 3 s later.
- **Off and stop.** Turning off removed the rule in 0.3 s. The service stopping removed it too.

Found and fixed on the way:

- Settings changes waited for a 5-second cycle (4.6 s for a deny rule); they now apply at once.
- The resolver wasn't among win4tress's protected programs, so Ask to Connect would have blocked its upstream while the local health checks still passed.
- The resolver would have been flagged as "uses its own DNS".
- Removing a list of your own handed its download to the next one.
- A resolver left by a crashed service kept port 53.

**Not yet checked live:** the resolver as LocalService (needs the service running as SYSTEM; a second run's UAC prompt was cancelled), the resolver's memory and CPU against SPEC §16, uninstall while active, and the matrix items the VM can't do (sleep/resume, Wi-Fi switch, VPN connect/disconnect, a sign-in page).

---

## Release track

Runs alongside the phases. Each item is due by the milestone shown.

| ID | Item | Due by |
|---|---|---|
| R1 | CI: build, clippy, fmt, tests, `cargo-deny`, short fuzz run; unsigned dev MSI (x64) | Alpha |
| R1 | Hyper-V test VM image + checkpoint workflow documented | Alpha |
| R2 | Code signing in CI; signed MSI for x64 + ARM64 | Beta |
| R2 | Auto-updater with signer pinning + signed manifest; beta channel | Beta |
| R2 | Local crash dumps + opt-in upload; privacy policy draft | Beta |
| R2 | User guide skeleton, alert dictionary, known limitations page | Beta |
| R2 | Name/trademark check done; licence decided (SPEC §20). Licence: MIT OR Apache-2.0 (2026-11-02) | Beta |
| R3 | Antivirus/SmartScreen submissions for the release build | v1.0 |
| R3 | Upgrade tests (n-1 → n), uninstall-restore tests, ARM64 hardware test | v1.0 |
| R3 | About screen with third-party notices (DB-IP attribution etc.). The screen and the data credits are done (0.1.18); the notices for open-source components (crates, npm packages) are left | v1.0 |
| R3 | Website/landing page, support channel, changelog | v1.0 |

**Status (2026-10-26):** an unsigned x64 MSI (`installer/`, WiX v7, `installer/build.ps1`) installed on the dev VM, then upgraded 0.1.0 → 0.1.1:
- **Install:** the service runs as LocalSystem and starts with Windows; the app starts at sign-in and opens as the user, not elevated; the Start menu shortcut is in place.
- **DNS filtering:** the resolver runs as LocalService and filters (confirmed through the status's new `resolver_account`).
- **Upgrade:** history, settings and the sign-in choice kept; the app reopened by itself; one entry in Apps.
- **Uninstall:** removed the service, the program files, the shortcut, the sign-in entry, the DNS routing rule (with filtering on at the time) and the win4tress firewall rules. Other software's NRPT rules and the profile defaults were untouched, and history stayed in `ProgramData\win4tress`.

Not yet: CI, ARM64, signing, and a clean-VM run.

## Test strategy

| Layer | Approach |
|---|---|
| Unit | Decoders, classifiers, rule compiler, rollups, blocklist matcher |
| Recorded traces | `.etl` captures checked into `tools/traces/` for decoder regression tests |
| Fuzzing | ETW decoders, DNS messages, IPC framing (`cargo-fuzz`); short runs in CI, long runs before releases |
| Integration (CI) | GitHub-hosted Windows runners (temporary, admin): rule create/update/delete, ETW smoke test, IPC authorization |
| VM matrix | Hyper-V with checkpoints: clean Win11; a week in Ask to Connect; third-party antivirus installed; domain-joined with Group Policy; VPN client; ARM64 device |
| Soak | 72 h run per release candidate with automated RAM/CPU sampling against §16 |

## Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| ETW attribution or accuracy not good enough in Rust | Monitor is untrustworthy | Spike 0.1 first; raw API fallback; .NET collector as last resort |
| Windows Firewall rule changes too slow under IP churn | Per-host rules lag | Batching; named IP lists (0.3); WFP backend trigger (SPEC §7.12) |
| Many users run third-party firewalls | No enforcement for them | Clear monitoring-only mode; WFP backend as a v2 candidate |
| Ask to Connect baseline misses something → Windows features break | Bad first impression | Curated baseline + learning mode + week-long VM exit test; baseline list updates through releases |
| DNS module breaks connectivity | Severe | Off by default, watchdog restore, `reset`, failover matrix |
| win4tress flagged by SmartScreen or antivirus | Install friction | Signing, vendor submissions, reputation built during beta |
| `ferrisetw` or `hickory` maintenance stalls | Blocked dependency | Wrapped behind our own crates; raw-API fallbacks |
| Solo-developer scope | Slipping | Phase gates; DNS module after 1.0; v2 list stays closed during v1 |

## Next steps

1. ~~Choose the licence, then `git init` and the first commit.~~ Done 2026-11-02: MIT OR Apache-2.0; the first commit, pushed to the private repo `Win4tress/Win4tress` on GitHub.
2. Build the Hyper-V Windows 11 test VM and take a clean checkpoint.
3. Phase 1 exit tests in the VM: cold install, 72 h soak with `tools/dev/soak.ps1`, accuracy within 5%, and the live-latency measurement.
4. Spikes 0.2–0.6, then Phase 2 (firewall).
