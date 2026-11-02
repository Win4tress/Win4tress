# win4tress: Product & Technical Specification

**Status:** Draft v0.1 · 2026-10-25
**Companion:** [PLAN.md](PLAN.md) (phases, spikes, milestones, risks)

---

## 1. Summary

win4tress is a network monitor and firewall front-end for Windows 11. It shows which apps use the network, how much data they use, and where they connect. It lets the user allow or block apps, and specific hosts, through Windows Firewall. It raises alerts about suspicious network changes. All data stays on the machine.

**Positioning:** a visibility and control tool. It's lightweight (no kernel driver), keeps data local, and is honest about its limits. It is **not** anti-malware: see [Known limitations](#19-known-limitations-user-facing).

**How it stands apart from existing tools:**

- It combines three things: polished graphs and history, a complete firewall (Ask to Connect and Block All included, with no paywall), and security alerts.
- It needs no kernel driver.
- It explains every decision: why something was blocked or allowed, and trust signals in every prompt.
- It knows which app made each DNS lookup. The optional DNS filtering module (Phase 7) uses this to attribute blocks to the app that made the lookup, which a network-wide DNS filter can't do.

## 2. Goals and non-goals

### Goals (v1.0)

- The core features of a network monitor and firewall:
  - live and historical traffic graphs
  - usage per app and per host
  - per-app inbound/outbound firewall
  - Click to Block, Ask to Connect, Block All
  - security alerts
  - network device scanner
- Explain decisions: "Blocked by rule X", plus trust signals (signer, origin, reputation) in prompts.
- Keep the footprint small; see [§16](#16-non-functional-requirements).
- Send no data off the machine unless the user turns on a feature that needs it ([§15](#15-privacy)).
- Make installation, upgrade, uninstall and recovery safe: no lockouts, and no orphaned rules or DNS settings.

### Non-goals (v1)

- An anti-malware scanning engine. We use the installed antivirus and reputation services instead ([§12](#12-trust--reputation)).
- A kernel driver, or holding connections open while a prompt is up.
- Our own WFP enforcement (a v2 candidate; [§7.12](#712-v2-wfp-backend-triggers)).
- Remote monitoring of other PCs. If it's ever added, it uses mutual TLS, not a password on an open port.
- Filtering for other devices on the network, or a DHCP server. That's a job for a network-wide DNS filter.
- Packet capture, deep packet inspection, TLS interception.
- Social media sharing.
- Windows 10 and Windows Server: post-v1, best effort.

## 3. Platform support

| Platform | Support |
|---|---|
| Windows 11, supported versions, **x64 and ARM64** | v1.0 |
| Windows Server 2022 / 2025 | Post-v1, best effort |
| Windows 10 | Not supported (consumer extended support ended October 2026) |

Requirements: admin rights to install. The WebView2 runtime is built into Windows 11.

## 4. Architecture

```
┌───────────────────────────────┐  named pipe \\.\pipe\win4tress   ┌──────────────────────────────────────┐
│ win4tress UI  (per user)      │ ◄──── JSON-RPC 2.0 ────────────► │ win4tress-svc  (LocalSystem)         │
│ Tauri 2: tray, windows,       │   requests + pushed events       │ ├ ETW collector (bytes, DNS names)   │
│ Ask prompts, toasts.          │                                  │ ├ App identity + trust signals       │
│ Also the per-user agent:      │                                  │ ├ Enforcement: EnforcementBackend    │
│ idle time, HKCU proxy.        │                                  │ │   └ WindowsFirewallBackend (v1)     │
└───────────────────────────────┘                                  │ ├ WFP drop events (read-only)        │
┌───────────────────────────────┐                                  │ ├ Security monitors                  │
│ win4tress-cli                 │ ◄──────────────────────────────► │ ├ Alert engine                       │
│ status, export, backup, reset │                                  │ ├ Store: SQLite (WAL) + rollups      │
└───────────────────────────────┘                                  │ ├ Updater                            │
                                                                   │ └ DNS watchdog (Phase 7)             │
┌───────────────────────────────┐  local health checks             └──────────────────────────────────────┘
│ win4tress-dns  (LocalService) │ ◄──────────────────────────────── (svc changes adapter DNS settings
│ Phase 7, optional, off by     │                                    and restores them on failure)
│ default: 127.0.0.1/::1 :53    │
└───────────────────────────────┘
```

### 4.1 Processes

| Process | Runs as | Role |
|---|---|---|
| `win4tress-svc` | Windows service, LocalSystem, starts automatically, set to restart on failure | Collection, enforcement, monitors, storage, IPC server, updater, DNS watchdog |
| `win4tress-dns` | Separate Windows service, **LocalService** (least privilege: it parses untrusted network input) | Local DNS resolver/forwarder (Phase 7) |
| `win4tress` (UI) | Per user, not elevated; auto-start at logon | Tray, windows, prompts. Also the per-user agent: reports idle time and per-user proxy settings |
| `win4tress-cli` | Caller's account | Scripting, diagnostics, backup, emergency `reset` |

The service works without the UI. Monitors that need the per-user agent (idle detection, per-user proxy) pause while no UI is running.

### 4.2 IPC

- JSON-RPC 2.0 over the named pipe `\\.\pipe\win4tress`. The server pushes notifications (live samples, alerts, prompts, status changes).
- The protocol is versioned. Clients send `hello {protocol_version}`, and mismatches are refused cleanly.
- Pipe access list: SYSTEM and Administrators have full access; Interactive Users can connect.
- The Tauri side of the UI reuses the shared `w4-ipc` crate and relays events to the web front-end.

### 4.3 Authorization

The service checks every method against the caller's token, by impersonating the pipe client.

| Method class | Allowed callers (default) |
|---|---|
| Read (graphs, usage, alerts, rules) | Any interactive user |
| Change (rules, modes, settings) | Members of Administrators; elevation not required |
| `reset`, uninstall-time cleanup | Elevated callers only. `win4tress reset` deletes every win4tress rule (audited as "reset"), removes them from Windows Firewall and returns to Click to Block. With the service stopped, the CLI does the same directly to the installed service's rule group and database |

**Hardening option, "Require elevation for changes":** change methods accept only elevated callers. The UI sends changes through a short-lived elevated helper (a UAC prompt), so malware running as the user without elevation can't silently allow itself.

- The setting itself needs an elevated caller, on and off: otherwise an administrator's unelevated process could just turn it off. It's set in the app's Firewall menu or with `win4tress require-elevation on|off` from an elevated prompt.
- A change refused for want of elevation fails with error code -32006. The app then runs the command-line client's hidden `rpc` command elevated (`ShellExecuteEx` "runas"), which makes the one call and writes the answer to a file the app reads.
- The request goes on the helper's command line, base64-encoded, not in a file: a process running as the user can't swap what gets elevated. Only change methods can be sent this way.

### 4.4 Desired state and reconciliation

Rules and modes live in our database, which is the **source of truth**. The enforcement backend projects that desired state into Windows Firewall and continuously reconciles what's actually there against it ([§7.8](#78-reconciliation-and-tamper-detection)). Every change is recorded in an audit table: who, when, what and why.

## 5. Technology stack

| Area | Choice | Notes |
|---|---|---|
| Language | Rust (stable) | Workspace layout in PLAN.md |
| Async | `tokio` | Also provides named pipes |
| Win32 / COM | `windows` crate | Windows Firewall COM, WFP, IP Helper, WLAN, Security Center, WinVerifyTrust |
| ETW | `ferrisetw` to start; raw `windows` API as fallback | Decided by spike 0.1 |
| Storage | SQLite via `rusqlite` (bundled), WAL mode | |
| DNS messages (Phase 7) | Hand-written (`w4-dns`), property-tested | Decided in Phase 7 ([§20](#20-decisions)) |
| Encrypted DNS upstream | WinHTTP | DNS over HTTPS; DoT not offered ([§20](#20-decisions)) |
| UI shell | Tauri 2 | WebView2 |
| UI front-end | TypeScript + Svelte 5 | Decided 2026-10-25 |
| Charts | uPlot | Handles hundreds of thousands of points |
| Logging | `tracing` → rolling files, plus optional Windows Event Log | |
| Installer | WiX MSI (x64, ARM64) | Not Tauri's default bundler: we install services |
| Dependency hygiene | `cargo-deny` (licences, advisories, duplicates), `cargo-audit` | Runs in CI |
| Fuzzing | `cargo-fuzz` | DNS parser, ETW decoders, IPC framing |

## 6. Data sources

| Need | Source | Notes |
|---|---|---|
| Per-app bytes, connects/disconnects | ETW `Microsoft-Windows-Kernel-Network` | Use the **process ID in the event data**, not the event header ([§8.1](#81-etw-collector)) |
| Hostnames per app | ETW `Microsoft-Windows-DNS-Client` | Reverse (PTR) lookup as fallback |
| Snapshot of connections at startup | `GetExtendedTcpTable` / `GetExtendedUdpTable` | Startup and reconciliation |
| Adapter totals | `GetIfTable2` | Accuracy check; "System/Other" bucket |
| Blocks, and which rule caused them | Real-time ETW `Microsoft-Windows-WFP` event 1001 ("Packet Dropped", keyword `0x10`) in its own session; filter ID → rule through WFP (`FwpmFilterGetById0`). WFP net events (`FwpmNetEventSubscribe`) as a cross-check. All **read-only** | Prompts and "why blocked". ETW arrives in ~0.13 s, net events in ~1 s batches ([spike 0.4](spikes/0.4-wfp-block-notifications.md)) |
| Firewall rules and profiles | Windows Firewall COM (`INetFwPolicy2`, `INetFwRule3`) | |
| Third-party firewall present | Windows Security Center API | Switches to monitoring-only |
| Firewall changes made by others | `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` event channel, plus periodic diff | |
| Process → app identity | ETW `Microsoft-Windows-Kernel-Process` start events (`ProcessSequenceNumber`, `ImageName`, `PackageFullName`); `QueryFullProcessImageNameW` for processes already running at startup; Service Control Manager map of service process IDs | Identity keyed by `ProcessSequenceNumber`, unique until reboot ([spike 0.1](spikes/0.1-etw-collector.md)) |
| Signer, hash, version | `WinVerifyTrust`, file version info, SHA-256 | |
| Download origin | Mark of the Web (`Zone.Identifier` stream) | |
| Country, network owner (ASN) | DB-IP Lite (country + ASN) | CC BY 4.0 |
| Adapter and DNS-server changes | `NotifyIpInterfaceChange`, `GetAdaptersAddresses` | |
| Internet connectivity | Network List Manager | |
| ARP table | `GetIpNetTable2` (polled) | |
| Wi-Fi | WLAN API (`WlanRegisterNotification`, `WlanGetNetworkBssList`) | |
| RDP | Service session-change notifications, plus inbound accepts on the RDP port (ETW) | |
| LAN devices | ARP sweep (`SendARP`), mDNS/NetBIOS names, IEEE manufacturer (OUI) list | |
| Idle time, per-user proxy | UI agent (`GetLastInputInfo`, HKCU Internet Settings) | |
| Set adapter DNS (Phase 7) | `SetInterfaceDnsSettings` | |

## 7. Firewall (enforcement)

### 7.1 Modes

| Mode | What the user sees | Windows Firewall implementation |
|---|---|---|
| **Off** | win4tress rules inactive; Windows Firewall behaves as before | Disable the win4tress rule group in one call (`EnableRuleGroup`); the rules stay, switched off, and come back on with the next mode. Restore saved profile defaults (once Ask to Connect saves any) |
| **Click to Block** (default) | Everything allowed unless blocked | Outbound default unchanged (Allow); per-app block rules |
| **Ask to Connect** | Unknown apps blocked until the user decides | Outbound default set to Block on all profiles; baseline allow rules; prompts on blocks ([§7.4](#74-ask-to-connect)) |
| **Block All** | Everything blocked except loopback | One inbound and one outbound block rule covering all non-loopback addresses ([§7.5](#75-block-all)). App rules untouched |

We never turn Windows Firewall itself off. Turning it **on** for a profile where it's off is offered (the Firewall menu and a banner in the app, `win4tress firewall-on`); it's a change like any other.

Profile defaults win4tress changes are saved first (`profile_originals`), and reset and uninstall put them back. Click to Block and Block All change no defaults; Ask to Connect (Phase 3) is the first mode that will.

### 7.2 Rule model

A desired-state rule has these fields: app identity, direction (in/out), action (allow/block), scope (any | host list), profiles, origin (user | prompt | baseline | import | cleanup), timestamps and a note.

How rules are written to Windows Firewall:

- **One Windows Firewall rule per (app, direction, action, scope kind)**, with address lists inside it. Never one rule per host. Rule count is limited on purpose.
- Name: `win4tress: <App name> (<In|Out>, <Allow|Block>) #<rule ID>`. Group: `win4tress`. Description: our rule ID. The ID keeps names unique: Windows allows duplicate names, and removing or looking up by name only reaches the first match (spike 0.2).
- Reconciliation compares parsed values, not strings: Windows rewrites addresses on read-back (`8.8.8.8` → `8.8.8.8/255.255.255.255`).
- Bulk changes (large Apply, Reset, uninstall) run in the background with progress: a delete takes ~10 ms, so hundreds of rules take seconds. Switching enforcement off disables the group in one call.

How each kind of app is identified:

| App kind | Windows Firewall condition |
|---|---|
| Win32 executable | Program (full path; Windows Firewall doesn't support wildcards) |
| Service inside a shared svchost | Program (svchost path) + Service name |
| Store/MSIX app | Package (`LocalAppPackageId`, the AppContainer SID) |
| Kernel (process ID 4) | Program `System` |

Our database also stores signer, hash and version for each app, for trust tracking ([§12](#12-trust--reputation)).

**Temporary rules (2026-10-29):** a whole-app verdict (scope any) can last for a while: 1 minute to 30 days, until the app quits, or until Windows restarts (`Lasts` in `rules.set` and `prompts.decide`; schema 12, `rules.expires` and `rules.revert`).

- A temporary verdict takes the place of the app's opposite rule for that direction and remembers its action (`revert`); when it ends, the rule goes back to it ("allow for an hour" on a blocked app: blocked again after the hour). Without an opposite rule it's deleted when it ends. It never shortens a rule that already says the same for good, and a decision for good (setting it again, or flipping its action) makes it permanent.
- The enforcer ends them, audited as "expired" by "win4tress (time up | app quit | restart)": at its time (the run loop wakes for the next one, as for Block All); when none of the program's processes runs (looked for every 5 s while such a rule exists); or on a later boot. The boot is Windows' boot time (`NtQuerySystemInformation`, as Task Manager's "Up time"), so a restart ends it and sleep or a shutdown with fast startup don't.
- "Until it quits" is refused for a program that isn't running and for Windows services; a rule for some hosts can't be temporary.
- In the app: the card's **How long** (Always, 15 minutes, 1 hour, 8 hours, until it quits, until Windows restarts); **Block for…** or **Allow for…** in an app's expanded row; **Block for a while** and **Allow for a while** in an app's firewall detail, which lists each temporary rule's end and what it goes back to; a small clock on the Apps switch. CLI: `block|allow <app> --for 30m|2h|1d|quit|restart`, `decide <id> allow|block --for …`.

**Export and import (2026-10-29):** `rules.export` gives every rule and profile as a file (format `win4tress-rules`, version 1): rules name their program by path (and svchost service or package), so another PC finds it; profiles carry the rules on in them in full (and, for an older win4tress, by their place in the file) and keep their networks and DNS filtering; the file also carries this PC's DNS filtering settings (a pause left out). A temporary rule is exported as what it goes back to, or left out. `rules.import` (with a dry run first) sets each rule (origin import), replacing the app's rule of that kind, leaves alone the ones already as in the file, adds or replaces profiles, sets DNS filtering's settings as in the file (a pause here kept; the preview says when they differ), and doesn't change the mode. Programs not on this PC still get their rules, for when they're installed. In Settings, **Rules and profiles** (Windows' Save and Open dialogs, then a preview: added, replaced, unchanged, missing programs); CLI `export <file>`, `import <file> [--dry-run] [--yes]`.

### 7.3 Per-host rules

- The scope is a list of remote IPs and ranges.
- Hostnames become the IPs **this app** received for that name, taken from DNS-Client ETW. Lists update as new answers arrive, and updates are batched.
- **Block hosts** ("allow app, block X"): a block rule scoped to X's addresses.
- **Allow only hosts** ("block app, except X"): a block rule scoped to the *complement* of X's addresses, recalculated when X's addresses change. This is needed because block rules always beat allow rules in Windows Firewall.
- Address lists are written **inline** in the rule. A rule with 10,000 addresses takes ~0.1 s to write (spike 0.2). Windows Firewall *dynamic keyword addresses* work without Defender Network Protection, but the COM API reads a keyword rule's addresses as `*`, so they would need a second (WMI) API to create and verify. They're reconsidered only if rule updates under IP churn become a measured problem ([spike 0.3](spikes/0.3-dynamic-keywords.md)).
- The UI must describe these rules honestly, e.g. *"Blocks the 4 IPs Chrome received for ads.example.com"*. With DNS filtering on (Phase 7) these rules still go by addresses: Windows' DNS Client service asks win4tress's resolver on every app's behalf, so the resolver can't answer one app differently from another ([§20](#20-decisions)). A name to block for every app belongs in DNS filtering's deny list, which matches the name exactly.

As built (Phase 2):

- A host is an address, a range (`a-b`), a network (`a/n`) or a name. `*.example.com` covers the name and its subdomains. Names are stored as names and resolved at every pass from the app's own lookups (the 30-day lookup history and the monitor's recent DNS log); new answers are picked up within 5 s.
- A name with no addresses yet gives no rule: never "any".
- The complement for "allow only" leaves out loopback, so the app still reaches this PC.
- Each kind is its own rule: `(Out, Block hosts)`, `(Out, Block all but hosts)`, `(Out, Block own DNS)`. Adding hosts adds to that rule's list.
- In the app: a **Block** button on each host in the Apps table's expanded row (the app's outgoing host rule), and the Firewall screen's detail for the rest. From the CLI: `win4tress block <app> --hosts …` or `--allow-only …`.

### 7.4 Ask to Connect

**Flow:**

1. An unknown app connects. The Windows Firewall default outbound block drops it. Within ~0.15 s a WFP drop event arrives naming one of the "Default Outbound" filters ([spike 0.4](spikes/0.4-wfp-block-notifications.md)).
2. The service removes duplicates (one prompt in flight per app), gathers trust signals, and sends a prompt to the UI in the active console session.
3. The user chooses **Allow**, **Block** or **Decide later**, and a scope: whole app (default) or only this host.
4. The service writes the rule. The app's next attempt succeeds. **The first attempt always fails**: this is a known limitation without a kernel driver.
5. If no UI responds within 60 s, the app stays blocked and the decision is queued as "pending" (UI badge plus tray state).

**Prompt rate limits:** at most 1 prompt per app at a time and 5 per minute overall. Bursts are grouped into one "N apps waiting" window.

**Learning mode:** when switching into Ask to Connect, the user is offered pre-allow rules for apps seen in the last 7 days of monitoring history.

**Baseline allow-list,** so Windows keeps working:

- Windows' built-in "Core Networking" outbound rules stay enabled.
- When Ask to Connect is turned on, allow rules are created up front for a curated list of Windows services (DHCP, DNS Client, NLA, Windows Time, Windows Update, BITS, Delivery Optimization, Store, Defender updates, licensing/activation, …). The list ships as a data file and is updated with releases.
- **Automatic allow on first block** for Microsoft-signed binaries under `%SystemRoot%`. The first block is logged, not prompted.
- **Except** the built-in tools malware commonly abuses. These always prompt: `powershell`, `pwsh`, `cmd`, `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, `wscript`, `cscript`, `msbuild`, `installutil`, `curl`, … The list ships as a data file.

**Protected components:** win4tress's own binaries (the service, the app and the command-line client, found next to the service) get outgoing allow rules and can't be blocked: a block rule for them is refused, and the app shows a lock instead of their switches. They are still blocked by Block All. These rules aren't stored rules; reconciliation puts them back like any of ours.

**Ask prompt:** a card in the corner above the taskbar.

```
┌──────────────────────────────────────────┐
│ ♜ Ask to Connect              ‹ 1 of 3 › ✕│
│ [icon] setup_helper.exe                  │
│        first seen 2 min ago              │
│ wants to connect to                      │
│ 🇳🇱 cdn.example-updates.net:443            │
│ [Unsigned] [User folder] [Downloaded]    │
│ [   Block   ] [   Allow   ]      Details │
└──────────────────────────────────────────┘
```

**Details** adds the program's path, the address, country and network owner, how often it was blocked, the scope (this app or only this host) and **Decide later**.

The card is a window of win4tress's own, not a Windows notification. Windows hides its notifications under Do Not Disturb and moves them to the notification centre after a few seconds, and a missed decision leaves an app blocked without a word. The card also has room for the trust signals.

**As built (Phase 3):**

- **The outbound default.** Turning Ask to Connect on creates the baseline rules, then sets every profile's outbound default to Block, saving the original settings first (only once). Leaving the mode (Click to Block or Off), reset and uninstall put them back before the baseline rules go. A default changed from outside is put back at once and reported in the "firewall changed" alert. The mode is unavailable when Group Policy or MDM sets the outbound default.
- **Baseline** (`data/baseline-services.txt`): rules by service name, so the service's SID matches whatever program hosts it; a few by program path. All these services have their own SID, which service rules need (checked with `sc qsidtype`).
- **Automatic allow on first block:** the kernel, and programs in the Windows folder whose signature verifies and whose signer is Microsoft ("Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"), unless their file name is in `data/abused-system-tools.txt`. The allow rule is audited as baseline, and logged; there's no prompt. A drop names only the executable; the process it was raised in tells svchost's services apart, so an allow covers one service, not all of svchost.
- **Prompts:** a drop by Windows Firewall's default (no rule allowed it) is an attempt. Attempts by an app with a prompt are counted on it. At most five prompts are shown a minute; the rest wait (`waiting`), and an open prompt unanswered for a minute becomes `pending` (the app stays blocked). **Allow** or **Block** sets an outgoing rule for the app, or only the host (its name if the app looked it up, else the address); **Decide later** marks it pending. A rule set any other way for the app clears its prompt; leaving the mode clears them all. Prompts live in memory: after a restart, the next blocked attempt asks again.
- **Learning mode:** choosing Ask to Connect lists the apps that used the network in the last 7 days and have no outgoing rule, for allowing first; flagged ones (unsigned, downloaded, …) start unticked. `win4tress mode ask-to-connect --allow-recent` allows them all.
- **Where it shows:** the header status ("Ask to Connect · N waiting"), the Firewall menu (with **Show**), the tray tooltip, `win4tress prompts`, and `win4tress decide <id> allow|block|later [--host]`.

**As built (the card, 2026-10-28):**

- **The window:** 360 logical pixels wide, as tall as what it shows, in the bottom right corner of the main display's work area, 12 px from its edges (by the visible card, not the window's invisible resize borders). Always on top, out of the taskbar, no frame (Windows 11 rounds it and gives it a shadow).
- **It never takes the keyboard:** it appears without activating, so typing elsewhere goes on. Clicking it activates it; Esc closes it.
- **Full screen:** while Windows reports a full-screen game, video or app, or presentation mode (`SHQueryUserNotificationState`), the card waits, checking every 3 s, and appears when that ends if anything is still waiting. Do Not Disturb doesn't hold it back: the user chose to be asked.
- **What it shows,** one at a time with ‹ N of M ›: Ask to Connect's prompts (Block / Allow / Details), then, in Click to Block, new apps (below). It closes when nothing is left; ✕ closes it with prompts still waiting (they show again with the next prompt, or from the Firewall menu's **Show**).
- **When the app connects** to the service, prompts left pending while no app was there to ask open the card too.
- **What the program belongs to,** under its name, when the name doesn't say: its install folder, the first two folders under Program Files, ProgramData or AppData ("in Adobe\Acrobat DC" for "Adobe AcroCEF"), else its file's product name ("Part of …"). Read by the app from the file, like the icon. Not for Windows' own programs, Store apps' package folders, or folder words the name already has (or generic ones such as `bin`).
- **New apps in Click to Block:** an app's first connection ("First network activity", §11) shows the card with **Block** (an outgoing block rule for the app, for good or for a while, which also ends its open connections) and **OK**. It shows the app's icon, publisher, trust flags and where it connected. Unanswered, it goes after a minute as the item showing: paging to another item pauses its minute, the pointer on the card stops it, and moving off leaves at least 10 s. The alert stays in the list. Not in Ask to Connect (the app was asked about anyway), Off, Block All or monitoring-only mode. A setting (Settings → Alerts and notifications → First network activity, on by default) turns these cards off; that alert then pops up like any other.
- **Memory:** the card is a web view like the main window: about 100 MB while it shows, freed when it closes.

### 7.5 Block All

- Two rules, inbound and outbound, with no program condition. Remote addresses are everything except `127.0.0.0/8` and `::1`.
- Durations: 15 min, 1 h, or until turned off. Timed Block All reverts automatically.
- If the current session is remote (RDP), warn that the connection will drop and require confirmation.
- Because block beats allow, Block All also blocks win4tress itself (updates, lookups). That's correct and documented.

As built: the service checks the caller's session (`WTSClientProtocolType` = RDP). Over Remote Desktop it refuses with error code -32007 unless the call confirms; the app then asks, and the CLI needs `--yes`. The end time is stored, so a timed Block All also ends after a service restart. It's shown as a red header status and a banner with **Stop blocking**.

### 7.6 Profiles (v1.1)

Named snapshots of mode + the rules that are on (in full) + DNS filtering's settings, switched manually or by the network the PC joins. A profile is exact: while it's active, every other rule is off.

**As built (Phase 6):** a profile holds the mode and every rule's on/off state when saved (schema 11, `profiles`). Switching puts back the state of each rule it knows (rules added since are left as they are; deleted ones are skipped) and the mode, with the same checks as changing the mode (Ask to Connect refused where policy forces the outbound default), then reconciles Windows Firewall at once. The last profile saved or switched to is the active one, marked "changed" when the mode or a rule differs from it. A rule can be switched off and on without deleting it (`rules.enable`; "Turn off" in an app's rules; `win4tress rule <id> on|off`), which is how profiles differ: block an app, save "Travel", turn the rule off, save "Home". Switches, saves and deletes are in the rules' audit trail. In the Firewall menu, and `win4tress profile [list|save|switch|delete]`.

**Exact profiles (2026-10-30, 0.1.14):** the Apps tab's switches create and delete rules (blocking makes a rule, unblocking in Click to Block deletes it, allow ↔ block replaces it), so on/off states alone missed them. A profile now holds each rule that's on in full: app, direction, allow or block, scope, origin and note (schema 14: `profiles.rules` as that list; profiles from before hold the rules they had on, as they were then, and rules deleted since are gone). A temporary rule is held as what it goes back to, or not at all. Switching makes the rules match: each of the profile's rules on as saved (made again if deleted, set back if its action or scope changed), every other rule turned off, not deleted, so another profile can turn it on again. Left alone, in every profile: Ask to Connect's baseline allows for Windows' programs and reputation blocks (§12), which also win over a profile's rule for the same app; and temporary rules, which run out as they would. "Changed" is any difference in the rules on (with temporary rules as what they go back to), so blocking or unblocking an app in the Apps tab brings up **Save changes**. Automatic cleanup takes an uninstalled app's rules out of every profile too (§7.10). The export carries each profile's rules in full (`rules_on`), with the old index map kept for an older win4tress.

**DNS filtering in profiles (2026-10-30, 0.1.13):** a profile also holds every DNS filtering setting (§13): on or off, the blocklists and custom lists, the DNS server, the blocked answer, observing, the allowed, blocked and regex names, and local records; not a pause (schema 13, `profiles.dns`). Switching puts them back through the settings, as Settings changes them, with the same checks (a blocklist gone from the catalogue refuses the switch before anything changes), and a pause stays as it is. "Changed" counts a difference in any of them, a pause aside. A profile saved before 0.1.13 holds none: switching leaves DNS filtering as it is and it never counts as changed, until it's saved again. The Firewall menu shows each profile's "DNS filtering on/off" and offers **Save changes** under the active profile when it differs, or when it holds no DNS filtering yet.

**Switching by network (2026-10-29):** a profile can name networks it's for: networks Windows knows by its own id (Network List Manager's, one per Wi-Fi network or wired network told apart by its gateway), and any public, private or domain network (schema 12, `profiles.networks`). Every 5 s the service reads the connected networks; only when they change does it pick a profile and switch to it, with the same checks as switching by hand, so a switch made by hand stands until the PC joins another network. Only the networks that reach the internet count when any do (a VPN's network doesn't pick the profile); a profile chosen for one by name wins over one chosen by kind; otherwise profiles go by name. It raises "Profile switched" (§11; info), audited as "win4tress (network “…”)". Not while win4tress can only monitor. In the Firewall menu, each profile's **Networks** (the networks Windows remembers, connected first, and the three kinds) and the last switch made by itself; `networks.list`, `profiles.set_networks`; CLI `networks`, `profile networks <name> [current | public | private | domain | a network's name or id]… | --clear`.

### 7.7 Environment detection

Checked at startup and whenever anything changes. The result appears in a persistent status header and in the tray icon state.

As built: the header's firewall status names the state (Click to Block, Off, Block All with its time left, Monitoring only, Windows Firewall off) and opens the Firewall menu: each profile with **Turn on** where it's off, the mode, Block All, and "Require elevation". In monitoring-only mode the service refuses changes and the app disables its switches and explains why.

| Condition | Behaviour |
|---|---|
| Third-party firewall registered with Security Center (Windows Firewall off) | **Monitoring only**: enforcement controls disabled, with an explanation |
| Windows Firewall off for a profile | Banner; enforcement inactive on that profile |
| Local rule merging disabled by Group Policy/MDM | Banner; enforcement off (our rules would be ignored) |
| Outbound default forced by policy | Ask to Connect unavailable |

How each is detected ([spike 0.5](spikes/0.5-environment-detection.md)). None of these checks needs elevation:

- **Third-party firewall:** Security Center's firewall product list (`IWSCProductList`) and health. Windows Firewall lists itself with product GUID `NULL`; recognise it by that, not by its (translated) name.
- **Firewall off per profile, outbound default, policy override:** `INetFwPolicy2` (`FirewallEnabled`, `DefaultOutboundAction`, `LocalPolicyModifyState`).
- **Which policy settings apply** (for the banner's explanation): the Group Policy key `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall` (`AllowLocalPolicyMerge`, `DefaultOutboundAction` per profile) and the MDM key `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall`.

### 7.8 Reconciliation and tamper detection

- Watch the Windows Firewall event channel, and also run a full diff of our rule group and profile defaults every 60 s.
  - The channel is `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`. It's readable without elevation.
  - Rule events carry the rule's name, and add and modify events also carry its group. Windows 11 uses 2097 (added), 2099 (modified) and 2052 (deleted); Windows 10 uses 2004, 2005 and 2006.
  - Settings events trigger a check too: 2002, 2003, 2082 and 2083 (setting changed), 2008 (Group Policy applied), 2032 and 2060 (reset to defaults), and 2033 and 2059 (all rules deleted).
  - Each event names the program that made the change (`ModifyingApplication`), so the service ignores its own changes.
  - The service waits 0.5 s after an event so a burst of changes is handled in one pass. Measured: an outside change is put back ~1.2 s after Windows logs it.
- An outside change is a difference from what win4tress **last wrote**, not from what it wants now: rule and mode changes, host rules' new addresses and Block All ending change what it wants, and aren't reported. At startup nothing was written yet in that run, so stored rules are compared with what they project to (changes made while the service was stopped); win4tress's built-in rules and resolved addresses are left out of that. After a pass that failed, nothing is reported until one succeeds, since the difference may be win4tress's own.
- On a difference, put win4tress's rules back at once and raise the alert "Firewall changed outside win4tress", listing what was changed per rule. **Keep these changes** (the "Accept" choice) adopts the outside change into win4tress's rules instead:
  - Keepable: a rule deleted, turned off or on, or switched between allow and block.
  - Not keepable: a change to the rule's program, addresses, ports or other conditions, and a rule added to win4tress's group (including a copy of one of ours).
  - Not keepable: turning a rule on while the mode is Off.
  - A rule changed in win4tress since the alert keeps that later decision.
  - Keeping is audited as "kept outside change".
- Rules outside our group are never changed unless the user asks, e.g. "disable the Steam rule". In that case the original state is recorded so it can be restored.

### 7.9 Explaining blocks

WFP block notifications identify the filter that dropped the traffic. We map that filter to its Windows Firewall rule. The UI shows **"Blocked by: \<rule\> (win4tress | Windows | \<other\>)"** for each blocked connection.

How the mapping works ([spike 0.4](spikes/0.4-wfp-block-notifications.md)):

- **Name match.** Windows Firewall gives each WFP filter its rule's name and description. A win4tress rule name ends with our rule ID. The default outbound block is three filters named "Default Outbound".
- **One rule, several filters.** A rule produces several filters, so map filter → name → rule, never by filter count.
- **Look up the filter at once.** Windows Firewall rebuilds its filters when the default policy changes, so an ID can vanish seconds later. Each drop event's filter is looked up as it arrives, and recent IDs are cached. An ID that can't be looked up is shown as such ("a filter that couldn't be looked up (#id)") and tried again after 5 s, since it may be missing only while filters are rebuilt.
- **Protocol.** ETW event 1001 has no protocol field. It comes from the layer, or from the net event that follows.

**Per-app verdicts** (`firewall.verdicts`, `win4tress why <app>`, the Apps table switches): whether each app's incoming and outgoing connections are allowed, and what decides it. Checked in this order:

1. Windows Firewall is off on a network in use: allowed.
2. A block rule, win4tress's or a Windows Firewall rule naming the app: blocked.
3. An allow rule: allowed.
4. Otherwise the default of the profiles in use.

Notes:
- Windows' own rules are read, never changed, on every check. Reading all of them takes about 25 ms. The firewall event log triggers a check when another program changes a rule.
- A rule names an app by program path (after expanding `%SystemRoot%` and the like), by service inside svchost, or by Store package. Rules that name no program apply to every app (port rules, Core Networking), so they aren't counted as any app's own.
- The verdict is approximate: ports, addresses and which network a connection uses aren't weighed.

**"Blocked by" as built:** the service records each drop by app, direction, remote address and port, and what blocked it, counted per minute; history keeps 30 days (`blocks` table). The Connections screen has a **Blocked** list (since the service started, 24 hours, 30 days), the Firewall screen's detail shows an app's last 30 days, and `win4tress blocked [--app …] [--days …]` lists them.

**Switches:** the knob is win4tress's own setting; the track is the verdict: teal for allowed, gray for blocked by Windows, coral for blocked by win4tress.
- A click adds or removes win4tress's block rule.
- Where no rule means blocked (outgoing in Ask to Connect), a click sets an allow or block rule instead.
- A switch never opens an app to incoming connections. That's a deliberate action in the app's detail, with confirmation (Firewall screen).

### 7.10 Automatic cleanup (v1.1)

| Trigger | Default | Behaviour |
|---|---|---|
| Uninstalled apps (binary missing for 7 days) | On | Remove rules; log it |
| Inactive apps (no traffic for N days) | Off, N = 30 | Remove rules; log it |

An app that comes back is treated as new.

**As built (Phase 6):** the service checks hourly (and the Settings screen and `win4tress cleanup` on demand) every app with rules other than baseline ones, skipping win4tress's own programs and paths that aren't a drive-letter file. A program found missing gets its "missing since" time (schema 11, `apps.missing_since_ms`); one that comes back loses it. After 7 days missing, its rules are removed, each audited as "removed: uninstalled" by "automatic cleanup", and its first network use is forgotten, so it's new again ("First network activity", Ask to Connect prompts). Inactive cleanup counts blocked attempts as activity, so a blocked app that keeps trying isn't unblocked by it; it's off until the user sets the days (1 to 3650). A removable drive's programs look uninstalled while it's away.

### 7.11 DNS bypass handling

Windows Firewall can't express "block DNS from every program except X": block rules beat allow rules, and a rule can't exclude programs. So in v1:

- **Detection:** ETW shows an app sending to port 53 or 853 itself, or to a known encrypted-DNS (DoH) server, instead of going through the DNS Client service. That raises the alert "App uses its own DNS".
- **One-click fix per app:** a block rule for that app covering remote ports 53/853 and the known DoH server addresses.
- In Ask to Connect mode, port 53/853 to the internet isn't added to app allow rules automatically.

As built: Windows' DNS Client service is exempt (it does every app's lookups). The alert offers **Block its own DNS**; so do the Firewall screen and `win4tress block <app> --own-dns`. The block is three rules: TCP and UDP to ports 53 and 853, and the DoH servers in `data/doh-servers.txt`. The Apps and Firewall lists badge such apps "Own DNS".

### 7.12 v2: WFP backend triggers

Enforcement sits behind `trait EnforcementBackend`. A WFP backend (our own provider and sublayer) is added only if one of these turns out to matter:

- Users with third-party firewalls want enforcement.
- "Allow only these hosts" becomes a core workflow.
- Rule-change speed under real IP churn becomes a problem.
- Tamper resistance needs to outrank transparency.

## 8. Monitoring

### 8.1 ETW collector

Validated by [spike 0.1](spikes/0.1-etw-collector.md).

- Providers:
  - `Microsoft-Windows-Kernel-Network` (TCP/UDP send, receive, connect, disconnect; IPv4/IPv6)
  - `Microsoft-Windows-Kernel-Process` (process start, keyword `0x10`)
  - `Microsoft-Windows-DNS-Client` (query completed, event 3008)
- **Bytes come only from data events:** TCP 10/11 (IPv4) and 26/27 (IPv6); UDP 42/43 and 58/59. Ignore event 18 ("TCP copy"): it repeats received data and would double-count.
- Ports in events are big-endian.
- **Endpoint orientation differs by protocol.** TCP events describe the connection, so `daddr` is always the remote end. UDP events describe the datagram, so on **receive** `daddr` is our own address and the remote end is `saddr`. This was found in Phase 1, when RDP over UDP was credited to the PC's own IP.
- Fixed session name `win4tress-etw`. **On startup, stop any leftover session with that name** before starting a new one. Sessions outlive crashed processes, and Windows allows only 64.
- Attribute traffic using the **process ID in the event data**. The header's process ID was wrong on 82% of data events in spike 0.1.
- **Flush timer 250 ms**, set with `EVENT_TRACE_USE_MS_FLUSH_TIMER`. ETW's default of 1 s delayed delivery by about 1.5 s. With per-CPU buffers (the default), a quiet provider's events arrive about **twice the flush timer** late, ~0.5 s here. With one set of buffers (`EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING`), it's about one flush timer ([spike 0.4](spikes/0.4-wfp-block-notifications.md)).
- WFP drop events (§7.9) use a **second, small session** with a 50 ms flush (~0.12 s delivery). It's kept apart from this high-volume one, so lost traffic events can't take block events with them.
- **Bucket traffic by event timestamp, not arrival time.** Events still arrive a few hundred ms late.
- Buffers are sized for sustained full line rate. The lost-event count is tracked and shown as "data incomplete" markers on the graph.
- The callback only decodes, adds to counters and returns. Decoders never panic: malformed events are counted and skipped. Decoders are fuzzed and tested against recorded `.etl` trace files.

### 8.2 Attribution

- **Process identity** = `ProcessSequenceNumber` from Kernel-Process start events, which is unique until reboot. The same event gives the image path (so short-lived processes still get names) and `PackageFullName` (Store apps). For svchost, the service name comes from the Service Control Manager.
- **App figures are payload bytes** (what ETW reports). **Usage and data-plan totals come from adapter counters**, which count whole frames. The difference is shown explicitly as **"Protocol overhead & other"**: headers, payload-free TCP ACKs, ARP/ICMP, and kernel traffic not attributed to an app. During a download, outbound adapter traffic is mostly ACKs that ETW never reports.
- **VPNs:** traffic may be counted twice, once inside the tunnel and once as the VPN client's encrypted traffic. v1 labels known VPN clients and offers "exclude from totals". As built: VPN clients are known by file name (`data/vpn-clients.txt`, the program carrying the tunnel), labelled "VPN" in the app lists, and "exclude from totals" leaves them out of the graph, usage and the live totals. Windows' built-in VPN (inside an svchost) can't be told apart this way.

### 8.3 Hostnames, geography, classification

- **Hostnames:** a per-app map of (IP → name) from DNS-Client ETW, bounded by each record's TTL. Reverse (PTR) lookup is the fallback (setting "Look up host names", default on, cached).
- **Country and network owner (ASN):** DB-IP Lite, refreshed monthly through our update channel. Unknown countries show a neutral striped flag.
- **Traffic types:** classified by protocol and port: HTTPS, HTTP, QUIC (UDP/443), DNS, DoT, NTP, mDNS, SSDP, NetBIOS, SMB, RDP, SSH, DHCP, Other. The remote port is checked first. If it's not a known service, the local port is used, so connections *to* this PC (RDP, SMB) are typed by our service port, not by the client's random port.
- **Local vs external:** loopback, private ranges (RFC 1918), carrier-grade NAT (100.64/10), link-local and IPv6 private (ULA, fc00::/7) count as local; everything else is external.

### 8.4 Idle and incognito

- **Idle:** the UI agent reports last input time. Periods with no input for more than 10 min (configurable) are shaded on the graph and feed the "While you were away" summary. As built: the app reports `GetLastInputInfo` every minute (`session.input`); the service keeps spans of 10 minutes or more (`idle` table, 2 years) and returns them with history. Without the app running, nothing is reported.
- **Incognito (v1.1):** global or per app. Traffic isn't written to history. Enforcement and security alerts continue. As built (Phase 6): settings `incognito` and `incognito_apps`; each flush to history leaves out the traffic, DNS lookups and blocked attempts of incognito apps (or all of them). The live view (the last 10 minutes in memory) still shows them, and usage, the data plan and the map don't count them. Per app from its details on the Firewall screen; all from Settings; `win4tress incognito on|off [--app …]`.

## 9. Storage

- **Location:** `%ProgramData%\win4tress\` (configurable). Access list: SYSTEM and Administrators only. The UI reads through the service, never the files.
- **Database:** SQLite in WAL mode. Online backup via `win4tress-cli backup <path>`. Restore requires the service to be stopped.
- **Main tables:**
  - `apps`, `app_versions` (hash and signer history), `hosts`
  - the traffic tiers below, `connections`, `dns_queries`, `dns_daily`
  - `rules` (desired state), `rule_audit`
  - `alerts`, `devices`, `profiles`, `reputation_cache`, `settings`

### 9.1 Rollups and retention

| Tier | Grouped by | Resolution | Retention |
|---|---|---|---|
| Live | app; app × host | 1 s | 10 min (in memory) |
| Recent detail | app × host × traffic type | 1 min | 48 h |
| App detail | app × traffic type | 1 min | 35 days |
| Long-term detail | app × host × traffic type | 1 h | 2 years (configurable) |
| Usage | app, host, country, traffic type | 1 day | Indefinite (configurable) |
| Connections | individual | — | 48 h |
| DNS queries | individual | — | 30 days, then daily app × domain counts |
| Alerts | — | — | 1 year |

**Budget:** ≤ 500 MB per year for typical use. "Clear history" removes traffic, connection and DNS data. Rules and settings are kept.

As built (Phase 4):

- **Tables:** `traffic_min` (minute, app, host), `traffic_app_min` (minute, app, traffic type), `traffic_hour` (hour, app, host), `usage_day` (local day; one dimension per row: app, host, country, type, total, internet, metered), `dns_daily`, `idle`.
- **Writing:** every flush adds to every tier in one transaction, so the tiers always agree. Local days use the offset at the time of writing.
- **Reading:** graph queries use the finest tier that still covers the range and has the detail the filter needs. Hosts (country, local or internet) exist only in the minute and hour tiers. Steps of a day or more come from `usage_day` when a single dimension is enough. Usage breakdowns read the minute tier for 48 hours and the hourly tier beyond.
- **Pruning:** retention runs hourly; DNS lookups become per-day counts before they go.
- **Measured** on a synthetic busy year: 158 MB; a month's graph 63 ms, its usage 189 ms; a year's graph by day 46 ms.
- Beyond 2 years only the per-day totals remain. No screen reads them yet, except the data plan.

## 10. User interface

### 10.1 Shell

- **Tray icon states:** normal; pending decisions; Block All active; monitoring-only / degraded.
- Toast notifications for alerts. The Ask prompt is its own window ([§7.4](#74-ask-to-connect)).
- Persistent status header showing mode, enforcement state ([§7.7](#77-environment-detection)) and snooze state.

### 10.2 Screens

| Screen | Contents | Phase |
|---|---|---|
| **Traffic** | Live graph (5 min at 1 s). Ranges 3 h / 24 h / week / month with a timeline scrubber. Inbound/outbound series. Click a moment to see apps and hosts sorted by bytes. Pause. Alert markers on the timeline. Idle shading. Filters: All / Apps / Traffic types / Publishers / Countries. Export to PNG | 1 (live), 4 (history) |
| **Usage** | Day / week / month with calendar and slider. Breakdowns by app, host, traffic type, country, publisher. Local / external / both. Data plan status | 4 |

**Traffic and Usage as built (Phase 4):**
- **Graph:** 1 and 5 minutes (live), and 1 hour, 3 hours, 24 hours, a week and a month from history. ‹ › steps back a range at a time. It can be filtered to the internet, the local network, one app, publisher, traffic type or country. Alerts are marked along the top, and times nobody used the PC are shaded. **Export PNG** saves the plot to Pictures\win4tress.
- **Usage:** a day, week (from Monday) or month, picked with a date and ‹ ›, for both, the internet or the local network. Five columns (apps, hosts, publishers, traffic types, countries) cross-filter, and the timeline below selects part of the period.
- **Data plan:** a card shows the period's usage against the limit (alerts at 75, 90 and 100%), and is set up and changed in place.
- **VPN clients:** "Leave out VPN clients" applies to the graph, the usage and the live view.
| **Firewall** | App list: icon, name, publisher, trust badges, sparkline, In and Out toggles, hosts. Filter allowed/blocked. Bulk select → preview → Apply, with confirmation for removals. Per-app detail: rules (ours and other programs', read-only), hosts, "Blocked by …" history. Mode switcher. **As built (Phase 2):** every app from history with its outgoing and incoming verdicts and rule count; filters All, Blocked by win4tress, Can connect out, Host rules, Flagged; checkboxes and a bulk bar (block outgoing or incoming, stop blocking, remove rules) that previews the changes and applies them in one `rules.apply`. The detail lists win4tress's rules with their hosts (each removable), adds host rules, "allow only", **Allow incoming…** (confirmed) and the own-DNS block, and shows Windows Firewall's rules naming the app, the program's trust facts and 30 days of blocks. The mode, Block All and turning Windows Firewall on are in the header's Firewall menu | 2–3 |
| **Alerts** | List sortable by date, app or type. Unread counts, mark all read, filters, severity | 5 |
| **Network** | LAN devices: IP, MAC, manufacturer, name, first/last seen, "known" flag. Scan now. **Scans private networks only by default**. **As built (Phase 5):** the scanner asks every address of each private IPv4 network that has a gateway (RFC 1918; host-only and public networks are skipped; prefixes wider than /22 are capped to the adapter's /24) for its hardware address with `SendARP`, 64 at a time, then looks names up by reverse DNS, also in parallel. Makers come from the IEEE MA-L registry (`tools/dev/fetch-oui.ps1` → `data\oui\oui.csv`); random (private) addresses show as such. "Scan now", or "Scan every half hour and alert on new devices" (`scanner` setting), which also reads the ARP table every 30 seconds. Devices are kept in history (schema 10) with first and last seen; **Known** marks the ones the user recognises, and the **Unknown** filter shows the rest. `win4tress scan`, `devices [--known MAC]`, `scanner on|off` | 5 |
| **DNS** | Query log by app, top domains (Phase 1). Lists, rules, upstream, pause, stats (Phase 7) | 1, 7 |
| **Settings** | General (startup, notifications, Event Log, time format, units in bytes or bits, language, theme, clear history, data location). Firewall. Security monitors (one toggle each). Data plan. Reputation. DNS. Privacy. Advanced | Throughout |

**Mini viewer (v1.1):** a small always-on-top live graph with adjustable opacity and position. As built (Phase 6): a frameless, transparent 300 × 118 window (Tauri label `mini`) with the download and upload rates and the last minute as a small area graph; drag it anywhere, × closes it. Opened from the tray menu, the header button or Settings, where its background opacity (20–100%) is set. Its position and opacity are kept per user (`mini.json` in the app's data folder).

**Map (Phase 6):** a third Traffic view beside Graph and Usage: internet traffic by country for 24 hours, 7 days, 30 days or 12 months, as a world map in five steps of one hue on a log scale (a few countries carry most traffic), with a legend, a hover card (down, up, share) and the countries as a clickable list beside it (the map's table view). Shapes are Natural Earth's 1:110m countries (public domain), projected (Equal Earth) ahead of time by `tools/dev/make-world-map.py` into `ui/src/lib/world-map.json` (115 KB, loaded with the view). Countries too small at that scale appear only in the list.

**Apps (as built):** apps that used the network since the service started, grouped into active (traffic in the last minute or a connection open) and not active, then **Blocked, no traffic**: apps that had attempts blocked since the service started, or have a win4tress block rule for the whole app, but no traffic, so they'd otherwise be missing from the list (2026-10-28). Each shows its attempts ("Blocked 2× · geo2.adobe.com", what blocked it on hover) and its switches; one whose outgoing connections are allowed now, with no block rule, leaves the group (incoming doesn't count: Windows Firewall blocks it for nearly every app). The header counts them ("· 1 blocked"). The CLI's app lookups (`why`, `block`, `allow`, `hosts`, …) look among the active apps first, then every app win4tress knows.

**Connections, ending one (2026-10-29):** a blocked app keeps connections it already has, so an open IPv4 TCP connection can be ended: **×** on its row in Connections, **Disconnect** in an app's expanded row (all of its connections), and the card's **Block** for a new app ends them too. Both ends get a reset (`SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB`; the service does it, as SYSTEM). Windows has no way to end IPv6 TCP connections or UDP flows, so those are counted, not ended. `connections.close` (an app's connections, or given ones); CLI `disconnect <app>`.

**Search everywhere (2026-10-29):** Ctrl+K, or the magnifier in the header, opens one box over every view: apps (all win4tress knows; an active one opens in Apps, another in Firewall), hosts connected now (Connections, searched for it), names looked up in the last 24 hours (DNS's log), alerts (Alerts, searched for its app), devices (Network), profiles (switch to one), and places in Settings and elsewhere ("Export rules", "Automatic cleanup", the mini viewer). Every word typed must match; a match at the start of a name ranks first. ↑ ↓ and Enter, Esc closes.

**Settings (Phase 6):** a Settings view (a gear button at the right end of the header since 2026-11-01, 0.1.16, no longer a tab) with Privacy (incognito, incognito apps), Reputation (lookups, keys, MalwareBazaar, thresholds, auto-block), Automatic cleanup (with what's due and "Clean up now"), the mini viewer, and About (2026-11-02, 0.1.18: the app's version, the service's with a warning when they differ, Windows' edition and build, "Copy details" for bug reports, the licence, and credits for DB-IP, Feodo Tracker, the IEEE registry, Natural Earth and the flags, each a link). The rest of the Settings row above is still to come (startup, units, language, data location; the theme stays in the header for now).

### 10.3 Accessibility and localization

- Full keyboard navigation, screen-reader labels, high-contrast support, light/dark themes that follow the system.
- **Themes:** two sets of colours, each light and dark.
  - Win4tress, from the win4tress swatch board: background, text, teal for interaction, a teal gradient for calls to action, coral for blocking and errors.
  - Indigo (2026-11-01, 0.1.15), after the Skote admin template's palette: indigo (#556ee6) for interaction and calls to action, gray text on near-white cards with a soft shadow, slate navy (#222736, #2a3042) for dark, and its green, amber and red for status.
  - The user picks the colours (Win4tress or Indigo) and "Match Windows", Light or Dark, in the header menu until Settings exists. Both are kept per user; light or dark also sets the title bar. Until the user picks, it's Indigo, dark (2026-11-01, 0.1.16); a pick made before is kept.
  - All colors are tokens in `ui/src/app.css`, picked by `data-palette` and `data-theme` on `<html>`. Where a swatch is too light for small text, a darker step of its hue is used (WCAG 4.5:1), and chart palettes are validated against each theme's surfaces. Another theme is one more pair of token blocks.
- **Emblem** (2026-11-02, 0.1.17): teal (#2cd2c3) and amber (#f1b44c) on an isometric grid, in `assets/logo/emblem.svg`. The app shows the SVG; `tools/dev/make-logo.py` draws the exe, window, tray and installer icons from it at each size. It shows on light and dark taskbars without a ring.
- All strings externalized. English at launch.

## 11. Alerts and security monitors

Each monitor is a plugin with its own enable toggle, a severity, and a reproducible trigger test.

| Alert | Trigger | Default | Phase |
|---|---|---|---|
| App info changed | Known app's hash, signer or version changes; signer change or unsigned replacement = high severity | On | 2 |
| Firewall changed outside win4tress | Rule or profile differs from what we expect; Windows Firewall turned off; third-party firewall registered | On | 2 |
| App uses its own DNS | App sends DNS directly (port 53/853 or a known DoH server) | On | 2 |
| First network activity | New app identity seen | On | 3 |
| Data plan / bandwidth | Usage crosses a threshold | On when a plan is set | 4 |
| System file changed | Changes under `drivers\etc\` (hosts, networks, …) | On | 5 |
| Network adapters changed | Adapter added or removed | On | 5 |
| DNS servers changed | Adapter DNS servers change | On | 5 |
| Proxy changed | WinINet (per user, through the agent) or WinHTTP (machine-wide) proxy changes | On | 5 |
| Internet access changed | Connectivity changes (Network List Manager) | Off (noisy) | 5 |
| ARP spoofing | Gateway's hardware address changes, or one hardware address claims several IPs | On | 5 |
| Wi-Fi evil twin | Same network name with a different security type, or the password removed. **Not** just a new access point: mesh and enterprise Wi-Fi are normal | On | 5 |
| RDP connection | Inbound RDP session or accept | On | 5 |
| Suspicious host contacted | Destination is on threat-intel lists ([§18](#18-third-party-data--licensing)) | On | 5 |
| New device on network | Scanner finds an unknown device | On when the scanner is enabled | 5 |
| While you were away | Summary after an idle period | On | 5 |
| Reputation result | VirusTotal detections ≥ threshold | On when reputation is enabled | 6 |
| Monitoring interrupted | Something stopped the traffic trace and the service restarted it; traffic in the gap wasn't counted | On | 1 |
| Profile switched | The PC joined a network a profile is chosen for, and it was switched to (§7.6) | On | 6 |

Global controls: snooze desktop pop-ups for 24 h, and copy alerts to the Windows Event Log (setting).

**As built (Phase 5):**

- **Framework.** Every alert kind is a monitor with an on/off switch and an optional severity that replaces the alert's own (`Settings.monitors`; `monitors.list`; `win4tress monitors`, `win4tress monitor <kind> on|off --severity …`; the Alerts screen's **Monitors** panel). A switched-off monitor's alerts are dropped before they're stored, so turning it back on doesn't replay them. The monitors in w4-monitors are pure functions over what Windows reports, with their memory kept in history (`meta`, `monitor:<name>`), so a restart doesn't re-learn; the service looks every 30 seconds. The first look after install learns and doesn't alert. Trigger procedures per monitor: `docs/monitor-tests.md`.
- **System files:** SHA-256 of each file directly in `drivers\etc`; created, changed and deleted files alert.
- **Adapters:** an adapter id never seen before alerts once (VPNs re-add theirs on every connect; removals don't alert).
- **DNS servers:** remembered per adapter *and network* (the gateway's hardware address), so moving between networks isn't a change; the same network handing out other servers is.
- **Proxy:** WinHTTP's (machine) by the service; the user's (WinINet) by the app, which reports it when it changes (`session.proxy`). Described as one line, e.g. "automatic detection; proxy 10.0.0.1:8080 (bypass <local>)".
- **Internet access:** Network List Manager's connectivity, off by default.
- **ARP spoofing:** per adapter, gateway and Wi-Fi network name: the gateway answering from a hardware address not seen for it before (once per address), or its hardware address also answering for another address. Incomplete and unreachable entries are ignored.
- **Wi-Fi evil twin:** the security each network name had when connected (open/WEP/OWE < personal < enterprise). A weaker network with the same name nearby, or the connected one now weaker, alerts once per name and security. Mesh and enterprise access points with the same security don't.
- **Suspicious hosts:** abuse.ch Feodo Tracker's botnet C2 list, downloaded daily over HTTPS (WinHTTP), not on metered connections, with the setting `threat_feeds` (on). URLhaus and ThreatFox need an abuse.ch Auth-Key since 2025 (anonymous downloads answer 410), so they're a follow-up with a user-supplied key. The user's own list is `%ProgramData%\win4tress\threats-local.txt` (admins only): one address or name per line, `#` comments, read when it changes. A connection is checked when an app first talks to an address, by the address and by the name the app looked up (and its parent domains); one alert per app and address.
- **While you were away:** when the user comes back after 30 minutes or more without input (the app reports input), a summary: bytes down and up, the three busiest apps, and the alerts raised meanwhile. Nothing is raised if nothing happened.
- **New device:** see the Network screen (§10.2); alerts only with automatic scans on, after the first scan has learned the network.
- **Desktop pop-ups** are shown by the app (tauri-plugin-notification), chosen per monitor: off, its warnings and critical alerts (the default), or all of them. A monitor without a choice of its own follows "for every monitor" (Off / Warnings and critical / All), which also clears the monitors' own choices. At most three at once plus a "N more" summary, none while win4tress has focus. In Click to Block, "First network activity" shows the card instead, with **Block** (§7.4). **Snooze** silences pop-ups for 24 hours for the alert's app, or its kind when it isn't about an app (the ⋯ menu). Alerts are still listed. Kept per user in the app's data folder (`popups.json`: `level`, `desktop` per kind, `snoozed`, `new_app_cards`).
- **Alerts and notifications** (Settings, 2026-10-28; a list and a detail pane): the monitors in a list, each with On or Off and a bell when its alerts pop up; beside it the chosen one's settings: **Alert me when this happens** (the monitor on or off), **Show a desktop notification** (for the three whose level varies, App info changed, Data plan and Reputation: Off, Warnings and critical only, or Every alert), **Alert level**, and what only it has (First network activity: the card in Click to Block; Suspicious hosts: the threat lists). Under them: pop-ups for every monitor, snoozes, and the Event Log. The Alerts tab's **Alert settings** opens it.
- **Event Log:** with `event_log` on, each alert is written to the Application log, source "win4tress", level from its severity (critical as Error), event id 100 + the kind's place in the catalogue (`MonitorInfo::event_id`; 105 system files, 108 proxy, 112 suspicious host, …). The source is registered on first use with .NET's `EventLogMessages.dll`, so Event Viewer shows the text.
- **Alerts screen:** sort by date (grouped by day), by app or by type; filters by kind are grouped (Apps, Network, This PC); a "Snoozed" chip on alerts whose pop-ups are snoozed.

## 12. Trust & reputation

No scanning engine of our own. Three tiers:

| Tier | Runs | Signals | Leaves machine |
|---|---|---|---|
| **1. Local** | Always; when an app is first seen and when its file changes | Signed or not, and by whom; signer changed; user-writable location (AppData, Temp, Downloads); Mark of the Web; first seen | Nothing |

Tier 1 as built (Phase 2):

- **Signature:** `WinVerifyTrust` on the file, then the Windows catalogs (most of Windows' own files are catalog-signed). Signed, unsigned, or invalid: changed after signing, revoked or untrusted. The signer is the signing certificate's display name.
- **Hash:** SHA-256 of the file.
- **Location:** Windows folder, Program Files, a user's folders, or elsewhere.
- **Mark of the Web:** the file's `Zone.Identifier` stream: zone, and the download and referrer URLs when present.
- Read when an app is first seen and at each service start, cached by path, size and modification time, and kept in history (schema 8).
- **Alerts:** "App info changed" for a new signer (warning) or a changed file with the same version (warning). A signed app whose file is now unsigned or invalid is critical.
- **Badges** in the Apps and Firewall lists: Bad signature, Unsigned, User folder (only when not signed: signed per-user installs are common), Downloaded, Own DNS.
| **2. Hash reputation** (v1.1) | Opt-in | CIRCL hashlookup first (known-good → stop). Then VirusTotal hash lookup with the **user's own API key**. MalwareBazaar optional. Results cached; unknowns re-checked after 24 h | File hash |
| **3. Manual** (v1.1) | Per file, on request | "Scan with installed antivirus" (`IAttachmentExecute`, works with any vendor). "Upload to VirusTotal", with a confirmation that uploads become visible to VirusTotal's community | The file, only after confirmation |

- **VirusTotal limits:** the free API allows about 4 lookups a minute and 500 a day. The queue skips files CIRCL knows to be good and puts apps that are actually using the network first.
- **Optional auto-block** at a detection threshold (default 5). Off by default.

Tiers 2 and 3 as built (Phase 6):

- **Lookups** (setting `reputation.enabled`, off): every 15 seconds the service takes the apps with a hash, asked-for ones first, then those with traffic in the last minute, then by last seen, one per file. CIRCL hashlookup (`/lookup/sha256`, 200 known, 404 unknown; a `KnownMalicious` field counts as malicious) up to 10 a tick; known good stops there. Then VirusTotal v3 (`/files/{sha256}` with the key; at most 4 a minute and 500 a day, paused an hour on 429) and, if asked, MalwareBazaar (`get_info`, with an abuse.ch Auth-Key). Answers are kept per file and source (schema 11, `reputation`); unknowns are asked again after a day, the rest after a week. The Firewall list flags Malicious and Suspicious; an app's details list every answer with "Details" links to VirusTotal and MalwareBazaar.
- **Verdicts:** VirusTotal counts engines flagging the file (`malicious`) out of those with an opinion (malicious, suspicious, undetected, harmless). At the alert threshold (`alert_at`, 3) it's Malicious, below it Suspicious, at 0 Clean. A MalwareBazaar find, CIRCL `KnownMalicious` or an antivirus find is Malicious.
- **Alert:** "Reputation" (critical), once per file and source, not again for the same answer on a weekly refresh. **Auto-block** (`auto_block`, off; `block_at`, 5): every app with that file is blocked both ways (origin `reputation`, noted with the count), never win4tress's own programs, and the alert says so.
- **Keys** (VirusTotal, abuse.ch) are checked for shape, stored DPAPI-encrypted with the machine key in history (readable only by administrators), never returned by the service, and their setting and removal is audited without the value. `reputation.status` says only whether each is set.
- **Scan with antivirus:** rather than `IAttachmentExecute` (whose Save also writes a Mark of the Web), win4tress calls what it calls: every antivirus registered in the `CATID_MSOfficeAntiVirus` component category, through `IOfficeAntiVirus::Scan`, with a read-only request. Microsoft Defender registers (`MpOav.dll`), as do most others. S_OK is clean; S_FALSE, E_FAIL and the Win32 virus errors are a threat; other errors are reported. The answer is kept like a lookup's (source "Microsoft Defender").
- **Upload to VirusTotal** (needs the key): only with an explicit confirmation (`confirm: true`, a warning in the app, `--yes` in the CLI), files up to 650 MB (over 32 MB through an upload address). The analysis is asked about once a minute until done, then kept as VirusTotal's answer.
- CLI: `win4tress reputation [--lookups on|off] [--virustotal-key …] [--abuse-ch-key …] [--malwarebazaar on|off] [--alert-at N] [--auto-block on|off] [--block-at N]`, `lookup <app> [--now]`, `av-scan <app>`, `vt-upload <app> --yes`.

## 13. DNS filtering module (Phase 7, v1.2)

**Resolver:**

- `win4tress-dns` listens on `127.0.0.1:53` and `[::1]:53` (UDP and TCP) only.
- Upstream is the system's original DNS servers (default, which keeps corporate and captive-portal behaviour) or a chosen DoH/DoT provider.
- Blocked lookups are answered with `0.0.0.0` / `::` (default) or NXDOMAIN.

**Blocklists:**

- **Supported formats:** hosts files, plain domain lists, Adblock-style `||domain^` (domain rules only; other rule types ignored), and regex lists.
- **Compile when downloaded, not at startup:** remove duplicates, hash each domain with a keyed 64-bit hash, store in a sorted array plus a list index, write atomically, and memory-map it.
- **Lookups check the name and each parent name** (`a.b.example.com` → `b.example.com` → `example.com`).
- **Regex rules** use non-backtracking matching, and their number is capped.

**Features:**

- allow/deny/regex rules
- pause blocking for N minutes
- CNAME inspection (catch blocked domains hidden behind an alias)
- local records
- statistics, and a query log showing which app made each lookup (correlated via DNS-Client ETW)

**Safety:**

- Lookups reach the resolver through a Name Resolution Policy Table (NRPT) rule, not by changing adapters' DNS servers ([spike 0.7](spikes/0.7-resolver-failover.md)). One rule of win4tress's own sends every name (`.`) to `127.0.0.1` and `::1`. Adapters keep their servers, which stay the resolver's upstream, and more specific rules (a VPN's) still win. Removing the rule puts Windows back as it was.
- The rule is in place only while the resolver answers. The **watchdog removes it if the resolver misses health checks for 2 s.** Turning filtering off, `reset`, the service stopping and uninstall remove it too, and the service removes a leftover one when it starts.

**Edge cases:**

- **Captive portals** (hotel/café sign-in pages): pass lookups through unfiltered until the network is online.
- **Corporate split DNS:** forward the network's own domain suffixes to the original servers.
- **VPN-provided DNS:** forward to the VPN's servers.
- **IPv6 DNS servers handed out by the router.**
- **Port 53 already in use** (Hyper-V/ICS, WSL): detect and report.

**Other tools and bypasses:**

- **A blocking DNS server already present:** if the upstream answers blocked domains with null responses (`0.0.0.0` or `::`), default to observe-only and label results "blocked upstream".
- **Bypass mitigation:**
  - answer Firefox's canary domain (`use-application-dns.net`) with NXDOMAIN
  - per-app DoH blocking ([§7.11](#711-dns-bypass-handling))
  - Chrome doesn't auto-upgrade to its own encrypted DNS when the system resolver is local

**Resource targets:** [§16](#16-non-functional-requirements).

As built (Phase 7):

- **Processes:** the service starts `win4tress-dns` and keeps it running. Installed (the service runs as SYSTEM), the resolver runs as **LocalService** and can only read its folder, `ProgramData\win4tress\dns`; in console runs it has the console's account. Its output goes to `resolver.log` there. It listens on `127.0.0.1:53` and `[::1]:53` (UDP and TCP), reloads `config.json` within a second of the service rewriting it, and reports its status and last 5,000 lookups over `\\.\pipe\win4tress-dns` (SYSTEM and Administrators; LocalService, the resolver itself, has read and write, which opening the pipe's next instance after each client takes). If that pipe can't be read for 10 s while filtering works, the status lists it as a problem instead of showing only zeros, and a pipe server that can't open its next instance tries again every second instead of ending. When the service starts, it ends a resolver a crash left behind.
- **Watchdog:** a query for `health.win4tress.invalid` straight to `127.0.0.1:53` every 500 ms. Four misses: the rule goes, Windows' DNS cache is flushed, and the alert "DNS filtering set aside" is raised. Two answers: the rule comes back. Measured with the resolver killed: rule gone after 1.71 s, lookups working 1.80 s after the kill, filtering back on its own 3 s later.
- **Messages:** parsed and built by hand (no `hickory-proto`); name-compression loops are capped, and property tests feed it malformed input.
- **Upstream:** the network's DNS servers (every connected adapter's, those with a gateway first; UDP from a random port with a random ID, TCP when an answer is truncated), or DNS over HTTPS: Cloudflare, Quad9, Google or your own `https://` address. DoH goes through WinHTTP, one connection kept open and closed after 60 s idle; the DoH server's own name is looked up through the network's servers. DoT isn't offered ([§20](#20-decisions)).
- **Blocklists:** a catalogue, each list with its licence and homepage: HaGeZi Light, Normal (the default), Pro, Ultimate and Threat Intelligence; OISD Small and Big; StevenBlack; AdGuard DNS filter. Plus your own `https://` lists. Lists are downloaded once a day if changed (ETag), and not on metered connections unless asked for.
- **Compiled:** one file of keyed 64-bit SipHash-1-3 hashes, sorted, 10 bytes a domain, memory-mapped. Each compile gets a new file name, because a mapped file can't be replaced. 1M domains: a 9.5 MB file, 117 ms to compile, 0.2 ms to open, 1.8–2.6 µs per lookup at p99 ([spike 0.8](spikes/0.8-blocklist-matcher.md)). HaGeZi Normal: 170,463 domains, compiled in 63 ms.
- **Rules:** allow wins over everything; then your deny list, your regex rules (at most 1,000; linear-time matching) and the lists. A name matches a listed domain or any parent of it, and CNAMEs in an answer are checked too. Local records answer `A` and `AAAA` for your own names.
- **Answers:** a cache of 10,000 answers whose TTLs count down. Blocked names get `0.0.0.0` / `::` (or NXDOMAIN) with a 60 s TTL.
- **Pause** for some minutes. **Observe only:** "Auto" observes when the network's DNS already blocks (an ad-blocking DNS server, probed hourly with `doubleclick.net` and `googleadservices.com`) and labels those lookups "blocked upstream".
- **Edge cases:**
  - A sign-in page (no internet, an adapter with a gateway up): lookups pass through unfiltered.
  - Local names (one label, adapters' DNS suffixes, `.local`, private reverse lookups) go to the network's servers, even with DoH. Split DNS sends a suffix to all of them, not only to the adapter it came from.
  - A VPN's own DNS servers count among the network's servers, and its NRPT rules win.
  - IPv6 servers from the router are used.
  - Port 53 taken: the status shows the resolver's error. Internet Connection Sharing holding `0.0.0.0:53` doesn't stop it binding loopback.
- **Firefox:** `use-application-dns.net` gets NXDOMAIN, so Firefox stays on the system resolver.
- **win4tress's own:** the resolver is a protected program (allowed out in every mode but Block All) and isn't flagged as using its own DNS.
- **App:** DNS → Filtering shows on/off and the state, counts, the catalogue with licences, your lists, rules and local names, where lookups go, NXDOMAIN, observe only, pause and the most blocked names. The DNS query log labels blocked lookups ("Blocked: HaGeZi Normal"). CLI: `dns-filter`, `dns-lists`, `dns-allow`, `dns-deny`, `dns-pause`, `dns-upstream`, `dns-log`.
- **Not built:** per-app DNS filtering (see §7.3) and DoT.

## 14. Security model

**In scope:**

| Threat | Mitigation |
|---|---|
| Malware running as the user, without elevation, changing rules through IPC | Authorization per method ([§4.3](#43-authorization)); optional "Require elevation" hardening |
| Malicious network input (DNS responses, mDNS/NetBIOS names, device data) | Parsers fuzzed; DNS resolver runs as LocalService |
| Hijacked updates | Authenticode signer pinning + signed release manifest ([§17](#17-release-engineering)) |
| Tampering with database or config | Files readable and writable only by SYSTEM and Administrators |
| DLL planting | Installed under Program Files; safe DLL search order |
| Rule tampering by other software | Reconciliation and alerts ([§7.8](#78-reconciliation-and-tamper-detection)) |

**Out of scope:** attackers with admin, SYSTEM or kernel access. They can turn off any user-mode firewall, and we say so.

**Network surface:** no listening ports, except the Phase 7 resolver on loopback only.

## 15. Privacy

- No telemetry or analytics. Crash reports are opt-in.
- History stays on the device.

What can leave the machine:

| Data | When | Default |
|---|---|---|
| Update checks and downloads | Daily | On (can be turned off; postponed on metered connections) |
| DB-IP and threat-list updates | Monthly / daily | On (postponed on metered connections) |
| Reverse (PTR) lookups | When a hostname is unknown | On (setting) |
| File hashes to CIRCL / VirusTotal / MalwareBazaar | Reputation enabled | **Off** |
| File upload to VirusTotal | Per file, confirmed | **Off** |
| Blocklist downloads | DNS module enabled | **Off** |
| Crash reports | Opt-in | **Off** |

A privacy policy is published before beta.

## 16. Non-functional requirements

| Area | Target |
|---|---|
| Service memory | ≤ 60 MB working set, typical use |
| Service CPU | < 1% average typical; < 5% at sustained 1 Gbps |
| UI | Resources used only while open; live update every 1 s; smooth chart interaction |
| Accuracy | Inbound app payload ≥ 95% of adapter bytes minus estimated headers over 24 h. Known-size transfers (50 MB down and up) credited ≥ 99% to the transferring app. The remainder shown as "Protocol overhead & other" |
| Rule change | ≤ 1 s from click to enforced |
| Ask prompt | Shown ≤ 1 s after the first blocked attempt |
| Crash recovery | Service back within 5 s; leftover ETW session cleaned up |
| History | Month view ≤ 500 ms with 1 year of data |
| Disk | ≤ 500 MB per year of history, typical use |
| DNS module | ≤ 50 MB RAM with 1M domains; added delay at the 99th percentile ≤ 2 ms for blocked or cached lookups; start to first answer ≤ 200 ms; watchdog restores settings within 2 s; < 0.1% CPU |
| Robustness | Survives sleep/resume, network changes, Wi-Fi roaming, reboots, upgrades |

## 17. Release engineering

- **Versioning:** SemVer. Channels: **beta** and **stable**.
- **Installer:** WiX MSI per architecture (x64 built; ARM64 to come), from `installer/win4tress.wxs` by `installer/build.ps1` (WiX Toolset v7). It:
  - installs the service, the app, the CLI and the DNS resolver (a program the service starts, not a service of its own), and the data read at run time (geolocation, device makers)
  - registers the service (starts with Windows as LocalSystem, restarted after a crash) and starts it; the service makes the protected-component allow rules and saves the original firewall profile settings itself, when it first changes them
  - adds a Start menu shortcut (carrying the app's notification identity) and starts the app at the installing user's sign-in, a per-user choice the user can change in Settings
  - closes the app before replacing its files, and starts it again afterwards
- **Upgrades:** a newer MSI removes the older version, then installs. `ProgramData\win4tress` stays (history, settings, rules; the database migrates itself), and so does the user's sign-in choice. Downgrades are refused. Firewall rules stay in force while the service is stopped.
- **Uninstall:**
  - stops and removes the service, which stops its ETW sessions and DNS filtering's routing rule
  - `win4tress-svc cleanup` then removes the DNS routing rule if left, the `win4tress` rule group, and restores the firewall profile settings it changed; only on a real uninstall, never the removal step of an upgrade
  - removes the app from the user's sign-in
  - keeps history in `ProgramData\win4tress` (decided 2026-10-26, rather than asking)
- **Code signing:** every binary and the MSI are Authenticode-signed. Route to be decided ([§20](#20-open-decisions)): Microsoft Trusted Signing (if eligible) or an OV certificate on a cloud HSM. SmartScreen reputation builds up over time. Check current policy before buying: EV certificates no longer guarantee instant reputation.
- **Updates:**
  - The service checks the release feed daily (GitHub Releases proposed).
  - Before installing with `msiexec`, it verifies the MSI's Authenticode signer **pinned to our certificate subject** and a separately signed (Ed25519) release manifest.
  - The user can postpone updates. Updates wait on metered connections.
- **Crash handling:**
  - Service recovery: restart up to 3 times.
  - Local minidumps.
  - Uploads opt-in only.
- **False positives from security software:** submit each release to the Microsoft Security Intelligence portal and major antivirus vendors before publishing. Network-manipulating tools get flagged often.
- **CI/CD (GitHub Actions):**
  - Every build: build, `clippy`, `fmt`, tests, `cargo-deny`, a short fuzz run, MSI build (x64 + ARM64 cross-compile).
  - Release builds only: signing.
- **Documentation:** user guide, alert dictionary, known limitations, privacy policy, changelog, third-party notices.

## 18. Third-party data & licensing

| Item | Use | Terms | Obligations |
|---|---|---|---|
| DB-IP Lite (country, ASN) | Flags, network owner | CC BY 4.0 | Attribution wherever results appear, with a link back to DB-IP.com (the Countries column shows the text today; make it a link that opens the browser) and in About (done, 0.1.18) and docs. Not committed to git: `tools/dev/fetch-geo.ps1` downloads it |
| country-flag-icons | Flags in the UI | MIT | Third-party notices |
| Natural Earth (1:110m countries) | The traffic map | Public domain | None; credited under the map. `tools/dev/make-world-map.py` builds `ui/src/lib/world-map.json` from it |
| IEEE OUI registry | Device manufacturers | Public registry | Verify terms before release. Not committed to git: `tools/dev/fetch-oui.ps1` downloads it (~4 MB) |
| abuse.ch feeds (Feodo Tracker, URLhaus, ThreatFox) | Suspicious hosts | Feodo Tracker's IP blocklist downloads anonymously (checked 2026-10-25). URLhaus and ThreatFox answer HTTP 410 without an abuse.ch Auth-Key (free account) | Link to abuse.ch's terms of use where the list is shown; verify commercial-use terms before release. URLhaus/ThreatFox: the user's own key, a follow-up |
| CIRCL hashlookup | Known-good check | Public service; verify terms | Polite rate limiting |
| VirusTotal | Reputation | Free API is **non-commercial**; users bring their own key | Upload warning |
| MalwareBazaar | Reputation | Verify | — |
| DNS blocklists | Phase 7: HaGeZi, OISD, AdGuard DNS filter (GPL-3.0); StevenBlack (MIT); the user's own | Per list | **Never bundled**: downloaded at runtime from each maker by the user's choice. Licence and homepage shown per list (app and `dns-lists`). Only a hashed compilation stays on the PC |
| Rust crates | — | Various | `cargo-deny` licence allowlist; generated NOTICE file |

## 19. Known limitations (user-facing)

These go into the documentation, worded plainly:

1. win4tress is **not antivirus**. Malware with admin rights can turn off any firewall, including this one.
2. If another firewall product is installed, win4tress can **monitor but not enforce**.
3. **Ask to Connect:** an app's first connection attempt fails. It works on retry after you allow it.
4. **Host rules match IP addresses.** The first connection to a newly resolved IP can get past a block, and blocking one host can block others that share its CDN IP, for that app only. With the DNS module on, matching is exact.
5. Apps that use **their own encrypted DNS** hide hostnames from win4tress and bypass DNS filtering. win4tress detects this and offers a per-app block.
6. **VPNs** can cause traffic to be counted twice.
7. On **managed PCs** (Group Policy/Intune), the organisation's policy may limit what win4tress can enforce.
8. **Block All blocks win4tress too** (updates, lookups) until it's turned off.

## 20. Decisions

### Decided

| # | Decision | Outcome | Date |
|---|---|---|---|
| 1 | Business model | **Open source.** Ask to Connect and Block All are free | 2026-10-25 |
| 1a | Licence | **MIT OR Apache-2.0**: dual-licensed like most Rust projects, permissive for anyone. GPL-3.0 and MPL-2.0 were considered. `LICENSE-MIT`, `LICENSE-APACHE` | 2026-11-02 |
| 4 | Front-end framework | **Svelte 5** + TypeScript | 2026-10-25 |
| 5 | Who can change rules by default | **Admins without a UAC prompt**; "Require elevation for changes" as a hardening option ([§4.3](#43-authorization)) | 2026-10-25 |
| 8 | Routing lookups to the resolver | **An NRPT rule**, not adapters' DNS servers: as fast to fail over, adapters untouched, VPN rules keep winning ([spike 0.7](spikes/0.7-resolver-failover.md)) | 2026-10-26 |
| 9 | DNS message handling | **Hand-written**, property-tested: the resolver needs a few record types and the question echoed, not a DNS library | 2026-10-26 |
| 10 | Encrypted upstream | **DNS over HTTPS through WinHTTP**; no DoT. WinHTTP brings Windows' TLS and proxy settings without a TLS library; DoT would need one (or raw SChannel), and the same providers offer DoH | 2026-10-26 |
| 11 | Per-host rules with DNS filtering on | **They stay address-based.** Windows' DNS Client asks the resolver for every app, so it can't tell apps apart; exact names are DNS filtering's deny list, for every app | 2026-10-26 |

### Open

| # | Decision | Options | Proposal |
|---|---|---|---|
| 2 | Name and trademark | Check "win4tress" against trademarks, domains, store names | Do before beta |
| 3 | Signing route | Trusted Signing vs. OV certificate on a cloud HSM | Check eligibility first |
| 6 | Crash-report backend (opt-in) | Self-hosted vs. Sentry | Decide by beta |
| 7 | Update host | GitHub Releases vs. own CDN | GitHub Releases |
