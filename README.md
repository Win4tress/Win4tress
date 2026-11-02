# win4tress

A network monitor and firewall front-end for Windows 11: see which apps use the
network, how much and where; allow or block them through Windows Firewall; get
alerts about suspicious network changes. Everything stays on your PC.

**Status:** pre-alpha. Phases 1 to 6 are built: the monitor, the firewall (Click
to Block, Ask to Connect, Block All, profiles, rules for a while), history and usage, the security
monitors, alerts and network scanner, and reputation, incognito, the map and
the mini viewer. Their exit tests in a clean VM (long soak,
clean install, reboot, a week in Ask to Connect) are still to run.

- [Specification](docs/SPEC.md)
- [Implementation plan](docs/PLAN.md)
- [Spike results](docs/spikes/)

## What works today

- **Service** (`win4tress-svc`): traces network traffic with ETW and attributes it
  to apps (Windows services inside `svchost` are told apart) and hosts. Hostnames
  come from each app's own DNS lookups, with reverse DNS as a fallback; countries
  and network owners from DB-IP. It keeps the last 10 minutes per second in memory,
  and on disk 48 hours per minute by host, 35 days per minute by app, 2 years per
  hour and daily totals for good (a busy year is about 160 MB). It logs DNS lookups, tracks live connections, and
  serves all of it over a named pipe. If something else stops its ETW session, it
  starts it again within 10 seconds. Runs as a Windows service or in a console.
- **App** (`win4tress-ui`):
  - **Traffic**: a **Graph** view (1 or 5 minutes live; 1, 3 or 24 hours, a week
    or a month from history, stepping back through it), filtered to the internet,
    the local network, an app, publisher, traffic type or country, with alerts
    marked and away time shaded, and **Export PNG**. A **Usage** view for a day,
    week or month (Apps / Hosts / Publishers / Traffic type / Countries, with
    cross-filtering and a totals strip), a **data plan** with alerts, and
    "leave out VPN clients". Click a moment or drag across a range to see who
    was talking.
  - **Apps**: every app that used the network, with its process IDs, publisher,
    version, path, current hosts, live download/upload rates and a last-minute
    graph. Expand a row for its totals and every host it talked to, with a
    **Block** button per host, **Block for…** (or **Allow for…**) a while,
    and **Disconnect**. **In** and **Out** switches block an app's
    incoming or outgoing connections; their color shows what actually happens
    (teal allowed, gray blocked by Windows Firewall, coral blocked by
    win4tress; hover for the rule; a small clock marks a rule for a while). Apps that were blocked and so had no
    traffic are listed too, under **Blocked, no traffic**. Badges flag unsigned or broken
    signatures, downloaded programs, unsigned programs in user folders, and
    apps that do their own DNS. win4tress's own programs show a lock.
  - **Firewall**: every app win4tress has seen, with what happens to its
    connections. Filter, search, check several and block or unblock them
    together after a preview. An app's detail lists win4tress's rules, adds
    rules for some hosts, "allow only these hosts", **Allow incoming…**,
    **Block its own DNS**, and blocking or allowing it for a while (15 minutes
    to 8 hours, until it quits, or until Windows restarts, then back to what it
    was), and shows Windows Firewall's rules for it, its
    signature, signer, hash and download origin, and what was blocked in the
    last 30 days.
  - **Firewall menu** (header): the state at a glance; turn Windows Firewall
    on where it's off; Click to Block, **Ask to Connect** or Off; **Block All**
    for 15 minutes, an hour or until turned off (with a warning over Remote
    Desktop); **profiles**, each switched to by hand or by itself when the PC
    joins a network you chose for it (by name, or any public, private or domain
    network); and **Require elevation**.
  - **Ask to Connect**: apps without a rule are blocked until you decide, in a
    small card above the taskbar (allow or block the app, always or for a
    while, or just that host, or decide later). It says where a helper program belongs when its name
    doesn't ("in Adobe\Acrobat DC"), never takes the keyboard, and waits
    while a game or video is full screen. In Click to Block, the same card offers **Block**
    when an app uses the network for the first time (it also ends the app's
    open connections). Windows' own services keep working, and Microsoft-signed system
    programs are allowed on their own, except tools malware likes to abuse.
    Turning it on offers to allow the apps you used in the last week first.
  - **Connections**: open and recently closed TCP connections and UDP flows
    (end an IPv4 TCP connection with **×**; Windows can't end IPv6 ones), and
    a **Blocked** list: each blocked attempt and what blocked it (a win4tress
    rule, a Windows Firewall rule, or its default).
  - **DNS**: a dashboard (lookups and failures over
    time and by app, query types, results, top domains, top failed domains,
    top apps, for the last hour up to 30 days), a query log of every lookup by
    the app that made it, and **Filtering**: win4tress's own resolver on this PC
    blocks the names on the blocklists you choose (HaGeZi, OISD, StevenBlack,
    AdGuard, or your own; downloaded from their makers, licence shown), with
    your allow, block and regex rules, local names, pause, and lookups sent to
    your network's DNS servers or over HTTPS (Cloudflare, Quad9, Google). If
    the resolver stops answering, Windows' own DNS is back within 2 seconds.
    Off by default.
  - **Map** (in Traffic): internet traffic by country on a world map, for a day,
    a week, a month or a year, with the countries listed beside it.
  - **Settings** (the gear at the right of the header): incognito (keep all traffic, or some apps', out of history),
    reputation lookups (CIRCL, and VirusTotal and MalwareBazaar with your own
    keys; off by default), automatic cleanup of rules for uninstalled or
    inactive apps, **Rules and profiles** (export them to a file and import
    them on another PC, with a preview first), the **mini viewer**, a small
    always-on-top live graph (also in the tray menu and the header), and
    **About**: the app's and the service's versions, the Windows build, **Copy
    details** for bug reports, and credits.
  - **Network**: devices on your local network (private networks with a
    gateway only), with address, hardware address, maker (IEEE registry),
    name, first and last seen. **Scan now**, or scan every half hour and get
    an alert when a new device joins. Mark the ones you know; **Unknown**
    shows the rest.
  - **Alerts**: a log of what needs your attention, by date, app or type: an
    app's version, publisher, signer or file changed (critical if a signed app
    became unsigned), an app does its own DNS (with **Block its own DNS**), an
    app used the network for the first time or talked to a host on a threat
    list (abuse.ch Feodo Tracker, or your own), the hosts file or another file
    in `drivers\etc` changed, a new network adapter appeared, DNS servers or
    proxy settings changed, signs of ARP spoofing or a Wi-Fi evil twin, a new
    device on the network, internet access came or went (off by default),
    someone connected with Remote Desktop, monitoring was interrupted, another
    program changed win4tress's firewall rules (with **Keep these changes**),
    and a summary when you come back after half an hour away. **Settings →
    Alerts and notifications** sets, per monitor, whether it alerts, whether
    its alerts pop up on the desktop (warnings and critical ones by default)
    and its level, and copies alerts to the Windows Event Log. Snooze an app's
    or a kind's pop-ups for 24 hours. Unread alerts are marked,
    and the tab shows how many.
  - **Search everywhere** (Ctrl+K): apps, hosts, names looked up, alerts,
    devices, profiles and settings from one box.
  - Real app icons and country flags. Themes: Indigo (the default, in dark) or
    Win4tress's own colours, each light or dark or following Windows, picked
    from the header. Closing the window keeps it in the tray, with the
    current rate in the tooltip.
- **CLI** (`win4tress`): `status`, `apps`, `hosts <app>`, `connections`, `dns`, `alerts`, `watch`;
  `monitors [--event-log on|off] [--threat-feeds on|off]`, `monitor <kind> [on|off] [--severity …]`,
  `scan`, `devices [--known MAC | --unknown MAC]`, `scanner on|off`;
  `profile [list|save|switch|delete|networks]`, `networks`, `rule <id> on|off`, `incognito on|off [--app …]`,
  `export <file>`, `import <file> [--dry-run]`, `disconnect <app>`,
  `cleanup [--run]`, `reputation …`, `lookup <app>`, `av-scan <app>`, `vt-upload <app> --yes`;
  `dns-filter [on|off]`, `dns-lists [--add id | --remove id | --update]`, `dns-allow|dns-deny <name> [--remove]`,
  `dns-pause [minutes | --resume]`, `dns-upstream system|cloudflare|quad9|google|https://…`, `dns-log [--blocked]`.
- **Firewall:**
  - CLI commands:
    - `win4tress block <app>` (`--inbound`; `--hosts …`, `--allow-only …` or `--own-dns`), `allow <app>` and `delete-rule <id>`; `--for 30m|2h|1d|quit|restart` for a while
    - `win4tress block-all [--minutes N | --off]` (asks for `--yes` over Remote Desktop)
    - `win4tress blocked [--app …] [--days N]` (what was blocked, and by what)
    - `win4tress firewall-on [profile]`
    - `win4tress require-elevation on|off` (from an elevated prompt)
    - `win4tress firewall` (state and rules)
    - `win4tress why <app>` (what allows or blocks its connections, Windows Firewall's own rules included)
    - `win4tress mode [off|click-to-block|ask-to-connect] [--allow-recent]`
    - `win4tress prompts` and `win4tress decide <id> allow|block|later [--host | --for …]`
    - `win4tress plan [--limit-gb N --reset-day D --metered-only | --off]` and `win4tress exclude-vpn on|off`
    - `win4tress keep-changes <alert id>`
    - `win4tress reset` (from an elevated prompt; it also works with the service stopped)
  - Rules are written to Windows Firewall in the `win4tress` group.
  - If something else changes them, Windows Firewall's event log shows it. They're put back within about a second and an alert is raised. A check every minute catches anything the log misses.
  - Changes need a member of Administrators; `reset` needs elevation. With **Require elevation** on, every change does, and the app asks through a UAC prompt.
  - With another firewall in charge, or Group Policy telling Windows Firewall to ignore local rules, win4tress only monitors and says why.

## Building

Requirements:

- Windows 11
- Rust via [rustup](https://rustup.rs) (the toolchain is pinned in `rust-toolchain.toml`)
- Visual Studio Build Tools with the C++ workload and a Windows SDK
- Node.js 24

```powershell
.\tools\dev\fetch-geo.ps1    # country and network-owner databases; optional
.\tools\dev\fetch-oui.ps1    # device makers for the Network screen; optional
cargo build --release -p win4tress-svc -p win4tress-cli -p win4tress-dns
cd ui
npm ci
npm run tauri build      # builds target\release\win4tress-ui.exe
```

## Installing

`installer\build.ps1` builds everything and then the installer,
`target\installer\win4tress-<version>-x64.msi` (unsigned for now). It needs
WiX Toolset v7 once: `dotnet tool install --global wix`, `wix eula accept wix7`
(its Open Source Maintenance Fee EULA), and
`wix extension add -g WixToolset.Util.wixext/7.0.0`; and the data from
`tools\dev\fetch-geo.ps1` and `tools\dev\fetch-oui.ps1`.

The MSI installs to `C:\Program Files\win4tress`, starts the service, adds
Win4tress to the Start menu and starts the app at sign-in. A newer MSI upgrades
in place, keeping history, settings and rules. Uninstalling (Settings → Apps)
removes win4tress's firewall rules and DNS routing and keeps the history in
`%ProgramData%\win4tress`. Stop a `console` run first: it and the installed
service can't both run.

## Running

The service needs admin rights; the app and CLI don't.

```powershell
# Option 1: in an elevated terminal, until Ctrl+C
target\release\win4tress-svc.exe console

# Option 2: as a Windows service (elevated); remove it with `uninstall`
target\release\win4tress-svc.exe install

# Then, in a normal terminal
target\release\win4tress-ui.exe
target\release\win4tress.exe status
```

Data lives in `%ProgramData%\win4tress`, readable by administrators only:
`history.db` for the service, `history-console.db` for console runs, and `logs`.
Console runs log to the terminal. Set `WIN4TRESS_LOG=debug` for more detail.

## Developing

```powershell
cargo test --workspace                 # unit, property and named-pipe tests, no admin needed
cargo clippy --workspace --all-targets -- -D warnings
cd ui; npm run check                   # Svelte/TypeScript
cd ui; npm run tauri dev               # app with hot reload (start the service first)
python tools/dev/make-logo.py          # icons from assets/logo/emblem.svg (needs Pillow)
```

Tools in `tools/dev`:

- `record-trace.ps1` (elevated): records 15 s of real ETW events to
  `tools/traces/local.etl`. `cargo test -p w4-etw --test replay` then decodes it
  as a regression test. The trace holds this PC's traffic, so git ignores it.
- `soak.ps1`: samples the running service once a minute into a CSV (memory, CPU,
  lost events, accuracy against the adapter counters, history size). This is for
  the Phase 1 exit tests.
- `capture-window.ps1`: saves a PNG of the app window for UI review.
- `fetch-geo.ps1`, `fetch-oui.ps1`: download DB-IP's databases and IEEE's
  manufacturer registry to `data\` (not committed).

How to make each security monitor raise its alert: [docs/monitor-tests.md](docs/monitor-tests.md).

## Credits

IP geolocation and network owners by [DB-IP.com](https://db-ip.com), licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Botnet command
servers from [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch)
([terms](https://abuse.ch/terms-of-use/)). Device makers from the
[IEEE registration authority](https://standards.ieee.org/products-programs/regauth/).
The world map is [Natural Earth](https://www.naturalearthdata.com) (public domain).
Optional lookups use [CIRCL hashlookup](https://hashlookup.circl.lu),
[VirusTotal](https://www.virustotal.com) and
[MalwareBazaar](https://bazaar.abuse.ch) with your own keys.

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT licence ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in win4tress, as defined in the Apache-2.0 licence, is dual
licensed as above, without any additional terms or conditions.

The data win4tress ships or downloads keeps its own terms: see Credits.
