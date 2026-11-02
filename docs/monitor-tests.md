# Security monitor trigger tests

How to make each security monitor (SPEC §11) raise its alert, for checking a
build in the test VM. Each test says what to do, what to expect, and how to put
things back. Run the service with `win4tress-svc console` in an elevated
terminal, or as the installed service; watch with `win4tress alerts --limit 5`.

The monitors look every 30 seconds, so allow up to half a minute. The first
look after a fresh install only learns what's there; it doesn't alert.

Every monitor can be switched off and given another severity:

```powershell
win4tress monitors                                  # the list, and the threat lists' state
win4tress monitor proxy_changed --severity critical # or info, warning, default
win4tress monitor internet_access_changed on        # or off
win4tress monitors --event-log on                   # copy alerts to the Application log
```

Unit tests cover each monitor's logic, including the false-positive cases in
the last column (`cargo test -p w4-monitors`).

| Alert | Trigger (elevated where it changes the system) | Expect | Put back | Not alerted (unit-tested) |
|---|---|---|---|---|
| System file changed | `Set-Content "$env:SystemRoot\System32\drivers\etc\w4-test.txt" test` | "System file created: …\w4-test.txt" (warning) | `Remove-Item` it: "deleted" | Files read but not changed |
| Network adapters changed | Add a Hyper-V internal switch: `New-VMSwitch w4-test -SwitchType Internal` (on a Hyper-V host), or install a VPN client that adds an adapter | "New network adapter: vEthernet (w4-test) …" (info) | `Remove-VMSwitch w4-test` | The same adapter coming back (VPNs re-add theirs on every connect) |
| DNS servers changed | `Set-DnsClientServerAddress -InterfaceAlias <alias> -ServerAddresses 9.9.9.9` | "DNS servers on <alias> changed from … to 9.9.9.9 on the same network" (warning) | `Set-DnsClientServerAddress -InterfaceAlias <alias> -ResetServerAddresses` (alerts again, back) | Moving to another network (another gateway) with other servers |
| Proxy changed (machine) | `netsh winhttp set proxy proxy-server="127.0.0.1:3128"` | "The machine's (WinHTTP) proxy settings changed from "direct" to …" (warning) | `netsh winhttp reset proxy` (alerts again) | — |
| Proxy changed (user) | Settings → Network & internet → Proxy → set a manual proxy, with the app running (it reports the user's settings every minute) | "Your proxy settings changed …" (warning) | Turn the manual proxy off | — |
| Internet access changed | Off by default: `win4tress monitor internet_access_changed on`, then disconnect the VM's network adapter | "Internet access was lost" (info), then "is back" | Reconnect; switch the monitor off again | — |
| ARP spoofing | Needs a second machine on the LAN: `arpspoof -i eth0 -t <VM> <gateway>` (dsniff), from a Linux VM on the same switch | "Possible ARP spoofing: the gateway … now answers from <attacker's MAC>" (critical) | Stop arpspoof; the VM's ARP entry expires | Incomplete or unreachable entries during a DHCP renewal; a router replaced once (alerts once, then known) |
| Wi-Fi evil twin | Needs Wi-Fi: connect to a WPA2 network once, then bring up an open hotspot with the same name (a phone hotspot) near the PC | "Possible Wi-Fi evil twin: a network named … with open security is nearby; yours has WPA2" (critical) | Turn the hotspot off | Mesh and enterprise access points with the same name and security; WPA3 alongside WPA2 |
| Suspicious host contacted | Add a name to the own list (`%ProgramData%\win4tress\threats-local.txt`, elevated): `example.com`; then `curl https://example.com` | "curl connected to example.com on port 443, which is on your own list" (critical) | Remove the line | The same app and address again (one alert each) |
| While you were away | Leave the PC (with the app running) for 30 minutes or more, then come back | "While you were away (35 min): … down, … up, mostly …" (info) | — | Absences under 30 minutes; nothing happened meanwhile |
| New device on network | `win4tress scanner on`; after the first scan, connect a phone to the same network | "New device on the network: …" (info), within half an hour (or `win4tress scan`) | `win4tress scanner off` | Devices found by the first scan (it learns the network) |
| RDP connection | Connect to the VM with Remote Desktop | "Remote Desktop connection from …" (warning) | — | The same address within 12 hours |
| Reputation | Lookup: `win4tress reputation --lookups on --virustotal-key …`, then `win4tress lookup <app> --now` for a program VirusTotal flags (check its page first), with `--alert-at` at or below its count. Antivirus: `win4tress av-scan <app>` shows the clean path; a find needs a real threat, which Defender's real-time protection removes first | "…'s file is likely malicious (VirusTotal: N of M engines…)" (critical); with `--auto-block on`, also blocked both ways | `win4tress reputation --lookups off`; delete the auto-block rules | The same answer again on the weekly refresh |

The live end-to-end run for Phase 5 covered system files, machine proxy,
suspicious host (own list), while you were away, the scanner, a monitor
switched off, a severity changed, the Event Log copy and a desktop pop-up
(PLAN, Phase 5).
