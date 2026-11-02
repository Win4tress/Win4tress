# etw-probe: spike 0.1

Measures whether ETW gives accurate per-process network byte counts. It traces
`Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-Kernel-Process` and
`Microsoft-Windows-DNS-Client`, then compares the totals with the adapters' own
counters. Pass criteria: [PLAN.md, Phase 0](../../../docs/PLAN.md#phase-0-spikes).
Results: [docs/spikes/0.1-etw-collector.md](../../../docs/spikes/0.1-etw-collector.md).

It only reads. Run it from an **elevated** terminal.

```powershell
cargo build -p etw-probe --release
$probe = ".\target\release\etw-probe.exe"
```

## Runs

| Purpose | Command |
|---|---|
| Quick look, with one JSON dump per event type | `& $probe --duration 60 --dump > dump.txt` |
| 24 h accuracy | `& $probe --interval 60 --csv etw-24h.csv` (use the PC normally) |
| 72 h memory | `& $probe --interval 300 --csv etw-72h.csv` (watch `working_set`) |
| Crash recovery | Start it, end it in Task Manager, start it again: it should print `Found a leftover ... session` and `First event ... ms` |

**Known-size transfers** (while the probe runs, in another elevated window):

```powershell
# Download: curl.exe should be credited with ~50.0 MB in
curl.exe -s -o NUL "https://speed.cloudflare.com/__down?bytes=50000000"

# Upload: curl.exe should be credited with ~50.0 MB out
fsutil file createnew up50.bin 50000000
curl.exe -s -o NUL -X POST --data-binary "@up50.bin" "https://speed.cloudflare.com/__up"
Remove-Item up50.bin
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--duration <s>` | until Ctrl+C | Stop after this many seconds |
| `--interval <s>` | 10 | Seconds between reports |
| `--csv <path>` | off | Append one row per interval (flushed each row) |
| `--dump` | off | Print the first event of each provider/ID as JSON |
| `--flush-ms <ms>` | 250 | ETW flush timer; this drives delivery delay |
| `--buffer-kb`, `--max-buffers` | 64, 256 | ETW buffer sizing |

## Reading the report

- **ETW/adapters**: ETW counts payload; adapters count whole frames. The
  "excl. est. headers" figure removes an estimated 54 bytes per packet.
  Outbound during a download is mostly payload-free TCP ACKs that ETW never
  reports, so judge outbound with the upload test, not the ratio.
- **Short intervals don't line up**: ETW events arrive a few hundred ms after
  the adapter counters move. Compare totals over minutes, not single intervals.
- **header-PID mismatch** shows how often the event header names the wrong
  process. The probe always uses the PID in the event data.
- **named** is the share of external bytes whose remote IP had a hostname from
  DNS-Client events.
- Memory grows slowly with the number of processes, hosts and DNS names it
  tracks (shown in each report). The production collector will roll these up.
