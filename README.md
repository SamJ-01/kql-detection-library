# KQL Detection Library

Detection queries for Microsoft Sentinel / Defender for Endpoint, organised by
MITRE ATT&CK tactic. Every query is documented to a production standard: detection
logic, data source, false-positive profile, and tuning guidance — because a query
without an FP analysis is a hypothesis, not a detection.

> **Lab scope:** these are lab detections written against synthetic telemetry. No
> real organisation, host or account data is included, and none of the queries are
> tuned for a specific production environment. Thresholds, path lists and
> allow-lists are starting points to adapt.

## Detections

| Tactic | Detection | ATT&CK | Table(s) | Severity |
|---|---|---|---|---|
| Initial Access | [Brute force followed by a successful logon](detections/initial-access/brute-force-then-success.kql) | T1110 → T1078 | DeviceLogonEvents | High |
| Execution | [PowerShell download-and-execute](detections/execution/powershell-download-execute.kql) | T1059.001, T1105 | DeviceProcessEvents | High |
| Credential Access | [Credential dumping (LSASS, SAM, NTDS.dit)](detections/credential-access/credential-dumping.kql) | T1003.001 / .002 / .003 | DeviceProcessEvents | High |
| Lateral Movement | [WMIC remote process execution](detections/lateral-movement/wmic-remote-execution.kql) | T1047 | DeviceProcessEvents | High |
| Collection | [Compress-Archive on sensitive paths](detections/collection/compress-archive-sensitive-paths.kql) | T1560 | DeviceProcessEvents, DeviceFileEvents | Medium |
| Defense Evasion | [certutil encode / decode](detections/defense-evasion/certutil-encode-decode.kql) | T1027, T1140 | DeviceProcessEvents | Medium |
| Defense Evasion | [Windows event log cleared](detections/defense-evasion/wevtutil-log-clearing.kql) | T1070.001 | DeviceProcessEvents (+ SecurityEvent 1102) | High |
| Command and Control | [netsh portproxy rule created](detections/command-and-control/netsh-portproxy.kql) | T1090.001 | DeviceProcessEvents, DeviceRegistryEvents | High |
| Exfiltration | [Scripting tool contacts a newly observed domain](detections/exfiltration/post-to-new-domain.kql) | T1041 | DeviceNetworkEvents (+ CommonSecurityLog) | Medium |

## Structure

```
detections/
├── initial-access/        brute-force-then-success.kql
├── execution/             powershell-download-execute.kql
├── credential-access/     credential-dumping.kql
├── lateral-movement/      wmic-remote-execution.kql
├── collection/            compress-archive-sensitive-paths.kql
├── defense-evasion/       certutil-encode-decode.kql, wevtutil-log-clearing.kql
├── command-and-control/   netsh-portproxy.kql
└── exfiltration/          post-to-new-domain.kql
```

netsh portproxy sits under Command and Control because ATT&CK files it as
T1090 Proxy, even though attackers use it to keep a way back in.

## Documentation Standard (every detection)

Each `.kql` file opens with a comment block containing:

| Field | Purpose |
|---|---|
| Hypothesis | The attacker behaviour this catches, in one sentence |
| ATT&CK | Technique ID(s) and tactic |
| Data source | Table(s) + required telemetry (e.g. DeviceProcessEvents, Sysmon EID 1) |
| Query | The KQL itself, commented |
| False positives | Known benign triggers and how to exclude them |
| Response | What an analyst should do when it fires |
| Validation | How the detection was tested (triggered behaviour + observed alert), or "not yet validated" |

## Example — Defense Evasion: Security Log Cleared

**Hypothesis:** An attacker clearing Windows event logs to remove evidence.
**ATT&CK:** T1070.001 · **File:** [wevtutil-log-clearing.kql](detections/defense-evasion/wevtutil-log-clearing.kql)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine matches regex @"(?i)\s(cl|clear-log)\s")
    or (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any ("Clear-EventLog", "Remove-EventLog", "ClearLog"))
| project Timestamp, DeviceName, AccountDomain, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**False positives:** rare; some imaging/decommissioning scripts. Exclude known
maintenance accounts rather than raising the threshold — this behaviour warrants
per-event review.
**Validated:** during Operation Silent Corridor, this pattern identified the
attacker's cleanup phase on the domain controller.

## Using the queries

- **Defender XDR advanced hunting:** paste a query in as-is.
- **Microsoft Sentinel:** the `Device*` tables arrive through the Microsoft Defender
  XDR connector and keep the `Timestamp` column. Alternatives at the bottom of some
  files use Sentinel-only tables (`SecurityEvent`, `CommonSecurityLog`).
- **As a custom detection rule:** Defender custom detections must return
  `Timestamp`, `DeviceId` and `ReportId`, so add those to the final `project` line.

## Related work

- [Operation Silent Corridor](https://github.com/SamJ-01/threat-hunt-silent-corridor) — the
  threat hunt several of these detections came out of.
- [MDE Detection & Automated Response](https://github.com/SamJ-01/mde-detection-automation) —
  custom detections with automatic device isolation.

## Licence

[MIT](LICENSE)
