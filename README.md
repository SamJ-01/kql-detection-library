# KQL Detection Library

Detection queries for Microsoft Sentinel / Defender for Endpoint, organised by
MITRE ATT&CK tactic. Every query is documented to a production standard: detection
logic, data source, false-positive profile, and tuning guidance — because a query
without an FP analysis is a hypothesis, not a detection.

## Structure

detections/
├── credential-access/
├── execution/          # e.g. RCE via Invoke-WebRequest + Start-Process
├── lateral-movement/   # e.g. WMIC remote execution (WmiPrvSE spawn analysis)
├── exfiltration/       # e.g. certutil -encode, suspicious POST patterns
├── persistence/        # e.g. netsh portproxy creation
├── defense-evasion/    # e.g. wevtutil log clearing
└── initial-access/     # e.g. brute-force fail→success transition

## Documentation Standard (every detection)

| Field | Purpose |
|---|---|
| Hypothesis | The attacker behaviour this catches, in one sentence |
| ATT&CK | Technique ID(s) |
| Data source | Table + required telemetry (e.g. DeviceProcessEvents, Sysmon EID 1) |
| Query | The KQL itself, commented |
| False positives | Known benign triggers and how to exclude them |
| Validation | How the detection was tested (triggered behaviour + observed alert) |

## Example — Defense Evasion: Security Log Cleared

**Hypothesis:** An attacker clearing Windows event logs to remove evidence.
**ATT&CK:** T1070.001

```kql
DeviceProcessEvents
| where ProcessCommandLine has "wevtutil" and ProcessCommandLine has_any ("cl", "clear-log")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**False positives:** rare; some imaging/decommissioning scripts. Exclude known
maintenance accounts rather than raising the threshold — this behaviour warrants
per-event review.
**Validated:** during Operation Silent Corridor, this pattern identified the
attacker's cleanup phase on the domain controller.
