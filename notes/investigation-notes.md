# Investigation Notes — Windows Script Host Abuse

## Investigation Summary

This investigation examined Windows Script Host activity involving `wscript.exe` and `cscript.exe` on `DESKTOP-9MMM37V`.

The activity was generated intentionally using a harmless Visual Basic script. The purpose was to validate Elastic endpoint telemetry and investigate how script execution appears from a SOC analyst's perspective.

The investigation focused on process execution, command-line arguments, process ancestry, executable locations, user context, and supporting file activity.

## Investigation Objectives

- Identify `wscript.exe` and `cscript.exe` executions.
- Determine how the processes were launched.
- Identify the script associated with each execution.
- Validate the executable paths.
- Compare the two Windows Script Host binaries.
- Investigate unusual process metadata.
- Separate controlled activity from unrelated endpoint events.
- Determine whether the evidence supports malicious execution.

## Controlled Activity

A harmless VBScript was created at:

```text
C:\Users\Public\lab03.vbs
```

The script created:

```text
C:\Users\Public\wsh_lab03.txt
```

The output file contained:

```text
Elastic Security Lab 03 - Windows Script Host
```

The script was executed using:

```powershell
wscript.exe C:\Users\Public\lab03.vbs
```

and:

```powershell
cscript.exe C:\Users\Public\lab03.vbs
```

## Elastic Telemetry Validation

The initial process-based query was:

```esql
FROM logs-*
| WHERE process.name IN ("wscript.exe", "cscript.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

Within the initial 15-minute window, this returned:

`0 documents processed`

This did not establish that WSH execution was absent.

A more targeted query was then used:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*lab03.vbs*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

This returned four documents.

## Observed WSH Events

### Wscript

Observed events:

```text
Sep 22, 2026 @ 06:35:04.887
Sep 22, 2026 @ 06:35:04.897
```

Process:

```text
wscript.exe
```

Parent:

```text
pwsh.exe
```

Command line:

```text
"C:\Windows\System32\wscript.exe" C:\Users\Public\lab03.vbs
```

Executable:

```text
C:\Windows\System32\wscript.exe
```

User:

```text
Dell
```

### Cscript

Observed event:

```text
Sep 22, 2026 @ 06:35:47.767
```

Process:

```text
cscript.exe
```

PID:

```text
17048
```

Parent:

```text
pwsh.exe
```

Parent PID:

```text
32400
```

Command line:

```text
"C:\Windows\System32\cscript.exe" C:\Users\Public\lab03.vbs
```

Executable:

```text
C:\Windows\System32\cscript.exe
```

User:

```text
Dell
```

## Process Relationship

The controlled execution established the following process relationship:

```text
pwsh.exe
    ↓
cscript.exe
    ↓
lab03.vbs
    ↓
wsh_lab03.txt
```

A similar PowerShell-to-WSH relationship was observed for the controlled `wscript.exe` activity.

This relationship is consistent with the way the scripts were intentionally launched during the lab.

## Parent PID Anomaly

Some `wscript.exe` telemetry contained:

```text
process.parent.pid = 4294967295
```

This value was not treated as evidence of malicious activity.

Instead, it was documented as a process-metadata or telemetry anomaly because other telemetry provided a PowerShell parent relationship for controlled executions.

This demonstrates an important SOC investigation principle:

> A single inconsistent telemetry field should be validated against other available evidence before drawing a conclusion.

## Script Path Analysis

The command line clearly exposed:

```text
C:\Users\Public\lab03.vbs
```

This was significant because it allowed the investigator to connect the process event directly to the known controlled script.

The script location was also useful for distinguishing the controlled lab activity from unrelated WSH activity.

## Executable Path Analysis

The observed binaries executed from:

```text
C:\Windows\System32\wscript.exe
```

and:

```text
C:\Windows\System32\cscript.exe
```

These paths were consistent with the expected Windows Script Host binaries used for the lab.

## File Validation

The script created:

```text
C:\Users\Public\wsh_lab03.txt
```

The file was then inspected from PowerShell.

Observed contents:

```text
Elastic Security Lab 03 - Windows Script Host
```

This confirmed that the controlled script executed as intended.

## Analyst Assessment

### Observed

- Windows Script Host process execution.
- `wscript.exe` and `cscript.exe` activity.
- Script path in the process command line.
- Expected Windows executable locations.
- PowerShell parent relationship for controlled activity.
- Expected output file creation.
- One unusual parent PID representation.

### Confirmed

- Controlled VBScript execution.
- Expected file creation.
- Elastic endpoint telemetry for the test activity.
- No malicious payload was introduced.

### Unknown / Requires Further Validation

- The reason for the anomalous parent PID value.
- Whether unrelated WSH events observed outside the controlled execution window represent legitimate system or user activity.

## Malicious Activity Assessment

The observed controlled executions do not establish malicious WSH abuse.

No evidence was demonstrated for:

- Persistence
- Credential theft
- Privilege escalation
- Malware execution
- Command-and-control
- Suspicious child processes
- Data theft

The investigation therefore remains focused on **telemetry validation and execution-context analysis**, rather than treating the WSH binaries themselves as malicious.

## MITRE ATT&CK Mapping

**T1059.005 — Command and Scripting Interpreter: Visual Basic**

The controlled lab demonstrates Visual Basic script execution through Windows Script Host.

## Investigation Conclusion

Elastic Defend successfully provided process-level visibility into the controlled Windows Script Host executions. The strongest evidence came from correlating the script path, command line, process name, parent process, executable location, user context, and resulting file.

The investigation also demonstrated that telemetry inconsistencies should be documented as limitations rather than converted into unsupported conclusions.
