# Timeline — Windows Script Host Abuse

## Investigation Timeline

| Time | Activity | Process | Parent | User | Evidence / Notes |
|---|---|---|---|---|---|
| 06:34 | Created `lab03.vbs` | PowerShell | — | Dell | Harmless VBScript created under `C:\Users\Public` |
| 06:34 | Verified script | PowerShell | — | Dell | Script contents confirmed |
| 06:35:04.887 | Controlled script execution | `wscript.exe` | `pwsh.exe` | Dell | Command line referenced `C:\Users\Public\lab03.vbs` |
| 06:35:04.897 | Controlled script execution | `wscript.exe` | `pwsh.exe` | Dell | Duplicate/related WSH process telemetry |
| 06:35 | Output file verified | — | — | Dell | `C:\Users\Public\wsh_lab03.txt` created with expected content |
| 06:35:47.767 | Controlled script execution | `cscript.exe` | `pwsh.exe` | Dell | Command line referenced `C:\Users\Public\lab03.vbs` |
| 06:35 | `cscript.exe` process reviewed | `cscript.exe` PID `17048` | `pwsh.exe` PID `32400` | Dell | Parent-child relationship validated |
| 06:35+ | Process metadata reviewed | `wscript.exe` | Variable | Dell | Some telemetry contained parent PID `4294967295` |
| 06:50:09.849 | Additional WSH activity observed | `wscript.exe` | `pwsh.exe` relationship observed | Dell | Reviewed as additional endpoint telemetry |

## Detailed Evidence

### 06:34 — Script Creation

A controlled Visual Basic script was created:

```text
C:\Users\Public\lab03.vbs
```

The script was intentionally designed to create a text file and did not contain a malicious payload.

### 06:35:04 — Wscript Execution

Elastic recorded `wscript.exe` execution associated with the controlled script.

Observed command line:

```text
"C:\Windows\System32\wscript.exe" C:\Users\Public\lab03.vbs
```

Observed executable:

```text
C:\Windows\System32\wscript.exe
```

Observed parent:

```text
pwsh.exe
```

### 06:35:47 — Cscript Execution

Elastic recorded `cscript.exe` execution associated with the same script.

Observed command line:

```text
"C:\Windows\System32\cscript.exe" C:\Users\Public\lab03.vbs
```

Observed executable:

```text
C:\Windows\System32\cscript.exe
```

Observed process relationship:

```text
pwsh.exe (PID 32400)
    ↓
cscript.exe (PID 17048)
```

### Output File Creation

The controlled VBScript created:

```text
C:\Users\Public\wsh_lab03.txt
```

The file contained:

```text
Elastic Security Lab 03 - Windows Script Host
```

This was consistent with the intended behavior of the script.

### Parent PID Anomaly

Some WSH telemetry reported:

```text
4294967295
```

as the parent PID.

This was documented as a telemetry/process-metadata anomaly.

The value was not independently treated as evidence of malicious activity.

### 06:50:09 — Additional WSH Activity

An additional `wscript.exe` event was observed around:

```text
06:50:09.849
```

The event was reviewed against process context and was not automatically classified as malicious.

## Investigation Conclusion

The timeline shows that the endpoint generated and executed a controlled Visual Basic script through both `wscript.exe` and `cscript.exe`.

Elastic Defend captured the expected process and command-line telemetry, including the script path and executable locations. The resulting file activity also matched the intended script behavior.

No malicious payload, persistence, credential access, privilege escalation, command-and-control, or confirmed compromise was demonstrated.

## Final Assessment

```text
Controlled WSH execution
        ↓
Elastic telemetry captured
        ↓
Process + command line validated
        ↓
Parent process reviewed
        ↓
Output file validated
        ↓
Telemetry anomaly documented
        ↓
No malicious behavior demonstrated
```

The investigation reinforces that Windows Script Host execution must be evaluated using process context and supporting telemetry rather than the presence of `wscript.exe` or `cscript.exe` alone.
