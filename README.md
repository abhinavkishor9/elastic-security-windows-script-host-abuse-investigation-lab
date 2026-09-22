# Elastic Security Lab 03 — Windows Script Host Abuse

## Overview

This lab investigates **Windows Script Host (WSH)** execution using `wscript.exe` and `cscript.exe` on a Windows endpoint monitored by **Elastic Defend**.

Windows Script Host is a legitimate Windows capability used to execute scripts such as Visual Basic scripts. From a SOC perspective, the presence of `wscript.exe` or `cscript.exe` is not sufficient to determine malicious activity. The investigation must examine the script being executed, command-line arguments, parent process, user context, executable path, and surrounding endpoint telemetry.

A controlled and harmless VBScript was created and executed through both Windows Script Host binaries. Elastic endpoint telemetry was then used to reconstruct the executions and compare the observed process relationships.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |

## Objectives

- Understand Windows Script Host execution from a SOC investigation perspective.
- Generate controlled `wscript.exe` and `cscript.exe` telemetry.
- Identify Windows Script Host processes in Elastic endpoint data.
- Analyze process parent-child relationships.
- Examine script paths and command-line arguments.
- Validate executable locations and user context.
- Investigate endpoint events using ES|QL.
- Compare controlled activity with any pre-existing WSH activity.
- Identify telemetry limitations and anomalous process metadata.
- Map the observed behavior to MITRE ATT&CK.
- Make an evidence-based assessment without treating WSH execution alone as malicious.

## Scenario

A SOC analyst is investigating endpoint activity involving Windows Script Host. The analyst wants to determine whether script execution represents normal administrative or user activity, suspicious behavior requiring additional investigation, or confirmed malicious execution.

To generate known-good telemetry, a harmless VBScript was created under:

`C:\Users\Public\lab03.vbs`

The script only creates:

`C:\Users\Public\wsh_lab03.txt`

The script was then executed through both:

`wscript.exe`

and

`cscript.exe`

Elastic telemetry was reviewed to identify the process execution, parent process, user, command line, executable path, and related activity.

## Controlled Script

The lab script was intentionally harmless:

```vbscript
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.CreateTextFile("C:\Users\Public\wsh_lab03.txt", True)
file.WriteLine "Elastic Security Lab 03 - Windows Script Host"
file.Close
```

The script was executed with:

```powershell
wscript.exe C:\Users\Public\lab03.vbs
```

and:

```powershell
cscript.exe C:\Users\Public\lab03.vbs
```

The expected output file was successfully created:

`C:\Users\Public\wsh_lab03.txt`

## Initial Telemetry Check

An initial ES|QL query searched directly for Windows Script Host processes:

```esql
FROM logs-*
| WHERE process.name IN ("wscript.exe", "cscript.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

With the investigation window set to **Last 15 minutes**, the query initially returned zero documents.

A more targeted query searching for the known script path later returned the expected endpoint events.

## Script-Specific Hunting

The following query successfully identified the controlled executions:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*lab03.vbs*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

Observed events included:

- `06:35:04.887` — `wscript.exe`
- `06:35:04.897` — `wscript.exe`
- `06:35:47.767` — `cscript.exe`

The observed command lines referenced:

`C:\Users\Public\lab03.vbs`

The executable paths were:

`C:\Windows\System32\wscript.exe`

and:

`C:\Windows\System32\cscript.exe`

## Process Context

The controlled `cscript.exe` execution showed:

```text
pwsh.exe
    |
    +-- cscript.exe
          |
          +-- lab03.vbs
```

The observed `cscript.exe` process used PID `17048` and was associated with parent `pwsh.exe` PID `32400`.

The controlled `wscript.exe` execution also showed Windows Script Host activity originating from the PowerShell environment.

Some WSH telemetry contained an unusual parent PID value:

`4294967295`

This was treated as a **telemetry or process-metadata anomaly**, not as evidence of malicious activity.

Additional WSH activity was also observed around `06:50:09.849`, providing another example of endpoint process telemetry that required validation against the execution context.

## Key Findings

### Observed

- `wscript.exe` executed the controlled VBScript.
- `cscript.exe` executed the same controlled VBScript.
- Elastic Defend captured the process activity.
- The script path appeared in process command-line telemetry.
- The binaries executed from the expected Windows System32 location.
- The controlled executions were associated with the `Dell` user.
- `cscript.exe` showed a `pwsh.exe` parent relationship.
- The script successfully created the expected output file.
- Some telemetry contained an unusual parent PID value.

### Confirmed

- The test script executed successfully.
- The observed WSH executions were intentionally generated for this lab.
- The script contained no malicious payload.
- No credential theft, persistence, privilege escalation, command-and-control, or malware execution was demonstrated.

### Not Demonstrated

- Malicious script execution
- Persistence through Windows Script Host
- Credential access
- Privilege escalation
- Malicious child-process execution
- Command-and-control
- Confirmed endpoint compromise

## Investigation Principle

The lab demonstrates the following investigation model:

```text
WSH process
    ↓
Script path
    ↓
Command line
    ↓
Parent process
    ↓
User context
    ↓
Executable location
    ↓
Child / file / network activity
    ↓
Evidence-based assessment
```

`wscript.exe` or `cscript.exe` alone should not be treated as proof of compromise.

## MITRE ATT&CK

### T1059.005 — Command and Scripting Interpreter: Visual Basic

The controlled activity demonstrates execution of a Visual Basic script through Windows Script Host.

The ATT&CK mapping describes the observed scripting behavior and does not indicate that the controlled activity itself was malicious.

## Telemetry Limitations

Several limitations were observed during the investigation:

- The initial process-name query returned zero documents within the selected 15-minute window.
- Searching for the known script path successfully located the expected events.
- Some process telemetry contained an unusual parent PID value of `4294967295`.
- Process metadata should therefore be validated using multiple fields instead of relying on one parent-process field.
- Existing endpoint activity may be mixed with controlled lab activity when using broad queries.
- A zero-result query should not automatically be interpreted as proof that no activity occurred.

## Final Assessment

Elastic successfully captured the controlled execution of both `wscript.exe` and `cscript.exe`. The available telemetry showed the script path, executable location, user context, and process relationships. The activity was intentionally generated and produced the expected output file.

The investigation demonstrates that Windows Script Host activity should be evaluated through execution context and supporting telemetry rather than through the process name alone.
