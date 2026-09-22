# elastic-security-windows-script-host-abuse-investigation-lab
## Overview
Windows Script Host is a legitimate Windows component used to execute scripts such as .vbs and .js files. From a SOC perspective, the important question is not simply whether wscript.exe or cscript.exe executed, but what script was executed, how it was launched, by whom, and what happened afterward.

For this lab, keep the activity fully benign. Create a harmless local script that performs a simple action such as writing a message to a temporary file, then execute it through Windows Script Host.

The investigation should examine:

wscript.exe and cscript.exe process execution
Parent-child process relationships
Script paths and command-line arguments
User context
Executable location
Child processes, if any
File activity associated with the script
Differences between wscript.exe and cscript.exe
Whether the observed activity is expected, suspicious, or inconclusive

The primary investigation question is:

Can Elastic Security distinguish legitimate Windows Script Host execution from activity that would require further investigation based on process context and script execution details?

The lab should demonstrate how endpoint telemetry can provide evidence such as:

powershell.exe
    ↓
wscript.exe
    ↓
lab03.vbs
    ↓
wsh_lab03.txt

The final assessment should distinguish between observed script execution, suspicious indicators, and confirmed malicious behavior rather than treating Windows Script Host execution itself as malicious.

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

# Lab Objectives

- Understand how Windows Script Host (`wscript.exe` and `cscript.exe`) appears in endpoint telemetry.
- Generate controlled Windows Script Host activity using a harmless Visual Basic script.
- Identify WSH process executions in Elastic endpoint telemetry.
- Analyze process command lines and identify the scripts being executed.
- Examine parent-child process relationships associated with WSH execution.
- Validate the executable paths of `wscript.exe` and `cscript.exe`.
- Correlate process activity with the user context and execution timestamps.
- Use ES|QL to investigate Windows Script Host activity in Elastic.
- Use known script names and paths to narrow endpoint hunting.
- Validate observed telemetry against the intentionally generated lab activity.
- Investigate unusual or inconsistent process metadata without treating it as automatic evidence of compromise.
- Distinguish observed telemetry from confirmed malicious behavior.
- Apply an evidence-based approach to assessing potentially suspicious script execution.
- Understand why `wscript.exe` or `cscript.exe` alone is insufficient to classify activity as malicious.
- Map the observed Visual Basic scripting behavior to MITRE ATT&CK technique `T1059.005`.

# Lab Scenario

A SOC analyst is investigating endpoint activity involving **Windows Script Host (WSH)** on a Windows workstation monitored by **Elastic Defend**. The presence of `wscript.exe` or `cscript.exe` has attracted attention because these legitimate Windows binaries can be used to execute scripts and may require additional investigation when their execution context is unusual.

The analyst needs to determine what the observed WSH activity actually represents rather than treating the process name alone as evidence of malicious behavior. The investigation will focus on:

- Identifying `wscript.exe` and `cscript.exe` executions in Elastic telemetry.
- Determining which script was executed and how it was launched.
- Reviewing command-line arguments and executable paths.
- Examining parent-child process relationships and user context.
- Validating the resulting endpoint activity against known lab-generated behavior.
- Investigating any inconsistent or unusual process metadata.

To create known-good telemetry, a harmless Visual Basic script is executed through both `wscript.exe` and `cscript.exe`. The script performs a simple file-creation operation, providing a controlled artifact that can be correlated with the process execution observed in Elastic.

The investigation is then conducted using **Discover and ES|QL**, with the analyst correlating process name, command line, script path, executable location, timestamps, user context, and process ancestry. Any telemetry inconsistencies are documented as investigation limitations and validated against other available evidence.

The goal is to determine whether the observed activity can be explained by the controlled test and to demonstrate an evidence-driven approach to investigating Windows Script Host activity without assuming that legitimate scripting tools are inherently malicious.

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

