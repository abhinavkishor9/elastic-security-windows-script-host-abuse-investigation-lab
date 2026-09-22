# Troubleshooting Notes 

## Issue 1 — Initial WSH Query Returned 0 Documents

### Query

```esql
FROM logs-*
| WHERE process.name IN ("wscript.exe", "cscript.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

Elastic displayed:

```text
No results match your search criteria
```

### Investigation

The investigation window was initially set to:

```text
Last 15 minutes
```

The result did not prove that WSH events were absent from Elastic.

The known script was then searched directly in the process command line.

### Resolution

The following query successfully located the controlled executions:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*lab03.vbs*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

This returned four documents.

### Lesson

A zero-result query should be treated as a query or time-window result first, not automatically as proof that an activity did not occur.

---

## Issue 2 — Parent-Process Query Returned 0 Documents

### Query

```esql
FROM logs-*
| WHERE process.parent.name IN ("wscript.exe", "cscript.exe")
| KEEP @timestamp, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, user.name
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Explanation

This query searches for processes whose **parent** is `wscript.exe` or `cscript.exe`.

It does not search for `wscript.exe` or `cscript.exe` themselves.

Because the controlled script did not intentionally spawn additional child processes, a zero-result response was reasonable.

### Correct Approach

To find the WSH processes themselves:

```esql
FROM logs-*
| WHERE process.name IN ("wscript.exe", "cscript.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

To search for children of WSH, use the parent-process query only when child-process activity is expected.

---

## Issue 3 — Direct Process Search Was Not Sufficient

The broad WSH process search did not initially return results in the selected time range.

A script-specific search was more effective because the known lab artifact was included in the command line:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*lab03.vbs*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

### Lesson

When investigating controlled activity, known artifacts such as:

- Script names
- File paths
- Process names
- Command-line arguments

can be used to narrow the investigation.

---

## Issue 4 — Unusual Parent PID

Some WSH telemetry contained:

```text
process.parent.pid = 4294967295
```

This value did not match the expected PowerShell parent relationship observed in other events.

### Handling

The value was documented as an anomaly rather than interpreted as malicious.

Other fields were used to validate the execution:

- `process.name`
- `process.parent.name`
- `process.command_line`
- `process.executable`
- `user.name`
- `@timestamp`

### Lesson

When process metadata is inconsistent, correlate multiple telemetry fields before reaching an assessment.

---

## Issue 5 — Distinguishing Controlled Activity from Other Endpoint Events

The endpoint may contain activity unrelated to the current lab.

The controlled executions were associated with known timestamps:

```text
06:35:04.887
06:35:04.897
06:35:47.767
```

The command line also contained:

```text
lab03.vbs
```

This made it possible to separate the controlled activity from unrelated endpoint events.

### Lesson

Known timestamps and known artifacts are useful when validating lab-generated telemetry.

---

## Issue 6 — Validating the Script Execution

The script was verified locally with:

```powershell
Get-Item C:\Users\Public\lab03.vbs
```

and:

```powershell
Get-Content C:\Users\Public\lab03.vbs
```

The resulting output file was verified with:

```powershell
Get-Item C:\Users\Public\wsh_lab03.txt
```

and:

```powershell
Get-Content C:\Users\Public\wsh_lab03.txt
```

Expected output:

```text
Elastic Security Lab 03 - Windows Script Host
```

### Lesson

Endpoint telemetry should be validated against the activity intentionally performed on the host.

---

## Issue 7 — Security Navigation Was Not Required

The investigation was performed successfully from the existing **Discover / ES|QL** interface.

A separate Security navigation path was not required for the core investigation.

### Lesson

For this lab, the required evidence could be obtained through Discover and ES|QL using endpoint process telemetry.

---

## Issue 8 — Time Range Selection

The investigation initially used:

```text
Last 15 minutes
```

This was appropriate for isolating controlled activity.

However, the initial zero-result query demonstrated that the selected time window must contain the actual execution timestamps.

For controlled testing:

```text
Last 15 minutes
```

is a useful starting point.

When results are unexpectedly absent, expand temporarily to:

```text
Last 1 hour
```

and repeat the query.

### Lesson

Always correlate the Elastic time range with the actual execution time of the test activity.

---

