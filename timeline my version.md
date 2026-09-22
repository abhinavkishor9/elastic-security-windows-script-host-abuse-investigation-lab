# Timeline 

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

