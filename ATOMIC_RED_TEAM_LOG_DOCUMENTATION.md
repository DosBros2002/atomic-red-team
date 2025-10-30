# Atomic Red Team Windows Runner - Log Documentation

## Overview

This document explains all the log files, CSV fields, and data sources collected by the enhanced `windows-runner.ps1` script during MITRE ATT&CK technique execution.

---

##  Process Snapshot CSV Files

### Source Information
- **Data Source**: PowerShell `Get-Process` cmdlet
- **API Source**: Windows Process Manager API / Windows Kernel
- **Collection Method**: Real-time system state enumeration
- **NOT from file directories** - Live system data

### File Locations
- `processes_before.csv` - System state before any attacks
- `processes_after.csv` - System state after all attacks complete
- `continuous_process_monitoring.csv` - 1-second interval snapshots during execution
- `per-technique/[TECHNIQUE_ID]/processes_snapshot.csv` - State after individual technique

---

##  Process CSV Field Definitions

### **Process Identity Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Example** |
|-----------|----------------|---------------|------------|-------------|
| `Name` | Process executable name | String | Process Control Block | `"powershell"` |
| `ProcessName` | Same as Name (duplicate field) | String | Process Control Block | `"powershell"` |
| `Id` | Process ID (PID) | Integer | Process Control Block | `16292` |
| `Path` | Full path to executable | String | Process Image Path | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"` |

### **Memory Management Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `WS` (Working Set) | Physical memory currently used | Bytes | Memory Manager | **High values indicate process injection** |
| `PM` (Private Memory) | Memory allocated exclusively to process | Bytes | Memory Manager | **Sudden increases suggest payload loading** |
| `VM` (Virtual Memory) | Total virtual address space | Bytes | Virtual Memory Manager | **Large values indicate memory manipulation** |
| `WorkingSet64` | 64-bit working set size | Bytes | Memory Manager | Same as WS but 64-bit |
| `PrivateMemorySize64` | 64-bit private memory size | Bytes | Memory Manager | Same as PM but 64-bit |
| `VirtualMemorySize64` | 64-bit virtual memory size | Bytes | Memory Manager | Same as VM but 64-bit |

### **Performance & Resource Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `CPU` | Total CPU time used | TimeSpan | Performance Counters | **High CPU indicates active malicious processing** |
| `TotalProcessorTime` | Total CPU time (user + kernel) | TimeSpan | Performance Counters | **Extended runtime suggests persistence** |
| `UserProcessorTime` | CPU time in user mode | TimeSpan | Performance Counters | **High user time indicates application-level activity** |
| `PrivilegedProcessorTime` | CPU time in kernel mode | TimeSpan | Performance Counters | **High kernel time suggests system-level operations** |

### **Handle & Resource Management**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `Handles` | Number of open handles | Integer | Object Manager | **Extremely high values (>2000) indicate injection** |
| `HandleCount` | Same as Handles | Integer | Object Manager | **Duplicate field** |
| `Threads` | Collection of process threads | Object | Thread Manager | **Multiple threads suggest complex operations** |

### **Process Lifecycle Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `StartTime` | When process was created | DateTime | Process Control Block | **Recent start times during attack window** |
| `HasExited` | Whether process has terminated | Boolean | Process State | **False for running processes** |
| `ExitTime` | When process terminated | DateTime | Process Control Block | **Only set if HasExited = True** |
| `ExitCode` | Process exit code | Integer | Process Control Block | **0 = success, non-zero = error** |

### **Security & Privilege Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `SessionId` | Terminal Services session ID | Integer | Session Manager | **0 = System session, >0 = User session** |
| `PriorityClass` | Process priority level | String | Scheduler | **"High" or "Realtime" may indicate privilege escalation** |
| `BasePriority` | Base priority value | Integer | Scheduler | **Higher values get more CPU time** |
| `Responding` | Whether process responds to UI | Boolean | Window Manager | **False may indicate hung or malicious process** |

### **File & Version Information**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `Company` | Company that created executable | String | PE File Headers | **Microsoft vs. unknown publishers** |
| `FileVersion` | File version number | String | PE File Headers | **Mismatched versions may indicate tampering** |
| `ProductVersion` | Product version number | String | PE File Headers | **Version inconsistencies are suspicious** |
| `Description` | File description | String | PE File Headers | **Generic descriptions may indicate malware** |
| `Product` | Product name | String | PE File Headers | **Legitimate vs. suspicious product names** |

### **Window & UI Fields**

| **Field** | **Description** | **Data Type** | **Source** | **Attack Significance** |
|-----------|----------------|---------------|------------|------------------------|
| `MainWindowHandle` | Handle to main window | IntPtr | Window Manager | **0 = no UI, >0 = has window** |
| `MainWindowTitle` | Title of main window | String | Window Manager | **"Administrator:" indicates elevated privileges** |

---

## Event Log Files (NEW)

### Real-Time Event Log Collection

The enhanced script now collects Windows Event Logs in **real-time** during technique execution:

### **Collection Structure**
```
per-technique/[TECHNIQUE_ID]/
├── Security.evtx                           ← Full Security event log
├── Security_windowed.xml                   ← Time-filtered Security events  
├── Security_source.json                    ← Source metadata
├── System.evtx                             ← Full System event log
├── System_windowed.xml                     ← Time-filtered System events
├── System_source.json                      ← Source metadata
├── Application.evtx                        ← Full Application event log
├── Microsoft-Windows-Sysmon_Operational.evtx ← Full Sysmon log
├── Microsoft-Windows-PowerShell_Operational.evtx ← Full PowerShell log
└── Microsoft-Windows-Windows_Defender_Operational.evtx ← Full Defender log
```

---

## Event Log Source Directories

### **Direct Directory Mapping**

| **Event Log File** | **Source Directory** | **Content** |
|-------------------|---------------------|-------------|
| `Security.evtx` | `C:\Windows\System32\winevt\Logs\Security.evtx` | Authentication, logons, process creation |
| `System.evtx` | `C:\Windows\System32\winevt\Logs\System.evtx` | System events, services, drivers |
| `Application.evtx` | `C:\Windows\System32\winevt\Logs\Application.evtx` | Application events, crashes |
| `Microsoft-Windows-Sysmon_Operational.evtx` | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | Detailed process monitoring |
| `Microsoft-Windows-PowerShell_Operational.evtx` | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | PowerShell execution logs |
| `Microsoft-Windows-Windows_Defender_Operational.evtx` | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx` | Antivirus detections |

---

## Attack-Specific Event IDs

### **Security.evtx - Key Events for Attack Detection**

| **Event ID** | **Description** | **Attack Relevance** |
|--------------|----------------|---------------------|
| **4688** | Process Creation | **Critical**: Shows InstallUtil.exe, rundll32.exe creation with full command lines |
| **4689** | Process Termination | **Important**: Shows when attack processes exit |
| **4624** | Successful Logon | **Lateral Movement**: New authentication events |
| **4625** | Failed Logon | **Brute Force**: Failed authentication attempts |
| **4672** | Special Privileges Assigned | **Privilege Escalation**: Admin rights granted |

### **Microsoft-Windows-Sysmon_Operational.evtx - Detailed Process Monitoring**

| **Event ID** | **Description** | **Attack Relevance** |
|--------------|----------------|---------------------|
| **1** | Process Creation | **Most Critical**: Full command line, parent process, hashes |
| **5** | Process Terminated | **Process Lifecycle**: When attacks complete |
| **7** | Image/DLL Loaded | **Code Injection**: DLL loading into processes |
| **8** | CreateRemoteThread | **Process Injection**: Thread creation in other processes |
| **10** | Process Accessed | **Process Injection**: Memory access between processes |
| **11** | File Created | **Persistence**: Files dropped by attacks |

### **Microsoft-Windows-PowerShell_Operational.evtx - PowerShell Activity**

| **Event ID** | **Description** | **Attack Relevance** |
|--------------|----------------|---------------------|
| **4103** | Module Logging | **Script Execution**: PowerShell modules loaded |
| **4104** | Script Block Logging | **Most Critical**: Actual PowerShell code executed |
| **4105** | Script Start | **Script Execution**: PowerShell script begins |
| **4106** | Script Stop | **Script Execution**: PowerShell script ends |

---

## Source Metadata Files

### **Format: `[LogName]_source.json`**

Each event log has an accompanying metadata file showing its source:

```json
{
  "LogType": "Windows Event Log",
  "ChannelName": "Security",
  "SourcePath": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  "CollectionMethod": "wevtutil epl (real-time per-technique)",
  "TechniqueTimeWindow": {
    "StartTime": "2025-10-24 10:49:48.123",
    "EndTime": "2025-10-24 10:49:49.456",
    "Duration": 1.333
  }
}
```

---

## Continuous Monitoring Files

### **New Real-Time Monitoring Capabilities**

| **File** | **Content** | **Update Frequency** | **Purpose** |
|----------|-------------|---------------------|-------------|
| `continuous_process_monitoring.csv` | All running processes | Every 1 second | **Catch short-lived processes like InstallUtil.exe** |
| `process_creation_events.csv` | WMI process start events | Real-time | **Process creation with command lines** |
| `process_termination_events.csv` | WMI process stop events | Real-time | **Process termination with exit codes** |

### **Process Creation Events CSV Fields**

| **Field** | **Description** | **Source** | **Example** |
|-----------|----------------|------------|-------------|
| `Timestamp` | When event occurred | WMI Event | `"2025-10-24 10:49:48.123"` |
| `ProcessName` | Executable name | WMI ProcessStartTrace | `"InstallUtil.exe"` |
| `ProcessID` | Process ID | WMI ProcessStartTrace | `15432` |
| `ParentProcessID` | Parent process ID | WMI ProcessStartTrace | `16292` |
| `CommandLine` | Full command line | Win32_Process | `"InstallUtil.exe /U malicious.dll"` |
| `EventType` | Event type | Script-generated | `"ProcessStart"` |

---

## T1218.004 (InstallUtil) Example

### **What You'll Find for InstallUtil Attack:**

#### **In `processes_snapshot.csv`:**
- **High-memory PowerShell process** (parent)
- **InstallUtil.exe may be missing** (completed before snapshot)

#### **In `continuous_process_monitoring.csv`:**
- **InstallUtil.exe creation** at exact timestamp
- **Memory usage progression** during execution
- **Process termination** when attack completes

#### **In `process_creation_events.csv`:**
```csv
Timestamp,ProcessName,ProcessID,ParentProcessID,CommandLine,EventType
2025-10-24 10:49:48.123,InstallUtil.exe,15432,16292,"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\malicious.dll",ProcessStart
```

#### **In `Security.evtx` (Event ID 4688):**
- **Process creation event** with full command line
- **Parent process information** (PowerShell)
- **User context** and **privileges**

#### **In `Microsoft-Windows-Sysmon_Operational.evtx` (Event ID 1):**
- **Detailed process creation** with file hashes
- **Parent process details**
- **Process GUID** for correlation

---

## Analysis Tips

### **Identifying Process Injection (T1055.x):**
1. **Look for**: High `Handles` count (>2000)
2. **Look for**: Large `PrivateMemorySize` increases
3. **Look for**: Sysmon Event ID 8 (CreateRemoteThread)
4. **Look for**: Sysmon Event ID 10 (ProcessAccess)

### **Identifying System Binary Proxy Execution (T1218.x):**
1. **Look for**: Short-lived system processes in `continuous_process_monitoring.csv`
2. **Look for**: Unusual command lines in `process_creation_events.csv`
3. **Look for**: Parent-child relationships (PowerShell → InstallUtil)
4. **Look for**: Security Event ID 4688 with suspicious parameters

### **Identifying PowerShell Activity (T1059.001):**
1. **Look for**: High CPU usage in PowerShell processes
2. **Look for**: PowerShell Event ID 4104 (Script Block Logging)
3. **Look for**: Multiple PowerShell instances
4. **Look for**: "Administrator:" in `MainWindowTitle`

---

## 🔧 Collection Methods

### **Process Data Collection:**
- **Method**: `Get-Process | Export-Csv`
- **Frequency**: Before, during (1-sec), after, per-technique
- **API**: Windows Process Manager API

### **Event Log Collection:**
- **Method**: `wevtutil epl [channel] [file]`
- **Frequency**: After each technique + comprehensive at end
- **Source**: Windows Event Log Service

### **WMI Event Monitoring:**
- **Method**: `Register-WmiEvent` with `Win32_ProcessStartTrace`
- **Frequency**: Real-time event-driven
- **Source**: Windows Management Instrumentation

---

## Complete File Structure

```
C:\ART-Results\[TIMESTAMP]\
├── logs\                                   ← Main event logs directory
│   ├── Security_latest.evtx               ← Latest Security log (updated per technique)
│   ├── System_latest.evtx                 ← Latest System log
│   ├── process_creation_events.csv        ← Real-time process creation
│   └── process_termination_events.csv     ← Real-time process termination
├── results\                               ← System state snapshots
│   ├── processes_before.csv               ← Pre-attack process state
│   ├── processes_after.csv                ← Post-attack process state
│   ├── services_before.csv                ← Pre-attack service state
│   └── network_before.csv                 ← Pre-attack network state
├── per-technique\                         ← Individual technique logs
│   ├── T1055.011\                         ← Process Injection technique
│   │   ├── Security.evtx                  ← Full Security log for this technique
│   │   ├── Security_windowed.xml          ← Time-filtered Security events
│   │   ├── Security_source.json           ← Source: C:\Windows\System32\winevt\Logs\Security.evtx
│   │   ├── Microsoft-Windows-Sysmon_Operational.evtx
│   │   ├── processes_snapshot.csv         ← Process state after technique
│   │   └── metadata.json                  ← Technique execution metadata
│   └── T1218.004\                         ← InstallUtil technique
│       ├── Security.evtx                  ← Contains InstallUtil process creation events
│       ├── Microsoft-Windows-Sysmon_Operational.evtx ← Detailed process monitoring
│       ├── Microsoft-Windows-PowerShell_Operational.evtx ← PowerShell execution logs
│       └── processes_snapshot.csv         ← Process state (may miss short-lived InstallUtil)
├── continuous_process_monitoring.csv      ← 1-second process snapshots (catches InstallUtil!)
└── SUMMARY.txt                           ← Execution summary and file locations
```

This comprehensive logging system provides complete visibility into both **system state changes** and **Windows event log activity** for thorough attack analysis and anomaly detection training.
