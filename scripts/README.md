# Atomic Red Team OS Runners

This directory contains comprehensive scripts to automatically execute all Atomic Red Team attacks for each operating system and collect extensive logs for anomaly detection analysis.

## Overview

Each script performs the following actions:
1. **Installs dependencies** (PowerShell 7, Invoke-AtomicRedTeam)
2. **Collects pre-execution system state** (processes, services, network, etc.)
3. **Executes all OS-specific atomic tests** with proper error handling and cleanup
4. **Collects comprehensive logs** from all relevant system directories
5. **Generates detailed reports** with execution results and log collection summary

## Scripts

### Windows Runner (`windows-runner.ps1`)
- **Requirements**: Windows with PowerShell 5.1+, Administrator privileges
- **Execution**: Runs all Windows-compatible atomic tests
- **Log Collection**: 
  - Windows Event Logs (Security, System, Application, Sysmon, PowerShell, etc.)
  - Windows Error Reporting (WER) logs
  - Windows Firewall logs
  - IIS logs (if present)
  - Windows Defender logs

### Linux Runner (`linux-runner.sh`)
- **Requirements**: Linux with bash, root privileges
- **Execution**: Runs all Linux-compatible atomic tests
- **Log Collection**:
  - `/var/log/*` (syslog, auth.log, kern.log, etc.)
  - systemd journal logs
  - auditd logs (if enabled)
  - Application logs (web servers, databases, containers)
  - Package manager logs

### macOS Runner (`macos-runner.sh`)
- **Requirements**: macOS with bash, root privileges
- **Execution**: Runs all macOS-compatible atomic tests
- **Log Collection**:
  - Unified logging system (`.logarchive` format)
  - `/var/log/*` traditional logs
  - Audit logs (if enabled)
  - Application logs (`/Library/Logs`, `~/Library/Logs`)
  - Diagnostics and crash reports
  - Security framework logs

## Usage

### Quick Start

```bash
# Windows (run as Administrator)
cd /path/to/atomic-red-team/scripts
.\windows-runner.ps1

# Linux (run as root)
cd /path/to/atomic-red-team/scripts
sudo ./linux-runner.sh

# macOS (run as root)
cd /path/to/atomic-red-team/scripts
sudo ./macos-runner.sh
```

### Advanced Usage

All scripts accept the same three optional parameters:

```bash
# Custom atomics path, output directory, and timeout
./script [atomics_path] [output_dir] [timeout_seconds]
```

**Examples:**
```bash
# Windows
.\windows-runner.ps1 "C:\custom\atomics" "D:\results" 600

# Linux
sudo ./linux-runner.sh "/opt/atomic-red-team/atomics" "/tmp/my-results" 180

# macOS  
sudo ./macos-runner.sh "/Users/analyst/atomics" "/tmp/art-logs" 300
```

## Output Structure

Each script creates a timestamped output directory with the following structure:

```
output_directory/
├── SUMMARY.txt                 # Execution summary and analysis guide
├── logs/                       # All collected system logs
│   ├── [OS-specific subdirs]   # Organized by log source
│   └── ...
└── results/                    # Execution results and system state
    ├── execution_results.csv   # Per-technique execution status
    ├── processes_before.txt    # Pre-execution system state
    ├── processes_after.txt     # Post-execution system state
    └── ...
```

### Windows Output
```
logs/
├── Security.evtx              # Windows Event Logs
├── System.evtx
├── Microsoft-Windows-Sysmon_Operational.evtx
├── *_windowed.xml             # Time-filtered events
├── WER_ReportArchive/         # Windows Error Reporting
├── Firewall/                  # Windows Firewall logs
└── IIS_LogFiles/              # IIS logs (if present)
```

### Linux Output
```
logs/
├── var_log.tar.gz             # Complete /var/log archive
├── journal/                   # systemd journal logs
│   ├── full_journal.log
│   └── windowed_journal.log
├── audit/                     # auditd logs
└── application/               # App-specific logs
    ├── nginx/
    ├── apache2/
    └── docker_containers.log
```

### macOS Output
```
logs/
├── unified/                   # Unified logging system
│   ├── execution_window.logarchive
│   ├── security.log
│   └── process_activity.log
├── var_log.tar.gz            # Traditional logs
├── audit/                    # Audit logs
├── application/              # Application logs
│   ├── Library_Logs/
│   └── Users_*/
└── diagnostics/              # Crash reports and diagnostics
```

## Prerequisites

### All Platforms
- **PowerShell 7**: Automatically installed by scripts if missing
- **Invoke-AtomicRedTeam**: Automatically installed/updated by scripts
- **Administrator/root privileges**: Required for comprehensive log collection

### Platform-Specific

**Windows:**
- PowerShell 5.1 or later
- Windows 10/11 or Windows Server 2016+

**Linux:**
- bash shell
- Common utilities: `tar`, `ps`, `netstat`/`ss`, `systemctl` (for systemd)
- Package manager: `apt`, `yum`, `dnf`, or `zypper`

**macOS:**
- macOS 10.14 (Mojave) or later
- Xcode Command Line Tools
- Homebrew (automatically installed if missing)

## Security Considerations

⚠️ **WARNING**: These scripts execute real attack techniques and should only be run in:
- Isolated test environments
- Dedicated security testing labs
- Systems specifically designated for red team exercises

**Do NOT run on:**
- Production systems
- Systems containing sensitive data
- Networks connected to critical infrastructure

## Execution Time

Typical execution times vary by system and number of techniques:
- **Windows**: 2-4 hours (depending on techniques and prerequisites)
- **Linux**: 1-3 hours (varies by distribution and available tools)
- **macOS**: 2-4 hours (includes Homebrew installation if needed)

## Troubleshooting

### Common Issues

**PowerShell Execution Policy (Windows):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Permission Denied (Linux/macOS):**
```bash
chmod +x linux-runner.sh
chmod +x macos-runner.sh
```

**Insufficient Privileges:**
- Ensure running as Administrator (Windows) or root (Linux/macOS)
- Some log collection requires elevated privileges

**Network Connectivity:**
- Scripts download PowerShell and modules from internet
- Ensure outbound HTTPS (443) access to Microsoft repositories

### Log Analysis

**Windows Event Logs:**
- Use Event Viewer, PowerShell `Get-WinEvent`, or import into SIEM
- Time-windowed XML files can be imported into analysis tools

**Linux Logs:**
- Use standard tools: `grep`, `awk`, `journalctl`
- Import journal exports into log analysis platforms

**macOS Unified Logs:**
- Use Console.app or `log show` command
- LogArchive files can be analyzed with third-party tools

## Integration with Analysis Tools

### SIEM Integration
The collected logs are formatted for easy ingestion into:
- Splunk
- Elastic Stack (ELK)
- IBM QRadar
- Microsoft Sentinel
- Chronicle Security

### Anomaly Detection
Use the collected logs to:
1. **Train baseline models** using pre-execution system state
2. **Identify attack patterns** in time-windowed logs
3. **Develop detection rules** based on observed techniques
4. **Test detection coverage** against MITRE ATT&CK framework

### Sample Analysis Queries

**Windows (PowerShell):**
```powershell
# Analyze execution results
Import-Csv execution_results.csv | Group-Object Status | Select Name, Count

# Search event logs for specific techniques
Get-WinEvent -Path "Security.evtx" | Where-Object {$_.Message -like "*atomic*"}
```

**Linux (bash):**
```bash
# Analyze successful vs failed techniques
awk -F',' '$2=="Success" {success++} $2=="Failed" {failed++} END {print "Success:", success, "Failed:", failed}' execution_results.csv

# Search journal logs for process creation
grep -i "execve\|fork\|clone" logs/journal/windowed_journal.log
```

**macOS (bash):**
```bash
# Query unified logs for security events
log show logs/unified/execution_window.logarchive --predicate 'subsystem == "com.apple.security"'

# Analyze process activity
log show logs/unified/execution_window.logarchive --predicate 'eventType == activityCreateEvent'
```

## Contributing

To extend or modify these scripts:

1. **Test thoroughly** in isolated environments
2. **Follow existing patterns** for error handling and logging
3. **Update documentation** for any new features or requirements
4. **Consider cross-platform compatibility** where applicable

## Support

For issues or questions:
1. Check the generated `SUMMARY.txt` file for execution details
2. Review the Atomic Red Team documentation: https://github.com/redcanaryco/atomic-red-team/wiki
3. Consult Invoke-AtomicRedTeam documentation: https://github.com/redcanaryco/invoke-atomicredteam

---

**Remember**: These tools are for authorized security testing only. Always ensure proper authorization and follow your organization's security policies before execution.
