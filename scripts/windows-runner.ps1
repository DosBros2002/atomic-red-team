#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Atomic Red Team Windows Runner - Execute all Windows atomics and collect comprehensive logs
.DESCRIPTION
    This script automatically:
    1. Installs Invoke-AtomicRedTeam if not present
    2. Executes all Windows-compatible atomic tests
    3. Collects comprehensive logs from all Windows logging locations
    4. Packages everything for anomaly detection analysis
.PARAMETER AtomicsPath
    Path to atomic-red-team atomics directory (default: current directory + atomics)
.PARAMETER OutputDir
    Directory to store collected logs and results (default: C:\ART-Results\timestamp)
.PARAMETER TimeoutSeconds
    Timeout for each atomic test execution (default: 300)
.EXAMPLE
    .\windows-runner.ps1
    .\windows-runner.ps1 -AtomicsPath "C:\atomic-red-team\atomics" -OutputDir "C:\MyResults"
#>

param(
    [string]$AtomicsPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "atomics"),
    [string]$OutputDir = "C:\ART-Results\$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]$TimeoutSeconds = 300
)

# Color output functions
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput $Message "Green" }
function Write-Warning { param([string]$Message) Write-ColorOutput $Message "Yellow" }
function Write-Error { param([string]$Message) Write-ColorOutput $Message "Red" }
function Write-Info { param([string]$Message) Write-ColorOutput $Message "Cyan" }

# Function to start continuous process monitoring
function Start-ProcessMonitoring {
    param(
        [string]$OutputFile,
        [int]$IntervalSeconds = 1
    )
    
    $MonitoringScript = {
        param($OutputFile, $IntervalSeconds)
        
        while ($true) {
            try {
                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $Processes = Get-Process | Select-Object Name, Id, ProcessName, Path, StartTime, CPU, WorkingSet, PrivateMemorySize, HandleCount, @{Name="Timestamp";Expression={$Timestamp}}
                
                # Append to CSV (create header if file doesn't exist)
                if (-not (Test-Path $OutputFile)) {
                    $Processes | Export-Csv $OutputFile -NoTypeInformation
                } else {
                    $Processes | Export-Csv $OutputFile -NoTypeInformation -Append
                }
                
                Start-Sleep -Seconds $IntervalSeconds
            } catch {
                # Continue monitoring even if there's an error
                Start-Sleep -Seconds $IntervalSeconds
            }
        }
    }
    
    # Start background monitoring job
    $Job = Start-Job -ScriptBlock $MonitoringScript -ArgumentList $OutputFile, $IntervalSeconds
    return $Job
}

# Function to stop process monitoring
function Stop-ProcessMonitoring {
    param([System.Management.Automation.Job]$MonitoringJob)
    
    if ($MonitoringJob) {
        Stop-Job $MonitoringJob -ErrorAction SilentlyContinue
        Remove-Job $MonitoringJob -ErrorAction SilentlyContinue
    }
}

# Function to start WMI process event monitoring
function Start-WMIProcessMonitoring {
    param(
        [string]$OutputDir
    )
    
    $ProcessCreateScript = {
        param($OutputDir)
        
        $ProcessCreateFile = "$OutputDir\process_creation_events.csv"
        $ProcessDeleteFile = "$OutputDir\process_termination_events.csv"
        
        # Monitor process creation
        Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
            $Event = $Event.SourceEventArgs.NewEvent
            $ProcessInfo = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                ProcessName = $Event.ProcessName
                ProcessID = $Event.ProcessID
                ParentProcessID = $Event.ParentProcessID
                CommandLine = ""
                EventType = "ProcessStart"
            }
            
            # Try to get command line from running process
            try {
                $Process = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($Event.ProcessID)" -ErrorAction SilentlyContinue
                if ($Process) {
                    $ProcessInfo.CommandLine = $Process.CommandLine
                }
            } catch {}
            
            # Append to CSV
            if (-not (Test-Path $ProcessCreateFile)) {
                $ProcessInfo | Export-Csv $ProcessCreateFile -NoTypeInformation
            } else {
                $ProcessInfo | Export-Csv $ProcessCreateFile -NoTypeInformation -Append
            }
        }
        
        # Monitor process termination
        Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStopTrace" -Action {
            $Event = $Event.SourceEventArgs.NewEvent
            $ProcessInfo = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                ProcessName = $Event.ProcessName
                ProcessID = $Event.ProcessID
                ParentProcessID = ""
                CommandLine = ""
                EventType = "ProcessStop"
                ExitCode = $Event.ExitStatus
            }
            
            # Append to CSV
            if (-not (Test-Path $ProcessDeleteFile)) {
                $ProcessInfo | Export-Csv $ProcessDeleteFile -NoTypeInformation
            } else {
                $ProcessInfo | Export-Csv $ProcessDeleteFile -NoTypeInformation -Append
            }
        }
        
        # Keep the monitoring job alive
        while ($true) {
            Start-Sleep -Seconds 30
        }
    }
    
    # Start background WMI monitoring job
    $Job = Start-Job -ScriptBlock $ProcessCreateScript -ArgumentList $OutputDir
    return $Job
}

# Function to stop WMI process monitoring
function Stop-WMIProcessMonitoring {
    param([System.Management.Automation.Job]$WMIJob)
    
    if ($WMIJob) {
        Stop-Job $WMIJob -ErrorAction SilentlyContinue
        Remove-Job $WMIJob -ErrorAction SilentlyContinue
        
        # Clean up WMI event registrations
        Get-EventSubscriber | Where-Object { $_.SourceObject -like "*Win32_Process*Trace*" } | Unregister-Event -ErrorAction SilentlyContinue
    }
}

# Function to collect real-time logs for individual techniques
function Collect-TechniqueLog {
    param(
        [string]$Technique,
        [string]$OutputDir,
        [datetime]$TechniqueStartTime,
        [datetime]$TechniqueEndTime
    )
    
    $TechniqueLogDir = "$OutputDir\per-technique\$Technique"
    New-Item -ItemType Directory -Path $TechniqueLogDir -Force | Out-Null
    
    $StartTimeUTC = $TechniqueStartTime.ToUniversalTime()
    $EndTimeUTC = $TechniqueEndTime.ToUniversalTime()
    
    # Key event log channels for real-time collection with source paths
    $KeyChannels = @{
        "Security" = "C:\Windows\System32\winevt\Logs\Security.evtx"
        "System" = "C:\Windows\System32\winevt\Logs\System.evtx"
        "Application" = "C:\Windows\System32\winevt\Logs\Application.evtx"
        "Microsoft-Windows-Sysmon/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
        "Microsoft-Windows-PowerShell/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
        "Microsoft-Windows-Windows Defender/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
    }
    
    foreach ($Channel in $KeyChannels.Keys) {
        try {
            $SourcePath = $KeyChannels[$Channel]
            $SafeChannelName = $Channel -replace '[\\/:*?"<>|]', '_'
            
            # Export full log file for this technique (real-time copy)
            $FullLogPath = "$TechniqueLogDir\$SafeChannelName.evtx"
            wevtutil epl $Channel $FullLogPath 2>$null
            
            # Export time-windowed events as XML for this specific technique
            $WindowedLogPath = "$TechniqueLogDir\$SafeChannelName`_windowed.xml"
            $Query = "*[System[TimeCreated[@SystemTime>='$($StartTimeUTC.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))' and @SystemTime<='$($EndTimeUTC.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
            wevtutil qe $Channel "/q:$Query" "/f:xml" > $WindowedLogPath 2>$null
            
            # Create source metadata for this technique's logs
            $SourceInfo = @{
                LogType = "Windows Event Log"
                ChannelName = $Channel
                SourcePath = $SourcePath
                CollectionMethod = "wevtutil epl (real-time per-technique)"
                TechniqueTimeWindow = @{
                    StartTime = $TechniqueStartTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
                    EndTime = $TechniqueEndTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Duration = ($TechniqueEndTime - $TechniqueStartTime).TotalSeconds
                }
            }
            $SourceInfo | ConvertTo-Json -Depth 3 | Out-File "$TechniqueLogDir\$SafeChannelName`_source.json" -Encoding UTF8
            
            # Only keep windowed files that have actual events
            if ((Get-Item $WindowedLogPath -ErrorAction SilentlyContinue).Length -eq 0) {
                Remove-Item $WindowedLogPath -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Silently continue if channel not available
        }
    }
    
    # Collect process snapshot for this technique
    Get-Process | Export-Csv "$TechniqueLogDir\processes_snapshot.csv" -NoTypeInformation -ErrorAction SilentlyContinue
    
    # Create metadata file with source information
    $MetadataInfo = @{
        Technique = $Technique
        StartTime = $TechniqueStartTime
        EndTime = $TechniqueEndTime
        Duration = ($TechniqueEndTime - $TechniqueStartTime).TotalSeconds
        SourceLogs = @{
            Security = "Windows Event Log: Security"
            System = "Windows Event Log: System"
            Sysmon = "Windows Event Log: Microsoft-Windows-Sysmon/Operational"
            PowerShell = "Windows Event Log: Microsoft-Windows-PowerShell/Operational"
            Defender = "Windows Event Log: Microsoft-Windows-Windows Defender/Operational"
            ProcessSnapshot = "PowerShell Get-Process cmdlet (live system state)"
        }
        LogPaths = @{
            Security = "C:\Windows\System32\winevt\Logs\Security.evtx"
            System = "C:\Windows\System32\winevt\Logs\System.evtx"
            Sysmon = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
            PowerShell = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
            Defender = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
        }
    }
    $MetadataInfo | ConvertTo-Json -Depth 3 | Out-File "$TechniqueLogDir\metadata.json" -Encoding UTF8
}

# Main execution
try {
    Write-Info "=== Atomic Red Team Windows Runner Started ==="
    Write-Info "Start Time: $(Get-Date)"
    Write-Info "Output Directory: $OutputDir"
    
    # Create output directory structure
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\logs" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\results" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\per-technique" -Force | Out-Null
    
    # Record start time for log collection window
    $StartTime = Get-Date
    $StartTimeUTC = $StartTime.ToUniversalTime()
    
    Write-Info "=== Installing/Updating Invoke-AtomicRedTeam ==="
    try {
        if (-not (Get-Module -ListAvailable -Name "Invoke-AtomicRedTeam")) {
            Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force -AllowClobber
            Write-Success "Invoke-AtomicRedTeam installed successfully"
        } else {
            Update-Module -Name Invoke-AtomicRedTeam -Force
            Write-Success "Invoke-AtomicRedTeam updated successfully"
        }
        Import-Module Invoke-AtomicRedTeam -Force
    } catch {
        Write-Error "Failed to install/import Invoke-AtomicRedTeam: $($_.Exception.Message)"
        exit 1
    }
    
    Write-Info "=== Configuring Security Settings ==="
    # Check Windows Defender status and warn user
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($DefenderStatus -and $DefenderStatus.RealTimeProtectionEnabled) {
            Write-Warning "Windows Defender Real-Time Protection is ENABLED"
            Write-Warning "Some atomic tests may fail due to Defender blocking them"
            Write-Warning "Consider temporarily disabling real-time protection for better results"
            Write-Warning "Run: Set-MpPreference -DisableRealtimeMonitoring `$true (requires admin)"
        }
    } catch {
        Write-Info "Could not check Windows Defender status"
    }
    
    # Set execution policy for current session
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
        Write-Success "Execution policy set to Bypass for current session"
    } catch {
        Write-Warning "Could not set execution policy: $($_.Exception.Message)"
    }
    
    Write-Info "=== Collecting Pre-Execution System State ==="
    # Collect baseline system state
    Get-Process | Export-Csv "$OutputDir\results\processes_before.csv" -NoTypeInformation
    Get-Service | Export-Csv "$OutputDir\results\services_before.csv" -NoTypeInformation
    Get-NetTCPConnection | Export-Csv "$OutputDir\results\network_before.csv" -NoTypeInformation
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Export-Csv "$OutputDir\results\registry_run_before.csv" -NoTypeInformation
    
    # Create system state source metadata
    $SystemStateInfo = @{
        CollectionType = "Pre-Execution System State"
        CollectionTime = Get-Date
        Sources = @{
            Processes = "PowerShell Get-Process cmdlet (live system state)"
            Services = "PowerShell Get-Service cmdlet (Windows Service Manager)"
            NetworkConnections = "PowerShell Get-NetTCPConnection cmdlet (Windows Network Stack)"
            RegistryAutorun = "PowerShell Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (Windows Registry)"
        }
        SourcePaths = @{
            Processes = "Windows Process Manager API"
            Services = "Windows Service Control Manager"
            NetworkConnections = "Windows Network Stack API"
            RegistryAutorun = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        }
    }
    $SystemStateInfo | ConvertTo-Json -Depth 3 | Out-File "$OutputDir\results\system_state_sources.json" -Encoding UTF8
    
    Write-Info "=== Loading Windows Atomic Tests ==="
    # Get all Windows techniques from the index
    $WindowsIndexPath = Join-Path $AtomicsPath "Indexes\windows-index.yaml"
    if (-not (Test-Path $WindowsIndexPath)) {
        Write-Error "Windows index not found at: $WindowsIndexPath"
        exit 1
    }
    
    $WindowsTechniques = @()
    Get-Content $WindowsIndexPath | ForEach-Object {
        if ($_ -match "^\s*(T\d{4}(?:\.\d{3})?):") {
            $WindowsTechniques += $matches[1]
        }
    }
    
    Write-Info "Found $($WindowsTechniques.Count) techniques in index, filtering for available implementations..."
    
    # Filter out techniques that don't have actual YAML files
    $AvailableTechniques = @()
    foreach ($Technique in $WindowsTechniques) {
        $TechniqueYaml = Join-Path $AtomicsPath "$Technique\$Technique.yaml"
        if (Test-Path $TechniqueYaml) {
            $AvailableTechniques += $Technique
        } else {
            Write-Warning "Skipping $Technique - no YAML file found at $TechniqueYaml"
        }
    }
    
    $WindowsTechniques = $AvailableTechniques
    Write-Success "Found $($WindowsTechniques.Count) Windows techniques with available implementations"
    
    # Results tracking
    $ExecutionResults = @()
    $SuccessCount = 0
    $FailureCount = 0
    
    Write-Info "=== Starting Continuous Monitoring ==="
    # Start continuous process monitoring
    $ProcessMonitoringJob = Start-ProcessMonitoring -OutputFile "$OutputDir\continuous_process_monitoring.csv" -IntervalSeconds 1
    Write-Success "Started continuous process monitoring (1-second intervals)"
    
    # Start WMI process event monitoring
    $WMIMonitoringJob = Start-WMIProcessMonitoring -OutputDir "$OutputDir\logs"
    Write-Success "Started WMI process event monitoring"
    
    Write-Info "=== Executing Atomic Tests ==="
    foreach ($Technique in $WindowsTechniques) {
        Write-Info "Processing technique: $Technique"
        
        # Record technique start time for real-time logging
        $TechniqueStartTime = Get-Date
        
        try {
            # Get prerequisites
            Write-Host "  Getting prerequisites..." -NoNewline
            try {
                Invoke-AtomicTest $Technique -PathToAtomicsFolder $AtomicsPath -GetPrereqs -Confirm:$false -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
                Write-Success " OK"
            } catch {
                Write-Warning " FAILED: $($_.Exception.Message)"
                # Continue anyway - some tests work without all prereqs
            }
            
            # Execute the test
            Write-Host "  Executing test..." -NoNewline
            $TestResult = Invoke-AtomicTest $Technique -PathToAtomicsFolder $AtomicsPath -Confirm:$false -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
            Write-Success " OK"
            
            # Record technique end time
            $TechniqueEndTime = Get-Date
            
            # Collect real-time logs for this technique
            Write-Host "  Collecting technique logs..." -NoNewline
            try {
                Collect-TechniqueLog -Technique $Technique -OutputDir $OutputDir -TechniqueStartTime $TechniqueStartTime -TechniqueEndTime $TechniqueEndTime
                Write-Success " OK"
            } catch {
                Write-Warning " FAILED: $($_.Exception.Message)"
            }
            
            # Collect real-time logs for this technique
            Write-Host "  Collecting technique logs..." -NoNewline
            Collect-TechniqueLog -Technique $Technique -OutputDir $OutputDir -TechniqueStartTime $TechniqueStartTime -TechniqueEndTime $TechniqueEndTime
            Write-Success " OK"
            
            # Copy key logs to main logs directory for immediate access
            Write-Host "  Updating main logs directory..." -NoNewline
            try {
                $KeyLogChannels = @("Security", "System", "Microsoft-Windows-Sysmon_Operational", "Microsoft-Windows-PowerShell_Operational")
                foreach ($ChannelName in $KeyLogChannels) {
                    $SourceLog = "$OutputDir\per-technique\$Technique\$ChannelName.evtx"
                    $DestLog = "$OutputDir\logs\$ChannelName`_latest.evtx"
                    
                    if (Test-Path $SourceLog) {
                        Copy-Item $SourceLog $DestLog -Force -ErrorAction SilentlyContinue
                    }
                }
                Write-Success " OK"
            } catch {
                Write-Warning " PARTIAL"
            }
            
            # Cleanup
            Write-Host "  Cleaning up..." -NoNewline
            Invoke-AtomicTest $Technique -PathToAtomicsFolder $AtomicsPath -Cleanup -Confirm:$false -ErrorAction SilentlyContinue
            Write-Success " OK"
            
            $ExecutionResults += [PSCustomObject]@{
                Technique = $Technique
                Status = "Success"
                ExecutionTime = $TechniqueEndTime
                Error = $null
                Duration = ($TechniqueEndTime - $TechniqueStartTime).TotalSeconds
            }
            $SuccessCount++
            
        } catch {
            $ErrorMessage = $_.Exception.Message
            $TechniqueEndTime = Get-Date
            Write-Error " FAILED: $ErrorMessage"
            
            # Still collect logs even for failed techniques (might show why it failed)
            Write-Host "  Collecting failure logs..." -NoNewline
            try {
                Collect-TechniqueLog -Technique $Technique -OutputDir $OutputDir -TechniqueStartTime $TechniqueStartTime -TechniqueEndTime $TechniqueEndTime
                
                # Create failure info file
                $FailureInfo = @{
                    Technique = $Technique
                    Error = $ErrorMessage
                    StartTime = $TechniqueStartTime
                    EndTime = $TechniqueEndTime
                    Duration = ($TechniqueEndTime - $TechniqueStartTime).TotalSeconds
                }
                $FailureInfo | ConvertTo-Json | Out-File "$OutputDir\per-technique\$Technique\failure_info.json" -Encoding UTF8
                Write-Success " OK"
            } catch {
                Write-Warning " FAILED: $($_.Exception.Message)"
            }
            
            # Categorize the error for better reporting
            $ErrorCategory = "Unknown"
            if ($ErrorMessage -match "Access is denied") {
                $ErrorCategory = "Permission Denied"
            } elseif ($ErrorMessage -match "not found|does not exist") {
                $ErrorCategory = "File Not Found"
            } elseif ($ErrorMessage -match "timeout") {
                $ErrorCategory = "Timeout"
            } elseif ($ErrorMessage -match "blocked|quarantined") {
                $ErrorCategory = "Antivirus Blocked"
            }
            
            $ExecutionResults += [PSCustomObject]@{
                Technique = $Technique
                Status = "Failed"
                ExecutionTime = $TechniqueEndTime
                Error = $ErrorMessage
                ErrorCategory = $ErrorCategory
                Duration = ($TechniqueEndTime - $TechniqueStartTime).TotalSeconds
            }
            $FailureCount++
            
            # Try cleanup even if execution failed
            try {
                Invoke-AtomicTest $Technique -PathToAtomicsFolder $AtomicsPath -Cleanup -Confirm:$false -ErrorAction SilentlyContinue
            } catch { }
        }
        
        # Brief pause between tests
        Start-Sleep -Seconds 2
    }
    
    # Record end time
    $EndTime = Get-Date
    $EndTimeUTC = $EndTime.ToUniversalTime()
    
    Write-Info "=== Stopping Continuous Monitoring ==="
    # Stop continuous process monitoring
    Stop-ProcessMonitoring -MonitoringJob $ProcessMonitoringJob
    Write-Success "Stopped continuous process monitoring"
    
    # Stop WMI process event monitoring
    Stop-WMIProcessMonitoring -WMIJob $WMIMonitoringJob
    Write-Success "Stopped WMI process event monitoring"
    
    Write-Info "=== Collecting Post-Execution System State ==="
    Get-Process | Export-Csv "$OutputDir\results\processes_after.csv" -NoTypeInformation
    Get-Service | Export-Csv "$OutputDir\results\services_after.csv" -NoTypeInformation
    Get-NetTCPConnection | Export-Csv "$OutputDir\results\network_after.csv" -NoTypeInformation
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Export-Csv "$OutputDir\results\registry_run_after.csv" -NoTypeInformation
    
    Write-Info "=== Collecting Windows Event Logs ==="
    # Define all important Windows event log channels with their source paths
    $EventLogChannels = @{
        "Security" = "C:\Windows\System32\winevt\Logs\Security.evtx"
        "System" = "C:\Windows\System32\winevt\Logs\System.evtx"
        "Application" = "C:\Windows\System32\winevt\Logs\Application.evtx"
        "Microsoft-Windows-Sysmon/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
        "Microsoft-Windows-PowerShell/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
        "Windows PowerShell" = "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx"
        "Microsoft-Windows-Windows Defender/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
        "Microsoft-Windows-TaskScheduler/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx"
        "Microsoft-Windows-WMI-Activity/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
        "Microsoft-Windows-AppLocker/EXE and DLL" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
        "Microsoft-Windows-AppLocker/MSI and Script" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4MSI and Script.evtx"
        "Microsoft-Windows-AppLocker/Packaged app-Deployment" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4Packaged app-Deployment.evtx"
        "Microsoft-Windows-AppLocker/Packaged app-Execution" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4Packaged app-Execution.evtx"
        "Microsoft-Windows-CodeIntegrity/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx"
        "Microsoft-Windows-Kernel-Process/Analytic" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Kernel-Process%4Analytic.evtx"
        "Microsoft-Windows-Kernel-File/Analytic" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Kernel-File%4Analytic.evtx"
        "Microsoft-Windows-DNS-Client/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx"
        "Microsoft-Windows-Winlogon/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Winlogon%4Operational.evtx"
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"
        "Microsoft-Windows-NetworkProfile/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-NetworkProfile%4Operational.evtx"
        "Microsoft-Windows-WLAN-AutoConfig/Operational" = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx"
    }
    
    foreach ($Channel in $EventLogChannels.Keys) {
        try {
            $SourcePath = $EventLogChannels[$Channel]
            Write-Host "  Collecting $Channel..." -NoNewline
            $SafeChannelName = $Channel -replace '[\\/:*?"<>|]', '_'
            
            # Export full log
            $FullLogPath = "$OutputDir\logs\$SafeChannelName.evtx"
            wevtutil epl $Channel $FullLogPath 2>$null
            
            # Export time-windowed events as XML for analysis
            $WindowedLogPath = "$OutputDir\logs\$SafeChannelName`_windowed.xml"
            $Query = "*[System[TimeCreated[@SystemTime>='$($StartTimeUTC.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))' and @SystemTime<='$($EndTimeUTC.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
            wevtutil qe $Channel "/q:$Query" "/f:xml" > $WindowedLogPath 2>$null
            
            # Create source path metadata file
            $SourceInfo = @{
                Channel = $Channel
                SourcePath = $SourcePath
                FullLogPath = $FullLogPath
                WindowedLogPath = $WindowedLogPath
                CollectionTime = Get-Date
            }
            $SourceInfo | ConvertTo-Json | Out-File "$OutputDir\logs\$SafeChannelName`_source.json" -Encoding UTF8
            
            Write-Success " OK"
        } catch {
            Write-Warning " SKIPPED (not available)"
        }
    }
    
    Write-Info "=== Collecting Additional Windows Logs ==="
    
    # Windows Error Reporting
    try {
        Write-Host "  Collecting WER reports..." -NoNewline
        $WERSources = @()
        if (Test-Path "$env:ProgramData\Microsoft\Windows\WER\ReportArchive") {
            Copy-Item "$env:ProgramData\Microsoft\Windows\WER\ReportArchive" "$OutputDir\logs\WER_ReportArchive" -Recurse -Force -ErrorAction SilentlyContinue
            $WERSources += "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
        }
        if (Test-Path "$env:ProgramData\Microsoft\Windows\WER\ReportQueue") {
            Copy-Item "$env:ProgramData\Microsoft\Windows\WER\ReportQueue" "$OutputDir\logs\WER_ReportQueue" -Recurse -Force -ErrorAction SilentlyContinue
            $WERSources += "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
        }
        
        # Create WER source metadata
        $WERInfo = @{
            LogType = "Windows Error Reporting"
            SourcePaths = $WERSources
            DestinationPath = "$OutputDir\logs\WER_*"
            CollectionTime = Get-Date
        }
        $WERInfo | ConvertTo-Json | Out-File "$OutputDir\logs\WER_sources.json" -Encoding UTF8
        
        Write-Success " OK"
    } catch {
        Write-Warning " FAILED"
    }
    
    # Windows Firewall logs
    try {
        Write-Host "  Collecting Firewall logs..." -NoNewline
        $FirewallSource = "$env:SystemRoot\System32\LogFiles\Firewall"
        if (Test-Path $FirewallSource) {
            Copy-Item $FirewallSource "$OutputDir\logs\Firewall" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Create Firewall source metadata
            $FirewallInfo = @{
                LogType = "Windows Firewall"
                SourcePath = $FirewallSource
                DestinationPath = "$OutputDir\logs\Firewall"
                CollectionTime = Get-Date
            }
            $FirewallInfo | ConvertTo-Json | Out-File "$OutputDir\logs\Firewall_sources.json" -Encoding UTF8
        }
        Write-Success " OK"
    } catch {
        Write-Warning " FAILED"
    }
    
    # IIS logs (if present)
    try {
        Write-Host "  Collecting IIS logs..." -NoNewline
        $IISSource = "$env:SystemDrive\inetpub\logs\LogFiles"
        if (Test-Path $IISSource) {
            Copy-Item $IISSource "$OutputDir\logs\IIS_LogFiles" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Create IIS source metadata
            $IISInfo = @{
                LogType = "IIS Web Server"
                SourcePath = $IISSource
                DestinationPath = "$OutputDir\logs\IIS_LogFiles"
                CollectionTime = Get-Date
            }
            $IISInfo | ConvertTo-Json | Out-File "$OutputDir\logs\IIS_sources.json" -Encoding UTF8
        }
        Write-Success " OK"
    } catch {
        Write-Warning " SKIPPED (IIS not present)"
    }
    
    # Windows Defender scan logs
    try {
        Write-Host "  Collecting Defender logs..." -NoNewline
        $DefenderSource = "$env:ProgramData\Microsoft\Windows Defender\Scans\History"
        if (Test-Path $DefenderSource) {
            Copy-Item $DefenderSource "$OutputDir\logs\Defender_History" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Create Defender source metadata
            $DefenderInfo = @{
                LogType = "Windows Defender"
                SourcePath = $DefenderSource
                DestinationPath = "$OutputDir\logs\Defender_History"
                CollectionTime = Get-Date
            }
            $DefenderInfo | ConvertTo-Json | Out-File "$OutputDir\logs\Defender_sources.json" -Encoding UTF8
        }
        Write-Success " OK"
    } catch {
        Write-Warning " FAILED"
    }
    
    Write-Info "=== Generating Execution Report ==="
    # Save execution results
    $ExecutionResults | Export-Csv "$OutputDir\results\execution_results.csv" -NoTypeInformation
    
    # Generate summary report
    $SummaryReport = @"
=== Atomic Red Team Windows Execution Summary ===
Execution Start: $StartTime
Execution End: $EndTime
Duration: $($EndTime - $StartTime)

Techniques Executed: $($WindowsTechniques.Count)
Successful: $SuccessCount
Failed: $FailureCount
Success Rate: $(if ($WindowsTechniques.Count -gt 0) { [math]::Round(($SuccessCount / $WindowsTechniques.Count) * 100, 2) } else { 0 })%

Output Directory: $OutputDir
Event Log Channels Collected: $($EventLogChannels.Count)

=== Failed Techniques ===
$($ExecutionResults | Where-Object {$_.Status -eq "Failed"} | ForEach-Object {"$($_.Technique): $($_.Error)"} | Out-String)

=== Collection Summary ===
- Event logs: $OutputDir\logs\*.evtx
- Windowed events: $OutputDir\logs\*_windowed.xml
- System state: $OutputDir\results\*_before.csv and *_after.csv
- Execution results: $OutputDir\results\execution_results.csv
- Additional logs: $OutputDir\logs\WER_*, Firewall, IIS_*, Defender_*
- Per-technique logs: $OutputDir\per-technique\[TECHNIQUE_ID]\*.xml
- Per-technique snapshots: $OutputDir\per-technique\[TECHNIQUE_ID]\processes_snapshot.csv

=== Source Path Metadata ===
- Event log sources: $OutputDir\logs\*_source.json
- Additional log sources: $OutputDir\logs\*_sources.json
- System state sources: $OutputDir\results\system_state_sources.json
- Per-technique metadata: $OutputDir\per-technique\[TECHNIQUE_ID]\metadata.json

REAL-TIME LOGGING: Each technique now has individual log files collected immediately after execution.
CONTINUOUS MONITORING: 1-second interval process snapshots capture short-lived processes like InstallUtil.
WMI EVENT MONITORING: Real-time process creation/termination events with command lines and parent processes.
SOURCE TRACKING: All logs include metadata files showing original source paths and collection details.
Use these logs for anomaly detection training and analysis.
"@
    
    $SummaryReport | Out-File "$OutputDir\SUMMARY.txt" -Encoding UTF8
    
    Write-Success "=== Execution Complete ==="
    Write-Info $SummaryReport
    
} catch {
    Write-Error "Critical error in main execution: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}
