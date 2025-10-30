#!/usr/bin/env bash

# Atomic Red Team macOS Runner - Execute all macOS atomics and collect comprehensive logs
# 
# This script automatically:
# 1. Installs PowerShell 7 and Invoke-AtomicRedTeam if not present
# 2. Executes all macOS-compatible atomic tests
# 3. Collects comprehensive logs from all macOS logging locations
# 4. Packages everything for anomaly detection analysis
#
# Usage:
#   sudo ./macos-runner.sh [atomics_path] [output_dir] [timeout_seconds]
#
# Examples:
#   sudo ./macos-runner.sh
#   sudo ./macos-runner.sh /path/to/atomics /tmp/art-results 300

set -euo pipefail

# Configuration
ATOMICS_PATH="${1:-$(pwd)/atomics}"
OUTPUT_DIR="${2:-/tmp/art-results/$(date +%Y%m%d_%H%M%S)}"
TIMEOUT_SECONDS="${3:-300}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root for comprehensive log collection"
   exit 1
fi

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    log_error "This script is designed for macOS only"
    exit 1
fi

# Trap to ensure cleanup
cleanup() {
    log_info "Performing cleanup..."
    # Kill any background processes we started
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

main() {
    log_info "=== Atomic Red Team macOS Runner Started ==="
    log_info "Start Time: $(date)"
    log_info "Output Directory: $OUTPUT_DIR"
    log_info "Atomics Path: $ATOMICS_PATH"
    log_info "macOS Version: $(sw_vers -productVersion)"
    
    # Create output directories
    mkdir -p "$OUTPUT_DIR"/{logs,results}
    
    # Record start time for log collection window
    START_TIME=$(date -Iseconds)
    START_EPOCH=$(date +%s)
    
    log_info "=== Installing Dependencies ==="
    install_dependencies
    
    log_info "=== Collecting Pre-Execution System State ==="
    collect_system_state "before"
    
    log_info "=== Loading macOS Atomic Tests ==="
    load_macos_techniques
    
    log_info "=== Executing Atomic Tests ==="
    execute_atomic_tests
    
    # Record end time
    END_TIME=$(date -Iseconds)
    END_EPOCH=$(date +%s)
    
    log_info "=== Collecting Post-Execution System State ==="
    collect_system_state "after"
    
    log_info "=== Collecting macOS System Logs ==="
    collect_system_logs
    
    log_info "=== Generating Execution Report ==="
    generate_report
    
    log_success "=== Execution Complete ==="
    log_info "Results saved to: $OUTPUT_DIR"
}

install_dependencies() {
    # Install Homebrew if not present (needed for PowerShell)
    if ! command -v brew >/dev/null 2>&1; then
        log_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        log_success "Homebrew installed"
    else
        log_success "Homebrew already available"
    fi
    
    # Install PowerShell 7 if not present
    if ! command -v pwsh >/dev/null 2>&1; then
        log_info "Installing PowerShell 7..."
        brew install --cask powershell
        log_success "PowerShell 7 installed"
    else
        log_success "PowerShell 7 already available"
    fi
    
    # Install/update Invoke-AtomicRedTeam
    log_info "Installing/updating Invoke-AtomicRedTeam..."
    pwsh -NoLogo -NoProfile -Command "
        if (-not (Get-Module -ListAvailable -Name 'Invoke-AtomicRedTeam')) {
            Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force -AllowClobber
            Write-Host 'Invoke-AtomicRedTeam installed successfully'
        } else {
            Update-Module -Name Invoke-AtomicRedTeam -Force
            Write-Host 'Invoke-AtomicRedTeam updated successfully'
        }
    "
}

collect_system_state() {
    local suffix="$1"
    log_info "Collecting system state ($suffix)..."
    
    # Process information
    ps aux > "$OUTPUT_DIR/results/processes_$suffix.txt"
    
    # Network connections
    netstat -an > "$OUTPUT_DIR/results/network_connections_$suffix.txt" 2>/dev/null || true
    lsof -i > "$OUTPUT_DIR/results/network_lsof_$suffix.txt" 2>/dev/null || true
    
    # Services (launchd)
    launchctl list > "$OUTPUT_DIR/results/launchctl_services_$suffix.txt" 2>/dev/null || true
    
    # System extensions and kernel extensions
    systemextensionsctl list > "$OUTPUT_DIR/results/system_extensions_$suffix.txt" 2>/dev/null || true
    kextstat > "$OUTPUT_DIR/results/kernel_extensions_$suffix.txt" 2>/dev/null || true
    
    # Scheduled tasks (cron and launchd)
    crontab -l > "$OUTPUT_DIR/results/root_crontab_$suffix.txt" 2>/dev/null || echo "No root crontab" > "$OUTPUT_DIR/results/root_crontab_$suffix.txt"
    ls -la /System/Library/LaunchDaemons/ > "$OUTPUT_DIR/results/system_launch_daemons_$suffix.txt" 2>/dev/null || true
    ls -la /Library/LaunchDaemons/ > "$OUTPUT_DIR/results/library_launch_daemons_$suffix.txt" 2>/dev/null || true
    ls -la /Library/LaunchAgents/ > "$OUTPUT_DIR/results/library_launch_agents_$suffix.txt" 2>/dev/null || true
    
    # Environment variables
    env > "$OUTPUT_DIR/results/environment_$suffix.txt"
    
    # File system mounts
    mount > "$OUTPUT_DIR/results/mounts_$suffix.txt"
    df -h > "$OUTPUT_DIR/results/disk_usage_$suffix.txt"
    
    # User information
    who > "$OUTPUT_DIR/results/logged_users_$suffix.txt"
    last -n 50 > "$OUTPUT_DIR/results/login_history_$suffix.txt"
    
    # System information
    system_profiler SPSoftwareDataType > "$OUTPUT_DIR/results/system_software_$suffix.txt" 2>/dev/null || true
    system_profiler SPHardwareDataType > "$OUTPUT_DIR/results/system_hardware_$suffix.txt" 2>/dev/null || true
    
    # Security settings
    spctl --status > "$OUTPUT_DIR/results/gatekeeper_status_$suffix.txt" 2>/dev/null || true
    csrutil status > "$OUTPUT_DIR/results/sip_status_$suffix.txt" 2>/dev/null || true
    
    # Firewall status
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate > "$OUTPUT_DIR/results/firewall_status_$suffix.txt" 2>/dev/null || true
    pfctl -s all > "$OUTPUT_DIR/results/pf_firewall_$suffix.txt" 2>/dev/null || true
}

load_macos_techniques() {
    local macos_index="$ATOMICS_PATH/../atomics/Indexes/macos-index.yaml"
    if [[ ! -f "$macos_index" ]]; then
        log_error "macOS index not found at: $macos_index"
        exit 1
    fi
    
    # Extract technique IDs from YAML
    MACOS_TECHNIQUES=($(grep -E "^\s*-\s*T[0-9]{4}(\.[0-9]{3})?\s*$" "$macos_index" | sed 's/^\s*-\s*//' | sort -u))
    
    log_success "Found ${#MACOS_TECHNIQUES[@]} macOS techniques to execute"
    echo "${MACOS_TECHNIQUES[@]}" > "$OUTPUT_DIR/results/techniques_list.txt"
}

execute_atomic_tests() {
    local success_count=0
    local failure_count=0
    
    # Initialize results file
    echo "Technique,Status,ExecutionTime,Error" > "$OUTPUT_DIR/results/execution_results.csv"
    
    for technique in "${MACOS_TECHNIQUES[@]}"; do
        log_info "Processing technique: $technique"
        
        local start_time=$(date -Iseconds)
        local status="Success"
        local error=""
        
        # Execute via PowerShell with error handling
        if pwsh -NoLogo -NoProfile -Command "
            Import-Module Invoke-AtomicRedTeam -Force
            try {
                Write-Host '  Getting prerequisites...' -NoNewline
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -GetPrereqs -Confirm:\$false -TimeoutSeconds $TIMEOUT_SECONDS -ErrorAction Stop
                Write-Host ' OK' -ForegroundColor Green
                
                Write-Host '  Executing test...' -NoNewline  
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Confirm:\$false -TimeoutSeconds $TIMEOUT_SECONDS -ErrorAction Stop
                Write-Host ' OK' -ForegroundColor Green
                
                Write-Host '  Cleaning up...' -NoNewline
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Cleanup -Confirm:\$false -ErrorAction SilentlyContinue
                Write-Host ' OK' -ForegroundColor Green
                
                exit 0
            } catch {
                Write-Host ' FAILED' -ForegroundColor Red
                Write-Error \$_.Exception.Message
                try {
                    Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Cleanup -Confirm:\$false -ErrorAction SilentlyContinue
                } catch { }
                exit 1
            }
        "; then
            ((success_count++))
        else
            status="Failed"
            error="PowerShell execution failed"
            ((failure_count++))
        fi
        
        # Log result
        echo "$technique,$status,$start_time,\"$error\"" >> "$OUTPUT_DIR/results/execution_results.csv"
        
        # Brief pause between tests
        sleep 2
    done
    
    log_success "Execution complete: $success_count successful, $failure_count failed"
    echo "$success_count" > "$OUTPUT_DIR/results/success_count.txt"
    echo "$failure_count" > "$OUTPUT_DIR/results/failure_count.txt"
}

collect_system_logs() {
    log_info "Collecting system logs..."
    
    # Create logs subdirectories
    mkdir -p "$OUTPUT_DIR/logs"/{unified,var_log,audit,application,diagnostics}
    
    # Unified logging (primary logging system in macOS)
    log_info "  Collecting unified logs..."
    
    # Calculate duration for log collection
    local duration_minutes=$(( (END_EPOCH - START_EPOCH) / 60 + 5 )) # Add 5 minutes buffer
    
    # Collect unified log archive for the execution window
    /usr/bin/log collect --output "$OUTPUT_DIR/logs/unified/execution_window.logarchive" --last "${duration_minutes}m" 2>/dev/null || {
        log_warning "Failed to collect unified log archive, trying alternative method..."
        /usr/bin/log collect --output "$OUTPUT_DIR/logs/unified/execution_window.logarchive" --start "$START_TIME" 2>/dev/null || true
    }
    
    # Export unified logs in different formats for analysis
    /usr/bin/log show --predicate 'eventMessage contains "atomic" OR eventMessage contains "test" OR eventMessage contains "attack"' --info --debug --last "${duration_minutes}m" > "$OUTPUT_DIR/logs/unified/atomic_related.log" 2>/dev/null || true
    
    # Security-related unified logs
    /usr/bin/log show --predicate 'category == "security" OR subsystem == "com.apple.security"' --last "${duration_minutes}m" > "$OUTPUT_DIR/logs/unified/security.log" 2>/dev/null || true
    
    # Process and network activity
    /usr/bin/log show --predicate 'eventType == activityCreateEvent OR eventType == activityDestroyEvent' --last "${duration_minutes}m" > "$OUTPUT_DIR/logs/unified/process_activity.log" 2>/dev/null || true
    
    # System events
    /usr/bin/log show --predicate 'subsystem == "com.apple.kernel"' --last "${duration_minutes}m" > "$OUTPUT_DIR/logs/unified/kernel.log" 2>/dev/null || true
    
    # Copy /var/log directory
    log_info "  Copying /var/log..."
    if [[ -d /var/log ]]; then
        tar -czf "$OUTPUT_DIR/logs/var_log.tar.gz" /var/log 2>/dev/null || {
            log_warning "Failed to create tar of /var/log, copying individual files..."
            cp -r /var/log/* "$OUTPUT_DIR/logs/var_log/" 2>/dev/null || true
        }
    fi
    
    # Copy /private/var/log (symlinked to /var/log but may have additional content)
    if [[ -d /private/var/log && ! -L /private/var/log ]]; then
        tar -czf "$OUTPUT_DIR/logs/private_var_log.tar.gz" /private/var/log 2>/dev/null || true
    fi
    
    # Audit logs (if enabled)
    if [[ -d /var/audit ]]; then
        log_info "  Collecting audit logs..."
        cp -r /var/audit/* "$OUTPUT_DIR/logs/audit/" 2>/dev/null || true
        
        # Parse audit logs for the execution window if praudit is available
        if command -v praudit >/dev/null 2>&1; then
            find /var/audit -name "*.trail" -newer "$OUTPUT_DIR/results/processes_before.txt" -exec praudit {} \; > "$OUTPUT_DIR/logs/audit/windowed_audit.log" 2>/dev/null || true
        fi
    fi
    
    # System-wide application logs
    log_info "  Collecting system application logs..."
    if [[ -d /Library/Logs ]]; then
        cp -r /Library/Logs "$OUTPUT_DIR/logs/application/Library_Logs" 2>/dev/null || true
    fi
    
    # User application logs (for current user and common users)
    for user_home in /Users/*; do
        if [[ -d "$user_home/Library/Logs" ]]; then
            local username=$(basename "$user_home")
            mkdir -p "$OUTPUT_DIR/logs/application/Users_$username"
            cp -r "$user_home/Library/Logs" "$OUTPUT_DIR/logs/application/Users_$username/" 2>/dev/null || true
        fi
    done
    
    # Diagnostics and performance logs
    log_info "  Collecting diagnostics logs..."
    if [[ -d /var/db/diagnostics ]]; then
        cp -r /var/db/diagnostics "$OUTPUT_DIR/logs/diagnostics/" 2>/dev/null || true
    fi
    
    if [[ -d /var/db/systemstats ]]; then
        cp -r /var/db/systemstats "$OUTPUT_DIR/logs/diagnostics/" 2>/dev/null || true
    fi
    
    # Crash reports
    if [[ -d /Library/Logs/DiagnosticReports ]]; then
        cp -r /Library/Logs/DiagnosticReports "$OUTPUT_DIR/logs/diagnostics/System_DiagnosticReports" 2>/dev/null || true
    fi
    
    for user_home in /Users/*; do
        if [[ -d "$user_home/Library/Logs/DiagnosticReports" ]]; then
            local username=$(basename "$user_home")
            mkdir -p "$OUTPUT_DIR/logs/diagnostics/Users_$username"
            cp -r "$user_home/Library/Logs/DiagnosticReports" "$OUTPUT_DIR/logs/diagnostics/Users_$username/" 2>/dev/null || true
        fi
    done
    
    # Additional system information
    log_info "  Collecting additional system information..."
    
    # Current system state
    dmesg > "$OUTPUT_DIR/logs/dmesg.log" 2>/dev/null || true
    
    # Network configuration
    ifconfig -a > "$OUTPUT_DIR/logs/network_interfaces.log" 2>/dev/null || true
    netstat -rn > "$OUTPUT_DIR/logs/network_routes.log" 2>/dev/null || true
    
    # DNS configuration
    scutil --dns > "$OUTPUT_DIR/logs/dns_config.log" 2>/dev/null || true
    
    # System preferences and security settings
    defaults read > "$OUTPUT_DIR/logs/system_defaults.log" 2>/dev/null || true
    
    # Installed applications
    ls -la /Applications > "$OUTPUT_DIR/logs/installed_applications.log" 2>/dev/null || true
    system_profiler SPApplicationsDataType > "$OUTPUT_DIR/logs/application_inventory.log" 2>/dev/null || true
    
    # Keychain information (non-sensitive)
    security list-keychains > "$OUTPUT_DIR/logs/keychain_list.log" 2>/dev/null || true
    
    # Code signing and notarization info for recently modified files
    find /Applications -name "*.app" -mtime -1 -exec codesign -dv {} \; > "$OUTPUT_DIR/logs/recent_codesign_info.log" 2>&1 || true
    
    # XProtect and MRT (malware removal tool) logs
    if [[ -d /var/log/xprotect ]]; then
        cp -r /var/log/xprotect "$OUTPUT_DIR/logs/application/" 2>/dev/null || true
    fi
    
    # Spotlight metadata (for file activity analysis)
    mdutil -s -a > "$OUTPUT_DIR/logs/spotlight_status.log" 2>/dev/null || true
}

generate_report() {
    local end_time=$(date)
    local duration=$((END_EPOCH - START_EPOCH))
    local success_count=$(cat "$OUTPUT_DIR/results/success_count.txt")
    local failure_count=$(cat "$OUTPUT_DIR/results/failure_count.txt")
    local total_count=${#MACOS_TECHNIQUES[@]}
    local success_rate=$(echo "scale=2; $success_count * 100 / $total_count" | bc -l 2>/dev/null || echo "N/A")
    
    cat > "$OUTPUT_DIR/SUMMARY.txt" << EOF
=== Atomic Red Team macOS Execution Summary ===
Execution Start: $(date -r "$START_EPOCH")
Execution End: $end_time
Duration: ${duration} seconds

Techniques Executed: $total_count
Successful: $success_count
Failed: $failure_count
Success Rate: ${success_rate}%

Output Directory: $OUTPUT_DIR
System: $(uname -a)
macOS Version: $(sw_vers -productVersion)
Build: $(sw_vers -buildVersion)

=== Failed Techniques ===
$(grep "Failed" "$OUTPUT_DIR/results/execution_results.csv" | cut -d',' -f1 | sed 's/^/- /')

=== Collection Summary ===
- Unified logs: $OUTPUT_DIR/logs/unified/execution_window.logarchive
- System logs: $OUTPUT_DIR/logs/var_log.tar.gz
- Audit logs: $OUTPUT_DIR/logs/audit/
- Application logs: $OUTPUT_DIR/logs/application/
- Diagnostics: $OUTPUT_DIR/logs/diagnostics/
- System state: $OUTPUT_DIR/results/*_before.txt and *_after.txt
- Execution results: $OUTPUT_DIR/results/execution_results.csv
- Security configs: $OUTPUT_DIR/logs/*_status.log, *_config.log

=== macOS-Specific Logs Collected ===
- Unified logging archive (primary log source)
- Security subsystem logs
- Process and kernel activity
- XProtect and system security logs
- Application crash reports and diagnostics
- Code signing and notarization information
- Keychain and security framework logs

Use these logs for anomaly detection training and analysis.

=== Next Steps ===
1. Review failed techniques in execution_results.csv
2. Analyze unified log archive with Console.app or log command
3. Correlate system state changes between before/after snapshots
4. Import logs into your SIEM/analysis platform
5. Use 'log show' command to query specific events from the logarchive

=== Log Analysis Commands ===
# View the collected log archive:
log show $OUTPUT_DIR/logs/unified/execution_window.logarchive

# Search for specific events:
log show $OUTPUT_DIR/logs/unified/execution_window.logarchive --predicate 'eventMessage contains "your_search_term"'

# Filter by time range:
log show $OUTPUT_DIR/logs/unified/execution_window.logarchive --start '$START_TIME' --end '$END_TIME'
EOF
    
    log_info "Summary report generated: $OUTPUT_DIR/SUMMARY.txt"
    cat "$OUTPUT_DIR/SUMMARY.txt"
}

# Execute main function
main "$@"
