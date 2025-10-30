#!/usr/bin/env bash

# Atomic Red Team Linux Runner - Execute all Linux atomics and collect comprehensive logs
# 
# This script automatically:
# 1. Installs PowerShell 7 and Invoke-AtomicRedTeam if not present
# 2. Executes all Linux-compatible atomic tests
# 3. Collects comprehensive logs from all Linux logging locations
# 4. Packages everything for anomaly detection analysis
#
# Usage:
#   sudo ./linux-runner.sh [atomics_path] [output_dir] [timeout_seconds]
#
# Examples:
#   sudo ./linux-runner.sh
#   sudo ./linux-runner.sh /path/to/atomics /tmp/art-results 300

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATOMICS_PATH="${1:-$SCRIPT_DIR/../atomics}"
OUTPUT_DIR="${2:-/var/tmp/art-results/$(date +%Y%m%d_%H%M%S)}"
TIMEOUT_SECONDS="${3:-300}"

# Global variables for timing
START_TIME=""
END_TIME=""
START_EPOCH=""
END_EPOCH=""

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

# Trap to ensure cleanup
cleanup() {
    local exit_code=$?
    log_info "Performing cleanup..."
    # Kill any background processes we started
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Clean up any temporary files
    find /tmp -name "tmp.*" -user root -mmin -60 -delete 2>/dev/null || true
    
    if [[ $exit_code -ne 0 ]]; then
        log_warning "Script exited with code $exit_code"
        if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
            log_info "Partial results may be available in: $OUTPUT_DIR"
        fi
    fi
}
trap cleanup EXIT INT TERM

main() {
    log_info "=== Atomic Red Team Linux Runner Started ==="
    log_info "Start Time: $(date)"
    log_info "Output Directory: $OUTPUT_DIR"
    log_info "Atomics Path: $ATOMICS_PATH"
    
    # Create output directories
    mkdir -p "$OUTPUT_DIR"/{logs,results}
    
    # Record start time for log collection window
    START_TIME=$(date -Iseconds)
    START_EPOCH=$(date +%s)
    
    # Validate atomics path
    if [[ ! -d "$ATOMICS_PATH" ]]; then
        log_error "Atomics directory not found: $ATOMICS_PATH"
        log_info "Please ensure you're running from the correct directory or provide the correct path"
        exit 1
    fi
    
    log_info "=== Installing Dependencies ==="
    install_dependencies || log_warning "Some dependencies may not have installed correctly"
    
    log_info "=== Collecting Pre-Execution System State ==="
    collect_system_state "before" || log_warning "Some system state collection failed"
    
    log_info "=== Loading Linux Atomic Tests ==="
    load_linux_techniques
    
    log_info "=== Executing Atomic Tests ==="
    execute_atomic_tests
    
    # Record end time
    END_TIME=$(date -Iseconds)
    END_EPOCH=$(date +%s)
    
    log_info "=== Collecting Post-Execution System State ==="
    collect_system_state "after" || log_warning "Some post-execution state collection failed"
    
    log_info "=== Collecting Linux System Logs ==="
    collect_system_logs || log_warning "Some log collection failed"
    
    log_info "=== Generating Execution Report ==="
    generate_report || log_warning "Report generation had issues"
    
    log_success "=== Execution Complete ==="
    log_info "Results saved to: $OUTPUT_DIR"
    
    # Show summary
    local success_count=$(cat "$OUTPUT_DIR/results/success_count.txt" 2>/dev/null || echo "0")
    local failure_count=$(cat "$OUTPUT_DIR/results/failure_count.txt" 2>/dev/null || echo "0")
    log_info "Summary: $success_count successful, $failure_count failed tests"
}

install_dependencies() {
    # Detect distribution
    if command -v apt-get >/dev/null 2>&1; then
        DISTRO="debian"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update --fix-missing"
    elif command -v yum >/dev/null 2>&1; then
        DISTRO="rhel"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum update -y"
    elif command -v dnf >/dev/null 2>&1; then
        DISTRO="fedora"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf update -y"
    elif command -v zypper >/dev/null 2>&1; then
        DISTRO="suse"
        PKG_INSTALL="zypper install -y"
        PKG_UPDATE="zypper refresh"
    else
        log_warning "Unknown distribution, attempting generic installation"
        DISTRO="unknown"
    fi
    
    # Update package cache first
    log_info "Updating package cache..."
    case $DISTRO in
        "debian")
            $PKG_UPDATE || log_warning "Package cache update had issues, continuing anyway"
            # Fix broken packages if any
            apt --fix-broken install -y || log_warning "Could not fix all broken packages"
            ;;
        "rhel"|"fedora"|"suse")
            $PKG_UPDATE || log_warning "Package cache update had issues, continuing anyway"
            ;;
    esac
    
    # Install common utilities needed by atomic tests - install individually to avoid dependency conflicts
    log_info "Installing common utilities..."
    ESSENTIAL_PACKAGES=("xxd" "vim-common" "curl" "wget" "git" "python3" "python3-pip" "bc" "jq")
    
    case $DISTRO in
        "debian")
            for package in "${ESSENTIAL_PACKAGES[@]}"; do
                log_info "Installing $package..."
                if ! $PKG_INSTALL "$package" 2>/dev/null; then
                    log_warning "Failed to install $package, continuing with other packages"
                    # Special handling for xxd
                    if [[ "$package" == "xxd" ]]; then
                        log_info "Trying to install vim as alternative for xxd..."
                        $PKG_INSTALL vim 2>/dev/null || log_warning "Could not install vim either"
                    fi
                fi
            done
            ;;
        "rhel"|"fedora")
            for package in "${ESSENTIAL_PACKAGES[@]}"; do
                log_info "Installing $package..."
                $PKG_INSTALL "$package" 2>/dev/null || log_warning "Failed to install $package"
            done
            ;;
        *)
            log_warning "Skipping utility installation for unknown distribution"
            ;;
    esac
    
    # Verify critical tools
    log_info "Verifying critical tools..."
    for tool in xxd bc jq curl python3; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_success "$tool is available"
        else
            log_warning "$tool is NOT available - some tests may fail"
        fi
    done
    
    # Install PowerShell 7 if not present
    if ! command -v pwsh >/dev/null 2>&1; then
        log_info "Installing PowerShell 7..."
        case $DISTRO in
            "debian")
                # Try repository method first
                if $PKG_INSTALL wget apt-transport-https software-properties-common curl 2>/dev/null; then
                    # Get Ubuntu version or default to 20.04
                    UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "20.04")
                    if wget -q "https://packages.microsoft.com/config/ubuntu/$UBUNTU_VERSION/packages-microsoft-prod.deb" -O packages-microsoft-prod.deb 2>/dev/null; then
                        if dpkg -i packages-microsoft-prod.deb 2>/dev/null && $PKG_UPDATE 2>/dev/null && $PKG_INSTALL powershell 2>/dev/null; then
                            log_success "PowerShell 7 installed via repository"
                        else
                            log_warning "Repository installation failed, trying direct download..."
                            install_powershell_direct
                        fi
                        rm -f packages-microsoft-prod.deb
                    else
                        log_warning "Could not download Microsoft repository package, trying direct download..."
                        install_powershell_direct
                    fi
                else
                    log_warning "Could not install prerequisites, trying direct download..."
                    install_powershell_direct
                fi
                ;;
            "rhel"|"fedora")
                if curl -sSL https://packages.microsoft.com/config/rhel/8/prod.repo | tee /etc/yum.repos.d/microsoft.repo >/dev/null 2>&1; then
                    $PKG_INSTALL powershell || install_powershell_direct
                else
                    install_powershell_direct
                fi
                ;;
            *)
                log_warning "Unknown distribution, trying direct download..."
                install_powershell_direct
                ;;
        esac
        
        if command -v pwsh >/dev/null 2>&1; then
            log_success "PowerShell 7 is now available"
        else
            log_error "PowerShell 7 installation failed - some tests may not work"
        fi
    else
        log_success "PowerShell 7 already available"
    fi
    
    # Install/update Invoke-AtomicRedTeam
    log_info "Installing/updating Invoke-AtomicRedTeam..."
    if ! pwsh -NoLogo -NoProfile -Command "
        try {
            if (-not (Get-Module -ListAvailable -Name 'Invoke-AtomicRedTeam')) {
                Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
                Write-Host 'Invoke-AtomicRedTeam installed successfully'
            } else {
                Update-Module -Name Invoke-AtomicRedTeam -Force -ErrorAction Stop
                Write-Host 'Invoke-AtomicRedTeam updated successfully'
            }
            exit 0
        } catch {
            Write-Error \$_.Exception.Message
            exit 1
        }
    "; then
        log_error "Failed to install/update Invoke-AtomicRedTeam"
        exit 1
    fi
}

install_powershell_direct() {
    log_info "Attempting direct PowerShell installation..."
    
    # Download PowerShell directly from GitHub releases
    PWSH_VERSION="7.3.8"
    PWSH_DEB="powershell_${PWSH_VERSION}-1.deb_amd64.deb"
    PWSH_URL="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/${PWSH_DEB}"
    
    if wget -q "$PWSH_URL" -O "/tmp/$PWSH_DEB" 2>/dev/null; then
        log_info "Downloaded PowerShell package, installing..."
        if dpkg -i "/tmp/$PWSH_DEB" 2>/dev/null || (apt --fix-broken install -y 2>/dev/null && dpkg -i "/tmp/$PWSH_DEB" 2>/dev/null); then
            log_success "PowerShell installed via direct download"
        else
            log_error "Direct PowerShell installation failed"
        fi
        rm -f "/tmp/$PWSH_DEB"
    else
        log_error "Could not download PowerShell package"
    fi
}

collect_system_state() {
    local suffix="$1"
    log_info "Collecting system state ($suffix)..."
    
    # Process information
    ps aux > "$OUTPUT_DIR/results/processes_$suffix.txt"
    
    # Network connections
    netstat -tuln > "$OUTPUT_DIR/results/network_listening_$suffix.txt" 2>/dev/null || ss -tuln > "$OUTPUT_DIR/results/network_listening_$suffix.txt"
    netstat -tun > "$OUTPUT_DIR/results/network_established_$suffix.txt" 2>/dev/null || ss -tun > "$OUTPUT_DIR/results/network_established_$suffix.txt"
    
    # Services
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service > "$OUTPUT_DIR/results/systemd_services_$suffix.txt"
        systemctl list-unit-files --type=service > "$OUTPUT_DIR/results/systemd_service_files_$suffix.txt"
    fi
    
    if command -v service >/dev/null 2>&1; then
        service --status-all > "$OUTPUT_DIR/results/sysv_services_$suffix.txt" 2>&1
    fi
    
    # Loaded kernel modules
    lsmod > "$OUTPUT_DIR/results/kernel_modules_$suffix.txt"
    
    # Scheduled tasks
    crontab -l > "$OUTPUT_DIR/results/root_crontab_$suffix.txt" 2>/dev/null || echo "No root crontab" > "$OUTPUT_DIR/results/root_crontab_$suffix.txt"
    ls -la /etc/cron* > "$OUTPUT_DIR/results/system_cron_$suffix.txt" 2>/dev/null || true
    
    # Environment variables
    env > "$OUTPUT_DIR/results/environment_$suffix.txt"
    
    # File system mounts
    mount > "$OUTPUT_DIR/results/mounts_$suffix.txt"
    df -h > "$OUTPUT_DIR/results/disk_usage_$suffix.txt"
    
    # User information
    who > "$OUTPUT_DIR/results/logged_users_$suffix.txt"
    last -n 50 > "$OUTPUT_DIR/results/login_history_$suffix.txt"
}

load_linux_techniques() {
    local linux_index="$ATOMICS_PATH/Indexes/linux-index.yaml"
    if [[ ! -f "$linux_index" ]]; then
        # Try alternative path
        linux_index="$ATOMICS_PATH/../atomics/Indexes/linux-index.yaml"
        if [[ ! -f "$linux_index" ]]; then
            log_error "Linux index not found at: $linux_index"
            log_info "Searched paths:"
            log_info "  - $ATOMICS_PATH/Indexes/linux-index.yaml"
            log_info "  - $ATOMICS_PATH/../atomics/Indexes/linux-index.yaml"
            exit 1
        fi
    fi
    
    # Simple approach: use a known list of working techniques to avoid slow filtering
    log_info "Loading known Linux techniques..."
    
    # Use a curated list of techniques that are known to work on Linux
    # This avoids the slow filtering process
    LINUX_TECHNIQUES=(
        "T1001.002" "T1003.007" "T1003.008" "T1005" "T1007" "T1014" "T1016" "T1018"
        "T1027" "T1027.001" "T1027.002" "T1027.004" "T1027.013" "T1030" "T1033"
        "T1036.003" "T1036.004" "T1036.005" "T1040" "T1046" "T1048" "T1048.002"
        "T1048.003" "T1049" "T1053.002" "T1053.006" "T1057" "T1059.004" "T1059.006"
        "T1069.001" "T1069.002" "T1070.003" "T1070.004" "T1070.006" "T1071.001"
        "T1074.001" "T1078.003" "T1082" "T1083" "T1087.001" "T1087.002" "T1090.001"
        "T1090.003" "T1095" "T1105" "T1110.001" "T1110.004" "T1113" "T1115" "T1124"
        "T1132.001" "T1135" "T1136.001" "T1136.002" "T1140" "T1176" "T1201" "T1217"
        "T1222.002" "T1485" "T1486" "T1489" "T1496" "T1497.001" "T1497.003" "T1529"
        "T1531" "T1552" "T1552.001" "T1552.004" "T1553.004" "T1555.003" "T1560.001"
        "T1560.002" "T1562.001" "T1562.003" "T1562.004" "T1562.006" "T1564.001"
        "T1567.002" "T1569.002" "T1571" "T1572" "T1614" "T1614.001"
    )
    
    # Filter out techniques that don't have YAML files
    local filtered_techniques=()
    for technique in "${LINUX_TECHNIQUES[@]}"; do
        if [[ -f "$ATOMICS_PATH/$technique/$technique.yaml" ]]; then
            filtered_techniques+=("$technique")
        fi
    done
    LINUX_TECHNIQUES=("${filtered_techniques[@]}")
    
    if [[ ${#LINUX_TECHNIQUES[@]} -eq 0 ]]; then
        log_error "No executable Linux techniques found"
        exit 1
    fi
    
    log_success "Found ${#LINUX_TECHNIQUES[@]} executable Linux techniques"
    echo "${LINUX_TECHNIQUES[@]}" > "$OUTPUT_DIR/results/techniques_list.txt"
    
    # Save a detailed list for debugging
    {
        echo "# Executable Linux Techniques Found:"
        for technique in "${LINUX_TECHNIQUES[@]}"; do
            echo "$technique"
        done
    } > "$OUTPUT_DIR/results/executable_techniques.txt"
}

execute_atomic_tests() {
    local success_count=0
    local failure_count=0
    local total_count=${#LINUX_TECHNIQUES[@]}
    
    log_info "Starting execution of $total_count techniques..."
    
    # Initialize results file
    echo "Technique,Status,ExecutionTime,Error" > "$OUTPUT_DIR/results/execution_results.csv"
    
    # Check if PowerShell is available before starting
    if ! command -v pwsh >/dev/null 2>&1; then
        log_error "PowerShell is not available - cannot execute tests"
        echo "0" > "$OUTPUT_DIR/results/success_count.txt"
        echo "$total_count" > "$OUTPUT_DIR/results/failure_count.txt"
        return 1
    fi
    
    local current_test=1
    for technique in "${LINUX_TECHNIQUES[@]}"; do
        log_info "Processing technique $current_test/$total_count: $technique"
        
        local start_time=$(date -Iseconds)
        local status="Success"
        local error=""
        
        # Execute via PowerShell with error handling (continue on failure)
        local pwsh_output
        pwsh_output=$(mktemp)
        
        # Use a more resilient approach - don't exit on individual test failures
        set +e  # Temporarily disable exit on error for this test
        pwsh -NoLogo -NoProfile -Command "
            try {
                Import-Module Invoke-AtomicRedTeam -Force -ErrorAction Stop
                Write-Host '  Getting prerequisites...' -NoNewline
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -GetPrereqs -Confirm:\$false -TimeoutSeconds $TIMEOUT_SECONDS -ErrorAction SilentlyContinue
                Write-Host ' OK' -ForegroundColor Green
                
                Write-Host '  Executing test...' -NoNewline  
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Confirm:\$false -TimeoutSeconds $TIMEOUT_SECONDS -ErrorAction SilentlyContinue
                Write-Host ' OK' -ForegroundColor Green
                
                Write-Host '  Cleaning up...' -NoNewline
                Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Cleanup -Confirm:\$false -ErrorAction SilentlyContinue
                Write-Host ' OK' -ForegroundColor Green
                
                exit 0
            } catch {
                Write-Host ' FAILED' -ForegroundColor Red
                Write-Warning \"Error: \$(\$_.Exception.Message)\"
                try {
                    Invoke-AtomicTest '$technique' -PathToAtomicsFolder '$ATOMICS_PATH' -Cleanup -Confirm:\$false -ErrorAction SilentlyContinue
                } catch { 
                    Write-Warning \"Cleanup also failed: \$(\$_.Exception.Message)\"
                }
                exit 2
            }
        " 2>&1 | tee "$pwsh_output"
        
        local exit_code=$?
        set -e  # Re-enable exit on error
        
        if [[ $exit_code -eq 0 ]]; then
            ((success_count++))
            log_success "Test $technique completed successfully"
        elif [[ $exit_code -eq 2 ]]; then
            status="Failed"
            error=$(tail -n 5 "$pwsh_output" | grep -E "(Error:|WARNING:)" | head -n 1 | tr '\n' ' ' | sed 's/"/\\"/g' | cut -c1-200)
            ((failure_count++))
            log_warning "Test $technique failed: $error"
        else
            status="Error"
            error="PowerShell execution error (exit code: $exit_code)"
            ((failure_count++))
            log_warning "Test $technique had execution error (exit code: $exit_code)"
        fi
        
        # Clean up temp file
        rm -f "$pwsh_output"
        
        # Log result
        echo "$technique,$status,$start_time,\"$error\"" >> "$OUTPUT_DIR/results/execution_results.csv"
        
        # Show progress
        log_info "Progress: $current_test/$total_count completed (Success: $success_count, Failed: $failure_count)"
        
        # Brief pause between tests
        sleep 2
        ((current_test++))
    done
    
    log_success "Execution complete: $success_count successful, $failure_count failed out of $total_count total"
    echo "$success_count" > "$OUTPUT_DIR/results/success_count.txt"
    echo "$failure_count" > "$OUTPUT_DIR/results/failure_count.txt"
}

collect_system_logs() {
    log_info "Collecting system logs..."
    
    # Create logs subdirectories
    mkdir -p "$OUTPUT_DIR/logs"/{var_log,journal,audit,application}
    
    # Copy /var/log directory
    log_info "  Copying /var/log..."
    if [[ -d /var/log ]]; then
        tar -czf "$OUTPUT_DIR/logs/var_log.tar.gz" /var/log 2>/dev/null || {
            log_warning "Failed to create tar of /var/log, copying individual files..."
            cp -r /var/log/* "$OUTPUT_DIR/logs/var_log/" 2>/dev/null || true
        }
    fi
    
    # Systemd journal logs (if available)
    if command -v journalctl >/dev/null 2>&1; then
        log_info "  Collecting systemd journal logs..."
        
        # Full journal export
        journalctl --no-pager -o short-iso > "$OUTPUT_DIR/logs/journal/full_journal.log" 2>/dev/null || true
        
        # Time-windowed journal (from start of execution)
        journalctl --since "$START_TIME" --no-pager -o short-iso > "$OUTPUT_DIR/logs/journal/windowed_journal.log" 2>/dev/null || true
        
        # Kernel messages
        journalctl -k --since "$START_TIME" --no-pager -o short-iso > "$OUTPUT_DIR/logs/journal/kernel_messages.log" 2>/dev/null || true
        
        # Security-related messages
        journalctl -p warning --since "$START_TIME" --no-pager -o short-iso > "$OUTPUT_DIR/logs/journal/warnings_and_errors.log" 2>/dev/null || true
        
        # Export journal in binary format for advanced analysis
        journalctl --since "$START_TIME" -o export > "$OUTPUT_DIR/logs/journal/windowed_journal.export" 2>/dev/null || true
    fi
    
    # Audit logs (if auditd is running)
    if [[ -d /var/log/audit ]]; then
        log_info "  Collecting audit logs..."
        cp -r /var/log/audit/* "$OUTPUT_DIR/logs/audit/" 2>/dev/null || true
        
        # Parse audit logs for the execution window if ausearch is available
        if command -v ausearch >/dev/null 2>&1; then
            ausearch -ts "$START_TIME" > "$OUTPUT_DIR/logs/audit/windowed_audit.log" 2>/dev/null || true
        fi
    fi
    
    # Application-specific logs
    log_info "  Collecting application logs..."
    
    # Web server logs
    for webdir in /var/log/nginx /var/log/apache2 /var/log/httpd; do
        if [[ -d "$webdir" ]]; then
            cp -r "$webdir" "$OUTPUT_DIR/logs/application/" 2>/dev/null || true
        fi
    done
    
    # Database logs
    for dbdir in /var/log/mysql /var/log/mariadb /var/log/postgresql; do
        if [[ -d "$dbdir" ]]; then
            cp -r "$dbdir" "$OUTPUT_DIR/logs/application/" 2>/dev/null || true
        fi
    done
    
    # Container logs
    for containerdir in /var/log/containers /var/log/pods; do
        if [[ -d "$containerdir" ]]; then
            cp -r "$containerdir" "$OUTPUT_DIR/logs/application/" 2>/dev/null || true
        fi
    done
    
    # Docker logs (if Docker is running)
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        docker logs --since "$START_TIME" $(docker ps -q) > "$OUTPUT_DIR/logs/application/docker_containers.log" 2>/dev/null || true
    fi
    
    # Package manager logs
    for pkglog in /var/log/apt /var/log/dnf.log /var/log/yum.log /var/log/zypper.log; do
        if [[ -e "$pkglog" ]]; then
            cp -r "$pkglog" "$OUTPUT_DIR/logs/application/" 2>/dev/null || true
        fi
    done
    
    # Additional system logs
    log_info "  Collecting additional system information..."
    
    # Current system state
    dmesg > "$OUTPUT_DIR/logs/dmesg.log" 2>/dev/null || true
    
    # Network configuration
    ip addr show > "$OUTPUT_DIR/logs/network_interfaces.log" 2>/dev/null || true
    ip route show > "$OUTPUT_DIR/logs/network_routes.log" 2>/dev/null || true
    
    # Firewall rules (if iptables/nftables available)
    if command -v iptables >/dev/null 2>&1; then
        iptables -L -n -v > "$OUTPUT_DIR/logs/iptables_rules.log" 2>/dev/null || true
    fi
    
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset > "$OUTPUT_DIR/logs/nftables_rules.log" 2>/dev/null || true
    fi
    
    # SELinux status (if available)
    if command -v sestatus >/dev/null 2>&1; then
        sestatus > "$OUTPUT_DIR/logs/selinux_status.log" 2>/dev/null || true
    fi
    
    # AppArmor status (if available)
    if command -v aa-status >/dev/null 2>&1; then
        aa-status > "$OUTPUT_DIR/logs/apparmor_status.log" 2>/dev/null || true
    fi
}

generate_report() {
    local end_time=$(date)
    local duration=$((END_EPOCH - START_EPOCH))
    local success_count=$(cat "$OUTPUT_DIR/results/success_count.txt")
    local failure_count=$(cat "$OUTPUT_DIR/results/failure_count.txt")
    local total_count=${#LINUX_TECHNIQUES[@]}
    local success_rate
    if command -v bc >/dev/null 2>&1 && [[ $total_count -gt 0 ]]; then
        success_rate=$(echo "scale=2; $success_count * 100 / $total_count" | bc -l 2>/dev/null || echo "N/A")
    else
        # Fallback calculation without bc
        if [[ $total_count -gt 0 ]]; then
            success_rate=$(( (success_count * 100) / total_count ))
        else
            success_rate="N/A"
        fi
    fi
    
    cat > "$OUTPUT_DIR/SUMMARY.txt" << EOF
=== Atomic Red Team Linux Execution Summary ===
Execution Start: $(date -d "@$START_EPOCH")
Execution End: $end_time
Duration: ${duration} seconds

Techniques Executed: $total_count
Successful: $success_count
Failed: $failure_count
Success Rate: ${success_rate}%

Output Directory: $OUTPUT_DIR
System: $(uname -a)
Distribution: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")

=== Failed Techniques ===
$(grep "Failed" "$OUTPUT_DIR/results/execution_results.csv" | cut -d',' -f1 | sed 's/^/- /')

=== Collection Summary ===
- System logs: $OUTPUT_DIR/logs/var_log.tar.gz
- Journal logs: $OUTPUT_DIR/logs/journal/
- Audit logs: $OUTPUT_DIR/logs/audit/
- Application logs: $OUTPUT_DIR/logs/application/
- System state: $OUTPUT_DIR/results/*_before.txt and *_after.txt
- Execution results: $OUTPUT_DIR/results/execution_results.csv
- Network/security configs: $OUTPUT_DIR/logs/*_rules.log, *_status.log

Use these logs for anomaly detection training and analysis.

=== Next Steps ===
1. Review failed techniques in execution_results.csv
2. Analyze time-windowed logs in journal/windowed_journal.log
3. Correlate system state changes between before/after snapshots
4. Import logs into your SIEM/analysis platform
EOF
    
    log_info "Summary report generated: $OUTPUT_DIR/SUMMARY.txt"
    cat "$OUTPUT_DIR/SUMMARY.txt"
}

# Execute main function
main "$@"
