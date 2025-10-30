#!/usr/bin/env bash

# Fix Kali Linux dependencies for Atomic Red Team
# This script addresses the 404 errors and installs required packages

set -euo pipefail

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

log_info "=== Fixing Kali Linux Dependencies for Atomic Red Team ==="

# Step 1: Update package cache and fix broken packages
log_info "Updating package cache..."
apt update --fix-missing || log_warning "Some repositories may have issues"

# Step 2: Fix any broken packages
log_info "Fixing broken packages..."
apt --fix-broken install -y || log_warning "Some packages may still have issues"

# Step 3: Install essential packages individually to avoid dependency conflicts
log_info "Installing essential packages individually..."

# Core utilities needed by atomic tests
ESSENTIAL_PACKAGES=(
    "xxd"           # Hex dump utility - needed for steganography tests
    "bc"            # Calculator - needed for calculations
    "jq"            # JSON processor - needed for API tests
    "curl"          # HTTP client - needed for web tests
    "wget"          # File downloader - needed for download tests
    "git"           # Version control - needed for git-based tests
    "python3"       # Python interpreter - needed for Python tests
    "python3-pip"   # Python package manager
    "vim-common"    # Vim utilities (includes xxd alternative)
)

for package in "${ESSENTIAL_PACKAGES[@]}"; do
    log_info "Installing $package..."
    if apt install -y "$package" 2>/dev/null; then
        log_success "$package installed successfully"
    else
        log_warning "Failed to install $package via apt, trying alternative methods..."
        
        case "$package" in
            "xxd")
                # xxd is usually part of vim-common, try installing vim
                if apt install -y vim 2>/dev/null; then
                    log_success "xxd available via vim installation"
                else
                    log_warning "xxd installation failed - some tests may not work"
                fi
                ;;
            "bc")
                # bc is essential for calculations
                log_warning "bc installation failed - calculations may not work properly"
                ;;
            "jq")
                # Try installing from source if package fails
                log_info "Attempting to install jq from GitHub releases..."
                if wget -q -O /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 2>/dev/null; then
                    chmod +x /usr/local/bin/jq
                    log_success "jq installed from GitHub releases"
                else
                    log_warning "jq installation failed - JSON processing may not work"
                fi
                ;;
            *)
                log_warning "$package installation failed - some tests may not work properly"
                ;;
        esac
    fi
done

# Step 4: Verify critical tools are available
log_info "Verifying critical tools..."
CRITICAL_TOOLS=("xxd" "bc" "jq" "curl" "python3")

for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        log_success "$tool is available"
    else
        log_error "$tool is NOT available - this may cause test failures"
    fi
done

# Step 5: Install PowerShell if not present (more reliable method)
if ! command -v pwsh >/dev/null 2>&1; then
    log_info "Installing PowerShell 7..."
    
    # Download and install PowerShell manually to avoid repository issues
    PWSH_VERSION="7.3.8"
    PWSH_DEB="powershell_${PWSH_VERSION}-1.deb_amd64.deb"
    PWSH_URL="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/${PWSH_DEB}"
    
    log_info "Downloading PowerShell from GitHub..."
    if wget -q "$PWSH_URL" -O "/tmp/$PWSH_DEB"; then
        log_info "Installing PowerShell package..."
        if dpkg -i "/tmp/$PWSH_DEB" 2>/dev/null || apt --fix-broken install -y; then
            log_success "PowerShell 7 installed successfully"
        else
            log_error "PowerShell installation failed"
        fi
        rm -f "/tmp/$PWSH_DEB"
    else
        log_error "Failed to download PowerShell - please install manually"
    fi
else
    log_success "PowerShell 7 is already available"
fi

# Step 6: Install/update Invoke-AtomicRedTeam module
if command -v pwsh >/dev/null 2>&1; then
    log_info "Installing/updating Invoke-AtomicRedTeam module..."
    if pwsh -NoLogo -NoProfile -Command "
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
        log_success "Invoke-AtomicRedTeam module ready"
    else
        log_error "Failed to install/update Invoke-AtomicRedTeam module"
    fi
else
    log_error "PowerShell not available - cannot install Invoke-AtomicRedTeam"
fi

log_success "=== Dependency installation complete ==="
log_info "You can now run the linux-runner.sh script"
log_info "Usage: sudo ./linux-runner.sh"
