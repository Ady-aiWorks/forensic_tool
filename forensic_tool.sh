#!/usr/bin/env bash
# =============================================================================
# forensic_tool.sh — Advanced Linux Malware Forensics & Analysis Toolkit
# =============================================================================
# Version   : 2.0
# Target    : Offline Linux systems (Ubuntu, Fedora, RHEL, Debian, Arch, etc.)
# Requires  : Root privileges
# Purpose   : APT/rootkit/malware detection, quarantine, analysis, reporting
#
# Usage     : sudo ./forensic_tool.sh [MODE] [OPTIONS]
# Modes     : scan | quarantine | analyze | report | full
# Options   : -v (verbose) | -q (quiet) | -h (help) | --whitelist <file>
#             --output <dir> | --quarantine-dir <dir> | --target <path>
# =============================================================================

# Do NOT use set -e here: forensic tools must survive /proc race conditions,
# missing files, and transient errors. Each critical failure is handled explicitly.
set -uo pipefail

# ---------------------------------------------------------------------------
# GLOBAL CONSTANTS & DEFAULTS
# ---------------------------------------------------------------------------
readonly TOOL_NAME="forensic_tool"
readonly TOOL_VERSION="2.0"
readonly TOOL_START_TS="$(date +%Y%m%d_%H%M%S)"
readonly TOOL_START_EPOCH="$(date +%s)"

# Directories
DEFAULT_OUTPUT_DIR="/var/forensics"
DEFAULT_QUARANTINE_DIR="/var/quarantine"
REPORT_DIR="${DEFAULT_OUTPUT_DIR}/reports/${TOOL_START_TS}"
QUARANTINE_DIR="${DEFAULT_QUARANTINE_DIR}/${TOOL_START_TS}"
EVIDENCE_DIR="${REPORT_DIR}/evidence"
LOG_FILE=""           # set after REPORT_DIR is confirmed
WHITELIST_FILE=""

# Runtime flags
MODE="full"
VERBOSE=0
QUIET=0
DO_QUARANTINE=0
TARGET_PATH=""

# Scoring thresholds
readonly SCORE_WARN=3
readonly SCORE_HIGH=6
readonly SCORE_CRITICAL=9

# Colour codes (disabled in quiet mode)
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Associative array: path -> suspicion score (requires bash 4+)
declare -A SUSPECT_SCORES
declare -A SUSPECT_REASONS

# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local level="$1"; shift
    local msg="$*"
    local colour=""
    case "$level" in
        INFO)  colour="$CYAN"   ;;
        WARN)  colour="$YELLOW" ;;
        ERROR) colour="$RED"    ;;
        OK)    colour="$GREEN"  ;;
        *)     colour="$NC"     ;;
    esac
    [[ $QUIET -eq 1 && "$level" == "INFO" ]] && return
    printf "${colour}[%s][%s]${NC} %s\n" "$(ts)" "$level" "$msg" | tee -a "${LOG_FILE:-/dev/null}"
}

vlog() { [[ $VERBOSE -eq 1 ]] && log INFO "$*" || true; }

die() { log ERROR "$*"; exit 1; }

section() {
    local title="$1"
    local line="============================================================"
    printf "\n${BOLD}${CYAN}%s\n%s\n${NC}" "$title" "$line" | tee -a "${LOG_FILE:-/dev/null}"
}

require_root() {
    [[ $EUID -eq 0 ]] || die "This tool must be run as root (or via sudo)."
}

cmd_exists() { command -v "$1" &>/dev/null; }

safe_run() {
    # Run a command; log failure but continue
    local desc="$1"; shift
    if "$@" 2>>"${LOG_FILE}.err" ; then
        vlog "OK: $desc"
    else
        log WARN "Command failed (continuing): $desc [$*]"
    fi
}

# Add suspicion score to a path with a reason tag
add_score() {
    local path="$1"
    local score="$2"
    local reason="$3"
    SUSPECT_SCORES["$path"]=$(( ${SUSPECT_SCORES["$path"]:-0} + score ))
    SUSPECT_REASONS["$path"]+="${reason}; "
}

# Determine severity label from score
severity_label() {
    local s="$1"
    if   [[ $s -ge $SCORE_CRITICAL ]]; then echo "CRITICAL"
    elif [[ $s -ge $SCORE_HIGH ]];     then echo "HIGH"
    elif [[ $s -ge $SCORE_WARN ]];     then echo "WARN"
    else                                    echo "LOW"
    fi
}

# Check if a path is whitelisted
is_whitelisted() {
    local path="$1"
    [[ -z "$WHITELIST_FILE" || ! -f "$WHITELIST_FILE" ]] && return 1
    grep -qF "$path" "$WHITELIST_FILE" 2>/dev/null
}

# Human-readable file size
human_size() {
    local bytes="$1"
    if   [[ $bytes -ge 1073741824 ]]; then printf "%.1fG" "$(echo "$bytes 1073741824" | awk '{printf "%.1f",$1/$2}')";
    elif [[ $bytes -ge 1048576 ]];    then printf "%.1fM" "$(echo "$bytes 1048576" | awk '{printf "%.1f",$1/$2}')";
    elif [[ $bytes -ge 1024 ]];       then printf "%.1fK" "$(echo "$bytes 1024" | awk '{printf "%.1f",$1/$2}')";
    else printf "%dB" "$bytes"; fi
}

# ---------------------------------------------------------------------------
# MODULE TIMING & PROGRESS WATCHDOG
# ---------------------------------------------------------------------------

# Tracks the PID of the active heartbeat ticker (one at a time)
_HEARTBEAT_PID=""

# Call before a module: prints START banner and launches background ticker
module_start() {
    local label="$1"
    local mod_start_epoch
    mod_start_epoch=$(date +%s)
    # Store start epoch for the ticker in a temp var accessible via env
    export _MOD_START_EPOCH="$mod_start_epoch"
    export _MOD_LABEL="$label"

    printf "\n${BOLD}${CYAN}>>> STARTING: %-40s [%s]${NC}\n" \
        "$label" "$(ts)" | tee -a "${LOG_FILE:-/dev/null}"

    # Background heartbeat: prints a "still running" line every 15 seconds
    (
        while true; do
            sleep 15
            local now elapsed
            now=$(date +%s)
            elapsed=$(( now - _MOD_START_EPOCH ))
            printf "${YELLOW}    [STILL RUNNING] %-40s — %ds elapsed${NC}\n" \
                "$_MOD_LABEL" "$elapsed" >&2
        done
    ) &
    _HEARTBEAT_PID=$!
    # Ensure ticker is killed if script exits unexpectedly mid-module
    disown "$_HEARTBEAT_PID" 2>/dev/null || true
}

# Call after a module: kills ticker and prints DONE banner with elapsed time
module_end() {
    local label="$1"
    local elapsed=$(( $(date +%s) - _MOD_START_EPOCH ))

    # Kill the heartbeat ticker for this module
    if [[ -n "$_HEARTBEAT_PID" ]]; then
        kill "$_HEARTBEAT_PID" 2>/dev/null || true
        wait "$_HEARTBEAT_PID" 2>/dev/null || true
        _HEARTBEAT_PID=""
    fi

    printf "${GREEN}<<< DONE:     %-40s [%ds elapsed]${NC}\n" \
        "$label" "$elapsed" | tee -a "${LOG_FILE:-/dev/null}"
}

# Wraps a module function call with start/end timing and heartbeat
# Usage: run_module "Label" function_name [args...]
run_module() {
    local label="$1"; shift
    module_start "$label"
    "$@"
    module_end "$label"
}

# ---------------------------------------------------------------------------
# HELP MENU
# ---------------------------------------------------------------------------
show_help() {
cat <<EOF
${BOLD}${TOOL_NAME} v${TOOL_VERSION}${NC} — Advanced Linux Forensics & Malware Detection Toolkit

${BOLD}USAGE:${NC}
  sudo $0 [MODE] [OPTIONS]

${BOLD}MODES:${NC}
  scan          Perform all scanning checks (processes, filesystem, rootkits,
                network artifacts, persistence mechanisms)
  quarantine    Move flagged items to quarantine directory
  analyze       Deep analysis of flagged/target items (hashes, strings, ldd, etc.)
  report        Generate final reports and bundle archive
  full          Run all modes end-to-end (default)

${BOLD}OPTIONS:${NC}
  -v, --verbose         Verbose output (show all checks)
  -q, --quiet           Suppress informational output; show only alerts
  -h, --help            Show this help message
  --quarantine          Enable file quarantine (required to move any files)
  --whitelist <file>    Path to whitelist file (one path/pattern per line)
  --output <dir>        Output directory for reports (default: ${DEFAULT_OUTPUT_DIR})
  --quarantine-dir <d>  Quarantine base directory (default: ${DEFAULT_QUARANTINE_DIR})
  --target <path>       Limit filesystem scan to this path (file or directory)

${BOLD}EXAMPLES:${NC}
  sudo $0 full -v --quarantine
  sudo $0 scan -q --whitelist /etc/forensic_whitelist.txt
  sudo $0 analyze --target /tmp/suspicious_binary
  sudo $0 report --output /mnt/usb/forensics

${BOLD}OUTPUT:${NC}
  Reports  : <output_dir>/reports/<timestamp>/
  Evidence : <output_dir>/reports/<timestamp>/evidence/
  Bundle   : <output_dir>/reports/<timestamp>.tar.gz
  Log      : <output_dir>/reports/<timestamp>/forensic.log
  JSON     : <output_dir>/reports/<timestamp>/report.json

${BOLD}NOTES:${NC}
  • Runs non-destructively by default; use --quarantine to enable file moves
  • Requires root; tested on bash 4+
  • All temp files are cleaned on exit
EOF
}

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
parse_args() {
    # Default mode if no positional arg
    local positional_seen=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            scan|quarantine|analyze|report|full)
                MODE="$1"; positional_seen=1 ;;
            -v|--verbose)  VERBOSE=1 ;;
            -q|--quiet)    QUIET=1 ;;
            -h|--help)     show_help; exit 0 ;;
            --quarantine)  DO_QUARANTINE=1 ;;
            --whitelist)   shift; WHITELIST_FILE="$1" ;;
            --output)      shift; DEFAULT_OUTPUT_DIR="$1"
                           REPORT_DIR="${DEFAULT_OUTPUT_DIR}/reports/${TOOL_START_TS}" ;;
            --quarantine-dir) shift; DEFAULT_QUARANTINE_DIR="$1"
                           QUARANTINE_DIR="${DEFAULT_QUARANTINE_DIR}/${TOOL_START_TS}" ;;
            --target)      shift; TARGET_PATH="$1" ;;
            *)             log WARN "Unknown argument: $1" ;;
        esac
        shift
    done

    EVIDENCE_DIR="${REPORT_DIR}/evidence"
    LOG_FILE="${REPORT_DIR}/forensic.log"
}

# ---------------------------------------------------------------------------
# INITIALISATION
# ---------------------------------------------------------------------------
init() {
    require_root

    mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR"
    [[ $DO_QUARANTINE -eq 1 ]] && mkdir -p "$QUARANTINE_DIR"

    LOG_FILE="${REPORT_DIR}/forensic.log"
    touch "$LOG_FILE"

    log INFO "============================================================"
    log INFO " ${TOOL_NAME} v${TOOL_VERSION} — $(ts)"
    log INFO " Mode      : $MODE"
    log INFO " Output    : $REPORT_DIR"
    log INFO " Quarantine: $( [[ $DO_QUARANTINE -eq 1 ]] && echo "$QUARANTINE_DIR" || echo "DISABLED (pass --quarantine)" )"
    log INFO " Whitelist : ${WHITELIST_FILE:-none}"
    log INFO "============================================================"

    # Collect basic system info
    {
        echo "=== SYSTEM INFO ==="
        echo "Hostname  : $(hostname)"
        echo "Kernel    : $(uname -r)"
        echo "OS        : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
        echo "Uptime    : $(uptime)"
        echo "Date/Time : $(date)"
        echo "Tool Ver  : ${TOOL_VERSION}"
        echo ""
    } > "${REPORT_DIR}/system_info.txt"
}

# ---------------------------------------------------------------------------
# MODULE 1: PROCESS SCANNING
# ---------------------------------------------------------------------------
scan_processes() {
    section "MODULE 1: PROCESS SCANNING"
    local out="${REPORT_DIR}/processes.txt"
    local ev="${EVIDENCE_DIR}/processes"
    mkdir -p "$ev"

    log INFO "Collecting full process list..."
    ps auxf > "${out}" 2>/dev/null || ps aux > "${out}" 2>/dev/null
    ps -eo pid,ppid,user,stat,pcpu,pmem,vsz,rss,comm,args \
        --sort=-pcpu > "${REPORT_DIR}/processes_sorted.txt" 2>/dev/null || true

    # --- 1a. Hidden PID detection: compare /proc vs ps ---
    section "  1a. Hidden PID Detection"
    local proc_pids ps_pids hidden_count=0
    proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
    ps_pids=$(ps -e --no-headers -o pid | tr -d ' ' | sort -n 2>/dev/null)

    {
        echo "=== HIDDEN PID ANALYSIS ==="
        echo "PIDs visible in /proc but NOT in ps output:"
    } > "${ev}/hidden_pids.txt"

    while IFS= read -r pid; do
        # Guard: PID directory may have vanished since the snapshot
        [[ ! -d "/proc/${pid}" ]] && continue
        if ! echo "$ps_pids" | grep -qx "$pid"; then
            local cmdline=""
            cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)
            cmdline="${cmdline:0:200}"
            local exe=""
            exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || echo "UNRESOLVABLE")
            echo "  HIDDEN PID: $pid | exe: $exe | cmdline: $cmdline" | tee -a "${ev}/hidden_pids.txt"
            add_score "pid:${pid}" 8 "Hidden PID (in /proc but not ps)"
            ((hidden_count++)) || true
        fi
    done <<< "$proc_pids"

    [[ $hidden_count -gt 0 ]] && log WARN "Found $hidden_count hidden PIDs!" \
                               || log OK  "No hidden PIDs detected."

    # --- 1b. Process with deleted/unlinked executable ---
    section "  1b. Processes with Deleted Executables"
    local del_count=0
    {
        echo "=== DELETED EXECUTABLE PROCESSES ==="
    } > "${ev}/deleted_exe_procs.txt"

    for pid_dir in /proc/[0-9]*/; do
        [[ -d "$pid_dir" ]] || continue
        local pid="${pid_dir%/}"; pid="${pid##*/}"
        local exe_link="${pid_dir}exe"
        if [[ -L "$exe_link" ]]; then
            local target=""
            target=$(readlink "$exe_link" 2>/dev/null || true)
            if [[ "$target" == *"(deleted)"* ]]; then
                local comm=""
                comm=$(cat "${pid_dir}comm" 2>/dev/null || echo "unknown")
                local cmdline=""
                cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null || true)
                cmdline="${cmdline:0:200}"
                echo "PID=$pid COMM=$comm EXE=$target CMD=$cmdline" \
                    | tee -a "${ev}/deleted_exe_procs.txt"
                add_score "pid:${pid}" 7 "Running from deleted/replaced executable"
                ((del_count++)) || true
            fi
        fi
    done
    [[ $del_count -gt 0 ]] && log WARN "Found $del_count processes running deleted executables!" \
                            || log OK  "No deleted-executable processes found."

    # --- 1c. Process /proc/maps analysis: anonymous rwx regions (shellcode indicator) ---
    section "  1b. Injected Code / Anonymous RWX Memory Regions"
    local inj_count=0
    {
        echo "=== ANONYMOUS RWX MEMORY REGIONS ==="
    } > "${ev}/rwx_memory.txt"

    for pid_dir in /proc/[0-9]*/; do
        [[ -d "$pid_dir" ]] || continue
        local pid="${pid_dir%/}"; pid="${pid##*/}"
        local maps="${pid_dir}maps"
        [[ ! -r "$maps" ]] && continue
        if grep -qE '^[0-9a-f]+-[0-9a-f]+ rwxp 00000000 00:00 0 *$' "$maps" 2>/dev/null; then
            local comm=""
            comm=$(cat "${pid_dir}comm" 2>/dev/null || echo "unknown")
            echo "PID=$pid COMM=$comm has anonymous rwxp regions:" \
                | tee -a "${ev}/rwx_memory.txt"
            grep -E '^[0-9a-f]+-[0-9a-f]+ rwxp 00000000 00:00 0' "$maps" 2>/dev/null \
                | tee -a "${ev}/rwx_memory.txt" || true
            add_score "pid:${pid}" 6 "Anonymous RWX memory region (possible shellcode injection)"
            ((inj_count++)) || true
        fi
    done
    [[ $inj_count -gt 0 ]] && log WARN "Found $inj_count processes with suspicious RWX regions!" \
                            || log OK  "No anonymous RWX regions detected."

    # --- 1d. High resource usage ---
    section "  1d. High CPU/Memory Processes"
    {
        echo "=== HIGH CPU/MEMORY PROCESSES ==="
        printf "%-8s %-8s %-6s %-6s %s\n" "PID" "USER" "CPU%" "MEM%" "COMMAND"
        ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -20
    } > "${ev}/high_resource_procs.txt"
    cat "${ev}/high_resource_procs.txt" >> "$out"

    # Flag processes with >80% CPU not owned by root (heuristic)
    while IFS= read -r line; do
        local pid user cpu mem comm
        read -r pid user cpu mem comm <<< "$line"
        local cpu_int="${cpu%%.*}"
        if [[ "${cpu_int}" =~ ^[0-9]+$ ]] && [[ $cpu_int -gt 80 ]]; then
            add_score "pid:${pid}" 2 "High CPU usage (${cpu}%)"
            vlog "High CPU: PID=$pid USER=$user CPU=${cpu}% CMD=$comm"
        fi
    done < <(ps -eo pid,user,pcpu,pmem,comm --no-headers 2>/dev/null)

    # --- 1e. Processes with suspicious env (LD_PRELOAD, LD_LIBRARY_PATH) ---
    section "  1e. Processes with Suspicious Environment Variables"
    local env_count=0
    {
        echo "=== PROCESSES WITH SUSPICIOUS ENV VARS ==="
    } > "${ev}/suspicious_env.txt"

    for pid_dir in /proc/[0-9]*/; do
        [[ -d "$pid_dir" ]] || continue
        local pid="${pid_dir%/}"; pid="${pid##*/}"
        local env_file="${pid_dir}environ"
        [[ ! -r "$env_file" ]] && continue
        local env_str=""
        env_str=$(tr '\0' '\n' < "$env_file" 2>/dev/null || true)
        if echo "$env_str" | grep -qE '(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)=.+'; then
            local comm=""
            comm=$(cat "${pid_dir}comm" 2>/dev/null || echo "unknown")
            local suspicious_vars
            suspicious_vars=$(echo "$env_str" | grep -E '(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)=.+')
            echo "PID=$pid COMM=$comm VARS=$suspicious_vars" \
                | tee -a "${ev}/suspicious_env.txt"
            add_score "pid:${pid}" 5 "Suspicious env vars: $suspicious_vars"
            ((env_count++)) || true
        fi
    done
    [[ $env_count -gt 0 ]] && log WARN "Found $env_count processes with suspicious LD_ env vars!" \
                            || log OK  "No suspicious LD_ env vars found in processes."

    # --- 1f. Unusual parent-child relationships ---
    section "  1f. Anomalous Parent-Child Relationships"
    {
        echo "=== ANOMALOUS PARENT-CHILD RELATIONS ==="
        # Web servers/interpreters spawning shells
        echo "--- Shells spawned by unusual parents ---"
        ps -eo pid,ppid,comm --no-headers 2>/dev/null | while read -r pid ppid comm; do
            if [[ "$comm" =~ ^(bash|sh|dash|zsh|ksh|csh|tcsh)$ ]]; then
                local parent_comm=""
                parent_comm=$(ps -p "$ppid" -o comm --no-headers 2>/dev/null | tr -d ' ')
                if [[ "$parent_comm" =~ ^(nginx|apache2|httpd|php|python|python3|ruby|node|java|mysqld)$ ]]; then
                    echo "SUSPICIOUS: PID=$pid ($comm) spawned by PPID=$ppid ($parent_comm)"
                    add_score "pid:${pid}" 7 "Shell spawned by $parent_comm (possible RCE)"
                fi
            fi
        done
    } >> "${ev}/parent_child.txt"

    log INFO "Process scanning complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 2: FILESYSTEM SCANNING
# ---------------------------------------------------------------------------
scan_filesystem() {
    section "MODULE 2: FILESYSTEM SCANNING"
    local scan_root="${TARGET_PATH:-/}"
    local out="${REPORT_DIR}/filesystem.txt"
    local ev="${EVIDENCE_DIR}/filesystem"
    mkdir -p "$ev"

    log INFO "Scanning filesystem from: $scan_root"

    # --- 2a. Files in suspicious locations ---
    section "  2a. Suspicious Locations Scan"
    local suspicious_dirs=("/tmp" "/dev/shm" "/run/shm" "/var/tmp" "/dev/.udev"
                            "/etc/.hidden" "/root" "/home" "/var/www" "/.hidden")
    {
        echo "=== SUSPICIOUS DIRECTORY CONTENTS ==="
    } > "${ev}/suspicious_locations.txt"

    for dir in "${suspicious_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue
        local files
        files=$(find "$dir" -maxdepth 3 -type f 2>/dev/null) || continue
        while IFS= read -r f; do
            is_whitelisted "$f" && continue
            local perms owner mtime ftype
            perms=$(stat -c "%a" "$f" 2>/dev/null || echo "???")
            owner=$(stat -c "%U:%G" "$f" 2>/dev/null || echo "???")
            mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
            ftype=$(file -b "$f" 2>/dev/null | head -c 80)
            echo "FILE=$f PERMS=$perms OWNER=$owner MTIME=$mtime TYPE=$ftype" \
                >> "${ev}/suspicious_locations.txt"
            # Score: executable in /tmp or /dev/shm
            if [[ "$perms" =~ [1-7][0-9][0-9] ]] || [[ "$ftype" =~ (ELF|executable|script) ]]; then
                add_score "$f" 5 "Executable in suspicious dir $dir"
            fi
        done <<< "$files"
    done
    local slcount
    slcount=$(grep -c '^FILE=' "${ev}/suspicious_locations.txt" 2>/dev/null || echo 0)
    log INFO "Found $slcount files in suspicious locations."

    # --- 2b. Recently modified system files (last 7 days) ---
    section "  2b. Recently Modified System Files"
    {
        echo "=== RECENTLY MODIFIED SYSTEM FILES (last 7 days) ==="
    } > "${ev}/recent_modifications.txt"

    local system_dirs=("/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin"
                        "/lib" "/lib64" "/usr/lib" "/boot" "/usr/local/bin")
    for dir in "${system_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue
        find "$dir" -maxdepth 3 -type f -newer /proc/1/cmdline -mtime -7 2>/dev/null \
        | while IFS= read -r f; do
            is_whitelisted "$f" && continue
            local mtime perms owner
            mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
            perms=$(stat -c "%a" "$f" 2>/dev/null)
            owner=$(stat -c "%U:%G" "$f" 2>/dev/null)
            echo "FILE=$f MTIME=$mtime PERMS=$perms OWNER=$owner" \
                >> "${ev}/recent_modifications.txt"
            add_score "$f" 3 "System file modified in last 7 days"
        done
    done
    local rmcount
    rmcount=$(grep -c '^FILE=' "${ev}/recent_modifications.txt" 2>/dev/null || echo 0)
    [[ $rmcount -gt 0 ]] && log WARN "Found $rmcount recently modified system files!" \
                         || log OK  "No recently modified system files."

    # --- 2c. SUID/SGID files ---
    section "  2c. SUID/SGID File Audit"
    {
        echo "=== SUID/SGID FILES ==="
        find "$scan_root" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
        | while IFS= read -r f; do
            is_whitelisted "$f" && continue
            local mtime owner perms
            mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
            owner=$(stat -c "%U:%G" "$f" 2>/dev/null)
            perms=$(stat -c "%a" "$f" 2>/dev/null)
            echo "SUID/SGID: $f PERMS=$perms OWNER=$owner MTIME=$mtime"
            # Non-standard SUID binaries score higher
            if ! echo "$f" | grep -qE '^/(bin|sbin|usr/bin|usr/sbin|usr/local/bin)/'; then
                add_score "$f" 5 "SUID/SGID in non-standard path"
            else
                add_score "$f" 1 "SUID/SGID (standard path, review)"
            fi
        done
    } >> "${ev}/suid_sgid.txt"

    # --- 2d. World-writable files in system paths ---
    section "  2d. World-Writable System Files"
    {
        echo "=== WORLD-WRITABLE SYSTEM FILES ==="
        find /etc /bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib \
            -xdev -perm -0002 -type f 2>/dev/null | while IFS= read -r f; do
            is_whitelisted "$f" && continue
            echo "WORLD-WRITABLE: $f"
            add_score "$f" 6 "World-writable system file"
        done
    } >> "${ev}/world_writable.txt"

    # --- 2e. Hidden files & dot-files in unusual places ---
    section "  2e. Hidden Files in System Directories"
    {
        echo "=== HIDDEN FILES IN SYSTEM DIRS ==="
        find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var /root \
            -name '.*' -type f 2>/dev/null | while IFS= read -r f; do
            is_whitelisted "$f" && continue
            local size owner mtime
            size=$(stat -c "%s" "$f" 2>/dev/null || echo 0)
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
            echo "HIDDEN: $f SIZE=$size OWNER=$owner MTIME=$mtime"
            add_score "$f" 2 "Hidden file in system/sensitive directory"
        done
    } >> "${ev}/hidden_files.txt"

    # --- 2f. ELF binary analysis (suspicious strings) ---
    section "  2f. ELF Binary String Analysis"
    {
        echo "=== ELF BINARIES WITH SUSPICIOUS STRINGS ==="
    } > "${ev}/suspicious_elf.txt"

    local elf_count=0
    local scan_dirs=("/tmp" "/dev/shm" "/var/tmp" "/home" "/root")
    [[ -n "$TARGET_PATH" ]] && scan_dirs=("$TARGET_PATH")

    # Directories known to contain huge numbers of non-malware files — skip them
    local elf_skip_pattern='.cache|node_modules|\.local/share/Steam|\.cargo|\.rustup|\.npm|snap/|\.mozilla|\.thunderbird|__pycache__|\.git/'

    for sdir in "${scan_dirs[@]}"; do
        [[ ! -d "$sdir" ]] && continue
        log INFO "  ELF scan: $sdir (max depth 4, max size 30MB)"
        while IFS= read -r f; do
            is_whitelisted "$f" && continue
            # Skip noisy user-data directories
            echo "$f" | grep -qE "$elf_skip_pattern" && continue
            # Use file's magic bytes directly — faster than calling file(1) on every file
            local magic=""
            magic=$(file -b "$f" 2>/dev/null)
            if [[ "$magic" =~ ELF ]]; then
                # timeout 10s on strings prevents a single large binary blocking forever
                local suspicious_hits=""
                suspicious_hits=$(timeout 10 strings -n 6 "$f" 2>/dev/null | grep -iE \
                    '(connect\(|socket\(|exec[lv]|/bin/sh|/etc/passwd|wget|curl|nc |ncat|/dev/tcp|ptrace|PTRACE|dlopen|dlsym|LD_PRELOAD|chmod.*777|base64|xor|encrypt|decrypt|backdoor|rootkit|keylog|exfil|reverse.shell|netcat|SIGTRAP|prctl|mprotect)' \
                    | head -30 || true)
                if [[ -n "$suspicious_hits" ]]; then
                    {
                        echo "--- FILE: $f ---"
                        echo "TYPE: $(file -b "$f" 2>/dev/null | head -c 120)"
                        echo "SUSPICIOUS STRINGS:"
                        echo "$suspicious_hits"
                        echo ""
                    } >> "${ev}/suspicious_elf.txt"
                    add_score "$f" 6 "ELF with suspicious function strings"
                    ((elf_count++)) || true
                fi
            fi
        done < <(find "$sdir" -maxdepth 4 -type f -size +0c -size -30M 2>/dev/null)
    done
    [[ $elf_count -gt 0 ]] && log WARN "Found $elf_count ELF binaries with suspicious strings!" \
                           || log OK  "No suspicious ELF strings found in scanned dirs."

    # --- 2g. High-entropy file detection (possible encrypted/compressed payload) ---
    section "  2g. High-Entropy File Detection"
    {
        echo "=== HIGH-ENTROPY FILES (possible encrypted/packed payloads) ==="
    } > "${ev}/high_entropy.txt"

    # Pure-bash entropy estimator using character frequency
    bash_entropy() {
        local f="$1"
        local size
        size=$(stat -c "%s" "$f" 2>/dev/null || echo 0)
        [[ $size -lt 64 || $size -gt 52428800 ]] && echo "0" && return  # skip <64B or >50MB
        # Sample up to 4096 bytes, count unique byte patterns via od
        local unique_bytes total_bytes entropy_approx
        total_bytes=$(od -An -tx1 "$f" 2>/dev/null | tr -s ' ' '\n' | grep -c '[0-9a-f][0-9a-f]' || echo 1)
        unique_bytes=$(od -An -tx1 "$f" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9a-f]{2}$' | sort -u | wc -l)
        # Ratio of unique to total as proxy for entropy (0-255 range)
        echo $(( unique_bytes * 100 / 256 ))
    }

    local entropy_dirs=("/tmp" "/dev/shm" "/var/tmp" "/root" "/home")
    [[ -n "$TARGET_PATH" ]] && entropy_dirs=("$TARGET_PATH")

    # Same skip pattern as ELF scan — avoid crawling package caches, browser data, etc.
    local entropy_skip_pattern='.cache|node_modules|\.local/share/Steam|\.cargo|\.rustup|\.npm|snap/|\.mozilla|\.thunderbird|__pycache__|\.git/'

    for dir in "${entropy_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        log INFO "  Entropy scan: $dir (max depth 4, 1k–10MB)"
        find "$dir" -maxdepth 4 -type f -size +1k -size -10M 2>/dev/null | while IFS= read -r f; do
            is_whitelisted "$f" && continue
            echo "$f" | grep -qE "$entropy_skip_pattern" && continue
            # Skip known archive/binary types that are legitimately high-entropy
            local ftype=""
            ftype=$(file -b "$f" 2>/dev/null)
            [[ "$ftype" =~ (gzip|bzip2|xz|ZIP|PE32|Java|SQLite|GIF|PNG|JPEG|MP4|WebM) ]] && continue
            local ent=0
            ent=$(bash_entropy "$f")
            if [[ "$ent" -ge 85 ]]; then
                echo "HIGH-ENTROPY($ent%): $f TYPE=$ftype" >> "${ev}/high_entropy.txt"
                add_score "$f" 4 "High entropy content ($ent%) — possible encrypted/packed payload"
            fi
        done
    done

    log INFO "Filesystem scanning complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 3: ROOTKIT DETECTION
# ---------------------------------------------------------------------------
scan_rootkits() {
    section "MODULE 3: ROOTKIT DETECTION"
    local ev="${EVIDENCE_DIR}/rootkits"
    mkdir -p "$ev"

    # --- 3a. Run chkrootkit if available ---
    if cmd_exists chkrootkit; then
        section "  3a. chkrootkit"
        log INFO "Running chkrootkit..."
        chkrootkit 2>/dev/null > "${ev}/chkrootkit.txt" || true
        if grep -iE '(INFECTED|Rootkit|suspicious|WARNING)' "${ev}/chkrootkit.txt" &>/dev/null; then
            log WARN "chkrootkit found suspicious items — see ${ev}/chkrootkit.txt"
            grep -iE '(INFECTED|Rootkit|suspicious|WARNING)' "${ev}/chkrootkit.txt" \
                | while IFS= read -r line; do
                add_score "system:chkrootkit" 8 "$line"
            done
        else
            log OK "chkrootkit: no rootkits detected."
        fi
    else
        log WARN "chkrootkit not found — performing manual checks."
    fi

    # --- 3b. Run rkhunter if available ---
    if cmd_exists rkhunter; then
        section "  3b. rkhunter"
        log INFO "Running rkhunter (non-interactive)..."
        rkhunter --check --skip-keypress --report-warnings-only \
            --logfile "${ev}/rkhunter.log" 2>/dev/null || true
        rkhunter --check --skip-keypress 2>/dev/null > "${ev}/rkhunter_stdout.txt" || true
        if grep -iE '(Warning|Suspicious|Infected|Rootkit)' "${ev}/rkhunter.log" &>/dev/null; then
            log WARN "rkhunter found warnings — see ${ev}/rkhunter.log"
            add_score "system:rkhunter" 7 "rkhunter reported warnings"
        else
            log OK "rkhunter: no warnings."
        fi
    else
        log WARN "rkhunter not found — performing manual binary integrity checks."
    fi

    # --- 3c. Manual binary integrity check ---
    section "  3c. Manual Tampered Binary Detection"
    {
        echo "=== CRITICAL BINARY INTEGRITY CHECK ==="
    } > "${ev}/binary_integrity.txt"

    # Critical binaries that rootkits commonly replace
    local critical_bins=("ps" "ls" "netstat" "ss" "find" "top" "lsof" "who" "w"
                          "last" "passwd" "login" "su" "sudo" "id" "ifconfig" "ip"
                          "iptables" "uname" "hostname" "stat" "date" "df" "du")

    for bin in "${critical_bins[@]}"; do
        local binpath
        binpath=$(command -v "$bin" 2>/dev/null) || continue
        # Check if it's statically linked (rootkit replacement often is)
        local file_info
        file_info=$(file -b "$binpath" 2>/dev/null)
        local ldd_info
        ldd_info=$(ldd "$binpath" 2>/dev/null | head -5 || echo "static/N/A")
        local size mtime perms
        size=$(stat -c "%s" "$binpath" 2>/dev/null)
        mtime=$(stat -c "%y" "$binpath" 2>/dev/null | cut -d'.' -f1)
        perms=$(stat -c "%a %U:%G" "$binpath" 2>/dev/null)
        local sha256
        sha256=$(sha256sum "$binpath" 2>/dev/null | awk '{print $1}')
        printf "%-20s PATH=%-40s SHA256=%s\n  SIZE=%-10s MTIME=%s PERMS=%s\n  TYPE=%s\n\n" \
            "$bin" "$binpath" "$sha256" "$(human_size $size)" "$mtime" "$perms" "$file_info" \
            >> "${ev}/binary_integrity.txt"
        # Heuristic: if a critical binary is statically linked, it may be a rootkit replacement
        if echo "$ldd_info" | grep -qi "not a dynamic executable"; then
            local is_known_static=0
            # Known-static binaries (busybox, alpine musl)
            echo "$binpath" | grep -qE '(busybox|musl)' && is_known_static=1
            if [[ $is_known_static -eq 0 ]]; then
                log WARN "POSSIBLE ROOTKIT: $binpath is statically linked (unusual for $bin)"
                add_score "$binpath" 7 "Critical binary is statically linked — possible rootkit replacement"
            fi
        fi
    done

    # --- 3d. Kernel module audit ---
    section "  3d. Kernel Module Audit"
    {
        echo "=== LOADED KERNEL MODULES ==="
        lsmod 2>/dev/null
        echo ""
        echo "=== MODULES NOT IN /proc/modules vs lsmod COMPARISON ==="
        comm -23 \
            <(lsmod | awk 'NR>1{print $1}' | sort) \
            <(awk '{print $1}' /proc/modules | sort) \
            2>/dev/null || echo "Comparison not possible."
    } > "${ev}/kernel_modules.txt"

    # Check for suspicious module names
    lsmod 2>/dev/null | awk 'NR>1{print $1}' | while IFS= read -r mod; do
        if echo "$mod" | grep -qiE '(hide|root|kit|spy|hook|inject|shadow|stealth|ghost)'; then
            log WARN "Suspicious module name: $mod"
            add_score "module:${mod}" 9 "Kernel module name matches rootkit pattern"
        fi
    done

    # --- 3e. /proc/modules vs /sys/module discrepancy ---
    section "  3e. /proc/modules vs /sys/module Discrepancy"
    {
        echo "=== MODULES IN /proc/modules NOT IN /sys/module ==="
        comm -23 \
            <(awk '{print $1}' /proc/modules | sort) \
            <(ls /sys/module/ 2>/dev/null | sort) \
            2>/dev/null || echo "N/A"
    } >> "${ev}/kernel_modules.txt"

    # --- 3f. Check for /proc/kallsyms hooks (system call table tampering) ---
    section "  3f. System Call Table Tampering"
    if [[ -r /proc/kallsyms ]]; then
        {
            echo "=== SUSPICIOUS KALLSYMS ENTRIES ==="
            grep -iE '(sys_call_table|ftrace_ops|kprobe|hook)' /proc/kallsyms 2>/dev/null | head -40
        } > "${ev}/kallsyms_hooks.txt"
        local hook_count
        hook_count=$(grep -c 'hook\|hook_' "${ev}/kallsyms_hooks.txt" 2>/dev/null || echo 0)
        [[ $hook_count -gt 2 ]] && {
            log WARN "Unusual number of hook symbols in kallsyms: $hook_count"
            add_score "system:kallsyms" 6 "Unusual hook symbols in kallsyms"
        }
    fi

    # --- 3g. Preloaded library check ---
    section "  3g. LD_PRELOAD / Preloaded Library Audit"
    {
        echo "=== /etc/ld.so.preload ==="
        if [[ -f /etc/ld.so.preload ]]; then
            cat /etc/ld.so.preload
            log WARN "ALERT: /etc/ld.so.preload exists and is non-empty!"
            while IFS= read -r lib; do
                [[ -z "$lib" ]] && continue
                add_score "$lib" 9 "Library listed in /etc/ld.so.preload — classic rootkit mechanism"
            done < /etc/ld.so.preload
        else
            echo "Not present (normal)."
            log OK "/etc/ld.so.preload: not present."
        fi
    } >> "${ev}/ld_preload.txt"

    # --- 3h. ClamAV scan if available ---
    if cmd_exists clamscan; then
        section "  3h. ClamAV Scan"
        log INFO "Running ClamAV (this may take time)..."
        clamscan -r --quiet --infected "${TARGET_PATH:-/}" \
            --exclude-dir="^/proc" --exclude-dir="^/sys" \
            --exclude-dir="^/dev" \
            > "${ev}/clamav_results.txt" 2>&1 || true
        local clam_infected
        clam_infected=$(grep -c 'FOUND' "${ev}/clamav_results.txt" 2>/dev/null || echo 0)
        [[ $clam_infected -gt 0 ]] && {
            log WARN "ClamAV found $clam_infected infected files!"
            add_score "system:clamav" 9 "ClamAV detected $clam_infected infected files"
        } || log OK "ClamAV: no infected files found."
    fi

    log INFO "Rootkit scanning complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 4: NETWORK ARTIFACT SCANNING (Offline)
# ---------------------------------------------------------------------------
scan_network() {
    section "MODULE 4: NETWORK ARTIFACT SCANNING"
    local ev="${EVIDENCE_DIR}/network"
    mkdir -p "$ev"

    # --- 4a. Active connections (even offline, may show local/loopback C2) ---
    section "  4a. Active Network Connections"
    {
        echo "=== CURRENT NETWORK CONNECTIONS ==="
        if cmd_exists ss; then
            ss -tulpan 2>/dev/null
        elif cmd_exists netstat; then
            netstat -tulpan 2>/dev/null
        else
            echo "Neither ss nor netstat available."
            cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null
        fi
    } > "${ev}/network_connections.txt"

    # Parse /proc/net/tcp for unusual listening ports
    {
        echo "=== /proc/net/tcp RAW CONNECTIONS ==="
        cat /proc/net/tcp 2>/dev/null
        echo "=== /proc/net/tcp6 RAW CONNECTIONS ==="
        cat /proc/net/tcp6 2>/dev/null
    } >> "${ev}/network_connections.txt"

    # Flag any non-standard listening ports
    awk 'NR>1 && $4=="0A" {print $2}' /proc/net/tcp 2>/dev/null | while IFS= read -r hexport; do
        local port=$(( 16#${hexport##*:} ))
        if [[ $port -gt 1024 && $port -ne 8080 && $port -ne 8443 ]]; then
            log WARN "Non-standard listening TCP port: $port"
            add_score "network:port:${port}" 3 "Unusual listening port $port in /proc/net/tcp"
        fi
    done

    # --- 4b. Raw sockets check ---
    section "  4b. Raw Socket Detection"
    {
        echo "=== RAW SOCKETS (/proc/net/raw) ==="
        cat /proc/net/raw 2>/dev/null
        echo ""
        echo "=== RAW IPv6 SOCKETS ==="
        cat /proc/net/raw6 2>/dev/null
    } > "${ev}/raw_sockets.txt"

    local raw_count
    raw_count=$(awk 'NR>1' /proc/net/raw 2>/dev/null | wc -l)
    if [[ $raw_count -gt 0 ]]; then
        log WARN "Found $raw_count raw socket(s) — potential stealth C2 or sniffer!"
        add_score "network:raw_sockets" 7 "$raw_count raw socket(s) active — possible covert channel"
    fi

    # --- 4c. /etc/hosts suspicious entries ---
    section "  4c. /etc/hosts Audit"
    {
        echo "=== /etc/hosts ==="
        cat /etc/hosts 2>/dev/null
        echo ""
        echo "=== SUSPICIOUS ENTRIES ==="
        grep -vE '^(#|$|127\.|::1|ff0|fe80)' /etc/hosts 2>/dev/null | while IFS= read -r line; do
            echo "UNUSUAL HOST ENTRY: $line"
            add_score "network:hosts" 4 "Unusual /etc/hosts entry: $line"
        done
    } > "${ev}/etc_hosts.txt"

    # --- 4d. DNS resolver configuration ---
    section "  4d. DNS Configuration Audit"
    {
        echo "=== /etc/resolv.conf ==="
        cat /etc/resolv.conf 2>/dev/null || echo "Not found."
        echo ""
        echo "=== /etc/nsswitch.conf ==="
        cat /etc/nsswitch.conf 2>/dev/null || echo "Not found."
    } > "${ev}/dns_config.txt"

    # --- 4e. Firewall rules ---
    section "  4e. Firewall Rules (iptables/nftables)"
    {
        echo "=== IPTABLES RULES ==="
        if cmd_exists iptables; then
            iptables -L -n -v 2>/dev/null || echo "iptables: permission denied or unavailable."
            iptables -t nat -L -n -v 2>/dev/null || true
            iptables -t mangle -L -n -v 2>/dev/null || true
        fi
        echo ""
        echo "=== NFT RULES ==="
        if cmd_exists nft; then
            nft list ruleset 2>/dev/null || echo "nft: unavailable."
        fi
    } > "${ev}/firewall_rules.txt"

    # Check for port redirection / DNAT rules (C2 proxy indicator)
    if cmd_exists iptables; then
        if iptables -t nat -L -n 2>/dev/null | grep -qi 'DNAT\|REDIRECT'; then
            log WARN "NAT/REDIRECT firewall rules found — possible C2 proxy or traffic redirection!"
            add_score "network:iptables_nat" 6 "DNAT/REDIRECT rules in iptables — possible covert traffic redirection"
        fi
    fi

    # --- 4f. Scan logs for suspicious IPs ---
    section "  4f. Log-Based IP/URL Artifact Extraction"
    {
        echo "=== SUSPICIOUS IPs/URLs IN LOGS ==="
        # Well-known malicious port patterns or private IP routing out
        local log_files=("/var/log/syslog" "/var/log/auth.log" "/var/log/secure"
                          "/var/log/messages" "/var/log/daemon.log" "/var/log/kern.log"
                          "/var/log/nginx/access.log" "/var/log/apache2/access.log")
        for lf in "${log_files[@]}"; do
            [[ ! -f "$lf" ]] && continue
            echo "--- $lf ---"
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$lf" 2>/dev/null \
                | grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
                | sort -u | head -50 \
                || true
        done
    } > "${ev}/log_ip_artifacts.txt"

    # --- 4g. Network interface in promiscuous mode ---
    section "  4g. Promiscuous Mode Detection"
    {
        echo "=== NETWORK INTERFACES IN PROMISC MODE ==="
        ip link 2>/dev/null | grep -i promisc && \
            log WARN "Network interface in PROMISCUOUS mode — possible sniffer!" || \
            echo "No promiscuous interfaces found."
        cat /proc/net/dev 2>/dev/null
    } > "${ev}/promisc_check.txt"

    if ip link 2>/dev/null | grep -qi 'PROMISC'; then
        add_score "network:promisc" 8 "Network interface in promiscuous mode — active sniffer suspected"
    fi

    log INFO "Network artifact scanning complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 5: PERSISTENCE MECHANISM DETECTION
# ---------------------------------------------------------------------------
scan_persistence() {
    section "MODULE 5: PERSISTENCE MECHANISM DETECTION"
    local ev="${EVIDENCE_DIR}/persistence"
    mkdir -p "$ev"

    # --- 5a. Crontabs ---
    section "  5a. Crontab Audit"
    {
        echo "=== SYSTEM CRONTABS ==="
        for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* \
                  /etc/cron.monthly/* /etc/cron.weekly/*; do
            [[ -f "$f" ]] || continue
            echo "--- $f ---"
            cat "$f" 2>/dev/null
            echo ""
        done

        echo "=== USER CRONTABS (via /var/spool/cron) ==="
        find /var/spool/cron/ -type f 2>/dev/null | while IFS= read -r cron_f; do
            echo "--- $cron_f ---"
            cat "$cron_f" 2>/dev/null
            echo ""
        done
    } > "${ev}/crontabs.txt"

    # Flag cron entries executing from suspicious paths
    grep -hE '[^ \t]+' "${ev}/crontabs.txt" 2>/dev/null \
    | grep -vE '^(#|$)' \
    | while IFS= read -r line; do
        if echo "$line" | grep -qE '(/tmp|/dev/shm|/var/tmp|bash -i|nc |curl|wget|eval|base64|python.*-c)'; then
            log WARN "SUSPICIOUS CRON: $line"
            add_score "persistence:cron" 8 "Suspicious cron entry: $line"
        fi
    done

    # --- 5b. Systemd services & timers ---
    section "  5b. Systemd Service/Timer Audit"
    {
        echo "=== ALL SYSTEMD UNITS (enabled) ==="
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null || true
        echo ""
        echo "=== SYSTEMD UNIT FILES ==="
        find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
            -name '*.service' -o -name '*.timer' 2>/dev/null | while IFS= read -r unit; do
            echo "--- $unit ---"
            cat "$unit" 2>/dev/null
            echo ""
        done
    } > "${ev}/systemd_units.txt"

    # Flag systemd units executing from suspicious paths
    find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
        -name '*.service' 2>/dev/null | while IFS= read -r unit; do
        if grep -qE '(ExecStart|ExecStartPre).*(/tmp|/dev/shm|/var/tmp|base64|nc |python.*-c)' \
            "$unit" 2>/dev/null; then
            log WARN "SUSPICIOUS SYSTEMD UNIT: $unit"
            add_score "$unit" 9 "Systemd unit executes from suspicious path or uses obfuscation"
        fi
    done

    # --- 5c. Init scripts ---
    section "  5c. Init Scripts (/etc/rc.local, /etc/init.d)"
    {
        echo "=== /etc/rc.local ==="
        cat /etc/rc.local 2>/dev/null || echo "Not present."
        echo ""
        echo "=== /etc/init.d/ ==="
        ls -la /etc/init.d/ 2>/dev/null || echo "Not present."
    } > "${ev}/init_scripts.txt"

    if [[ -f /etc/rc.local ]]; then
        if grep -qE '(/tmp|/dev/shm|base64|eval|bash -i|nc )' /etc/rc.local 2>/dev/null; then
            log WARN "Suspicious content in /etc/rc.local!"
            add_score "/etc/rc.local" 8 "rc.local contains suspicious commands"
        fi
    fi

    # --- 5d. Shell profile backdoors ---
    section "  5d. Shell Profile Backdoor Detection"
    {
        echo "=== SHELL STARTUP FILES AUDIT ==="
        local shell_configs=(
            /etc/profile /etc/bashrc /etc/bash.bashrc
            /etc/environment /etc/profile.d/*.sh
            /root/.bashrc /root/.bash_profile /root/.profile /root/.bash_logout
            /root/.zshrc /root/.zprofile
        )
        # Add all user home directories
        while IFS=: read -r _ _ _ _ _ homedir _; do
            [[ -d "$homedir" ]] || continue
            for f in "$homedir"/.bashrc "$homedir"/.bash_profile "$homedir"/.profile \
                     "$homedir"/.zshrc "$homedir"/.bash_logout "$homedir"/.config/autostart/*; do
                [[ -f "$f" ]] && shell_configs+=("$f")
            done
        done < /etc/passwd

        for f in "${shell_configs[@]}"; do
            [[ ! -f "$f" ]] && continue
            echo "--- $f ---"
            cat "$f" 2>/dev/null
            echo ""
            # Check for backdoor patterns
            if grep -qE '(LD_PRELOAD|base64.*decode|eval.*curl|bash -i.*>&|/dev/tcp|reverse.shell|nc .*-e)' \
                "$f" 2>/dev/null; then
                log WARN "BACKDOOR in $f!"
                add_score "$f" 9 "Shell profile contains backdoor pattern"
            fi
        done
    } > "${ev}/shell_profiles.txt"

    # --- 5e. XDG autostart & desktop entries ---
    section "  5e. XDG Autostart & Desktop Entries"
    {
        echo "=== XDG AUTOSTART ENTRIES ==="
        find /etc/xdg/autostart /home \
            -name '*.desktop' 2>/dev/null | while IFS= read -r df; do
            echo "--- $df ---"
            cat "$df" 2>/dev/null
            if grep -qE '(Exec=.*(/tmp|/dev/shm|wget|curl|bash -i|nc ))' "$df" 2>/dev/null; then
                log WARN "SUSPICIOUS AUTOSTART: $df"
                add_score "$df" 7 "Suspicious desktop autostart entry"
            fi
        done
    } > "${ev}/autostart.txt"

    # --- 5f. PAM module audit ---
    section "  5f. PAM Module Audit"
    {
        echo "=== /etc/pam.d/ ==="
        ls -la /etc/pam.d/ 2>/dev/null
        echo ""
        echo "=== PAM CONFIGS WITH UNUSUAL MODULES ==="
        grep -rh 'pam_' /etc/pam.d/ 2>/dev/null | grep -vE '^(#|$)' \
            | grep -v 'pam_unix\|pam_env\|pam_deny\|pam_permit\|pam_limits\|pam_nologin\|pam_systemd\|pam_lastlog\|pam_motd\|pam_mail\|pam_selinux\|pam_keyinit' \
            | sort -u
    } > "${ev}/pam_modules.txt"

    # --- 5g. AT jobs ---
    section "  5g. AT Job Audit"
    {
        echo "=== AT JOBS ==="
        if cmd_exists atq; then
            atq 2>/dev/null || echo "atq unavailable."
        fi
        find /var/spool/at/ /var/spool/cron/atjobs/ -type f 2>/dev/null | while IFS= read -r atf; do
            echo "--- $atf ---"
            cat "$atf" 2>/dev/null
        done
    } > "${ev}/at_jobs.txt"

    # --- 5h. SSH authorized_keys audit ---
    section "  5h. SSH Authorized Keys Audit"
    {
        echo "=== SSH AUTHORIZED_KEYS ==="
        find /root /home -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null \
        | while IFS= read -r akf; do
            echo "--- $akf ---"
            cat "$akf" 2>/dev/null
            local keycount
            keycount=$(grep -c 'ssh-' "$akf" 2>/dev/null || echo 0)
            echo "Key count: $keycount"
            if [[ $keycount -gt 5 ]]; then
                add_score "$akf" 4 "Unusually high number of authorized SSH keys ($keycount)"
            fi
        done
        echo ""
        echo "=== /etc/ssh/sshd_config ==="
        cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^(#|$)'
    } > "${ev}/ssh_keys.txt"

    log INFO "Persistence scanning complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 6: DEEP ANALYSIS
# ---------------------------------------------------------------------------
analyze_suspects() {
    section "MODULE 6: DEEP ANALYSIS OF SUSPECT ITEMS"
    local ev="${EVIDENCE_DIR}/analysis"
    mkdir -p "$ev"

    if [[ ${#SUSPECT_SCORES[@]} -eq 0 ]]; then
        log INFO "No suspect items to analyze. Run 'scan' mode first."
        return
    fi

    local analyzed=0
    for item in "${!SUSPECT_SCORES[@]}"; do
        local score="${SUSPECT_SCORES[$item]}"
        local reason="${SUSPECT_REASONS[$item]}"
        local severity
        severity=$(severity_label "$score")

        # Only deep-analyze medium+ severity file-based items
        [[ $score -lt $SCORE_WARN ]] && continue
        # Skip non-file items (pid:, network:, etc.)
        [[ "$item" =~ ^(pid:|network:|module:|system:) ]] && continue
        [[ ! -f "$item" ]] && continue
        is_whitelisted "$item" && continue

        local safe_name
        safe_name=$(echo "$item" | tr '/' '_' | tr -d ' ')
        local item_ev="${ev}/${safe_name}"
        mkdir -p "$item_ev"

        log INFO "Analyzing [$severity] $item (score=$score)"
        echo "ITEM=$item SCORE=$score SEVERITY=$severity REASONS=$reason" \
            > "${item_ev}/summary.txt"

        # Hashes
        {
            echo "=== FILE HASHES ==="
            md5sum "$item" 2>/dev/null || echo "md5sum failed"
            sha256sum "$item" 2>/dev/null || echo "sha256sum failed"
            sha1sum "$item" 2>/dev/null || echo "sha1sum failed"
        } > "${item_ev}/hashes.txt"

        # File metadata
        {
            echo "=== FILE METADATA ==="
            stat "$item" 2>/dev/null
            echo ""
            echo "=== FILE TYPE ==="
            file "$item" 2>/dev/null
        } > "${item_ev}/metadata.txt"

        # Strings extraction
        {
            echo "=== EXTRACTED STRINGS (min 6 chars) ==="
            strings -n 6 "$item" 2>/dev/null | head -500
        } > "${item_ev}/strings.txt"

        # Dynamic library dependencies
        {
            echo "=== DYNAMIC DEPENDENCIES (ldd) ==="
            ldd "$item" 2>/dev/null || echo "ldd failed (static or non-ELF)"
        } > "${item_ev}/ldd.txt"

        # Hexdump (first 2KB)
        {
            echo "=== HEXDUMP (first 2048 bytes) ==="
            hexdump -C "$item" 2>/dev/null | head -128
        } > "${item_ev}/hexdump.txt"

        # objdump disassembly (first 100 instructions) if available
        if cmd_exists objdump; then
            {
                echo "=== OBJDUMP DISASSEMBLY (entry point, first 100 insns) ==="
                objdump -d -j .text --no-show-raw-insn "$item" 2>/dev/null | head -150 \
                    || echo "objdump failed."
                echo ""
                echo "=== SECTION HEADERS ==="
                objdump -h "$item" 2>/dev/null | head -40 || echo "objdump headers failed."
            } > "${item_ev}/disassembly.txt"
        fi

        # readelf if available
        if cmd_exists readelf; then
            {
                echo "=== ELF HEADERS ==="
                readelf -h "$item" 2>/dev/null || echo "Not ELF."
                echo ""
                echo "=== ELF DYNAMIC SECTION ==="
                readelf -d "$item" 2>/dev/null | head -50 || echo "No dynamic section."
                echo ""
                echo "=== ELF SYMBOLS ==="
                readelf -s "$item" 2>/dev/null | head -100 || echo "No symbols."
            } > "${item_ev}/readelf.txt"
        fi

        # strace on running PID matching this file
        if cmd_exists strace; then
            local matching_pid=""
            matching_pid=$(grep -rl "$item" /proc/*/exe 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
            if [[ -n "$matching_pid" ]]; then
                {
                    echo "=== STRACE (PID $matching_pid, 3 seconds) ==="
                    timeout 3 strace -p "$matching_pid" -e trace=network,process,file \
                        -f -s 200 2>&1 | head -200 || echo "strace failed."
                } > "${item_ev}/strace.txt"
            fi
        fi

        ((analyzed++)) || true
    done

    # Also analyze user-specified target
    if [[ -n "$TARGET_PATH" && -f "$TARGET_PATH" ]]; then
        local safe_name
        safe_name=$(echo "$TARGET_PATH" | tr '/' '_')
        local item_ev="${ev}/TARGET_${safe_name}"
        mkdir -p "$item_ev"
        log INFO "Analyzing user-specified target: $TARGET_PATH"
        {
            echo "=== HASHES ===" && sha256sum "$TARGET_PATH" 2>/dev/null
            echo "=== FILE TYPE ===" && file "$TARGET_PATH" 2>/dev/null
            echo "=== METADATA ===" && stat "$TARGET_PATH" 2>/dev/null
            echo "=== STRINGS ===" && strings -n 6 "$TARGET_PATH" 2>/dev/null | head -300
            echo "=== LDD ===" && ldd "$TARGET_PATH" 2>/dev/null || true
            echo "=== HEXDUMP ===" && hexdump -C "$TARGET_PATH" 2>/dev/null | head -128
        } > "${item_ev}/full_analysis.txt"
    fi

    log INFO "Deep analysis complete. $analyzed items analyzed. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 7: QUARANTINE
# ---------------------------------------------------------------------------
quarantine_suspects() {
    section "MODULE 7: QUARANTINE"

    if [[ $DO_QUARANTINE -ne 1 ]]; then
        log WARN "Quarantine is DISABLED. Pass --quarantine to enable file moves."
        return
    fi

    mkdir -p "$QUARANTINE_DIR"
    local qlog="${QUARANTINE_DIR}/quarantine.log"
    touch "$qlog"
    local q_count=0

    log INFO "Quarantine directory: $QUARANTINE_DIR"

    for item in "${!SUSPECT_SCORES[@]}"; do
        local score="${SUSPECT_SCORES[$item]}"
        local reason="${SUSPECT_REASONS[$item]}"

        # Only quarantine files (not PIDs/modules) above HIGH threshold
        [[ $score -lt $SCORE_HIGH ]] && continue
        [[ "$item" =~ ^(pid:|network:|module:|system:) ]] && continue
        [[ ! -f "$item" ]] && continue
        is_whitelisted "$item" && continue

        local severity
        severity=$(severity_label "$score")
        local safe_dest
        safe_dest="${QUARANTINE_DIR}/$(echo "$item" | tr '/' '_' | tr -d ' ')"

        log WARN "QUARANTINING [$severity score=$score]: $item → $safe_dest"

        # Make a copy first (preserve original for forensics)
        if cp -a "$item" "$safe_dest" 2>/dev/null; then
            # Record metadata and hash
            {
                echo "QUARANTINE RECORD"
                echo "Timestamp   : $(ts)"
                echo "Original    : $item"
                echo "Destination : $safe_dest"
                echo "Score       : $score ($severity)"
                echo "Reasons     : $reason"
                echo "SHA256      : $(sha256sum "$item" 2>/dev/null)"
                echo "Metadata    : $(stat "$item" 2>/dev/null)"
                echo "---"
            } >> "$qlog"

            # Make quarantine copy immutable (preserve evidence)
            if cmd_exists chattr; then
                chattr +i "$safe_dest" 2>/dev/null || true
            fi

            # Remove execute bit on original (neutralize without full delete)
            chmod a-x "$item" 2>/dev/null || true
            log OK "Quarantined: $item (execute bit removed from original)"
            ((q_count++)) || true
        else
            log ERROR "Failed to quarantine: $item"
        fi
    done

    log INFO "Quarantine complete. $q_count items processed."
}

# ---------------------------------------------------------------------------
# MODULE 8: REPORT GENERATION
# ---------------------------------------------------------------------------
generate_report() {
    section "MODULE 8: REPORT GENERATION"

    local txt_report="${REPORT_DIR}/report.txt"
    local json_report="${REPORT_DIR}/report.json"
    local elapsed=$(( $(date +%s) - TOOL_START_EPOCH ))

    # --- Text Report ---
    {
        echo "============================================================"
        echo " LINUX FORENSIC ANALYSIS REPORT"
        echo " Generated  : $(ts)"
        echo " Tool       : ${TOOL_NAME} v${TOOL_VERSION}"
        echo " Hostname   : $(hostname)"
        echo " Kernel     : $(uname -r)"
        echo " Mode       : ${MODE}"
        echo " Scan Time  : ${elapsed}s"
        echo "============================================================"
        echo ""

        echo "=== EXECUTIVE SUMMARY ==="
        local crit_count=0 high_count=0 warn_count=0 low_count=0
        for item in "${!SUSPECT_SCORES[@]}"; do
            local s="${SUSPECT_SCORES[$item]}"
            local sev
            sev=$(severity_label "$s")
            case "$sev" in
                CRITICAL) ((crit_count++)) || true ;;
                HIGH)     ((high_count++)) || true ;;
                WARN)     ((warn_count++)) || true ;;
                LOW)      ((low_count++)) || true ;;
            esac
        done
        echo "  CRITICAL : $crit_count items"
        echo "  HIGH     : $high_count items"
        echo "  WARN     : $warn_count items"
        echo "  LOW      : $low_count items"
        echo "  TOTAL    : ${#SUSPECT_SCORES[@]} flagged items"
        echo ""

        echo "=== FLAGGED ITEMS (sorted by score, descending) ==="
        printf "%-12s %-10s %-60s %s\n" "SEVERITY" "SCORE" "ITEM" "REASONS"
        printf "%-12s %-10s %-60s %s\n" "--------" "-----" "----" "-------"

        # Sort by score descending
        for item in "${!SUSPECT_SCORES[@]}"; do
            echo "${SUSPECT_SCORES[$item]} $item ${SUSPECT_REASONS[$item]}"
        done | sort -rn | while IFS=' ' read -r score item reasons; do
            local sev
            sev=$(severity_label "$score")
            printf "%-12s %-10s %-60s %s\n" "$sev" "$score" "$item" "$reasons"
        done
        echo ""

        echo "=== EVIDENCE DIRECTORY ==="
        echo "  $EVIDENCE_DIR"
        find "$EVIDENCE_DIR" -type f 2>/dev/null | while IFS= read -r f; do
            echo "  $f"
        done
        echo ""

        echo "=== RAW SYSTEM DATA ==="
        cat "${REPORT_DIR}/system_info.txt" 2>/dev/null
        echo ""
        echo "=== END OF REPORT ==="
    } > "$txt_report"

    # --- JSON Report ---
    {
        echo "{"
        echo "  \"report_meta\": {"
        echo "    \"tool\": \"${TOOL_NAME}\","
        echo "    \"version\": \"${TOOL_VERSION}\","
        echo "    \"timestamp\": \"$(ts)\","
        echo "    \"hostname\": \"$(hostname)\","
        echo "    \"kernel\": \"$(uname -r)\","
        echo "    \"mode\": \"${MODE}\","
        echo "    \"scan_duration_seconds\": ${elapsed}"
        echo "  },"
        echo "  \"summary\": {"
        local total="${#SUSPECT_SCORES[@]}"
        echo "    \"total_flagged\": ${total},"

        local crit=0 hi=0 wa=0 lo=0
        for item in "${!SUSPECT_SCORES[@]}"; do
            case "$(severity_label "${SUSPECT_SCORES[$item]}")" in
                CRITICAL) ((crit++)) || true ;;
                HIGH) ((hi++)) || true ;;
                WARN) ((wa++)) || true ;;
                LOW)  ((lo++)) || true ;;
            esac
        done
        echo "    \"critical\": $crit,"
        echo "    \"high\": $hi,"
        echo "    \"warn\": $wa,"
        echo "    \"low\": $lo"
        echo "  },"
        echo "  \"flagged_items\": ["

        local first=1
        for item in "${!SUSPECT_SCORES[@]}"; do
            local score="${SUSPECT_SCORES[$item]}"
            local reason="${SUSPECT_REASONS[$item]}"
            local sev
            sev=$(severity_label "$score")
            # JSON-escape basic special chars
            local item_j="${item//\"/\\\"}"
            local reason_j="${reason//\"/\\\"}"
            [[ $first -eq 0 ]] && echo "    ,"
            echo "    {"
            echo "      \"item\": \"${item_j}\","
            echo "      \"score\": ${score},"
            echo "      \"severity\": \"${sev}\","
            echo "      \"reasons\": \"${reason_j}\""
            echo -n "    }"
            first=0
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$json_report"

    log OK "Text report   : $txt_report"
    log OK "JSON report   : $json_report"

    # --- Bundle everything into tar.gz ---
    local bundle="${DEFAULT_OUTPUT_DIR}/reports/${TOOL_START_TS}.tar.gz"
    log INFO "Creating archive bundle: $bundle"
    tar -czf "$bundle" -C "${DEFAULT_OUTPUT_DIR}/reports" "${TOOL_START_TS}" 2>/dev/null \
        && log OK "Bundle created: $bundle" \
        || log WARN "Failed to create bundle."

    # --- Print summary to terminal ---
    echo ""
    section "SCAN COMPLETE — SUMMARY"
    cat "$txt_report" | grep -A 20 "EXECUTIVE SUMMARY" | head -25

    log INFO "All evidence at: $REPORT_DIR"
    log INFO "Bundle archive : $bundle"
}

# ---------------------------------------------------------------------------
# MODULE 9: MEMORY ANALYSIS
# ---------------------------------------------------------------------------
scan_memory() {
    section "MODULE 9: MEMORY ANALYSIS"
    local ev="${EVIDENCE_DIR}/memory"
    mkdir -p "$ev"

    # --- 9a. volatility3 if available ---
    if cmd_exists vol3 || cmd_exists volatility3; then
        local vcmd="vol3"; cmd_exists vol3 || vcmd="volatility3"
        log INFO "volatility3 found. Running basic plugins..."
        {
            echo "=== VOLATILITY3 PSLIST ==="
            $vcmd -f /proc/kcore linux.pslist 2>/dev/null | head -100 || echo "vol3 pslist failed."
            echo ""
            echo "=== VOLATILITY3 NETSTAT ==="
            $vcmd -f /proc/kcore linux.netstat 2>/dev/null | head -100 || echo "vol3 netstat failed."
            echo ""
            echo "=== VOLATILITY3 LSMOD ==="
            $vcmd -f /proc/kcore linux.lsmod 2>/dev/null | head -100 || echo "vol3 lsmod failed."
        } > "${ev}/volatility3.txt" 2>&1
    else
        log WARN "volatility3 not found. Performing /proc-based memory analysis."
    fi

    # --- 9b. /proc/kcore basic info ---
    {
        echo "=== /proc/kcore INFO ==="
        ls -lh /proc/kcore 2>/dev/null || echo "/proc/kcore not accessible."
        echo ""
        echo "=== /proc/iomem (memory map) ==="
        cat /proc/iomem 2>/dev/null | head -40
        echo ""
        echo "=== /proc/meminfo ==="
        cat /proc/meminfo 2>/dev/null
    } > "${ev}/memory_info.txt"

    # --- 9c. Scan each process's memory maps for patterns ---
    section "  9c. Process Memory Map Analysis"
    {
        echo "=== SUSPICIOUS MEMORY MAPPINGS ==="
    } > "${ev}/memory_maps.txt"

    for pid_dir in /proc/[0-9]*/; do
        [[ -d "$pid_dir" ]] || continue
        local pid="${pid_dir%/}"; pid="${pid##*/}"
        local maps="${pid_dir}maps"
        [[ ! -r "$maps" ]] && continue
        local comm=""
        comm=$(cat "${pid_dir}comm" 2>/dev/null || echo "unknown")

        # Look for: memory-fd backed regions (memfd_create), anonymous exec, /dev/shm backed
        local suspicious_maps=""
        suspicious_maps=$(grep -E '(/dev/shm|/tmp|memfd|anon_inode)' "$maps" 2>/dev/null \
            | grep -E '(r-xp|rwxp)' || true)
        if [[ -n "$suspicious_maps" ]]; then
            echo "PID=$pid COMM=$comm"
            echo "$suspicious_maps"
            echo ""
            add_score "pid:${pid}" 7 "Memory mapped from /dev/shm, /tmp, or memfd with exec permission"
        fi
    done >> "${ev}/memory_maps.txt"

    log INFO "Memory analysis complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# MODULE 10: USER & ACCOUNT AUDIT
# ---------------------------------------------------------------------------
scan_users() {
    section "MODULE 10: USER & ACCOUNT AUDIT"
    local ev="${EVIDENCE_DIR}/users"
    mkdir -p "$ev"

    # --- 10a. Users with UID=0 (root equivalents) ---
    {
        echo "=== USERS WITH UID=0 ==="
        awk -F: '$3==0{print}' /etc/passwd 2>/dev/null
        echo ""
        local root_equiv
        root_equiv=$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null | wc -l)
        if [[ $root_equiv -gt 1 ]]; then
            log WARN "Multiple UID=0 users found ($root_equiv)!"
            add_score "users:uid0" 9 "$root_equiv users with UID=0 (only root should have UID=0)"
        fi

        echo "=== ALL SYSTEM ACCOUNTS ==="
        cat /etc/passwd 2>/dev/null

        echo ""
        echo "=== ACCOUNTS WITH SHELL (potential interactive users) ==="
        awk -F: '$NF !~ /(nologin|false|sync|halt|shutdown)$/{print}' /etc/passwd 2>/dev/null

        echo ""
        echo "=== SUDO ACCESS (/etc/sudoers) ==="
        grep -vE '^(#|$|Defaults)' /etc/sudoers 2>/dev/null || echo "Cannot read /etc/sudoers."
        grep -rl 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while IFS= read -r f; do
            echo "NOPASSWD grant in: $f"
            grep 'NOPASSWD' "$f" 2>/dev/null
            add_score "users:sudoers:$f" 6 "NOPASSWD sudo grant in $f — possible privilege escalation persistence"
        done

        echo ""
        echo "=== PASSWD/SHADOW ANOMALIES ==="
        # Users with empty passwords
        awk -F: '$2=="" {print "EMPTY PASSWORD: "$1}' /etc/shadow 2>/dev/null || true
        # Accounts not in /etc/passwd but in /etc/shadow
        comm -23 \
            <(awk -F: '{print $1}' /etc/shadow 2>/dev/null | sort) \
            <(awk -F: '{print $1}' /etc/passwd 2>/dev/null | sort) \
            2>/dev/null | while IFS= read -r orphan; do
            echo "ORPHAN SHADOW ENTRY: $orphan"
            add_score "users:shadow:orphan" 5 "Account in /etc/shadow but not /etc/passwd: $orphan"
        done

        echo ""
        echo "=== LAST LOGINS ==="
        last 2>/dev/null | head -30 || echo "last command unavailable."
        echo ""
        echo "=== FAILED AUTH (lastb) ==="
        lastb 2>/dev/null | head -20 || echo "lastb unavailable."
    } > "${ev}/user_audit.txt"

    log INFO "User audit complete. Evidence: ${ev}/"
}

# ---------------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    # Kill any active heartbeat ticker
    if [[ -n "${_HEARTBEAT_PID:-}" ]]; then
        kill "$_HEARTBEAT_PID" 2>/dev/null || true
        wait "$_HEARTBEAT_PID" 2>/dev/null || true
    fi
    # Remove any temp files we created
    local tmp_files=()
    for f in "${tmp_files[@]}"; do
        [[ -f "$f" ]] && rm -f "$f" 2>/dev/null || true
    done
    # Ensure log error file is preserved
    [[ -f "${LOG_FILE}.err" && -s "${LOG_FILE}.err" ]] \
        && log WARN "Some errors occurred — see ${LOG_FILE}.err" \
        || rm -f "${LOG_FILE}.err" 2>/dev/null || true
    [[ $exit_code -ne 0 ]] && log ERROR "Tool exited with code $exit_code."
    exit $exit_code
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# MAIN ORCHESTRATOR
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    init

    case "$MODE" in
        scan)
            run_module "Module 1: Process Scanning"         scan_processes
            run_module "Module 2: Filesystem Scanning"      scan_filesystem
            run_module "Module 3: Rootkit Detection"        scan_rootkits
            run_module "Module 4: Network Artifacts"        scan_network
            run_module "Module 5: Persistence Mechanisms"   scan_persistence
            run_module "Module 10: User & Account Audit"    scan_users
            run_module "Module 9: Memory Analysis"          scan_memory
            ;;
        quarantine)
            # Run scan silently first to build scores
            QUIET=1
            run_module "Module 1: Process Scanning"         scan_processes
            run_module "Module 2: Filesystem Scanning"      scan_filesystem
            run_module "Module 3: Rootkit Detection"        scan_rootkits
            run_module "Module 4: Network Artifacts"        scan_network
            run_module "Module 5: Persistence Mechanisms"   scan_persistence
            run_module "Module 10: User & Account Audit"    scan_users
            QUIET=0
            run_module "Module 7: Quarantine"               quarantine_suspects
            ;;
        analyze)
            QUIET=1
            run_module "Module 1: Process Scanning"         scan_processes
            run_module "Module 2: Filesystem Scanning"      scan_filesystem
            run_module "Module 3: Rootkit Detection"        scan_rootkits
            run_module "Module 4: Network Artifacts"        scan_network
            run_module "Module 5: Persistence Mechanisms"   scan_persistence
            run_module "Module 10: User & Account Audit"    scan_users
            QUIET=0
            run_module "Module 6: Deep Analysis"            analyze_suspects
            ;;
        report)
            QUIET=1
            run_module "Module 1: Process Scanning"         scan_processes
            run_module "Module 2: Filesystem Scanning"      scan_filesystem
            run_module "Module 3: Rootkit Detection"        scan_rootkits
            run_module "Module 4: Network Artifacts"        scan_network
            run_module "Module 5: Persistence Mechanisms"   scan_persistence
            run_module "Module 10: User & Account Audit"    scan_users
            run_module "Module 9: Memory Analysis"          scan_memory
            run_module "Module 6: Deep Analysis"            analyze_suspects
            QUIET=0
            run_module "Module 8: Report Generation"        generate_report
            ;;
        full)
            run_module "Module 1: Process Scanning"         scan_processes
            run_module "Module 2: Filesystem Scanning"      scan_filesystem
            run_module "Module 3: Rootkit Detection"        scan_rootkits
            run_module "Module 4: Network Artifacts"        scan_network
            run_module "Module 5: Persistence Mechanisms"   scan_persistence
            run_module "Module 10: User & Account Audit"    scan_users
            run_module "Module 9: Memory Analysis"          scan_memory
            run_module "Module 6: Deep Analysis"            analyze_suspects
            [[ $DO_QUARANTINE -eq 1 ]] && \
                run_module "Module 7: Quarantine"           quarantine_suspects
            run_module "Module 8: Report Generation"        generate_report
            ;;
        *)
            die "Unknown mode: $MODE. Use -h for help."
            ;;
    esac

    log OK "All modules complete. Total elapsed: $(( $(date +%s) - TOOL_START_EPOCH ))s"
}

main "$@"
