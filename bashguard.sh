#!/bin/bash

# ============================================================
#   BashGuard: A Lightweight System Security Monitoring Tool
#   Author  : [Khushboo Banjara]
#   Version : 1.3 (Final — Production Ready)
# ============================================================

# ---------- Colors ----------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------- Config ----------
LOG_FILE="bashguard.log"
INTEGRITY_DIR="test_files"
HASH_STORE="baseline_hashes.txt"
CPU_WARN=50
CPU_HIGH=80

# Port whitelist with justification:
#   22   → SSH   (remote login)
#   80   → HTTP  (web server)
#   443  → HTTPS (secure web)
#   3306 → MySQL (database)
#   8080 → Alternate HTTP (dev/proxy server)
PORT_WHITELIST=(22 80 443 3306 8080)

# ---------- Timestamp ----------
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# ---------- Logger ----------
log_alert() {
    echo "[$(timestamp)] $1" >> "$LOG_FILE"
}

# ---------- Dependency Check ----------
# Ensures all required commands exist before the script proceeds
check_dependencies() {
    for cmd in ss sha256sum ps awk; do
        command -v "$cmd" >/dev/null 2>&1 || {
            echo -e "${RED}[ERROR]${RESET} Required command '$cmd' not found. Exiting."
            exit 1
        }
    done
}

# ---------- Log Rotation ----------
# Prevents log from growing indefinitely — keeps last 100 entries only
rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        tail -n 100 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
}

# ---------- ASCII Banner ----------
print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo " ██████╗  █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo " ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo " ██████╔╝███████║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo " ██╔══██╗██╔══██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo " ██████╔╝██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo " ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo ""
    echo "          Lightweight System Security Monitoring Tool v1.3"
    echo -e "${RESET}"
    echo -e "  Scan started at: ${BOLD}$(timestamp)${RESET}"
    echo "  ─────────────────────────────────────────────────────────────"
    echo ""
}

# ============================================================
#   MODULE 1: PROCESS MONITOR
# ============================================================
process_monitor() {
    echo -e "${BOLD}${CYAN}[ MODULE 1 — PROCESS MONITOR ]${RESET}"
    echo "  ─────────────────────────────────────────────────────────────"

    local flagged=0

    while IFS= read -r line; do
        # Single read replaces 3 separate awk calls — cleaner and faster
        read user cpu proc <<< "$line"

        # Safe CPU rounding — handles decimals and empty/malformed values
        cpu_int=$(printf "%.0f" "$cpu" 2>/dev/null)
        cpu_int=${cpu_int:-0}

        if [ "$cpu_int" -ge "$CPU_HIGH" ]; then
            echo -e "  ${RED}[HIGH]   ${RESET} $proc  (User: $user | CPU: $cpu%)"
            log_alert "HIGH - Process '$proc' by '$user' using ${cpu}% CPU"
            flagged=1
        elif [ "$cpu_int" -ge "$CPU_WARN" ]; then
            echo -e "  ${YELLOW}[MEDIUM] ${RESET} $proc  (User: $user | CPU: $cpu%)"
            log_alert "MEDIUM - Process '$proc' by '$user' using ${cpu}% CPU"
            flagged=1
        else
            echo -e "  ${GREEN}[OK]     ${RESET} $proc  (User: $user | CPU: $cpu%)"
        fi

    # Process substitution keeps loop in current shell — variables persist
    done < <(ps aux --sort=-%cpu | awk 'NR>1 && NR<=6 {printf "%s %s %s\n", $1, $3, $11}')

    [ "$flagged" -eq 0 ] && echo -e "  ${GREEN}System process load is within safe limits.${RESET}"

    echo ""
}

# ============================================================
#   MODULE 2: OPEN PORT SCANNER
# ============================================================
port_scanner() {
    echo -e "${BOLD}${CYAN}[ MODULE 2 — OPEN PORT SCANNER ]${RESET}"
    echo "  ─────────────────────────────────────────────────────────────"

    # awk -F: splits on colon and takes the last field (port number)
    # Avoids grep -oP which requires Perl regex — not portable on all systems
    open_ports=$(ss -tuln 2>/dev/null \
        | awk 'NR>1 {print $5}' \
        | awk -F: '{print $NF}' \
        | grep -E '^[0-9]+$' \
        | sort -un)

    if [ -z "$open_ports" ]; then
        echo -e "  ${YELLOW}[WARN]   ${RESET} Could not retrieve port list."
        echo ""
        return
    fi

    local flagged=0

    while IFS= read -r port; do
        is_whitelisted=0
        for wp in "${PORT_WHITELIST[@]}"; do
            [ "$port" -eq "$wp" ] && is_whitelisted=1 && break
        done

        if [ "$is_whitelisted" -eq 0 ]; then
            echo -e "  ${RED}[ALERT]  ${RESET} Port $port is OPEN and NOT in whitelist"
            log_alert "HIGH - Unexpected open port: $port"
            flagged=1
        else
            echo -e "  ${GREEN}[OK]     ${RESET} Port $port is open (whitelisted)"
        fi
    done <<< "$open_ports"

    [ "$flagged" -eq 0 ] && echo -e "  ${GREEN}All open ports are within the approved whitelist.${RESET}"

    echo ""
}

# ============================================================
#   MODULE 3: FILE INTEGRITY CHECKER
# ============================================================
file_integrity() {
    echo -e "${BOLD}${CYAN}[ MODULE 3 — FILE INTEGRITY CHECK ]${RESET}"
    echo "  ─────────────────────────────────────────────────────────────"

    # Setup: create test directory and sample files if missing
    if [ ! -d "$INTEGRITY_DIR" ]; then
        mkdir -p "$INTEGRITY_DIR"
        echo "config_value=true" > "$INTEGRITY_DIR/config.cfg"
        echo "admin:password123"  > "$INTEGRITY_DIR/credentials.txt"
        echo "#!/bin/bash"        > "$INTEGRITY_DIR/startup.sh"
        echo -e "  ${YELLOW}[INFO]   ${RESET} Test directory created: $INTEGRITY_DIR/"
    fi

    # nullglob prevents sha256sum from receiving a literal glob on empty dir
    shopt -s nullglob
    files=("$INTEGRITY_DIR"/*)

    if [ "${#files[@]}" -eq 0 ]; then
        echo -e "  ${YELLOW}[WARN]   ${RESET} No files found in $INTEGRITY_DIR/ — nothing to scan."
        shopt -u nullglob
        echo ""
        return
    fi

    # First run: generate and store baseline hashes
    if [ ! -f "$HASH_STORE" ]; then
        echo -e "  ${YELLOW}[INFO]   ${RESET} No baseline found. Creating baseline hashes..."
        # Using sha256sum for stronger integrity verification compared to md5
        sha256sum "${files[@]}" > "$HASH_STORE"
        echo -e "  ${GREEN}[OK]     ${RESET} Baseline stored in: $HASH_STORE"
        shopt -u nullglob
        echo ""
        return
    fi

    # Subsequent runs: compare current hashes against stored baseline
    local flagged=0

    while IFS= read -r entry; do
        # FIX: Single read replaces 2 awk forks — consistent with rest of script
        read stored_hash filepath <<< "$entry"
        filename=$(basename "$filepath")

        # Check if a previously tracked file was deleted
        if [ ! -f "$filepath" ]; then
            echo -e "  ${RED}[ALERT]  ${RESET} $filename — FILE DELETED"
            log_alert "HIGH - File deleted: $filepath"
            flagged=1
            continue
        fi

        # Recompute hash and compare against stored value
        current_hash=$(sha256sum "$filepath" | awk '{print $1}')
        if [ "$stored_hash" != "$current_hash" ]; then
            echo -e "  ${RED}[ALERT]  ${RESET} $filename — MODIFIED (hash mismatch)"
            log_alert "HIGH - File modified: $filepath"
            flagged=1
        else
            echo -e "  ${GREEN}[OK]     ${RESET} $filename — Integrity intact"
        fi
    done < "$HASH_STORE"

    # Detect new files added after baseline was created
    # FIX: -F (fixed string) prevents special characters in filenames
    #      from being misinterpreted as regex patterns
    for file in "${files[@]}"; do
        if ! grep -Fq "$file" "$HASH_STORE" 2>/dev/null; then
            echo -e "  ${YELLOW}[WARN]   ${RESET} $(basename "$file") — NEW FILE (not in baseline)"
            log_alert "MEDIUM - New file detected: $file"
            flagged=1
        fi
    done

    [ "$flagged" -eq 0 ] && echo -e "  ${GREEN}All monitored files are intact. No changes detected.${RESET}"

    shopt -u nullglob
    echo ""
}

# ============================================================
#   SUMMARY REPORT
# ============================================================
print_summary() {
    echo "  ─────────────────────────────────────────────────────────────"
    echo -e "${BOLD}${CYAN}[ SCAN SUMMARY ]${RESET}"
    echo "  ─────────────────────────────────────────────────────────────"

    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        alert_count=$(wc -l < "$LOG_FILE")
        high=$(grep -c "HIGH"   "$LOG_FILE" 2>/dev/null || echo 0)
        medium=$(grep -c "MEDIUM" "$LOG_FILE" 2>/dev/null || echo 0)

        echo -e "  Total Alerts Logged  : ${BOLD}$alert_count${RESET}"
        echo -e "  ${RED}HIGH   Alerts        : $high${RESET}"
        echo -e "  ${YELLOW}MEDIUM Alerts        : $medium${RESET}"
        echo ""
        echo -e "  Log saved to         : ${BOLD}$LOG_FILE${RESET}"
    else
        echo -e "  ${GREEN}No alerts triggered. System looks clean.${RESET}"
    fi

    echo "  ─────────────────────────────────────────────────────────────"
    echo -e "  Scan completed at: ${BOLD}$(timestamp)${RESET}"
    echo ""
}

# ============================================================
#   MAIN
# ============================================================
main() {
    clear
    check_dependencies   # Verify all required tools exist before running
    rotate_log           # Keep log file size under control
    print_banner
    process_monitor
    port_scanner
    file_integrity
    print_summary
}

main
