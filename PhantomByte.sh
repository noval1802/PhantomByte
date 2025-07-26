#!/bin/bash

# Current timestamp in UTC
timestamp="2025-05-08 13:54:24"
timestamp_clean=$(echo "$timestamp" | tr ' :' '_-')
current_user="noval1802"

# Colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

# Icons for better visibility
INFO_ICON="[ℹ]"
WARN_ICON="[⚠]"
ERROR_ICON="[✗]"
SUCCESS_ICON="[✓]"
RUN_ICON="[►]"
SCAN_ICON="[🔍]"
VULN_ICON="[⚡]"

# Scan Configuration
QUICK_SCAN=false
TOP_PORTS="--top-ports 1000"
SCAN_TIMEOUT="30s"
MODULES="all"
DEBUG_MODE=false
VALID_OPTIONS=false

# Configuration
output_dir="phantombyte_results_${timestamp_clean}"
mkdir -p "$output_dir"
log_file="$output_dir/phantombyte.log"

# Logging function
log() {
    local message=$1
    local type=${2:-"info"}
    local time=$(date -u +"%H:%M:%S")

    case $type in
        "info")    echo -e "${BLUE}${INFO_ICON} ${time} INFO    ${message}${NC}" | tee -a "$log_file" ;;
        "warn")    echo -e "${YELLOW}${WARN_ICON} ${time} WARN    ${message}${NC}" | tee -a "$log_file" ;;
        "error")   echo -e "${RED}${ERROR_ICON} ${time} ERROR   ${message}${NC}" | tee -a "$log_file" ;;
        "success") echo -e "${GREEN}${SUCCESS_ICON} ${time} SUCCESS ${message}${NC}" | tee -a "$log_file" ;;
        "run")     echo -e "${CYAN}${RUN_ICON} ${time} RUN     ${message}${NC}" | tee -a "$log_file" ;;
        "scan")    echo -e "${PURPLE}${SCAN_ICON} ${time} SCAN    ${message}${NC}" | tee -a "$log_file" ;;
        "vuln")    echo -e "${RED}${VULN_ICON} ${time} VULN    ${message}${NC}" | tee -a "$log_file" ;;
    esac
}

# Show banner function
show_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
 ____  _                 _                 ____        _
|  _ \| |__   __ _ _ __ | |_ ___  _ __ _| __ ) _   _| |_ ___
| |_) | '_ \ / _` | '_ \| __/ _ \| '_ (_)  _ \| | | | __/ _ \
|  __/| | | | (_| | | | | || (_) | | | || |_) | |_| | ||  __/
|_|   |_| |_|\__,_|_| |_|\__\___/|_| |_||____/ \__, |\__\___|
                                                |___/
[*] Advanced Reconnaissance & Vulnerability Assessment Tool
[*] Version 1.0 - Codename: Phantom
EOF
    echo -e "${NC}\n"
}

# Help menu function
show_help() {
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  ${GREEN}./PhantomByte.sh${NC} -t <target> [options]\n"

    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${GREEN}-h, --help${NC}              Show this help message"
    echo -e "  ${GREEN}-t, --target${NC} <domain>   Specify target domain (required)"
    echo -e "  ${GREEN}-q, --quick${NC}             Perform quick scan (top 1000 ports)"
    echo -e "  ${GREEN}-m, --modules${NC} <modules> Specify modules to run (comma-separated)"
    echo -e "  ${GREEN}-d, --debug${NC}             Enable debug mode\n"

    echo -e "${BOLD}Examples:${NC}"
    echo -e "  # Full scan of a domain"
    echo -e "  ${GREEN}./PhantomByte.sh${NC} -t example.com\n"
    echo -e "  # Quick scan with specific modules"
    echo -e "  ${GREEN}./PhantomByte.sh${NC} -t example.com -q -m \"info,vuln\"\n"
    echo -e "  # Debug mode with full scan"
    echo -e "  ${GREEN}./PhantomByte.sh${NC} -t example.com -d\n"

    echo -e "${BOLD}Version:${NC} 1.0"
    echo -e "${BOLD}Author:${NC}  PhantomByte Team\n"
}

# Check if tools are installed
check_tools() {
    local tools=("subfinder" "httpx" "dirsearch" "amass" "nmap" "katana" "dalfox" "nuclei" "webdav" "naabu" "gf" "arjun" "wafw00f")
    local missing=0
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "$tool is not installed" "warn"
            missing=1
        fi
    done
    if [ $missing -eq 1 ]; then
        log "Some tools are missing. Please install them before proceeding." "error"
        exit 1
    else
        log "All required tools are available" "success"
    fi
}

# Phase 1: Reconnaissance Functions
run_reconnaissance() {
    local target=$1
    local recon_dir="$output_dir/reconnaissance"
    mkdir -p "$recon_dir"/{whois,dns,ssl,waf,subdomains}

    log "Starting Reconnaissance Phase" "run"

    # WHOIS Lookup
    log "Performing WHOIS lookup..." "scan"
    whois "$target" > "$recon_dir/whois/whois_info.txt"

    # DNS Information
    log "Gathering DNS information..." "scan"
    dig "$target" ANY +noall +answer > "$recon_dir/dns/dns_records.txt"

    # Subdomain Reconnaissance
    log "Gathering subdomains..." "scan"
    subfinder -d "$target" -all -recursive -silent | httpx -silent > "$recon_dir/subdomains/subfinder.txt"
    amass enum -passive -d "$target" 2>/dev/null | grep -v '\[' > "$recon_dir/subdomains/amass.txt"
    # httpx -l "$recon_dir/subdomains/subfinder.txt" -silent > "$recon_dir/subdomains/subfinder.txt"

    # SSL/TLS Information
    if timeout 5 bash -c "echo > /dev/tcp/$target/433" 2>/dev/null; then
        log "Checking SSL/TLS..." "scan"
        openssl s_client -connect "$target":443 </dev/null 2>/dev/null | openssl x509 -text > "$recon_dir/ssl/ssl_info.txt"
    else
        log "port 433 not open. Skipping SSL/TLS check." "warn"
    fi

    # WAF Detection
    if dig +short "$target" | grep -qE '^[0-9]+'; then
        log "Detecting WAF..." "scan"
        wafw00f "$target" -o "$recon_dir/waf/waf_detection.txt" > /dev/null 2>&1
    else
        log "Domain cannot be resolved. Skipping WAF detection." "warn"
    fi
    log "Reconnaissance phase completed" "success"
}

# Phase 2: Enumeration Functions
run_enumeration() {
    local target=$1
    local enum_dir="$output_dir/enumeration"
    mkdir -p "$enum_dir"/{subdomains,ports,directories,technology}
    log "Starting Enumeration Phase" "run"

    # Port Scanning
    log "Scanning ports..." "scan"
    if [ "$QUICK_SCAN" = true ]; then
        nmap -T4 -F "$target" -oN "$enum_dir/ports/quick_scan.txt" > /dev/null 2>&1
    else
        nmap -T4 -p- -A "$target" -oN "$enum_dir/ports/full_scan.txt" > /dev/null 2>&1
    fi

    # Directory Enumeration
    log "Enumerating directories..." "scan"
    dirsearch -u "http://$target" -o "$enum_dir/directories/dirs.txt" -e php,asp,aspx,jsp,html,txt

    # Crawling Subdomain Use Katana
    #katana -list "$recon_dir/subdomains/"subd_alive.txt \ -d 5 \ -kf all \ -jc -jsl \-hl -xhr \ -fx \ -iqp \ -td \ -ef png,jpg,jpeg,svg,woff,woff2,css,js,gif,ico,ttf,eot \ -cs 'yourdomain.com' \ -f url \ -j -o katana.txt

    # Technology Detection
    log "Detecting technologies..." "scan"
    add_http_prefix() {
    if [[ "$1" =~ ^https?:// ]]; then
        echo "$1"
    else
        echo "http://$1"
    fi
    }
    whatweb "$(add_http_prefix "$target")" > "$enum_dir/technology/tech_stack.txt"

    # HTTP Probe
    log "Probing for live hosts..." "scan"
    if [ -f "$enum_dir/subdomains/all_subdomains.txt" ]; then
        httpx -l "$enum_dir/subdomains/all_subdomains.txt" -silent -title -tech-detect -status-code \
            -o "$enum_dir/technology/live_hosts.txt"
    fi

    log "Enumeration phase completed" "success"
}

# Phase 3: Exploitation Functions
run_exploitation() {
    local target=$1
    local exploit_dir="$output_dir/exploitation"
    mkdir -p "$exploit_dir"/{vulnerabilities,xss,injection,webdav}

    log "Starting Exploitation Phase" "run"

    # Vulnerability Scanning
    log "Running vulnerability scan..." "scan"
    nuclei -u "http://$target" -o "$exploit_dir/vulnerabilities/nuclei_vulns.txt"

    # XSS Scanning
    log "Scanning for XSS Dalfox..." "scan"
    dalfox url "http://$target" -o "$exploit_dir/xss/xss_vulns.txt"

    # Parameter Discovery and Testing
    log "Discovering and testing parameters..." "scan"
    arjun -u "http://$target" -oT "$exploit_dir/injection/params.txt"

    # WebDAV Testing
    log "Testing WebDAV..." "scan"
    davtest -url "http://$target" > "$exploit_dir/webdav/webdav_test.txt"

    log "Exploitation phase completed" "success"
}

# Main function
main() {
    # Reset variables
    target=""
    VALID_OPTIONS=false

    # Show banner first
    show_banner

    # If no arguments, show help and exit
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target)
                if [ -n "$2" ]; then
                    target="$2"
                    VALID_OPTIONS=true
                    shift 2
                else
                    show_help
                    log "Target domain is required with -t option" "error"
                    exit 1
                fi
                ;;
            -q|--quick)
                QUICK_SCAN=true
                shift
                ;;
            -m|--modules)
                if [ -n "$2" ]; then
                    MODULES="$2"
                    shift 2
                else
                    show_help
                    log "Module name is required with -m option" "error"
                    exit 1
                fi
                ;;
            -d|--debug)
                DEBUG_MODE=true
                shift
                ;;
            *)
                show_help
                log "Unknown option: $1" "error"
                exit 1
                ;;
        esac
    done

    # Validate required options
    if [ "$VALID_OPTIONS" = false ]; then
        log "Target domain is required. Use -t option to specify target." "error"
        show_help
        exit 1
    fi

    # Check required tools
    check_tools

    # Start scanning process
    log "Starting full scan for $target" "run"

    # Phase 1: Reconnaissance
    run_reconnaissance "$target"

    # Phase 2: Enumeration
    run_enumeration "$target"

    # Phase 3: Exploitation
    run_exploitation "$target"

    # Generate summary
    generate_summary "$target"

    log "All phases completed successfully" "success"
    log "Results saved in: $output_dir" "info"
}
# Generate summary report
generate_summary() {
    local target=$1
    local summary_file="$output_dir/summary.txt"

    {
        echo "PhantomByte Scan Summary"
        echo "========================"
        echo "Target: $target"
        echo "Scan Date: $timestamp"
        echo "User: $current_user"
        echo
        echo "Reconnaissance Results:"
        echo "---------------------"
        echo "- WAF Detection: $(cat "$output_dir/reconnaissance/waf/waf_detection.txt" 2>/dev/null | grep "Detected" || echo "None detected")"
        echo
        echo "Enumeration Results:"
        echo "-------------------"
        echo "- Subdomains found: $(wc -l < "$output_dir/enumeration/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")"
        echo "- Open ports: $(grep "open" "$output_dir/enumeration/ports/"*"_scan.txt" 2>/dev/null | wc -l || echo "0")"
        echo
        echo "Exploitation Results:"
        echo "--------------------"
        echo "- Vulnerabilities found: $(wc -l < "$output_dir/exploitation/vulnerabilities/nuclei_vulns.txt" 2>/dev/null || echo "0")"
        echo "- XSS vulnerabilities: $(wc -l < "$output_dir/exploitation/xss/xss_vulns.txt" 2>/dev/null || echo "0")"
    } > "$summary_file"

    log "Summary report generated at $summary_file" "success"
}

# Execute main with provided arguments
main "$@"


# PhantomByte - Terminal-based Penetration Toolkit
# Copyright 2025 Noval1802
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
