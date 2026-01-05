#!/usr/bin/env bash
# Cloudflare MCP Server - Claude Code Installation Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check for jq
command -v jq >/dev/null 2>&1 || error "jq is required. Install with: sudo apt install jq"

# Check for config.json
if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f "${SCRIPT_DIR}/config.json.example" ]]; then
        info "Creating config.json from example..."
        cp "${SCRIPT_DIR}/config.json.example" "$CONFIG_FILE"
        warn "Please edit config.json with your Cloudflare API token, then re-run this script."
        warn "Create a token at: https://dash.cloudflare.com/profile/api-tokens"
        warn "Required permissions: Zone → Zone → Read, Zone → DNS → Edit"
        exit 0
    else
        error "config.json not found. Create it from config.json.example"
    fi
fi

# Parse config.json
CLOUDFLARE_TOKEN=$(jq -r '.cloudflare_api_token // ""' "$CONFIG_FILE")

# Validate
if [[ -z "$CLOUDFLARE_TOKEN" ]]; then
    error "cloudflare_api_token not configured in config.json"
fi

# Create Python venv if needed
if [[ ! -d "${SCRIPT_DIR}/.venv" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "${SCRIPT_DIR}/.venv"
    info "Installing dependencies..."
    "${SCRIPT_DIR}/.venv/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"
fi

# Register with Claude Code
MCP_NAME="cloudflare"
PYTHON_PATH="${SCRIPT_DIR}/.venv/bin/python"

info "Registering MCP server with Claude Code..."
claude mcp add "$MCP_NAME" -s user \
    --env "CLOUDFLARE_API_TOKEN=${CLOUDFLARE_TOKEN}" \
    -- "$PYTHON_PATH" "${SCRIPT_DIR}/cloudflare_mcp.py"

info "Cloudflare MCP server registered successfully!"
info "Restart Claude Code to use the new server."
