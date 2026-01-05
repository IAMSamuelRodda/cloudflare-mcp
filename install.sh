#!/usr/bin/env bash
# Cloudflare MCP Server - Claude Code Installation Script
# Reads from config.json and registers the MCP server with Claude Code

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
OPENBAO_ENABLED=$(jq -r '.openbao_enabled // false' "$CONFIG_FILE")

# Validate
if [[ "$OPENBAO_ENABLED" != "true" && -z "$CLOUDFLARE_TOKEN" ]]; then
    error "cloudflare_api_token required when openbao_enabled is false"
fi

# Check for Python venv
if [[ ! -d "${SCRIPT_DIR}/.venv" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "${SCRIPT_DIR}/.venv"
    info "Installing dependencies..."
    "${SCRIPT_DIR}/.venv/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"
fi

# Build claude mcp add command
MCP_NAME="cloudflare"
PYTHON_PATH="${SCRIPT_DIR}/.venv/bin/python"

if [[ "$OPENBAO_ENABLED" == "true" ]]; then
    info "Registering with OpenBao credential management..."
    claude mcp add "$MCP_NAME" -s user -- "$PYTHON_PATH" "${SCRIPT_DIR}/cloudflare_mcp.py"
else
    info "Registering with environment variable credentials..."
    claude mcp add "$MCP_NAME" -s user \
        --env "CLOUDFLARE_API_TOKEN=${CLOUDFLARE_TOKEN}" \
        --env "OPENBAO_DEV_MODE=1" \
        -- "$PYTHON_PATH" "${SCRIPT_DIR}/cloudflare_mcp.py"
fi

info "Cloudflare MCP server registered successfully!"
info "Restart Claude Code to use the new server."
