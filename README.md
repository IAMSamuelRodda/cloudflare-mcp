# Cloudflare MCP Server

MCP (Model Context Protocol) server for managing Cloudflare DNS records and zones via Claude Code.

## Features

- **List Zones** - View all domains in your Cloudflare account
- **List DNS Records** - Browse DNS records with filtering by type and name
- **Create DNS Records** - Add A, AAAA, CNAME, MX, TXT, and other record types
- **Update DNS Records** - Modify existing records (content, TTL, proxy status)
- **Delete DNS Records** - Remove records (with confirmation)

## Quick Install (Claude Code)

```bash
# Clone the repository
git clone https://github.com/IAMSamuelRodda/cloudflare-mcp.git
cd cloudflare-mcp

# Create config from example
cp config.json.example config.json

# Edit config.json with your Cloudflare API token
# Then run the install script
./install.sh
```

The install script will:
1. Create a Python virtual environment
2. Install dependencies
3. Register the MCP server with Claude Code

## Manual Installation

### 1. Get Your Cloudflare API Token

1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create a new token with permissions:
   - **Zone** → Zone → Read
   - **Zone** → DNS → Edit
3. Copy your token

### 2. Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "/path/to/cloudflare-mcp/.venv/bin/python",
      "args": ["/path/to/cloudflare-mcp/cloudflare_mcp.py"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `cloudflare_list_zones` | List all zones (domains) in your account |
| `cloudflare_get_zone` | Get details for a specific zone |
| `cloudflare_list_dns_records` | List DNS records with filtering |
| `cloudflare_create_dns_record` | Create a new DNS record |
| `cloudflare_update_dns_record` | Update an existing record |
| `cloudflare_delete_dns_record` | Delete a DNS record |

## Usage Examples

Once configured, you can ask Claude:

- "List my Cloudflare zones"
- "Show DNS records for example.com"
- "Create an A record for mail.example.com pointing to 192.168.1.1"
- "Add MX record for example.com pointing to mail.example.com with priority 10"
- "Update the TTL of my www record to 3600"
- "Delete the old CNAME record for legacy.example.com"

## Response Formats

All tools support two output formats:
- **markdown** (default) - Human-readable, formatted output
- **json** - Machine-readable structured data

## Creating DNS Records

Examples of creating different record types:

```
# A record
type=A, name='www', content='192.168.1.1'

# MX record
type=MX, name='@', content='mail.example.com', priority=10

# TXT record (SPF)
type=TXT, name='@', content='v=spf1 mx -all'

# CNAME record
type=CNAME, name='blog', content='example.github.io'
```

## License

MIT
