# Cloudflare MCP Server

MCP server for Cloudflare DNS management. Provides 6 tools for zones and DNS records.

## Features

- **List Zones** - View all domains in your Cloudflare account
- **List DNS Records** - Browse DNS records with filtering by type and name
- **Create DNS Records** - Add A, AAAA, CNAME, MX, TXT, and other record types
- **Update DNS Records** - Modify existing records (content, TTL, proxy status)
- **Delete DNS Records** - Remove records (with confirmation)

## Installation

### Option 1: uvx (Recommended)

Zero-install method using [uv](https://docs.astral.sh/uv/). Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/IAMSamuelRodda/cloudflare-mcp", "cloudflare-mcp"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

### Option 2: Local Clone

```bash
mkdir -p ~/.claude/mcp-servers
git clone https://github.com/IAMSamuelRodda/cloudflare-mcp.git ~/.claude/mcp-servers/cloudflare-mcp
cd ~/.claude/mcp-servers/cloudflare-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "~/.claude/mcp-servers/cloudflare-mcp/.venv/bin/python",
      "args": ["~/.claude/mcp-servers/cloudflare-mcp/cloudflare_mcp.py"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

### Get Your API Token

1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create a new token with permissions:
   - **Zone** → Zone → Read
   - **Zone** → DNS → Edit
3. Copy your token

## Updating

### uvx users

```bash
uv cache clean cloudflare-mcp
```

### Local clone users

```bash
cd ~/.claude/mcp-servers/cloudflare-mcp
git pull
source .venv/bin/activate
pip install -r requirements.txt
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
