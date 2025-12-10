# Cloudflare MCP Server

MCP (Model Context Protocol) server for managing Cloudflare DNS records and zones via Claude Code.

## Features

- **List Zones** - View all domains in your Cloudflare account
- **List DNS Records** - Browse DNS records with filtering by type and name
- **Create DNS Records** - Add A, AAAA, CNAME, MX, TXT, and other record types
- **Update DNS Records** - Modify existing records (content, TTL, proxy status)
- **Delete DNS Records** - Remove records (with confirmation)

## Installation

```bash
cd /home/x-forge/repos/cloudflare-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Authentication

Create a Cloudflare API Token at https://dash.cloudflare.com/profile/api-tokens

Required permissions:
- **Zone** → Zone → Read
- **Zone** → DNS → Edit

Set the token as an environment variable:
```bash
export CLOUDFLARE_API_TOKEN="your_token_here"
```

## Usage with Claude Code (Lazy-MCP)

Add to `~/.claude/lazy-mcp/config.json`:

```json
{
  "mcpServers": {
    "cloudflare": {
      "transportType": "stdio",
      "command": "/home/x-forge/repos/cloudflare-mcp/.venv/bin/python",
      "args": ["/home/x-forge/repos/cloudflare-mcp/cloudflare_mcp.py"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your_token_here"
      },
      "options": {
        "lazyLoad": true
      }
    }
  }
}
```

## Tools

### cloudflare_list_zones
List all zones (domains) in your Cloudflare account.

### cloudflare_get_zone
Get details for a specific zone by name or ID.

### cloudflare_list_dns_records
List DNS records for a zone. Supports filtering by type (A, MX, TXT, etc.) and name.

### cloudflare_create_dns_record
Create a new DNS record. Examples:
- A record: `type=A, name='www', content='192.168.1.1'`
- MX record: `type=MX, name='@', content='mail.example.com', priority=10`
- TXT record: `type=TXT, name='@', content='v=spf1 mx -all'`

### cloudflare_update_dns_record
Update an existing DNS record by ID.

### cloudflare_delete_dns_record
Delete a DNS record by ID (irreversible).

## Response Formats

All tools support two output formats:
- **markdown** (default) - Human-readable, formatted output
- **json** - Machine-readable structured data

## Example Usage in Claude Code

```
> List my Cloudflare zones
> Show DNS records for arcforge.au
> Create an A record for mail.arcforge.au pointing to 170.64.169.203
> Add MX record for arcforge.au pointing to mail.arcforge.au with priority 10
```
