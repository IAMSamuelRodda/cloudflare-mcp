# Cloudflare MCP Servers - Deployment Guide

## Overview

Two Cloudflare MCP servers are now deployed via Lazy-MCP:

| Server | Tools | Purpose | Permissions Required |
|--------|-------|---------|---------------------|
| **cloudflare** | 6 | DNS-only management | Zone:Read, DNS:Edit |
| **cloudflare-full** | 23 | Full account management | Zone:Read, DNS:Edit, Workers:Edit, KV:Edit, Firewall:Edit, Cache:Purge, Zone Settings:Edit, Account:Read, Analytics:Read |

## Quick Start with Global API Key

**Fastest path to get everything working:**

1. **Get Global API Key**: https://dash.cloudflare.com/profile/api-tokens → View Global API Key
2. **Set environment variable**:
   ```bash
   export CLOUDFLARE_API_TOKEN_FULL="your_global_api_key_here"
   ```
3. **Restart Claude Code** and verify both servers appear with `/mcp`
4. **Later**: Use the `cloudflare_create_api_token` tool to create a scoped token and replace the Global API Key

---

## Setup Instructions

### 1. Create API Token(s)

Visit: https://dash.cloudflare.com/profile/api-tokens

**Option A: Single Token (Recommended for Testing)**
Create one token with ALL permissions and use it for both servers:
- Set both `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_API_TOKEN_FULL` to the same value

**Option B: Separate Tokens (Recommended for Production)**
- **DNS-only token**: Zone:Read + DNS:Edit → `CLOUDFLARE_API_TOKEN`
- **Full account token**: All permissions listed above → `CLOUDFLARE_API_TOKEN_FULL`

### 2. Set Environment Variables

Add to your shell RC file (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
# Option A: Single token for both servers
export CLOUDFLARE_API_TOKEN="your_token_here"
export CLOUDFLARE_API_TOKEN_FULL="your_token_here"  # Same token

# Option B: Separate tokens
export CLOUDFLARE_API_TOKEN="your_dns_only_token"
export CLOUDFLARE_API_TOKEN_FULL="your_full_account_token"
```

Then reload:
```bash
source ~/.bashrc  # or ~/.zshrc
```

### 3. Restart Claude Code

The lazy-mcp proxy loads configuration at startup:

```bash
# Exit current Claude Code session
exit

# Start new session to load updated config
claude
```

### 4. Verify Deployment

```bash
# In Claude Code, run:
/mcp

# You should see both:
# - cloudflare (6 tools) - DNS-only
# - cloudflare-full (22 tools) - Account-wide
```

## Configuration Files

### Lazy-MCP Config
`~/.claude/lazy-mcp/config.json`:
- Added `cloudflare-full` server entry (lines 120-132)
- Existing `cloudflare` server unchanged (lines 92-104)

### Hierarchy Files
`~/.claude/lazy-mcp/hierarchy/`:
- `cloudflare/` - Existing DNS-only tool definitions
- `cloudflare-full/` - New account-wide tool definitions
- `root.json` - Updated to show 10 servers, 105 tools total

## Server Capabilities

### cloudflare (DNS-only)
- `cloudflare_list_zones` - View all domains
- `cloudflare_get_zone` - Get zone details
- `cloudflare_list_dns_records` - Browse DNS records
- `cloudflare_create_dns_record` - Add A, AAAA, CNAME, MX, TXT records
- `cloudflare_update_dns_record` - Modify existing records
- `cloudflare_delete_dns_record` - Remove records

### cloudflare-full (Account-wide)

**API Token Management (1 tool)** ⭐ NEW
- `cloudflare_create_api_token` - Create scoped API tokens programmatically (use to replace Global API Key)

**Firewall & Security (3 tools)**
- `cloudflare_list_firewall_rules` - List firewall rules
- `cloudflare_create_firewall_rule` - Create custom firewall rule
- `cloudflare_delete_firewall_rule` - Remove firewall rule

**Cache Management (2 tools)**
- `cloudflare_purge_cache` - Purge by URLs, tags, hosts, prefixes, or everything
- `cloudflare_get_cache_settings` - Get cache configuration

**SSL/TLS (2 tools)**
- `cloudflare_get_ssl_settings` - Get SSL/TLS mode and certificate status
- `cloudflare_update_ssl_settings` - Change SSL mode (off/flexible/full/strict)

**Page Rules (3 tools)**
- `cloudflare_list_page_rules` - List page rules with patterns and actions
- `cloudflare_create_page_rule` - Create page rule for URL pattern
- `cloudflare_delete_page_rule` - Remove page rule

**Cloudflare Workers (4 tools)**
- `cloudflare_list_workers` - List deployed Worker scripts
- `cloudflare_get_worker` - Get Worker script source code
- `cloudflare_deploy_worker` - Deploy/update Worker script
- `cloudflare_delete_worker` - Remove Worker script

**Workers KV Storage (6 tools)**
- `cloudflare_list_kv_namespaces` - List KV namespaces
- `cloudflare_create_kv_namespace` - Create KV namespace
- `cloudflare_write_kv` - Write key-value pair
- `cloudflare_read_kv` - Read value by key
- `cloudflare_delete_kv` - Delete key
- `cloudflare_list_kv_keys` - List keys in namespace

**Account & Analytics (2 tools)**
- `cloudflare_get_account` - Get account details and settings
- `cloudflare_get_zone_analytics` - Get traffic, bandwidth, and threat stats

## Usage Examples

### DNS Management (cloudflare server)
```
> List DNS records for example.com
> Add A record for www.example.com pointing to 192.168.1.1
> Update TTL for the mail.example.com A record to 3600
```

### Firewall Rules (cloudflare-full server)
```
> List all firewall rules for example.com
> Create a firewall rule to block IP 1.2.3.4 on example.com
> Show me firewall rules and then delete the one blocking 1.2.3.4
```

### Cache Management (cloudflare-full server)
```
> Purge cache for https://example.com/blog/post1.html
> Purge all cached images tagged with "product-photos" on example.com
> Get cache settings for example.com
```

### Workers & KV (cloudflare-full server)
```
> List all Workers scripts in my account
> Deploy a Worker script named "api-router" with this code: [JavaScript]
> List KV namespaces
> Write key "user:123" with value "John Doe" to namespace abc123
> Read key "user:123" from namespace abc123
```

### SSL/TLS (cloudflare-full server)
```
> Get SSL settings for example.com
> Update SSL mode to "strict" for example.com
```

### Token Management (cloudflare-full server)
```
> Create a scoped API token named "MCP Full Access" with permissions: dns_write, workers_write, cache_purge, firewall_write, zone_settings_write for all zones
> [Copy the token value from the output]
> [Set: export CLOUDFLARE_API_TOKEN_FULL="new_token_value"]
> [Restart Claude Code]
```

## Troubleshooting

### Server Not Appearing
1. Check environment variables are set: `echo $CLOUDFLARE_API_TOKEN_FULL`
2. Verify config syntax: `cat ~/.claude/lazy-mcp/config.json | jq`
3. Restart Claude Code completely

### Permission Errors
Check your API token has required permissions at https://dash.cloudflare.com/profile/api-tokens

### Tool Execution Fails
1. Verify token is valid: Test at https://dash.cloudflare.com
2. Check token hasn't expired
3. Ensure token has permissions for the specific operation

## Security Notes

- Store API tokens as environment variables, never in code
- Use separate tokens for DNS-only vs full account access when possible
- Regularly rotate API tokens
- Review Cloudflare audit logs for API activity

## Next Steps

1. ✅ Set environment variables
2. ✅ Restart Claude Code
3. ✅ Verify both servers appear in `/mcp`
4. Test DNS operations with `cloudflare` server
5. Test account-wide operations with `cloudflare-full` server

For questions or issues, check:
- Cloudflare API Docs: https://developers.cloudflare.com/api/
- MCP Protocol: https://modelcontextprotocol.io/
