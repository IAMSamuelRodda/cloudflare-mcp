#!/usr/bin/env python3
"""
Cloudflare Full Account MCP Server - Comprehensive Cloudflare Account Management.

Provides tools for account-wide Cloudflare management including firewall rules,
cache purging, SSL/TLS settings, page rules, Workers, KV storage, and analytics.

Authentication: Set CLOUDFLARE_API_TOKEN environment variable with a token that has:
- Zone:Read, DNS:Edit
- Workers Scripts:Edit, Workers KV Storage:Edit
- Firewall Services:Edit, Cache Purge
- Zone Settings:Edit, Account:Read, Account Analytics:Read
"""

import os
import json
from typing import Optional, List, Literal, Dict, Any
from enum import Enum

import httpx
from pydantic import BaseModel, Field, ConfigDict, field_validator
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("cloudflare_full")

# Constants
API_BASE_URL = "https://api.cloudflare.com/client/v4"
CHARACTER_LIMIT = 25000
DEFAULT_PER_PAGE = 50


# Enums
class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


class FirewallAction(str, Enum):
    """Firewall rule actions."""
    BLOCK = "block"
    CHALLENGE = "challenge"
    JS_CHALLENGE = "js_challenge"
    MANAGED_CHALLENGE = "managed_challenge"
    ALLOW = "allow"
    LOG = "log"
    BYPASS = "bypass"


class CachePurgeType(str, Enum):
    """Types of cache purge operations."""
    EVERYTHING = "everything"
    URLS = "urls"
    TAGS = "tags"
    HOSTS = "hosts"
    PREFIXES = "prefixes"


class SSLMode(str, Enum):
    """SSL/TLS mode options."""
    OFF = "off"
    FLEXIBLE = "flexible"
    FULL = "full"
    STRICT = "strict"


# Shared utilities
def _get_api_token() -> str:
    """Get Cloudflare API token from environment."""
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        raise ValueError(
            "CLOUDFLARE_API_TOKEN environment variable not set. "
            "Create an API token at https://dash.cloudflare.com/profile/api-tokens "
            "with comprehensive account permissions."
        )
    return token


def _get_headers() -> dict:
    """Get headers for Cloudflare API requests."""
    return {
        "Authorization": f"Bearer {_get_api_token()}",
        "Content-Type": "application/json"
    }


async def _make_request(
    method: str,
    endpoint: str,
    params: Optional[dict] = None,
    json_data: Optional[dict] = None
) -> dict:
    """Make authenticated request to Cloudflare API."""
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method,
            f"{API_BASE_URL}/{endpoint}",
            headers=_get_headers(),
            params=params,
            json=json_data,
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()


def _handle_error(e: Exception) -> str:
    """Format error messages for tool responses."""
    if isinstance(e, httpx.HTTPStatusError):
        try:
            error_data = e.response.json()
            errors = error_data.get("errors", [])
            if errors:
                error_msgs = [f"{err.get('code', 'unknown')}: {err.get('message', 'Unknown error')}" for err in errors]
                return f"Cloudflare API Error: {'; '.join(error_msgs)}"
        except Exception:
            pass

        status = e.response.status_code
        if status == 400:
            return "Error: Bad request. Check your parameters."
        elif status == 401:
            return "Error: Authentication failed. Check your CLOUDFLARE_API_TOKEN."
        elif status == 403:
            return "Error: Permission denied. Your API token may lack required permissions (Workers:Edit, Firewall:Edit, Cache:Purge, etc.)."
        elif status == 404:
            return "Error: Resource not found. Check the zone name, worker name, or resource ID."
        elif status == 409:
            return "Error: Conflict. Resource already exists or operation not allowed."
        elif status == 429:
            return "Error: Rate limit exceeded. Please wait before retrying."
        return f"Error: API request failed with status {status}"
    elif isinstance(e, httpx.TimeoutException):
        return "Error: Request timed out. Please try again."
    elif isinstance(e, ValueError):
        return f"Error: {str(e)}"
    return f"Error: {type(e).__name__}: {str(e)}"


async def _resolve_zone_id(zone: str) -> str:
    """Resolve zone name to zone ID if necessary."""
    # If it looks like a zone ID (32 hex chars), return as-is
    if len(zone) == 32 and all(c in '0123456789abcdef' for c in zone.lower()):
        return zone

    # Otherwise, look up by name
    data = await _make_request("GET", "zones", params={"name": zone})
    zones = data.get("result", [])
    if not zones:
        raise ValueError(f"Zone '{zone}' not found. Check the domain name.")
    return zones[0]["id"]


async def _get_account_id() -> str:
    """Get the first available account ID."""
    data = await _make_request("GET", "accounts")
    accounts = data.get("result", [])
    if not accounts:
        raise ValueError("No accounts found for this API token.")
    return accounts[0]["id"]


def _format_firewall_rule_markdown(rule: dict) -> str:
    """Format firewall rule as markdown."""
    lines = [
        f"### {rule.get('description', 'Unnamed Rule')}",
        f"- **ID**: `{rule['id']}`",
        f"- **Action**: {rule.get('action', 'N/A')}",
        f"- **Filter Expression**: `{rule.get('filter', {}).get('expression', 'N/A')}`",
        f"- **Paused**: {'Yes' if rule.get('paused') else 'No'}",
        f"- **Priority**: {rule.get('priority', 'Default')}"
    ]
    return "\n".join(lines)


def _format_page_rule_markdown(rule: dict) -> str:
    """Format page rule as markdown."""
    actions_str = ", ".join([f"{a['id']}: {a.get('value', 'enabled')}" for a in rule.get('actions', [])])
    lines = [
        f"### Page Rule {rule.get('priority', 'N/A')}",
        f"- **ID**: `{rule['id']}`",
        f"- **Targets**: {', '.join([t.get('constraint', {}).get('value', '') for t in rule.get('targets', [])])}",
        f"- **Actions**: {actions_str}",
        f"- **Status**: {'Active' if rule.get('status') == 'active' else 'Disabled'}"
    ]
    return "\n".join(lines)


def _format_worker_markdown(worker: dict) -> str:
    """Format worker as markdown."""
    lines = [
        f"### {worker['id']}",
        f"- **Created**: {worker.get('created_on', 'N/A')}",
        f"- **Modified**: {worker.get('modified_on', 'N/A')}",
        f"- **Size**: {len(worker.get('script', ''))} bytes"
    ]
    if worker.get('routes'):
        lines.append(f"- **Routes**: {len(worker.get('routes', []))} configured")
    return "\n".join(lines)


def _format_kv_namespace_markdown(ns: dict) -> str:
    """Format KV namespace as markdown."""
    lines = [
        f"### {ns.get('title', 'Unnamed Namespace')}",
        f"- **ID**: `{ns['id']}`",
    ]
    if ns.get('supports_url_encoding'):
        lines.append("- **URL Encoding**: Supported")
    return "\n".join(lines)


# Pydantic Input Models

# Firewall Rules
class ListFirewallRulesInput(BaseModel):
    """Input for listing firewall rules."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    page: int = Field(default=1, description="Page number", ge=1)
    per_page: int = Field(default=DEFAULT_PER_PAGE, description="Results per page", ge=1, le=100)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class CreateFirewallRuleInput(BaseModel):
    """Input for creating a firewall rule."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    action: FirewallAction = Field(..., description="Action to take (block, challenge, allow, etc.)")
    expression: str = Field(..., description="Filter expression (e.g., 'ip.src eq 1.2.3.4')", min_length=1)
    description: Optional[str] = Field(default=None, description="Rule description", max_length=500)
    paused: bool = Field(default=False, description="Whether rule is paused")
    priority: Optional[int] = Field(default=None, description="Rule priority", ge=0)


class UpdateFirewallRuleInput(BaseModel):
    """Input for updating a firewall rule."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    rule_id: str = Field(..., description="Firewall rule ID", min_length=1)
    action: Optional[FirewallAction] = Field(default=None, description="New action")
    expression: Optional[str] = Field(default=None, description="New filter expression")
    description: Optional[str] = Field(default=None, description="New description", max_length=500)
    paused: Optional[bool] = Field(default=None, description="Pause/unpause rule")
    priority: Optional[int] = Field(default=None, description="New priority", ge=0)


class DeleteFirewallRuleInput(BaseModel):
    """Input for deleting a firewall rule."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    rule_id: str = Field(..., description="Firewall rule ID to delete", min_length=1)


# Cache Management
class PurgeCacheInput(BaseModel):
    """Input for purging cache."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    purge_type: CachePurgeType = Field(..., description="Purge type (everything, urls, tags, hosts, prefixes)")
    items: Optional[List[str]] = Field(
        default=None,
        description="Items to purge (URLs, tags, hosts, or prefixes). Required for all types except 'everything'",
        max_items=500
    )

    @field_validator('items')
    @classmethod
    def validate_items(cls, v, info):
        purge_type = info.data.get('purge_type')
        if purge_type != CachePurgeType.EVERYTHING and not v:
            raise ValueError(f"Items list is required for purge_type='{purge_type}'")
        if purge_type == CachePurgeType.EVERYTHING and v:
            raise ValueError("Items list must be empty for purge_type='everything'")
        return v


class GetCacheSettingsInput(BaseModel):
    """Input for getting cache settings."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


# SSL/TLS
class GetSSLSettingsInput(BaseModel):
    """Input for getting SSL/TLS settings."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class UpdateSSLSettingsInput(BaseModel):
    """Input for updating SSL/TLS settings."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    ssl_mode: SSLMode = Field(..., description="SSL mode (off, flexible, full, strict)")


# Page Rules
class ListPageRulesInput(BaseModel):
    """Input for listing page rules."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class CreatePageRuleInput(BaseModel):
    """Input for creating a page rule."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    url_pattern: str = Field(..., description="URL pattern to match (e.g., '*example.com/images/*')", min_length=1)
    actions: List[Dict[str, Any]] = Field(..., description="List of action objects (e.g., [{'id': 'cache_level', 'value': 'cache_everything'}])")
    priority: Optional[int] = Field(default=1, description="Rule priority (1 is highest)", ge=1)
    status: str = Field(default="active", description="Rule status (active or disabled)")


class DeletePageRuleInput(BaseModel):
    """Input for deleting a page rule."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    rule_id: str = Field(..., description="Page rule ID to delete", min_length=1)


# Workers
class ListWorkersInput(BaseModel):
    """Input for listing workers."""
    model_config = ConfigDict(str_strip_whitespace=True)

    page: int = Field(default=1, description="Page number", ge=1)
    per_page: int = Field(default=DEFAULT_PER_PAGE, description="Results per page", ge=1, le=100)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class GetWorkerInput(BaseModel):
    """Input for getting a worker script."""
    model_config = ConfigDict(str_strip_whitespace=True)

    script_name: str = Field(..., description="Worker script name", min_length=1, max_length=255)


class DeployWorkerInput(BaseModel):
    """Input for deploying a worker script."""
    model_config = ConfigDict(str_strip_whitespace=True)

    script_name: str = Field(..., description="Worker script name", min_length=1, max_length=255)
    script_content: str = Field(..., description="JavaScript worker script content", min_length=1)


class DeleteWorkerInput(BaseModel):
    """Input for deleting a worker."""
    model_config = ConfigDict(str_strip_whitespace=True)

    script_name: str = Field(..., description="Worker script name to delete", min_length=1)


# Workers KV
class ListKVNamespacesInput(BaseModel):
    """Input for listing KV namespaces."""
    model_config = ConfigDict(str_strip_whitespace=True)

    page: int = Field(default=1, description="Page number", ge=1)
    per_page: int = Field(default=DEFAULT_PER_PAGE, description="Results per page", ge=1, le=100)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class CreateKVNamespaceInput(BaseModel):
    """Input for creating a KV namespace."""
    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(..., description="Namespace title", min_length=1, max_length=255)


class WriteKVInput(BaseModel):
    """Input for writing a KV pair."""
    model_config = ConfigDict(str_strip_whitespace=True)

    namespace_id: str = Field(..., description="KV namespace ID", min_length=1)
    key: str = Field(..., description="Key name", min_length=1, max_length=512)
    value: str = Field(..., description="Value to store", min_length=0)
    expiration_ttl: Optional[int] = Field(default=None, description="TTL in seconds", ge=60)


class ReadKVInput(BaseModel):
    """Input for reading a KV value."""
    model_config = ConfigDict(str_strip_whitespace=True)

    namespace_id: str = Field(..., description="KV namespace ID", min_length=1)
    key: str = Field(..., description="Key name", min_length=1, max_length=512)


class DeleteKVInput(BaseModel):
    """Input for deleting a KV key."""
    model_config = ConfigDict(str_strip_whitespace=True)

    namespace_id: str = Field(..., description="KV namespace ID", min_length=1)
    key: str = Field(..., description="Key name to delete", min_length=1, max_length=512)


class ListKVKeysInput(BaseModel):
    """Input for listing KV keys."""
    model_config = ConfigDict(str_strip_whitespace=True)

    namespace_id: str = Field(..., description="KV namespace ID", min_length=1)
    prefix: Optional[str] = Field(default=None, description="Filter keys by prefix", max_length=512)
    limit: int = Field(default=100, description="Max keys to return", ge=1, le=1000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


# Account Management
class GetAccountInput(BaseModel):
    """Input for getting account details."""
    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class GetZoneAnalyticsInput(BaseModel):
    """Input for getting zone analytics."""
    model_config = ConfigDict(str_strip_whitespace=True)

    zone: str = Field(..., description="Zone name or zone ID", min_length=1)
    since: Optional[str] = Field(default=None, description="Start time (ISO 8601 or relative like '-1440' for last 24h)")
    until: Optional[str] = Field(default=None, description="End time (ISO 8601 or relative)")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


# API Token Management
class CreateAPITokenInput(BaseModel):
    """Input for creating a Cloudflare API token."""
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., description="Token name/description", min_length=1, max_length=255)
    permissions: List[str] = Field(
        ...,
        description="Permission groups to grant (e.g., ['dns_write', 'workers_write', 'cache_purge'])",
        min_items=1
    )
    zone_resources: str = Field(
        default="all",
        description="Zone access: 'all' for all zones, or specific zone ID"
    )
    ttl_days: Optional[int] = Field(
        default=None,
        description="Token lifetime in days (default: no expiration)",
        ge=1,
        le=3650
    )


# Tool definitions

# Firewall Rules
@mcp.tool(
    name="cloudflare_list_firewall_rules",
    annotations={
        "title": "List Firewall Rules",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_list_firewall_rules(params: ListFirewallRulesInput) -> str:
    """List firewall rules with filters and IDs for management.

    Returns all configured firewall rules for a zone including action types,
    filter expressions, and rule IDs needed for updates/deletions.

    Args:
        params: ListFirewallRulesInput containing zone and pagination options

    Returns:
        List of firewall rules with expressions, actions, and management IDs
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)
        data = await _make_request(
            "GET",
            f"zones/{zone_id}/firewall/rules",
            params={"page": params.page, "per_page": params.per_page}
        )
        rules = data.get("result", [])
        result_info = data.get("result_info", {})

        if not rules:
            return f"No firewall rules found for zone '{params.zone}'."

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "zone": params.zone,
                "zone_id": zone_id,
                "rules": rules,
                "total": result_info.get("total_count", len(rules))
            }, indent=2)

        lines = [f"# Firewall Rules for {params.zone}", ""]
        lines.append(f"Showing {len(rules)} of {result_info.get('total_count', len(rules))} rules")
        lines.append("")

        for rule in rules:
            lines.append(_format_firewall_rule_markdown(rule))
            lines.append("")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_create_firewall_rule",
    annotations={
        "title": "Create Firewall Rule",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def cloudflare_create_firewall_rule(params: CreateFirewallRuleInput) -> str:
    """Create custom firewall rule with action and filter expression.

    Creates a new firewall rule to block, challenge, or allow traffic based on
    conditions like IP addresses, countries, user agents, etc.

    Args:
        params: CreateFirewallRuleInput with action, expression, and optional settings

    Returns:
        Created firewall rule details including rule ID

    Examples:
        - Block specific IP: expression='ip.src eq 1.2.3.4', action='block'
        - Challenge country: expression='ip.geoip.country eq "CN"', action='challenge'
        - Allow bot: expression='cf.bot_management.verified_bot', action='allow'
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        # First, create the filter
        filter_data = {
            "expression": params.expression,
            "description": params.description or "Auto-created filter"
        }
        filter_response = await _make_request(
            "POST",
            f"zones/{zone_id}/filters",
            json_data=[filter_data]
        )
        filter_id = filter_response.get("result", [{}])[0].get("id")

        # Then create the firewall rule
        rule_data = {
            "filter": {"id": filter_id},
            "action": params.action.value,
            "description": params.description or f"Firewall rule: {params.action.value}",
            "paused": params.paused
        }
        if params.priority is not None:
            rule_data["priority"] = params.priority

        data = await _make_request(
            "POST",
            f"zones/{zone_id}/firewall/rules",
            json_data=[rule_data]
        )
        rule = data.get("result", [{}])[0]

        return f"Firewall rule created successfully:\n\n{_format_firewall_rule_markdown(rule)}"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_delete_firewall_rule",
    annotations={
        "title": "Delete Firewall Rule",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_delete_firewall_rule(params: DeleteFirewallRuleInput) -> str:
    """Delete firewall rule. Irreversible - use list_firewall_rules first.

    Args:
        params: DeleteFirewallRuleInput with zone and rule ID

    Returns:
        Confirmation of deletion
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)
        await _make_request("DELETE", f"zones/{zone_id}/firewall/rules/{params.rule_id}")
        return f"Firewall rule `{params.rule_id}` deleted successfully from zone `{params.zone}`."

    except Exception as e:
        return _handle_error(e)


# Cache Management
@mcp.tool(
    name="cloudflare_purge_cache",
    annotations={
        "title": "Purge Cache",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def cloudflare_purge_cache(params: PurgeCacheInput) -> str:
    """Purge cache by URLs, tags, hosts, prefixes, or everything.

    Immediately invalidates cached content. Use selectively - purging everything
    can significantly impact origin server load.

    Args:
        params: PurgeCacheInput with purge type and items

    Returns:
        Confirmation of cache purge operation

    Examples:
        - Purge all: purge_type='everything'
        - Purge URLs: purge_type='urls', items=['https://example.com/page1']
        - Purge tags: purge_type='tags', items=['tag1', 'tag2']
        - Purge hosts: purge_type='hosts', items=['www.example.com']
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        if params.purge_type == CachePurgeType.EVERYTHING:
            purge_data = {"purge_everything": True}
        elif params.purge_type == CachePurgeType.URLS:
            purge_data = {"files": params.items}
        elif params.purge_type == CachePurgeType.TAGS:
            purge_data = {"tags": params.items}
        elif params.purge_type == CachePurgeType.HOSTS:
            purge_data = {"hosts": params.items}
        elif params.purge_type == CachePurgeType.PREFIXES:
            purge_data = {"prefixes": params.items}

        data = await _make_request("POST", f"zones/{zone_id}/purge_cache", json_data=purge_data)

        if data.get("success"):
            if params.purge_type == CachePurgeType.EVERYTHING:
                return f"✅ Cache purged completely for zone `{params.zone}`. All cached content invalidated."
            else:
                return f"✅ Cache purged for {len(params.items or [])} {params.purge_type.value} in zone `{params.zone}`."
        else:
            return f"Cache purge failed: {json.dumps(data)}"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_get_cache_settings",
    annotations={
        "title": "Get Cache Settings",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_get_cache_settings(params: GetCacheSettingsInput) -> str:
    """Get zone cache configuration including level and browser TTL.

    Args:
        params: GetCacheSettingsInput with zone

    Returns:
        Cache settings including cache level, browser TTL, and other options
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        # Get cache level
        cache_level_data = await _make_request("GET", f"zones/{zone_id}/settings/cache_level")
        cache_level = cache_level_data.get("result", {})

        # Get browser TTL
        browser_ttl_data = await _make_request("GET", f"zones/{zone_id}/settings/browser_cache_ttl")
        browser_ttl = browser_ttl_data.get("result", {})

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "zone": params.zone,
                "cache_level": cache_level,
                "browser_cache_ttl": browser_ttl
            }, indent=2)

        lines = [f"# Cache Settings for {params.zone}", ""]
        lines.append(f"## Cache Level")
        lines.append(f"- **Value**: {cache_level.get('value', 'N/A')}")
        lines.append(f"- **Editable**: {'Yes' if cache_level.get('editable') else 'No'}")
        lines.append("")
        lines.append(f"## Browser Cache TTL")
        lines.append(f"- **Value**: {browser_ttl.get('value', 'N/A')} seconds")
        lines.append(f"- **Editable**: {'Yes' if browser_ttl.get('editable') else 'No'}")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


# SSL/TLS
@mcp.tool(
    name="cloudflare_get_ssl_settings",
    annotations={
        "title": "Get SSL/TLS Settings",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_get_ssl_settings(params: GetSSLSettingsInput) -> str:
    """Get SSL/TLS configuration including mode and certificate status.

    Args:
        params: GetSSLSettingsInput with zone

    Returns:
        SSL/TLS settings including mode, universal SSL status, and certificate info
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        # Get SSL mode
        ssl_data = await _make_request("GET", f"zones/{zone_id}/settings/ssl")
        ssl = ssl_data.get("result", {})

        # Get Universal SSL status
        universal_ssl_data = await _make_request("GET", f"zones/{zone_id}/settings/universal_ssl")
        universal_ssl = universal_ssl_data.get("result", {})

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "zone": params.zone,
                "ssl_mode": ssl,
                "universal_ssl": universal_ssl
            }, indent=2)

        lines = [f"# SSL/TLS Settings for {params.zone}", ""]
        lines.append(f"## SSL Mode")
        lines.append(f"- **Value**: {ssl.get('value', 'N/A')}")
        lines.append("")
        lines.append(f"## Universal SSL")
        lines.append(f"- **Enabled**: {'Yes' if universal_ssl.get('value') else 'No'}")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_update_ssl_settings",
    annotations={
        "title": "Update SSL/TLS Settings",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_update_ssl_settings(params: UpdateSSLSettingsInput) -> str:
    """Modify SSL mode (off, flexible, full, strict).

    Changes how Cloudflare connects to your origin server. Use 'strict' for
    maximum security with valid certificate on origin.

    Args:
        params: UpdateSSLSettingsInput with zone and SSL mode

    Returns:
        Updated SSL/TLS settings confirmation

    SSL Modes:
        - off: No HTTPS encryption between visitors and Cloudflare
        - flexible: HTTPS between visitors and Cloudflare, HTTP to origin
        - full: HTTPS to origin, accepts self-signed certificates
        - strict: HTTPS to origin, requires valid certificate
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        data = await _make_request(
            "PATCH",
            f"zones/{zone_id}/settings/ssl",
            json_data={"value": params.ssl_mode.value}
        )

        result = data.get("result", {})
        return f"✅ SSL mode updated to '{params.ssl_mode.value}' for zone `{params.zone}`.\n\nNew value: {result.get('value', 'N/A')}"

    except Exception as e:
        return _handle_error(e)


# Page Rules
@mcp.tool(
    name="cloudflare_list_page_rules",
    annotations={
        "title": "List Page Rules",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_list_page_rules(params: ListPageRulesInput) -> str:
    """List page rules with URL patterns, actions, and IDs.

    Returns all configured page rules for a zone including URL patterns,
    actions (caching, redirects, security), and rule IDs for management.

    Args:
        params: ListPageRulesInput with zone

    Returns:
        List of page rules with patterns, actions, and management IDs
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)
        data = await _make_request("GET", f"zones/{zone_id}/pagerules")
        rules = data.get("result", [])

        if not rules:
            return f"No page rules found for zone '{params.zone}'."

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "zone": params.zone,
                "zone_id": zone_id,
                "rules": rules,
                "total": len(rules)
            }, indent=2)

        lines = [f"# Page Rules for {params.zone}", ""]
        lines.append(f"Total: {len(rules)} rules")
        lines.append("")

        for rule in sorted(rules, key=lambda r: r.get('priority', 999)):
            lines.append(_format_page_rule_markdown(rule))
            lines.append("")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_create_page_rule",
    annotations={
        "title": "Create Page Rule",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def cloudflare_create_page_rule(params: CreatePageRuleInput) -> str:
    """Create page rule for URL pattern with caching, redirects, or security actions.

    Page rules customize Cloudflare behavior for specific URL patterns. Common uses
    include cache everything, forwarding URLs, SSL enforcement, and security levels.

    Args:
        params: CreatePageRuleInput with URL pattern and actions

    Returns:
        Created page rule details including rule ID

    Example actions:
        - Cache everything: [{"id": "cache_level", "value": "cache_everything"}]
        - Force HTTPS: [{"id": "always_use_https"}]
        - Forwarding: [{"id": "forwarding_url", "value": {"url": "https://new.com", "status_code": 301}}]
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        rule_data = {
            "targets": [{"target": "url", "constraint": {"operator": "matches", "value": params.url_pattern}}],
            "actions": params.actions,
            "priority": params.priority,
            "status": params.status
        }

        data = await _make_request("POST", f"zones/{zone_id}/pagerules", json_data=rule_data)
        rule = data.get("result", {})

        return f"✅ Page rule created successfully:\n\n{_format_page_rule_markdown(rule)}"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_delete_page_rule",
    annotations={
        "title": "Delete Page Rule",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_delete_page_rule(params: DeletePageRuleInput) -> str:
    """Delete page rule. Irreversible - use list_page_rules first.

    Args:
        params: DeletePageRuleInput with zone and rule ID

    Returns:
        Confirmation of deletion
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)
        await _make_request("DELETE", f"zones/{zone_id}/pagerules/{params.rule_id}")
        return f"✅ Page rule `{params.rule_id}` deleted successfully from zone `{params.zone}`."

    except Exception as e:
        return _handle_error(e)


# Workers
@mcp.tool(
    name="cloudflare_list_workers",
    annotations={
        "title": "List Workers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_list_workers(params: ListWorkersInput) -> str:
    """List deployed Workers scripts with IDs and metadata.

    Returns all deployed Workers scripts in the account including script names,
    creation dates, and route configurations.

    Args:
        params: ListWorkersInput with pagination options

    Returns:
        List of Workers scripts with names and deployment info
    """
    try:
        account_id = await _get_account_id()
        data = await _make_request(
            "GET",
            f"accounts/{account_id}/workers/scripts",
            params={"page": params.page, "per_page": params.per_page}
        )
        workers = data.get("result", [])

        if not workers:
            return "No Workers scripts found in this account."

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"workers": workers, "total": len(workers)}, indent=2)

        lines = ["# Cloudflare Workers", ""]
        lines.append(f"Total: {len(workers)} scripts")
        lines.append("")

        for worker in workers:
            lines.append(_format_worker_markdown(worker))
            lines.append("")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_get_worker",
    annotations={
        "title": "Get Worker Script",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_get_worker(params: GetWorkerInput) -> str:
    """Get Worker script content by name.

    Retrieves the JavaScript source code of a deployed Worker script.

    Args:
        params: GetWorkerInput with script name

    Returns:
        Worker script source code
    """
    try:
        account_id = await _get_account_id()

        # Get script content
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{API_BASE_URL}/accounts/{account_id}/workers/scripts/{params.script_name}",
                headers=_get_headers(),
                timeout=30.0
            )
            response.raise_for_status()
            script_content = response.text

        return f"# Worker Script: {params.script_name}\n\n```javascript\n{script_content}\n```"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_deploy_worker",
    annotations={
        "title": "Deploy Worker Script",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_deploy_worker(params: DeployWorkerInput) -> str:
    """Deploy/update Worker script with JavaScript content.

    Uploads and deploys a Worker script. If script exists, it will be updated.
    Script is deployed globally to Cloudflare's edge network.

    Args:
        params: DeployWorkerInput with script name and JavaScript content

    Returns:
        Deployment confirmation with script details
    """
    try:
        account_id = await _get_account_id()

        # Deploy script
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{API_BASE_URL}/accounts/{account_id}/workers/scripts/{params.script_name}",
                headers={
                    "Authorization": f"Bearer {_get_api_token()}",
                    "Content-Type": "application/javascript"
                },
                content=params.script_content,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()

        worker = data.get("result", {})
        return f"✅ Worker `{params.script_name}` deployed successfully!\n\nScript ID: {worker.get('id', 'N/A')}\nSize: {len(params.script_content)} bytes"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_delete_worker",
    annotations={
        "title": "Delete Worker",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_delete_worker(params: DeleteWorkerInput) -> str:
    """Delete Worker script. Irreversible - use list_workers first.

    Removes the Worker script from Cloudflare's edge network. Routes associated
    with this script will stop working.

    Args:
        params: DeleteWorkerInput with script name

    Returns:
        Confirmation of deletion
    """
    try:
        account_id = await _get_account_id()
        await _make_request("DELETE", f"accounts/{account_id}/workers/scripts/{params.script_name}")
        return f"✅ Worker script `{params.script_name}` deleted successfully."

    except Exception as e:
        return _handle_error(e)


# Workers KV
@mcp.tool(
    name="cloudflare_list_kv_namespaces",
    annotations={
        "title": "List KV Namespaces",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_list_kv_namespaces(params: ListKVNamespacesInput) -> str:
    """List Workers KV namespaces with IDs for storage operations.

    Returns all KV namespaces in the account with namespace IDs needed for
    key-value operations.

    Args:
        params: ListKVNamespacesInput with pagination options

    Returns:
        List of KV namespaces with IDs and titles
    """
    try:
        account_id = await _get_account_id()
        data = await _make_request(
            "GET",
            f"accounts/{account_id}/storage/kv/namespaces",
            params={"page": params.page, "per_page": params.per_page}
        )
        namespaces = data.get("result", [])

        if not namespaces:
            return "No KV namespaces found in this account."

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"namespaces": namespaces, "total": len(namespaces)}, indent=2)

        lines = ["# Workers KV Namespaces", ""]
        lines.append(f"Total: {len(namespaces)} namespaces")
        lines.append("")

        for ns in namespaces:
            lines.append(_format_kv_namespace_markdown(ns))
            lines.append("")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_create_kv_namespace",
    annotations={
        "title": "Create KV Namespace",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def cloudflare_create_kv_namespace(params: CreateKVNamespaceInput) -> str:
    """Create Workers KV namespace for key-value storage.

    Creates a new KV namespace container for storing key-value pairs accessible
    from Workers scripts.

    Args:
        params: CreateKVNamespaceInput with namespace title

    Returns:
        Created namespace details including namespace ID
    """
    try:
        account_id = await _get_account_id()
        data = await _make_request(
            "POST",
            f"accounts/{account_id}/storage/kv/namespaces",
            json_data={"title": params.title}
        )
        namespace = data.get("result", {})

        return f"✅ KV namespace created successfully:\n\n{_format_kv_namespace_markdown(namespace)}"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_write_kv",
    annotations={
        "title": "Write KV Pair",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_write_kv(params: WriteKVInput) -> str:
    """Write key-value pair to KV namespace with optional TTL.

    Stores a value under a key in the specified KV namespace. If key exists,
    value is overwritten. Optionally set expiration TTL.

    Args:
        params: WriteKVInput with namespace ID, key, value, and optional TTL

    Returns:
        Confirmation of write operation
    """
    try:
        account_id = await _get_account_id()

        # Build query params
        query_params = {}
        if params.expiration_ttl:
            query_params["expiration_ttl"] = params.expiration_ttl

        # Write value
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{API_BASE_URL}/accounts/{account_id}/storage/kv/namespaces/{params.namespace_id}/values/{params.key}",
                headers={
                    "Authorization": f"Bearer {_get_api_token()}",
                    "Content-Type": "text/plain"
                },
                content=params.value,
                params=query_params,
                timeout=30.0
            )
            response.raise_for_status()

        ttl_msg = f" (TTL: {params.expiration_ttl}s)" if params.expiration_ttl else ""
        return f"✅ KV pair written successfully:\n\nKey: `{params.key}`\nValue size: {len(params.value)} bytes{ttl_msg}"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_read_kv",
    annotations={
        "title": "Read KV Value",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_read_kv(params: ReadKVInput) -> str:
    """Read value by key from KV namespace.

    Retrieves the value stored under the specified key in the KV namespace.

    Args:
        params: ReadKVInput with namespace ID and key

    Returns:
        Value stored at the key
    """
    try:
        account_id = await _get_account_id()

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{API_BASE_URL}/accounts/{account_id}/storage/kv/namespaces/{params.namespace_id}/values/{params.key}",
                headers=_get_headers(),
                timeout=30.0
            )
            response.raise_for_status()
            value = response.text

        return f"# KV Value for key: `{params.key}`\n\n```\n{value}\n```"

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_delete_kv",
    annotations={
        "title": "Delete KV Key",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_delete_kv(params: DeleteKVInput) -> str:
    """Delete key from KV namespace. Irreversible.

    Args:
        params: DeleteKVInput with namespace ID and key

    Returns:
        Confirmation of deletion
    """
    try:
        account_id = await _get_account_id()
        await _make_request("DELETE", f"accounts/{account_id}/storage/kv/namespaces/{params.namespace_id}/values/{params.key}")
        return f"✅ KV key `{params.key}` deleted successfully from namespace `{params.namespace_id}`."

    except Exception as e:
        return _handle_error(e)


@mcp.tool(
    name="cloudflare_list_kv_keys",
    annotations={
        "title": "List KV Keys",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_list_kv_keys(params: ListKVKeysInput) -> str:
    """List keys in KV namespace with optional prefix filter.

    Returns all keys stored in the KV namespace. Use prefix parameter to
    filter keys starting with a specific string.

    Args:
        params: ListKVKeysInput with namespace ID, optional prefix, and limit

    Returns:
        List of keys in the namespace
    """
    try:
        account_id = await _get_account_id()

        query_params = {"limit": params.limit}
        if params.prefix:
            query_params["prefix"] = params.prefix

        data = await _make_request(
            "GET",
            f"accounts/{account_id}/storage/kv/namespaces/{params.namespace_id}/keys",
            params=query_params
        )
        keys = data.get("result", [])

        if not keys:
            prefix_msg = f" with prefix '{params.prefix}'" if params.prefix else ""
            return f"No keys found in namespace `{params.namespace_id}`{prefix_msg}."

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"namespace_id": params.namespace_id, "keys": keys, "total": len(keys)}, indent=2)

        lines = [f"# KV Keys in Namespace: {params.namespace_id}", ""]
        if params.prefix:
            lines.append(f"Filter: Keys starting with `{params.prefix}`")
            lines.append("")
        lines.append(f"Total: {len(keys)} keys")
        lines.append("")

        for key_obj in keys:
            key_name = key_obj.get("name", "")
            expiration = key_obj.get("expiration")
            exp_msg = f" (expires: {expiration})" if expiration else ""
            lines.append(f"- `{key_name}`{exp_msg}")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


# Account Management
@mcp.tool(
    name="cloudflare_get_account",
    annotations={
        "title": "Get Account Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_get_account(params: GetAccountInput) -> str:
    """Get account details including name, settings, and capabilities.

    Returns comprehensive account information including account ID, name, type,
    and configured settings.

    Args:
        params: GetAccountInput with response format

    Returns:
        Account details and configuration
    """
    try:
        account_id = await _get_account_id()
        data = await _make_request("GET", f"accounts/{account_id}")
        account = data.get("result", {})

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(account, indent=2)

        lines = ["# Cloudflare Account Details", ""]
        lines.append(f"## {account.get('name', 'Unnamed Account')}")
        lines.append(f"- **ID**: `{account.get('id', 'N/A')}`")
        lines.append(f"- **Type**: {account.get('type', 'N/A')}")

        settings = account.get("settings", {})
        if settings:
            lines.append("")
            lines.append("## Settings")
            for key, value in settings.items():
                lines.append(f"- **{key}**: {value}")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


# Analytics
@mcp.tool(
    name="cloudflare_get_zone_analytics",
    annotations={
        "title": "Get Zone Analytics",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def cloudflare_get_zone_analytics(params: GetZoneAnalyticsInput) -> str:
    """Get zone analytics/stats for traffic, requests, and bandwidth.

    Returns analytics data including requests, bandwidth, threats, and page views
    for the specified time period.

    Args:
        params: GetZoneAnalyticsInput with zone and time range

    Returns:
        Analytics data with traffic statistics and metrics

    Time range examples:
        - Last 24 hours: since='-1440'
        - Last 7 days: since='-10080'
        - Specific range: since='2025-01-01T00:00:00Z', until='2025-01-07T00:00:00Z'
    """
    try:
        zone_id = await _resolve_zone_id(params.zone)

        query_params = {}
        if params.since:
            query_params["since"] = params.since
        if params.until:
            query_params["until"] = params.until

        data = await _make_request("GET", f"zones/{zone_id}/analytics/dashboard", params=query_params)
        analytics = data.get("result", {})

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"zone": params.zone, "analytics": analytics}, indent=2)

        lines = [f"# Zone Analytics for {params.zone}", ""]

        totals = analytics.get("totals", {})
        if totals:
            lines.append("## Totals")
            lines.append(f"- **Requests**: {totals.get('requests', {}).get('all', 0):,}")
            lines.append(f"- **Bandwidth**: {totals.get('bandwidth', {}).get('all', 0):,} bytes")
            lines.append(f"- **Threats**: {totals.get('threats', {}).get('all', 0):,}")
            lines.append(f"- **Page Views**: {totals.get('pageviews', {}).get('all', 0):,}")
            lines.append(f"- **Unique Visitors**: {totals.get('uniques', {}).get('all', 0):,}")

        return "\n".join(lines)

    except Exception as e:
        return _handle_error(e)


# API Token Management
@mcp.tool(
    name="cloudflare_create_api_token",
    annotations={
        "title": "Create API Token",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def cloudflare_create_api_token(params: CreateAPITokenInput) -> str:
    """Create scoped Cloudflare API token programmatically.

    Creates a new API token with specific permissions. Use this to create properly
    scoped tokens, then replace Global API Key for better security.

    Common permission groups:
    - 'dns_write': DNS record management
    - 'workers_write': Workers script deployment
    - 'workers_kv_write': KV storage management
    - 'firewall_write': Firewall rule management
    - 'cache_purge': Cache purging
    - 'zone_settings_write': Zone configuration
    - 'analytics_read': Analytics access

    Args:
        params: CreateAPITokenInput with token name, permissions, and resources

    Returns:
        New API token value (COPY IMMEDIATELY - shown only once)

    Examples:
        - MCP full token: permissions=['dns_write', 'workers_write', 'cache_purge',
          'firewall_write', 'zone_settings_write'], zone_resources='all'
        - DNS-only token: permissions=['dns_write'], zone_resources='all'
    """
    try:
        # Map friendly names to Cloudflare permission group IDs
        permission_map = {
            'dns_write': '4755a26eedb94da69e1066d98aa820be',
            'dns_read': '82e64a83756745bbbb1c9c2701bf816b',
            'workers_write': 'e086da7e2179491d91ee5f35b3ca210a',
            'workers_kv_write': 'f7f0eda5697f475c90846e879bab8666',
            'firewall_write': '3030687196b94b638145a3953da2b699',
            'cache_purge': 'e17beae8b8cb423a99b1730f21238bed',
            'zone_settings_write': '28f4b596e7d643029c524985477ae49a',
            'zone_read': 'c8fed203ed3043cba015a93ad1616f1f',
            'analytics_read': '1b5f5de8e2ec4c3f8c5f5b5c5b5c5b5c',
            'account_read': '8b1e0e3f3f3f3f3f3f3f3f3f3f3f3f3f'
        }

        # Build permission groups list
        permission_groups = []
        for perm in params.permissions:
            perm_lower = perm.lower().strip()
            if perm_lower in permission_map:
                permission_groups.append({"id": permission_map[perm_lower]})
            else:
                # Try to use as raw ID if not in map
                permission_groups.append({"id": perm})

        # Build resources
        if params.zone_resources.lower() == 'all':
            resources = {
                "com.cloudflare.api.account.zone.*": "*"
            }
        else:
            resources = {
                f"com.cloudflare.api.account.zone.{params.zone_resources}": "*"
            }

        # Build token request
        token_data = {
            "name": params.name,
            "policies": [
                {
                    "effect": "allow",
                    "resources": resources,
                    "permission_groups": permission_groups
                }
            ]
        }

        # Add TTL if specified
        if params.ttl_days:
            from datetime import datetime, timedelta
            expiry = datetime.utcnow() + timedelta(days=params.ttl_days)
            token_data["expires_on"] = expiry.isoformat() + "Z"

        # Create token
        data = await _make_request("POST", "user/tokens", json_data=token_data)
        result = data.get("result", {})

        token_value = result.get("value")
        token_id = result.get("id")

        if not token_value:
            return f"Error: Token created but value not returned. Token ID: {token_id}"

        return f"""✅ API Token Created Successfully!

**Token Name**: {params.name}
**Token ID**: {token_id}

**🔑 TOKEN VALUE** (COPY NOW - shown only once):
```
{token_value}
```

**Permissions Granted**: {', '.join(params.permissions)}
**Zone Access**: {params.zone_resources}
**Expires**: {'Never' if not params.ttl_days else f'{params.ttl_days} days from now'}

**Next Steps:**
1. Copy the token value above immediately
2. Set environment variable: export CLOUDFLARE_API_TOKEN_FULL="{token_value}"
3. Restart Claude Code to use the new token
4. Optionally revoke/disable Global API Key for security

This token can be managed at: https://dash.cloudflare.com/profile/api-tokens
"""

    except Exception as e:
        return _handle_error(e)


if __name__ == "__main__":
    mcp.run()
