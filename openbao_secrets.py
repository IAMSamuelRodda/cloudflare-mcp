"""
OpenBao Secrets Client for MCP Servers.

This module provides a simple interface for MCP servers to read secrets
from a local OpenBao Agent using Arc Forge's secret path pattern.

Secret Path Pattern:
    secret/{namespace}/{environment}-{type}-{service}-{identifier}

    Examples:
    - secret/client0/prod-mcp-vikunja-samuel
    - secret/client0/prod-mcp-joplin-desktop

SECURITY: Environment variable fallback is DISABLED by default.
Only enable for local development environments, never in production.

Usage:
    from src.utils.openbao_secrets import get_mcp_token, get_mcp_config

    # Production: Agent only (no fallback)
    token = get_mcp_token("vikunja")

    # Development only: Allow env var fallback (explicit opt-in)
    token = get_mcp_token("vikunja", dev_fallback="VIKUNJA_TOKEN")

    # Get full MCP config
    config = get_mcp_config("vikunja")
"""

import os
import socket
import subprocess
import warnings
from typing import Optional, Dict, Any
from functools import lru_cache

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


# Configuration
# Default port 18200 is the local agent listener (distinct from VPS tunnel on 8200)
AGENT_ADDR = os.getenv("OPENBAO_AGENT_ADDR", "http://127.0.0.1:18200")
AGENT_TIMEOUT = float(os.getenv("OPENBAO_AGENT_TIMEOUT", "5.0"))

# Arc Forge secret path configuration
ARC_CLIENT = os.getenv("ARC_CLIENT", "client0")
ARC_ENVIRONMENT = os.getenv("ARC_ENVIRONMENT", "prod")

# Development mode detection
# Set OPENBAO_DEV_MODE=1 to allow env var fallbacks (local dev only)
DEV_MODE = os.getenv("OPENBAO_DEV_MODE", "").lower() in ("1", "true", "yes")


class OpenBaoError(Exception):
    """Base exception for OpenBao errors."""
    pass


class AgentNotRunningError(OpenBaoError):
    """Raised when the OpenBao Agent is not running."""
    pass


class SecretNotFoundError(OpenBaoError):
    """Raised when a secret path doesn't exist."""
    pass


def _get_client():
    """Get HTTP client for agent communication."""
    if not HTTPX_AVAILABLE:
        raise OpenBaoError("httpx is required for OpenBao agent support")
    return httpx.Client(
        base_url=AGENT_ADDR,
        timeout=AGENT_TIMEOUT,
        headers={"X-Vault-Request": "true"}
    )


def _get_git_email() -> Optional[str]:
    """Get user email from git config."""
    try:
        result = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _detect_identifier(service: str) -> str:
    """
    Auto-detect identifier for service credential.

    Args:
        service: Service name (e.g., "vikunja", "joplin")

    Returns:
        Identifier string (username or hostname)

    Detection strategy:
    - vikunja: User-scoped → git email username
    - joplin: Machine-scoped → hostname
    - default: hostname
    """
    if service == "joplin":
        # Machine-scoped: use hostname
        return socket.gethostname().split('.')[0]

    elif service == "vikunja":
        # User-scoped: use git email username
        email = _get_git_email()
        if email:
            return email.split('@')[0]  # "samuel@arcforge.au" → "samuel"
        # Fallback to system user
        return os.getenv("USER", "default")

    # Default: user-scoped (git email username)
    email = _get_git_email()
    if email:
        return email.split('@')[0]  # "samuel@arcforge.au" → "samuel"
    # Fallback to system user
    return os.getenv("USER", "default")


def build_mcp_secret_path(service: str, identifier: Optional[str] = None) -> str:
    """
    Build secret path using Arc Forge pattern.

    Pattern: secret/{client}/{environment}-mcp-{service}-{identifier}

    Args:
        service: Service name (e.g., "vikunja", "joplin")
        identifier: Optional explicit identifier (auto-detected if not provided)

    Returns:
        Secret path string (e.g., "client0/prod-mcp-vikunja-samuel")

    Examples:
        >>> build_mcp_secret_path("vikunja")
        "client0/prod-mcp-vikunja-samuel"

        >>> build_mcp_secret_path("joplin", "laptop")
        "client0/prod-mcp-joplin-laptop"
    """
    if identifier is None:
        identifier = _detect_identifier(service)

    return f"{ARC_CLIENT}/{ARC_ENVIRONMENT}-mcp-{service}-{identifier}"


def check_agent_health() -> bool:
    """
    Check if the OpenBao Agent is running and healthy.

    Returns:
        True if agent is healthy, False otherwise.
    """
    if not HTTPX_AVAILABLE:
        return False
    try:
        with _get_client() as client:
            response = client.get("/v1/sys/health")
            return response.status_code in (200, 429, 472, 473, 501, 503)
    except Exception:
        return False


def get_secret(path: str, key: Optional[str] = None) -> Any:
    """
    Read a secret from the OpenBao Agent.

    Args:
        path: Secret path (e.g., "mcp/vikunja")
        key: Optional specific key within the secret data

    Returns:
        The secret data dict, or specific key value if key provided.

    Raises:
        AgentNotRunningError: If agent is not running
        SecretNotFoundError: If secret path doesn't exist
        OpenBaoError: For other OpenBao errors
    """
    if not HTTPX_AVAILABLE:
        raise AgentNotRunningError("httpx not installed - cannot connect to agent")

    # Ensure path doesn't start with /
    path = path.lstrip("/")

    # Build the full path for KV v2
    full_path = f"/v1/secret/data/{path}"

    try:
        with _get_client() as client:
            response = client.get(full_path)

            if response.status_code == 404:
                raise SecretNotFoundError(f"Secret not found: {path}")

            if response.status_code != 200:
                raise OpenBaoError(
                    f"Failed to read secret: {response.status_code} - {response.text}"
                )

            data = response.json()
            secret_data = data.get("data", {}).get("data", {})

            if key:
                if key not in secret_data:
                    raise SecretNotFoundError(f"Key '{key}' not found in {path}")
                return secret_data[key]

            return secret_data

    except httpx.ConnectError:
        raise AgentNotRunningError(
            f"Cannot connect to OpenBao Agent at {AGENT_ADDR}. "
            "Start the agent with:\n"
            "  export BW_SESSION=$(bw unlock --raw)\n"
            "  start-openbao-mcp"
        )


def get_mcp_token(
    service: str,
    dev_fallback: Optional[str] = None,
    required: bool = True,
    identifier: Optional[str] = None
) -> Optional[str]:
    """
    Get an MCP service token from the OpenBao agent.

    Uses Arc Forge secret path pattern:
    secret/{client}/{environment}-mcp-{service}-{identifier}

    SECURITY: Environment variable fallback is DISABLED by default.
    Fallback only works when OPENBAO_DEV_MODE=1 is set AND dev_fallback
    is specified. This ensures production environments always use the agent.

    Args:
        service: Service name (e.g., "vikunja", "joplin")
        dev_fallback: Environment variable name for dev-only fallback.
                      Only used when OPENBAO_DEV_MODE=1 is set.
        required: If True, raise error when token not found
        identifier: Optional explicit identifier (auto-detected if not provided)

    Returns:
        The token string, or None if not found and not required.

    Raises:
        AgentNotRunningError: If agent not running (production)
        SecretNotFoundError: If secret not found (production)
        ValueError: If required=True and token not found

    Example:
        # Production: Agent only (will fail if agent not running)
        token = get_mcp_token("vikunja")

        # Development: Allow env fallback (requires OPENBAO_DEV_MODE=1)
        token = get_mcp_token("vikunja", dev_fallback="VIKUNJA_TOKEN")

        # Explicit identifier override
        token = get_mcp_token("vikunja", identifier="kayla")
    """
    # Build secret path using Arc Forge pattern
    secret_path = build_mcp_secret_path(service, identifier)

    # Try agent first
    try:
        return get_secret(secret_path, "token")
    except OpenBaoError as e:
        # Catch all OpenBao errors (agent not running, secret not found, permission denied, etc.)
        # Only allow fallback in dev mode with explicit fallback specified
        if DEV_MODE and dev_fallback:
            token = os.getenv(dev_fallback)
            if token:
                warnings.warn(
                    f"[DEV MODE] Using {dev_fallback} env var (agent error: {type(e).__name__}). "
                    "This fallback is disabled in production.",
                    UserWarning
                )
                return token

        # No fallback available - raise appropriate error
        if isinstance(e, AgentNotRunningError):
            if required:
                raise AgentNotRunningError(
                    f"OpenBao Agent not running at {AGENT_ADDR}. "
                    "Start the agent with:\n"
                    "  export BW_SESSION=$(bw unlock --raw)\n"
                    "  start-openbao-mcp"
                ) from e
            return None
        elif isinstance(e, SecretNotFoundError):
            if required:
                raise ValueError(
                    f"Token for '{service}' not found in agent at secret/{secret_path}. "
                    "Ensure the secret exists in OpenBao with the correct path pattern: "
                    f"secret/{ARC_CLIENT}/{ARC_ENVIRONMENT}-mcp-{{service}}-{{identifier}}"
                ) from e
            return None
        else:
            # Other OpenBaoError (like permission denied)
            if required:
                identifier = _detect_identifier(service)
                raise ValueError(
                    f"Failed to retrieve token for '{service}' from agent: {e}\n"
                    f"Expected path: secret/{secret_path}\n\n"
                    f"To create this secret, connect to your OpenBao server and run:\n"
                    f"  bao kv put secret/{secret_path} token=\"your-{service}-token\" url=\"https://your-{service}-url\"\n\n"
                    f"Or for development, enable dev mode:\n"
                    f"  export OPENBAO_DEV_MODE=1\n"
                    f"  export VIKUNJA_TOKEN=your-token\n"
                    f"  export VIKUNJA_URL=https://your-url"
                ) from e
            return None


def get_mcp_config(
    service: str,
    dev_fallbacks: Optional[Dict[str, str]] = None,
    identifier: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get full configuration for an MCP service from the OpenBao agent.

    Uses Arc Forge secret path pattern:
    secret/{client}/{environment}-mcp-{service}-{identifier}

    SECURITY: Environment variable fallback is DISABLED by default.
    Fallback only works when OPENBAO_DEV_MODE=1 is set AND dev_fallbacks
    is specified. This ensures production environments always use the agent.

    Args:
        service: Service name (e.g., "vikunja")
        dev_fallbacks: Dict mapping config keys to env var names for dev-only fallback.
                       Only used when OPENBAO_DEV_MODE=1 is set.
                       e.g., {"token": "VIKUNJA_TOKEN", "url": "VIKUNJA_URL"}
        identifier: Optional explicit identifier (auto-detected if not provided)

    Returns:
        Dict with all config keys for the service.

    Example:
        # Production: Agent only
        config = get_mcp_config("vikunja")

        # Development: Allow env fallback (requires OPENBAO_DEV_MODE=1)
        config = get_mcp_config("vikunja", dev_fallbacks={
            "token": "VIKUNJA_TOKEN",
            "url": "VIKUNJA_URL"
        })

        # Explicit identifier override
        config = get_mcp_config("vikunja", identifier="kayla")
    """
    # Build secret path using Arc Forge pattern
    secret_path = build_mcp_secret_path(service, identifier)

    try:
        return get_secret(secret_path)
    except OpenBaoError as e:
        # Catch all OpenBao errors (agent not running, secret not found, permission denied, etc.)
        # Only allow fallback in dev mode with explicit fallbacks specified
        if DEV_MODE and dev_fallbacks:
            config = {}
            for key, env_var in dev_fallbacks.items():
                value = os.getenv(env_var)
                if value:
                    config[key] = value
            if config:
                warnings.warn(
                    f"[DEV MODE] Using environment variables for {service} (agent error: {type(e).__name__}). "
                    "This fallback is disabled in production.",
                    UserWarning
                )
                return config
        raise


@lru_cache(maxsize=1)
def is_agent_available() -> bool:
    """
    Check if agent is available (cached for performance).

    Use this at startup to decide between agent and fallback mode.
    Result is cached for the lifetime of the process.

    Returns:
        True if agent is available.
    """
    return check_agent_health()


# Convenience aliases
read_secret = get_secret


# =============================================================================
# Deferred Credential Loading (for FastMCP lifespan pattern)
# =============================================================================


class DeferredCredentialLoader:
    """
    Deferred credential loader for MCP servers.

    This class delays credential loading until the lifespan context is entered,
    preventing import-time failures when the OpenBao agent isn't running.

    Usage:
        # At module level (no I/O)
        _stripe_loader = DeferredCredentialLoader(
            "stripe",
            "api_key",
            dev_fallback="STRIPE_API_KEY"
        )

        @asynccontextmanager
        async def lifespan(app):
            # Load credentials here (fails fast if unavailable)
            api_key = _stripe_loader.load()
            stripe.api_key = api_key
            print("MCP_SERVER_READY", file=sys.stderr)
            yield

    Error codes printed to stderr for lazy-mcp detection:
        - OPENBAO_AGENT_NOT_RUNNING: Agent not responding
        - SECRET_NOT_FOUND: Secret path doesn't exist
        - SECRET_PERMISSION_DENIED: No access to secret
        - SECRET_INVALID_TOKEN: Token expired or invalid
        - SOURCE_ENV: Using environment variable fallback
    """

    def __init__(
        self,
        service: str,
        key: str = "token",
        dev_fallback: Optional[str] = None,
        identifier: Optional[str] = None
    ):
        """
        Initialize deferred loader.

        Args:
            service: Service name (e.g., "stripe", "vikunja")
            key: Key within the secret data (default: "token")
            dev_fallback: Environment variable name for dev-only fallback
            identifier: Optional explicit identifier (auto-detected if not provided)
        """
        self.service = service
        self.key = key
        self.dev_fallback = dev_fallback
        self.identifier = identifier
        self._cached_value: Optional[str] = None
        self._source: Optional[str] = None
        self._loaded = False

    def is_available(self) -> bool:
        """
        Check if credential can be loaded (either from agent or dev fallback).

        Returns:
            True if credential is available from either source.
        """
        try:
            self.load()
            return True
        except (OpenBaoError, ValueError):
            return False

    def get_source(self) -> Optional[str]:
        """Get the source of the credential after loading."""
        return self._source

    def load(self) -> str:
        """
        Load the credential from OpenBao or dev fallback.

        Returns:
            The credential value.

        Raises:
            AgentNotRunningError: If agent not running and no fallback
            SecretNotFoundError: If secret not found and no fallback
            ValueError: If credential cannot be retrieved
        """
        if self._loaded and self._cached_value:
            return self._cached_value

        secret_path = build_mcp_secret_path(self.service, self.identifier)

        try:
            self._cached_value = get_secret(secret_path, self.key)
            self._source = "SOURCE_OPENBAO"
            self._loaded = True
            return self._cached_value

        except OpenBaoError as e:
            # Try dev fallback if available
            if DEV_MODE and self.dev_fallback:
                value = os.getenv(self.dev_fallback)
                if value:
                    self._cached_value = value
                    self._source = "SOURCE_ENV"
                    self._loaded = True
                    import sys
                    print(
                        f"[DEV MODE] Using {self.dev_fallback} env var "
                        f"(agent error: {type(e).__name__}). "
                        "This fallback is disabled in production.",
                        file=sys.stderr
                    )
                    return self._cached_value

            # Output structured error for lazy-mcp detection
            import sys
            error_code = self._map_error_code(e)
            error_json = {
                "error_code": error_code,
                "error_message": str(e),
                "service": self.service,
                "secret_path": secret_path
            }
            import json
            print(f"OPENBAO_ERROR:{json.dumps(error_json)}", file=sys.stderr)

            raise

    def _map_error_code(self, error: OpenBaoError) -> str:
        """Map OpenBaoError to error code string."""
        if isinstance(error, AgentNotRunningError):
            return "OPENBAO_AGENT_NOT_RUNNING"
        elif isinstance(error, SecretNotFoundError):
            return "SECRET_NOT_FOUND"
        else:
            error_str = str(error).lower()
            if "permission denied" in error_str or "403" in error_str:
                return "SECRET_PERMISSION_DENIED"
            elif "invalid token" in error_str or "token expired" in error_str:
                return "SECRET_INVALID_TOKEN"
            return "OPENBAO_AGENT_NOT_RUNNING"


def check_agent_status() -> Dict[str, Any]:
    """
    Check OpenBao agent status and return structured result.

    Returns:
        Dict with 'available', 'error_code', 'error_message' keys.

    This is useful for lifespan context to check availability before
    attempting to load credentials.
    """
    result = {
        "available": False,
        "error_code": None,
        "error_message": None
    }

    try:
        if check_agent_health():
            result["available"] = True
        else:
            result["error_code"] = "OPENBAO_AGENT_NOT_RUNNING"
            result["error_message"] = f"Agent not healthy at {AGENT_ADDR}"
    except Exception as e:
        result["error_code"] = "OPENBAO_AGENT_NOT_RUNNING"
        result["error_message"] = str(e)

    return result
