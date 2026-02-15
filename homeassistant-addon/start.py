#!/usr/bin/env python3
"""Home Assistant MCP Server Add-on startup script."""

import json
import os
import secrets
import sys
from datetime import datetime
from pathlib import Path


def _log_with_timestamp(level: str, message: str, stream=None) -> None:
    """Log a message with a timestamp."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now} [{level}] {message}", file=stream, flush=True)


def log_info(message: str) -> None:
    """Log info message."""
    _log_with_timestamp("INFO", message)


def log_error(message: str) -> None:
    """Log error message."""
    _log_with_timestamp("ERROR", message, sys.stderr)


def generate_secret_path() -> str:
    """Generate a secure random path with 128-bit entropy.

    Format: /private_<22-char-urlsafe-token>
    Example: /private_zctpwlX7ZkIAr7oqdfLPxw
    """
    return "/private_" + secrets.token_urlsafe(16)


def get_or_create_secret_path(data_dir: Path, custom_path: str = "") -> str:
    """Get existing secret path or create a new one.

    Args:
        data_dir: Path to the /data directory
        custom_path: Optional custom path from config (overrides auto-generated)

    Returns:
        The secret path to use
    """
    secret_file = data_dir / "secret_path.txt"

    # If custom path is provided, use it and update the stored path
    if custom_path and custom_path.strip():
        path = custom_path.strip()
        if not path.startswith("/"):
            path = "/" + path
        log_info("Using custom secret path from configuration")
        # Update stored path for consistency
        secret_file.write_text(path)
        return path

    # Check if we have a stored secret path
    if secret_file.exists():
        try:
            stored_path = secret_file.read_text().strip()
            if stored_path:
                log_info("Using existing auto-generated secret path")
                return stored_path
        except Exception as e:
            log_error(f"Failed to read stored secret path: {e}")

    # Generate new secret path
    new_path = generate_secret_path()
    log_info("Generated new secret path with 128-bit entropy")
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(new_path)
        return new_path
    except Exception as e:
        log_error(f"Failed to save secret path: {e}")
        # Return the path anyway - it will work for this session
        return new_path


def _get_oidc_config(config: dict) -> dict[str, str]:
    """Extract OIDC configuration from add-on options.

    Returns:
        Dict with OIDC fields that are set (non-empty).
    """
    oidc_fields = {
        "oidc_config_url": config.get("oidc_config_url", ""),
        "oidc_client_id": config.get("oidc_client_id", ""),
        "oidc_client_secret": config.get("oidc_client_secret", ""),
        "oidc_base_url": config.get("oidc_base_url", ""),
        "oidc_jwt_signing_key": config.get("oidc_jwt_signing_key", ""),
    }
    return {k: v for k, v in oidc_fields.items() if v and v.strip()}


def _validate_oidc_config(oidc_config: dict[str, str]) -> str | None:
    """Validate OIDC configuration completeness.

    Returns:
        Error message if partial config detected, None if valid or empty.
    """
    all_fields = {"oidc_config_url", "oidc_client_id", "oidc_client_secret", "oidc_base_url"}
    present = set(oidc_config.keys()) & all_fields  # Only check required fields

    if not present:
        return None  # No OIDC config — use secret path mode

    missing = all_fields - present
    if missing:
        friendly_names = {
            "oidc_config_url": "OIDC Discovery URL",
            "oidc_client_id": "OIDC Client ID",
            "oidc_client_secret": "OIDC Client Secret",
            "oidc_base_url": "OIDC Public Base URL",
        }
        missing_names = [friendly_names[f] for f in sorted(missing)]
        return (
            f"Incomplete OIDC configuration. Missing: {', '.join(missing_names)}. "
            f"Either set all OIDC fields or leave them all empty to use secret path mode."
        )

    return None  # All fields present — valid


def _run_oidc_mode(oidc_config: dict[str, str], port: int) -> int:
    """Start the server in OIDC authentication mode.

    Args:
        oidc_config: Validated OIDC configuration dict.
        port: Internal container port.

    Returns:
        Exit code.
    """
    # Set OIDC environment variables for ha_mcp.__main__.main_oidc()
    os.environ["OIDC_CONFIG_URL"] = oidc_config["oidc_config_url"]
    os.environ["OIDC_CLIENT_ID"] = oidc_config["oidc_client_id"]
    os.environ["OIDC_CLIENT_SECRET"] = oidc_config["oidc_client_secret"]
    os.environ["MCP_BASE_URL"] = oidc_config["oidc_base_url"]
    os.environ["MCP_PORT"] = str(port)
    os.environ["MCP_SECRET_PATH"] = "/mcp"

    # Optional: JWT signing key for persistent sessions across restarts
    jwt_key = oidc_config.get("oidc_jwt_signing_key", "")
    if jwt_key:
        os.environ["OIDC_JWT_SIGNING_KEY"] = jwt_key

    base_url = oidc_config["oidc_base_url"].rstrip("/")

    log_info("")
    log_info("=" * 80)
    log_info("  OIDC Authentication Mode")
    log_info("")
    log_info(f"  MCP Endpoint: {base_url}/mcp")
    log_info(f"  OIDC Provider: {oidc_config['oidc_config_url']}")
    log_info(f"  Auth Callback: {base_url}/auth/callback")
    log_info("")
    log_info("  Users must authenticate via your OIDC provider before accessing MCP.")
    log_info("  Ensure your reverse proxy forwards HTTPS traffic to port %d." % port)
    log_info("=" * 80)
    log_info("")

    try:
        log_info("Starting OIDC-authenticated MCP server...")
        from ha_mcp.__main__ import main_oidc

        main_oidc()
    except Exception as e:
        log_error(f"Failed to start OIDC server: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


def _run_secret_path_mode(secret_path: str, port: int) -> int:
    """Start the server in secret path mode (no authentication).

    Args:
        secret_path: The obfuscated URL path.
        port: Internal container port.

    Returns:
        Exit code.
    """
    log_info("")
    log_info("=" * 80)
    log_info(f"  MCP Server URL: http://<home-assistant-ip>:{port}{secret_path}")
    log_info("")
    log_info(f"  Secret Path: {secret_path}")
    log_info("")
    log_info("  IMPORTANT: Copy this exact URL - the secret path is required!")
    log_info("  This path is auto-generated and persisted to /data/secret_path.txt")
    log_info("")
    log_info("  TIP: For better security, configure OIDC authentication in the add-on options.")
    log_info("=" * 80)
    log_info("")

    try:
        log_info("Importing ha_mcp module...")
        from ha_mcp.__main__ import mcp, _get_timestamped_uvicorn_log_config

        log_info("Starting MCP server...")
        mcp.run(
            transport="streamable-http",
            host="0.0.0.0",
            port=port,
            path=secret_path,
            log_level="info",
            uvicorn_config={"log_config": _get_timestamped_uvicorn_log_config()},
        )
    except Exception as e:
        log_error(f"Failed to start MCP server: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


def main() -> int:
    """Start the Home Assistant MCP Server."""
    log_info("Starting Home Assistant MCP Server...")

    # Read configuration from Supervisor
    config_file = Path("/data/options.json")
    data_dir = Path("/data")
    config = {}

    if config_file.exists():
        try:
            with open(config_file) as f:
                config = json.load(f)
        except Exception as e:
            log_error(f"Failed to read config: {e}, using defaults")

    backup_hint = config.get("backup_hint", "normal")
    custom_secret_path = config.get("secret_path", "")

    log_info(f"Backup hint mode: {backup_hint}")

    # Set up environment for ha-mcp
    os.environ["HOMEASSISTANT_URL"] = "http://supervisor/core"
    os.environ["BACKUP_HINT"] = backup_hint

    # Validate Supervisor token
    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if not supervisor_token:
        log_error("SUPERVISOR_TOKEN not found! Cannot authenticate.")
        return 1

    os.environ["HOMEASSISTANT_TOKEN"] = supervisor_token

    log_info(f"Home Assistant URL: {os.environ['HOMEASSISTANT_URL']}")
    log_info("Authentication configured via Supervisor token")

    # Fixed port (internal container port)
    port = 9583

    # Check for OIDC configuration
    oidc_config = _get_oidc_config(config)
    oidc_error = _validate_oidc_config(oidc_config)

    if oidc_error:
        log_error(oidc_error)
        return 1

    if oidc_config:
        return _run_oidc_mode(oidc_config, port)

    # Fall back to secret path mode
    secret_path = get_or_create_secret_path(data_dir, custom_secret_path)
    return _run_secret_path_mode(secret_path, port)


if __name__ == "__main__":
    sys.exit(main())
