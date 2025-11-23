"""Configuration management for Axioms Flask integration.

Provides Flask-specific configuration initialization and management,
integrating with axioms-core-py's AxiomsConfig and JWKSManager.
"""

import logging
from typing import Any, Dict, Optional

from axioms_core import AxiomsConfig, initialize_jwks_manager, shutdown_jwks_manager
from flask import Flask, current_app

logger = logging.getLogger(__name__)

# Configuration key where AxiomsConfig instance is stored in Flask app.config
_AXIOMS_CONFIG_KEY = "_axioms_config"


def init_axioms(app: Flask, **kwargs) -> AxiomsConfig:
    """Initialize Axioms authentication for a Flask application.

    This function is OPTIONAL. If not called, axioms-flask-py will work using
    fallback JWKS fetching (on-demand fetch with caching). For better performance
    in production, call this function to enable background JWKS refresh.

    Args:
        app: Flask application instance.
        **kwargs: Optional override values for AxiomsConfig.
            If not provided, values are read from app.config.

    Returns:
        Initialized AxiomsConfig instance.

    Example:
        Basic usage (reads from app.config):
            from flask import Flask
            from axioms_flask import init_axioms

            app = Flask(__name__)
            app.config['AXIOMS_AUDIENCE'] = 'my-api'
            app.config['AXIOMS_DOMAIN'] = 'auth.example.com'
            init_axioms(app)

        With explicit configuration:
            init_axioms(
                app,
                AXIOMS_AUDIENCE='my-api',
                AXIOMS_DOMAIN='auth.example.com',
                AXIOMS_JWKS_REFRESH_INTERVAL=1800,
            )

    Note:
        Initializing enables:
        - Background JWKS refresh (default: every 3600 seconds)
        - Persistent httpx connection pool
        - Prefetch JWKS on startup
        - Consistent request latency (no blocking fetches)
    """
    # Build config from app.config if not provided in kwargs
    config_dict = {}

    # List of all AxiomsConfig fields
    config_fields = [
        "AXIOMS_DOMAIN",
        "AXIOMS_ISS_URL",
        "AXIOMS_AUDIENCE",
        "AXIOMS_JWKS_URL",
        "AXIOMS_TOKEN_TYPS",
        "AXIOMS_JWKS_REFRESH_INTERVAL",
        "AXIOMS_JWKS_CACHE_TTL",
        "AXIOMS_JWKS_PREFETCH",
        "AXIOMS_SCOPE_CLAIMS",
        "AXIOMS_ROLES_CLAIMS",
        "AXIOMS_PERMISSIONS_CLAIMS",
    ]

    # Extract from app.config, allow kwargs to override
    for field in config_fields:
        if field in kwargs:
            config_dict[field] = kwargs[field]
        elif field in app.config:
            config_dict[field] = app.config[field]

    # Create AxiomsConfig instance
    config = AxiomsConfig(**config_dict)

    # Store in Flask app.config for later retrieval
    app.config[_AXIOMS_CONFIG_KEY] = config

    # Initialize JWKS manager with config
    initialize_jwks_manager(
        config=config,
        refresh_interval=config.AXIOMS_JWKS_REFRESH_INTERVAL,
        cache_ttl=config.AXIOMS_JWKS_CACHE_TTL,
        prefetch=config.AXIOMS_JWKS_PREFETCH,
    )

    logger.info(
        f"Axioms initialized for Flask app with JWKS manager "
        f"(refresh_interval={config.AXIOMS_JWKS_REFRESH_INTERVAL}s, "
        f"cache_ttl={config.AXIOMS_JWKS_CACHE_TTL}s)"
    )

    return config


def get_config() -> Optional[Dict[str, Any]]:
    """Get Axioms configuration from Flask application context.

    Returns AxiomsConfig instance if init_axioms() was called, otherwise
    returns app.config dict for fallback compatibility.

    Returns:
        AxiomsConfig instance or Flask app.config dict, or None if no Flask context.

    Example:
        from axioms_flask.config import get_config
        config = get_config()
        if config:
            audience = config.get('AXIOMS_AUDIENCE')
    """
    try:
        # Try to get AxiomsConfig instance first (if init_axioms was called)
        if _AXIOMS_CONFIG_KEY in current_app.config:
            return current_app.config[_AXIOMS_CONFIG_KEY]
        # Fallback to app.config dict for backward compatibility
        return current_app.config
    except RuntimeError:
        # No Flask application context
        logger.debug("No Flask application context available")
        return None


def shutdown_axioms() -> None:
    """Shutdown Axioms JWKS manager and cleanup resources.

    This function is OPTIONAL. The JWKS manager will automatically cleanup
    on process exit. Call this if you need explicit shutdown control.

    Example:
        from axioms_flask import shutdown_axioms

        @app.teardown_appcontext
        def cleanup(error):
            shutdown_axioms()
    """
    shutdown_jwks_manager()
    logger.info("Axioms JWKS manager shutdown")
