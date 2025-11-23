"""Middleware for Flask request authentication.

Provides before_request handler to extract and validate JWT tokens,
setting request-scoped attributes for use in route handlers.
"""

import logging

import jwt as pyjwt
from axioms_core import (
    ALLOWED_ALGORITHMS,
    AxiomsError,
    check_token_validity,
    get_expected_issuer,
    get_key_from_jwks_json,
)
from flask import Flask, g, request

from .config import get_config

logger = logging.getLogger(__name__)


def setup_token_middleware(app: Flask) -> None:
    """Set up middleware to extract and validate JWT tokens on every request.

    This function registers a before_request handler that:
    1. Extracts JWT token from Authorization header
    2. Validates token signature, expiration, audience, and issuer
    3. Sets request-scoped attributes on flask.g for route handlers

    Args:
        app: Flask application instance.

    Example:
        Basic usage::

            from flask import Flask, g
            from axioms_flask import init_axioms, setup_token_middleware

            app = Flask(__name__)
            init_axioms(app, AXIOMS_AUDIENCE='my-api', AXIOMS_ISS_URL='...')
            setup_token_middleware(app)

            @app.route('/protected')
            def protected():
                if g.auth_jwt:
                    return {'user': g.auth_jwt.sub}
                return {'error': 'Unauthorized'}, 401

    Request Attributes Set:
        ``g.auth_jwt``: Token payload as Box object if valid, False if invalid, None if missing
        ``g.missing_auth_header``: True if Authorization header is absent
        ``g.invalid_bearer_token``: True if Authorization header format is invalid

    Note:

        - This middleware does NOT reject requests - it only sets attributes
        - Route handlers decide whether to allow access based on ``g.auth_jwt``
        - Requires ``init_axioms()`` to be called first for configuration
    """

    @app.before_request
    def extract_and_validate_token():
        """Extract and validate JWT token from Authorization header."""
        # Initialize attributes
        g.auth_jwt = None
        g.missing_auth_header = False
        g.invalid_bearer_token = False

        # Get configuration
        config = get_config()
        if not config:
            logger.warning("Axioms config not available - skipping token validation")
            return

        # Extract Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            g.missing_auth_header = True
            return

        # Parse Bearer token
        try:
            scheme, _, token = auth_header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                g.invalid_bearer_token = True
                return
            token = token.strip()
        except (ValueError, AttributeError):
            g.invalid_bearer_token = True
            return

        # Validate token
        try:
            # Get token header
            try:
                header = pyjwt.get_unverified_header(token)
            except Exception as e:
                logger.debug(f"Invalid token header: {e}")
                g.auth_jwt = False
                return

            # Validate algorithm
            alg = header.get("alg")
            if not alg or alg not in ALLOWED_ALGORITHMS:
                logger.debug(f"Invalid or unsupported algorithm: {alg}")
                g.auth_jwt = False
                return

            # Get key ID
            kid = header.get("kid")
            if not kid:
                logger.debug("Missing key ID in token header")
                g.auth_jwt = False
                return

            # Get public key from JWKS
            key = get_key_from_jwks_json(kid, config)

            # Get expected values
            audience = (
                config.get("AXIOMS_AUDIENCE")
                if hasattr(config, "get")
                else getattr(config, "AXIOMS_AUDIENCE", None)
            )
            expected_issuer = get_expected_issuer(config)

            # Validate token
            payload = check_token_validity(
                token=token,
                key=key,
                alg=alg,
                audience=audience,
                issuer=expected_issuer,
            )

            if payload:
                g.auth_jwt = payload
            else:
                g.auth_jwt = False

        except AxiomsError as e:
            logger.debug(f"Token validation failed: {e.error}")
            g.auth_jwt = False
        except Exception as e:
            logger.exception(f"Unexpected error during token validation: {e}")
            g.auth_jwt = False
