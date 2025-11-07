"""Token validation and JWT verification for Axioms authentication.

Configuration:
    ==================  ========  ===========================================================
    Parameter           Required  Description
    ==================  ========  ===========================================================
    AXIOMS_AUDIENCE     Yes       Expected audience claim in the JWT token.
    AXIOMS_JWKS_URL     No        Full URL to JWKS endpoint (e.g.,
                                  https://my-auth.domain.com/oauth2/.well-known/jwks.json).
                                  If provided, this takes precedence over AXIOMS_DOMAIN.
    AXIOMS_DOMAIN       No        Axioms domain name. If AXIOMS_JWKS_URL is not provided,
                                  the JWKS URL will be constructed as:
                                  https://{AXIOMS_DOMAIN}/oauth2/.well-known/jwks.json
    ==================  ========  ===========================================================

Note:
    Either AXIOMS_JWKS_URL or AXIOMS_DOMAIN must be configured for token validation.
"""

import json
import ssl
import time
import jwt
from jwcrypto import jwk, jws
from flask import request
from flask import current_app as app
from urllib.request import urlopen
from box import Box
from .error import AxiomsError


class SimpleCache:
    """Simple in-memory cache with timeout support."""

    def __init__(self):
        """Initialize the cache storage."""
        self._cache = {}

    def get(self, key):
        """Get value from cache if not expired.

        Args:
            key: Cache key to retrieve.

        Returns:
            Cached value or None if not found or expired.
        """
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry is None or time.time() < expiry:
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key, value, timeout=300):
        """Set value in cache with optional timeout.

        Args:
            key: Cache key to store.
            value: Value to cache.
            timeout: Expiration timeout in seconds (default: 300).
        """
        expiry = time.time() + timeout if timeout else None
        self._cache[key] = (value, expiry)


cache = SimpleCache()


def has_bearer_token(request_obj):
    """Extract and validate bearer token from request Authorization header.

    Args:
        request_obj: Flask request object containing HTTP headers.

    Returns:
        str: The extracted bearer token.

    Raises:
        AxiomsError: If Authorization header is missing, invalid, or malformed.
    """
    header_name = "Authorization"
    token_prefix = "bearer"
    auth_header = request_obj.headers.get(header_name, None)
    if auth_header is None:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Missing Authorization Header",
            },
            401,
        )
    try:
        bearer, _, token = auth_header.partition(" ")
        if bearer.lower() == token_prefix and token != "":
            return token
        else:
            raise AxiomsError(
                {
                    "error": "unauthorized_access",
                    "error_description": "Invalid Authorization Bearer",
                },
                401,
            )
    except (ValueError, AttributeError):
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid Authorization Header",
            },
            401,
        )


def has_valid_token(token):
    """Validate JWT token and verify audience claim.

    Extracts the key ID from the token, retrieves the public key from JWKS,
    validates the token signature and expiration, and checks the audience claim.

    Args:
        token: JWT token string to validate.

    Returns:
        bool: True if token is valid and audience matches.

    Raises:
        AxiomsError: If token is invalid or audience doesn't match.
    """
    kid = jwt.get_unverified_header(token)["kid"]
    key = get_key_from_jwks_json(kid)
    payload = check_token_validity(token, key)
    if payload and app.config["AXIOMS_AUDIENCE"] in payload.aud:
        request.auth_jwt = payload
        return True
    else:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )


def check_token_validity(token, key):
    """Verify token signature and check expiration.

    Args:
        token: JWT token string to validate.
        key: Public key for signature verification.

    Returns:
        Box or bool: Token payload as Box object if valid, False otherwise.
    """
    payload = get_payload_from_token(token, key)
    now = time.time()
    if payload and (now <= payload.exp):
        return payload
    else:
        return False


def get_payload_from_token(token, key):
    """Extract and verify JWT payload.

    Args:
        token: JWT token string.
        key: Public key for signature verification.

    Returns:
        Box or None: Token payload as Box object if signature is valid, None otherwise.
    """
    jws_token = jws.JWS()
    jws_token.deserialize(token)
    try:
        jws_token.verify(key)
        return Box(json.loads(jws_token.payload))
    except jws.InvalidJWSSignature:
        return None


def check_scopes(provided_scopes, required_scopes):
    """Check if any required scopes are present in provided scopes.

    Args:
        provided_scopes: Space-separated string of scopes from the token.
        required_scopes: Iterable of required scope strings.

    Returns:
        bool: True if any required scope is present in provided scopes.
    """
    if not required_scopes:
        return True

    token_scopes = set(provided_scopes.split())
    scopes = set(required_scopes)
    return len(token_scopes.intersection(scopes)) > 0


def check_roles(token_roles, view_roles):
    """Check if any required roles are present in token roles.

    Args:
        token_roles: List or iterable of roles from the token.
        view_roles: List or iterable of required role strings.

    Returns:
        bool: True if any required role is present in token roles.
    """
    if not view_roles:
        return True

    token_roles = set(token_roles)
    view_roles = set(view_roles)
    return len(token_roles.intersection(view_roles)) > 0


def check_permissions(token_permissions, view_permissions):
    """Check if any required permissions are present in token permissions.

    Args:
        token_permissions: List or iterable of permissions from the token.
        view_permissions: List or iterable of required permission strings.

    Returns:
        bool: True if any required permission is present in token permissions.
    """
    if not view_permissions:
        return True

    token_permissions = set(token_permissions)
    view_permissions = set(view_permissions)
    return len(token_permissions.intersection(view_permissions)) > 0


def get_jwks_url():
    """Get JWKS URL from application config.

    Checks for AXIOMS_JWKS_URL first, then constructs URL from AXIOMS_DOMAIN.

    Returns:
        str: Full JWKS URL.

    Raises:
        Exception: If neither AXIOMS_JWKS_URL nor AXIOMS_DOMAIN is configured.
    """
    jwks_url = app.config.get("AXIOMS_JWKS_URL")
    if jwks_url:
        return jwks_url

    domain = app.config.get("AXIOMS_DOMAIN")
    if domain:
        return f"https://{domain}/oauth2/.well-known/jwks.json"

    raise Exception(
        "Please set either AXIOMS_JWKS_URL or AXIOMS_DOMAIN in your config. "
        "For more details review axioms-flask-py docs."
    )


def get_key_from_jwks_json(kid):
    """Retrieve public key from JWKS endpoint for token verification.

    Args:
        kid: Key ID from the JWT header.

    Returns:
        JWK: JSON Web Key for signature verification.

    Raises:
        AxiomsError: If key cannot be retrieved or is invalid.
    """
    fetcher = CacheFetcher()
    jwks_url = get_jwks_url()
    data = fetcher.fetch(jwks_url, 600)
    try:
        key = jwk.JWKSet().from_json(data).get_key(kid)
        return key
    except Exception:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )


class CacheFetcher:
    """Cache fetcher for JWKS data with simple in-memory caching."""

    def fetch(self, url, max_age=300):
        """Fetch URL data with caching.

        Args:
            url: URL to fetch.
            max_age: Cache timeout in seconds (default: 300).

        Returns:
            bytes: Fetched data from URL or cache.
        """
        # Redis cache
        cached = cache.get("jwks" + url)
        if cached:
            return cached
        # Retrieve and cache
        context = ssl._create_unverified_context()
        data = urlopen(url, context=context).read()
        cache.set("jwks" + url, data, timeout=max_age)
        return data
