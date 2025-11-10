"""Token validation and JWT verification for Axioms authentication.

This module handles JWT token validation, signature verification, JWKS key retrieval,
and claim extraction. It supports configurable claim names to work with different
authorization servers (AWS Cognito, Auth0, Okta, etc.).

For complete configuration documentation, see the Configuration section in the API reference.
"""

import json
import ssl
import time
from urllib.request import urlopen

import jwt
from box import Box
from flask import current_app as app
from flask import request
from jwcrypto import jwk, jws

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

# Allowed signature algorithms for JWT validation
# Only asymmetric algorithms are allowed to prevent algorithm confusion attacks
ALLOWED_ALGORITHMS = frozenset(
    [
        "RS256",
        "RS384",
        "RS512",  # RSA with SHA-256, SHA-384, SHA-512
        "ES256",
        "ES384",
        "ES512",  # ECDSA with SHA-256, SHA-384, SHA-512
        "PS256",
        "PS384",
        "PS512",  # RSA-PSS with SHA-256, SHA-384, SHA-512
    ]
)


def get_claim_names(claim_type):
    """Get list of claim names to check for a given claim type.

    Checks configuration for custom claim names, falling back to defaults.
    Supports both single claim name and list of claim names.

    Args:
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').

    Returns:
        list: List of claim names to check in priority order.

    Example:

        >>> get_claim_names('ROLES')
        ['roles']
    """
    # Check if list configuration exists (e.g., AXIOMS_ROLES_CLAIMS)
    list_config = f"AXIOMS_{claim_type.upper()}_CLAIMS"
    if list_config in app.config:
        claims = app.config[list_config]
        return claims if isinstance(claims, list) else [claims]

    # Check single claim configuration (e.g., AXIOMS_ROLES_CLAIM)
    single_config = f"AXIOMS_{claim_type.upper()}_CLAIM"
    if single_config in app.config:
        return [app.config[single_config]]

    # Default claim names
    defaults = {"SCOPE": ["scope"], "ROLES": ["roles"], "PERMISSIONS": ["permissions"]}

    return defaults.get(claim_type.upper(), [])


def get_claim_from_token(payload, claim_type):
    """Extract claim value from token payload.

    Checks multiple possible claim names based on configuration,
    returning the first non-None value found.

    Args:
        payload: Decoded JWT token payload (Box object).
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').

    Returns:
        The claim value if found, None otherwise.

    Example:

        >>> get_claim_from_token(payload, 'ROLES')
        ['admin', 'editor']
    """
    for claim_name in get_claim_names(claim_type):
        value = getattr(
            payload,
            claim_name.replace(":", "_").replace("/", "_").replace("-", "_"),
            None,
        )
        if value is None:
            # Try with original claim name (for standard claims)
            try:
                value = payload.get(claim_name)
            except (AttributeError, KeyError):
                value = None
        if value is not None:
            return value
    return None


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
    """Validate JWT token and verify audience and issuer claims.

    Extracts the key ID from the token, retrieves the public key from JWKS,
    validates the token signature and expiration, and checks the audience claim.
    If issuer configuration is available, also validates the issuer claim.

    Args:
        token: JWT token string to validate.

    Returns:
        bool: True if token is valid and audience matches.

    Raises:
        AxiomsError: If token is invalid, audience doesn't match, or issuer doesn't match.
    """
    # Get and validate the token header
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid token header",
            },
            401,
        )

    # Validate algorithm - must be in allowed list to prevent algorithm confusion attacks
    alg = header.get("alg")
    if not alg or alg not in ALLOWED_ALGORITHMS:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": f"Invalid or unsupported algorithm: {alg}",
            },
            401,
        )

    kid = header.get("kid")
    if not kid:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Missing key ID in token header",
            },
            401,
        )

    key = get_key_from_jwks_json(kid)
    payload = check_token_validity(token, key, alg)

    if not payload:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )

    # Validate audience
    if app.config["AXIOMS_AUDIENCE"] not in payload.aud:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )

    # Validate issuer if configured
    expected_issuer = get_expected_issuer()
    if expected_issuer:
        token_issuer = getattr(payload, "iss", None)
        if not token_issuer:
            raise AxiomsError(
                {
                    "error": "unauthorized_access",
                    "error_description": "Missing issuer claim in token",
                },
                401,
            )
        if token_issuer != expected_issuer:
            raise AxiomsError(
                {
                    "error": "unauthorized_access",
                    "error_description": "Invalid issuer",
                },
                401,
            )

    request.auth_jwt = payload
    return True


def check_token_validity(token, key, alg):
    """Verify token signature and check expiration.

    Args:
        token: JWT token string to validate.
        key: Public key for signature verification.
        alg: Expected algorithm from token header (already validated).

    Returns:
        Box or bool: Token payload as Box object if valid, False otherwise.
    """
    payload = get_payload_from_token(token, key, alg)
    now = time.time()
    if payload and (now <= payload.exp):
        return payload
    else:
        return False


def get_payload_from_token(token, key, alg):
    """Extract and verify JWT payload with algorithm validation.

    Ensures the algorithm used for verification matches the algorithm specified
    in the JWT header, preventing algorithm confusion attacks.

    Args:
        token: JWT token string.
        key: Public key for signature verification.
        alg: Expected algorithm from token header (must match key's algorithm).

    Returns:
        Box or None: Token payload as Box object if signature is valid, None otherwise.
    """
    jws_token = jws.JWS()
    jws_token.deserialize(token)

    # Verify that the algorithm in the token matches what we expect
    # This prevents algorithm substitution attacks
    token_alg = jws_token.jose_header.get("alg")
    if token_alg != alg:
        return None

    try:
        # Verify signature with the expected algorithm
        # jwcrypto will ensure the key type matches the algorithm
        jws_token.verify(key, alg=alg)
        return Box(json.loads(jws_token.payload))
    except (jws.InvalidJWSSignature, Exception):
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


def get_expected_issuer():
    """Get expected issuer URL from application config.

    Checks for AXIOMS_ISS_URL first, then constructs from AXIOMS_DOMAIN.
    The issuer is used to validate the 'iss' claim in JWT tokens.

    Returns:
        str or None: Expected issuer URL (e.g., 'https://auth.example.com'),
                     or None if neither AXIOMS_ISS_URL nor AXIOMS_DOMAIN is configured.

    Example:
        >>> app.config['AXIOMS_ISS_URL'] = 'https://auth.example.com/oauth2'
        >>> get_expected_issuer()
        'https://auth.example.com/oauth2'

        >>> app.config['AXIOMS_DOMAIN'] = 'auth.example.com'
        >>> get_expected_issuer()
        'https://auth.example.com'
    """
    # Check for explicit issuer URL first
    iss_url = app.config.get("AXIOMS_ISS_URL")
    if iss_url:
        return iss_url

    # Construct from domain if available
    domain = app.config.get("AXIOMS_DOMAIN")
    if domain:
        return f"https://{domain}"

    return None


def get_jwks_url():
    """Get JWKS URL from application config.

    Checks for AXIOMS_JWKS_URL first, then constructs URL from AXIOMS_ISS_URL.
    If AXIOMS_ISS_URL is not set, it will be derived from AXIOMS_DOMAIN.

    Configuration hierarchy:
        1. AXIOMS_JWKS_URL (if set, used directly)
        2. AXIOMS_ISS_URL + /.well-known/jwks.json
        3. https://{AXIOMS_DOMAIN} + /.well-known/jwks.json (via AXIOMS_ISS_URL)

    Returns:
        str: Full JWKS URL.

    Raises:
        Exception: If JWKS URL cannot be determined from configuration.
    """
    # Check for explicit JWKS URL first
    jwks_url = app.config.get("AXIOMS_JWKS_URL")
    if jwks_url:
        return jwks_url

    # Construct from issuer URL
    issuer_url = get_expected_issuer()
    if issuer_url:
        return f"{issuer_url}/.well-known/jwks.json"

    raise Exception(
        "Please set either AXIOMS_JWKS_URL, AXIOMS_ISS_URL, or AXIOMS_DOMAIN in your config. "
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
