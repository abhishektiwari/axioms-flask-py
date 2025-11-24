"""Decorators for Flask route authentication and authorization.

This module provides decorators for protecting Flask routes with JWT-based authentication
and authorization. Supports scope-based, role-based, permission-based, and object-level
access control with configurable claim names for different authorization servers.

For complete configuration documentation, see the Configuration section in the API reference.
"""

from functools import wraps
from typing import Callable, Optional

import jwt as pyjwt
from axioms_core import (
    ALLOWED_ALGORITHMS,
    AxiomsError,
    check_permissions,
    check_roles,
    check_scopes,
    check_token_validity,
    get_claim_from_token,
    get_expected_issuer,
    get_key_from_jwks_json,
)
from axioms_core.config import get_config_value
from flask import current_app as app
from flask import g, request

from .config import get_config


def has_required_scopes(*required_scopes, safe_methods=None):
    """Decorator to enforce scope-based authorization.

    Checks if the authenticated user's token contains any of the required scopes.
    Uses OR logic: the token must have at least ONE of the specified scopes.

    To require ALL scopes (AND logic), chain multiple decorators.

    Args:
        *required_scopes: Variable length list of required scope strings.
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Callable: Decorated function that enforces scope check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required scopes.

    Example:
        OR logic - requires EITHER scope::

            @app.route('/api/resource')
            @has_required_scopes('read:resource', 'write:resource')
            def protected_route():
                return {'data': 'protected'}

    Example:
        AND logic - requires BOTH scopes via chaining::

            @app.route('/api/strict')
            @has_required_scopes('read:resource')
            @has_required_scopes('write:resource')
            def strict_route():
                return {'data': 'requires both scopes'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return fn(*args, **kwargs)

            payload = getattr(g, "auth_jwt", None)
            if payload is None or payload is False:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get scope from configured claim names
            token_scope = get_claim_from_token(payload, "SCOPE", config) or ""

            # Convert required_scopes to list if needed
            required = (
                list(required_scopes[0])
                if isinstance(required_scopes[0], (list, tuple))
                else list(required_scopes)
            )

            if check_scopes(token_scope, required):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_scope",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def has_required_roles(*view_roles, safe_methods=None):
    """Decorator to enforce role-based authorization.

    Checks if the authenticated user's token contains any of the required roles.
    Uses OR logic: the token must have at least ONE of the specified roles.

    To require ALL roles (AND logic), chain multiple decorators.

    Args:
        *view_roles: Variable length list of required role strings.
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Callable: Decorated function that enforces role check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required roles.

    Example:
        OR logic - requires EITHER role::

            @app.route('/admin/users')
            @has_required_roles('admin', 'superuser')
            def admin_route():
                return {'users': []}

    Example:
        AND logic - requires BOTH roles via chaining::

            @app.route('/admin/critical')
            @has_required_roles('admin')
            @has_required_roles('superuser')
            def critical_route():
                return {'message': 'requires both roles'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return fn(*args, **kwargs)

            payload = getattr(g, "auth_jwt", None)
            if payload is None or payload is False:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get roles from configured claim names
            token_roles = get_claim_from_token(payload, "ROLES", config) or []

            # Convert view_roles to list if needed
            required = (
                list(view_roles[0])
                if isinstance(view_roles[0], (list, tuple))
                else list(view_roles)
            )

            if check_roles(token_roles, required):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_scope",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def has_required_permissions(*view_permissions, safe_methods=None):
    """Decorator to enforce permission-based authorization.

    Checks if the authenticated user's token contains any of the required permissions.
    Uses OR logic: the token must have at least ONE of the specified permissions.

    To require ALL permissions (AND logic), chain multiple decorators.

    Args:
        *view_permissions: Variable length list of required permission strings.
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Callable: Decorated function that enforces permission check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required permissions.

    Example:
        OR logic - requires EITHER permission::

            @app.route('/api/resource')
            @has_required_permissions('resource:read', 'resource:write')
            def resource_route():
                return {'data': 'success'}

    Example:
        AND logic - requires BOTH permissions via chaining::

            @app.route('/api/critical')
            @has_required_permissions('resource:read')
            @has_required_permissions('resource:admin')
            def critical_route():
                return {'message': 'requires both permissions'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return fn(*args, **kwargs)

            payload = getattr(g, "auth_jwt", None)
            if payload is None or payload is False:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get permissions from configured claim names
            token_permissions = (
                get_claim_from_token(payload, "PERMISSIONS", config) or []
            )

            # Convert view_permissions to list if needed
            required = (
                list(view_permissions[0])
                if isinstance(view_permissions[0], (list, tuple))
                else list(view_permissions)
            )

            if check_permissions(token_permissions, required):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_scope",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def _has_bearer_token(request_obj):
    """Extract and validate bearer token from request Authorization header.

    Flask-specific wrapper for token extraction from request object.

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
                "error": "invalid_token",
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
                    "error": "invalid_token",
                    "error_description": "Invalid Authorization Bearer",
                },
                401,
            )
    except (ValueError, AttributeError):
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid Authorization Header",
            },
            401,
        )


def _has_valid_token(token):
    """Validate JWT token and verify audience and issuer claims.

    Flask-specific wrapper that validates token using axioms-core-py functions
    and stores the payload in g.auth_jwt.

    Args:
        token: JWT token string to validate.

    Returns:
        bool: True if token is valid and audience matches.

    Raises:
        AxiomsError: If token is invalid, audience doesn't match, or issuer doesn't match.
    """
    # Get configuration
    config = get_config()

    # Get and validate the token header
    try:
        header = pyjwt.get_unverified_header(token)
    except Exception:
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid token header",
            },
            401,
        )

    # Validate algorithm - must be in allowed list to prevent algorithm confusion attacks
    alg = header.get("alg")
    if not alg or alg not in ALLOWED_ALGORITHMS:
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": f"Invalid or unsupported algorithm: {alg}",
            },
            401,
        )

    kid = header.get("kid")
    if not kid:
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Missing key ID in token header",
            },
            401,
        )

    # Get key from JWKS (uses fallback if manager not initialized)
    key = get_key_from_jwks_json(kid, config)

    # Get expected audience and issuer
    audience = (
        config.get("AXIOMS_AUDIENCE")
        if hasattr(config, "get")
        else getattr(config, "AXIOMS_AUDIENCE", None)
    )
    expected_issuer = get_expected_issuer(config)

    # Validate token using core function
    payload = check_token_validity(
        token=token, key=key, alg=alg, audience=audience, issuer=expected_issuer
    )

    if not payload:
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid access token",
            },
            401,
        )

    # Store payload in Flask g object for route access
    g.auth_jwt = payload
    return True


def has_valid_access_token(fn=None, *, safe_methods=None):
    """Decorator to enforce JWT token authentication.

    Validates the JWT access token in the Authorization header and sets
    the token payload in g.auth_jwt for use in the route handler.

    Required config:
        - AXIOMS_AUDIENCE: The expected audience claim
        - AXIOMS_JWKS_URL (or AXIOMS_DOMAIN): JWKS endpoint URL or domain

    Args:
        fn: The Flask route function to decorate.
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Callable: Decorated function that enforces token validation.

    Raises:
        AxiomsError: If token is missing or invalid.
        Exception: If required config is not set.

    Example:
        Has valid access token::

            @app.route('/api/protected')
            @has_valid_access_token
            def protected_route():
                user_id = g.auth_jwt.sub
                return {'user_id': user_id}
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return func(*args, **kwargs)

            # Check AXIOMS_AUDIENCE
            if "AXIOMS_AUDIENCE" not in app.config:
                raise Exception(
                    "Please set AXIOMS_AUDIENCE in your config. "
                    "For more details review axioms-flask-py docs."
                )

            # Check for JWKS URL or domain
            if (
                "AXIOMS_JWKS_URL" not in app.config
                and "AXIOMS_DOMAIN" not in app.config
            ):
                raise Exception(
                    "Please set either AXIOMS_JWKS_URL or AXIOMS_DOMAIN in your config. "
                    "For more details review axioms-flask-py docs."
                )
            token = _has_bearer_token(request)
            if token and _has_valid_token(token):
                return func(*args, **kwargs)
            else:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

        return wrapper

    # Support both @has_valid_access_token and @has_valid_access_token()
    if fn is None:
        # Called with arguments: @has_valid_access_token()
        return decorator
    else:
        # Called without arguments: @has_valid_access_token
        return decorator(fn)


def check_object_ownership(
    get_object: Callable,
    owner_field: str = "user",
    claim_field: str = "sub",
    inject_as: Optional[str] = None,
    safe_methods: Optional[list] = None,
) -> Callable:
    """Decorator to enforce object-level permissions based on ownership.

    Verifies that the authenticated user owns the requested object by comparing
    a field on the object with a claim in the JWT token. Useful for implementing
    row-level security where users can only access their own data.

    Args:
        get_object: Callable that fetches the object. Receives same arguments as decorated function.
            Should raise 404 (abort(404)) if object not found.
        owner_field: Attribute/key name on the object containing owner identifier (default: "user").
        claim_field: Claim name in JWT token containing user identifier (default: "sub").
        inject_as: Optional parameter name to inject the fetched object into route handler.
            If None, object is not injected.
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Decorator function that enforces ownership checking.

    Raises:
        AxiomsError (401): If user is not authenticated.
        AxiomsError (400): If object is missing the owner_field.
        AxiomsError (403): If JWT is missing claim_field OR ownership check fails.
        404: If object not found (raised by get_object).

    Example:
        Basic usage with default fields::

            def get_article(article_id):
                article = Article.query.get(article_id)
                if not article:
                    abort(404)
                return article

            @app.patch('/articles/<int:article_id>')
            @check_object_ownership(get_article)
            def update_article(article_id):
                # Only owner can access
                # article.user must match token.sub
                article = get_article(article_id)
                article.title = request.json['title']
                db.session.commit()
                return {'id': article.id}

        With object injection::

            @app.patch('/articles/<int:article_id>')
            @check_object_ownership(get_article, inject_as='article')
            def update_article(article_id, article):
                # article is injected, no need to call get_article again
                article.title = request.json['title']
                db.session.commit()
                return {'id': article.id}

        Custom owner field::

            def get_comment(comment_id):
                comment = Comment.query.get(comment_id)
                if not comment:
                    abort(404)
                return comment

            @app.patch('/comments/<int:comment_id>')
            @check_object_ownership(get_comment, owner_field='created_by')
            def update_comment(comment_id):
                # comment.created_by must match token.sub
                pass

        Custom claim field (match by email)::

            @app.patch('/projects/<int:project_id>')
            @check_object_ownership(
                get_project,
                owner_field='owner_email',
                claim_field='email'
            )
            def update_project(project_id):
                # project.owner_email must match token.email
                pass

    Note:
        - Works with SQLAlchemy/SQLModel objects (uses getattr)
        - Works with dictionaries (uses .get())
        - Requires middleware or @has_valid_access_token decorator to set g.auth_jwt
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return f(*args, **kwargs)

            # Check authentication
            if not hasattr(g, "auth_jwt") or not g.auth_jwt:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Authentication required",
                    },
                    401,
                )

            # Fetch the object
            obj = get_object(*args, **kwargs)

            # Extract owner value from object
            if hasattr(obj, owner_field):
                # SQLAlchemy/SQLModel object
                owner_value = getattr(obj, owner_field)
            elif isinstance(obj, dict) and owner_field in obj:
                # Dictionary
                owner_value = obj[owner_field]
            else:
                # Object missing owner field
                raise AxiomsError(
                    {
                        "error": "invalid_request",
                        "error_description": f"Object does not have '{owner_field}' field",
                    },
                    400,
                )

            # Extract claim value from JWT
            payload = g.auth_jwt
            if hasattr(payload, claim_field):
                # Box object (attribute access)
                claim_value = getattr(payload, claim_field)
            elif isinstance(payload, dict) and claim_field in payload:
                # Dictionary
                claim_value = payload[claim_field]
            else:
                # JWT missing claim field
                raise AxiomsError(
                    {
                        "error": "insufficient_scope",
                        "error_description": f"Token does not have '{claim_field}' claim",
                    },
                    403,
                )

            # Check ownership
            if str(owner_value) != str(claim_value):
                raise AxiomsError(
                    {
                        "error": "insufficient_scope",
                        "error_description": "You do not have permission to access this resource",
                    },
                    403,
                )

            # Inject object into kwargs if requested
            if inject_as:
                kwargs[inject_as] = obj

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_ownership(
    owner_field: str = "user",
    claim_field: str = "sub",
    safe_methods: Optional[list] = None,
) -> Callable:
    """Decorator to check ownership of an object passed as function argument.

    Simpler alternative to check_object_ownership when the object is already
    fetched by the route handler. Checks ownership of the object passed as
    the first positional argument.

    Args:
        owner_field: Attribute/key name on object containing owner ID (default: "user").
        claim_field: Claim name in JWT containing user ID (default: "sub").
        safe_methods: List of HTTP methods that bypass authorization
            (default: from config AXIOMS_SAFE_METHODS or ['OPTIONS']).

    Returns:
        Decorator function.

    Example:
        Basic usage::

            @app.patch('/articles/<int:article_id>')
            @require_ownership(owner_field='user')
            def update_article(article_id):
                article = Article.query.get_or_404(article_id)
                # Ownership is checked against article
                article.title = request.json['title']
                db.session.commit()
                return {'id': article.id}
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get config
            config = get_config()

            # Skip authorization for safe methods (e.g., OPTIONS for CORS)
            default_safe_methods = get_config_value(
                config, "AXIOMS_SAFE_METHODS", ["OPTIONS"]
            )
            methods = safe_methods if safe_methods is not None else default_safe_methods
            if request.method in methods:
                return f(*args, **kwargs)

            # Check authentication
            if not hasattr(g, "auth_jwt") or not g.auth_jwt:
                raise AxiomsError(
                    {
                        "error": "invalid_token",
                        "error_description": "Authentication required",
                    },
                    401,
                )

            # Object should be first positional argument
            if not args:
                raise AxiomsError(
                    {
                        "error": "invalid_request",
                        "error_description": "No object provided to check ownership",
                    },
                    400,
                )

            obj = args[0]

            # Extract owner value
            if hasattr(obj, owner_field):
                owner_value = getattr(obj, owner_field)
            elif isinstance(obj, dict) and owner_field in obj:
                owner_value = obj[owner_field]
            else:
                raise AxiomsError(
                    {
                        "error": "invalid_request",
                        "error_description": f"Object does not have '{owner_field}' field",
                    },
                    400,
                )

            # Extract claim value
            payload = g.auth_jwt
            if hasattr(payload, claim_field):
                claim_value = getattr(payload, claim_field)
            elif isinstance(payload, dict) and claim_field in payload:
                claim_value = payload[claim_field]
            else:
                raise AxiomsError(
                    {
                        "error": "insufficient_scope",
                        "error_description": f"Token does not have '{claim_field}' claim",
                    },
                    403,
                )

            # Check ownership
            if str(owner_value) != str(claim_value):
                raise AxiomsError(
                    {
                        "error": "insufficient_scope",
                        "error_description": "You do not have permission to access this resource",
                    },
                    403,
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator
