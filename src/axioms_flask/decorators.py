"""Decorators for Flask route authentication and authorization.

This module provides decorators for protecting Flask routes with JWT-based authentication
and authorization. Supports scope-based, role-based, and permission-based access control
with configurable claim names for different authorization servers.

For complete configuration documentation, see the Configuration section in the API reference.
"""

from functools import wraps

from flask import current_app as app
from flask import request

from .error import AxiomsError
from .token import (
    check_permissions,
    check_roles,
    check_scopes,
    get_claim_from_token,
    has_bearer_token,
    has_valid_token,
)


def has_required_scopes(*required_scopes):
    """Decorator to enforce scope-based authorization.

    Checks if the authenticated user's token contains any of the required scopes.
    Uses OR logic: the token must have at least ONE of the specified scopes.

    To require ALL scopes (AND logic), chain multiple decorators.

    Args:
        *required_scopes: Variable length list of required scope strings.

    Returns:
        Callable: Decorated function that enforces scope check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required scopes.

    Example (OR logic - requires EITHER scope)::

        @app.route('/api/resource')
        @has_required_scopes('read:resource', 'write:resource')
        def protected_route():
            return {'data': 'protected'}

    Example (AND logic - requires BOTH scopes via chaining)::

        @app.route('/api/strict')
        @has_required_scopes('read:resource')
        @has_required_scopes('write:resource')
        def strict_route():
            return {'data': 'requires both scopes'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            payload = getattr(request, "auth_jwt", None)
            if payload is None:
                raise AxiomsError(
                    {
                        "error": "unauthorized_access",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get scope from configured claim names
            token_scope = get_claim_from_token(payload, "SCOPE") or ""

            if check_scopes(token_scope, required_scopes[0]):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def has_required_roles(*view_roles):
    """Decorator to enforce role-based authorization.

    Checks if the authenticated user's token contains any of the required roles.
    Uses OR logic: the token must have at least ONE of the specified roles.

    To require ALL roles (AND logic), chain multiple decorators.

    Args:
        *view_roles: Variable length list of required role strings.

    Returns:
        Callable: Decorated function that enforces role check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required roles.

    Example (OR logic - requires EITHER role)::

        @app.route('/admin/users')
        @has_required_roles('admin', 'superuser')
        def admin_route():
            return {'users': []}

    Example (AND logic - requires BOTH roles via chaining)::

        @app.route('/admin/critical')
        @has_required_roles('admin')
        @has_required_roles('superuser')
        def critical_route():
            return {'message': 'requires both roles'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            payload = getattr(request, "auth_jwt", None)
            if payload is None:
                raise AxiomsError(
                    {
                        "error": "unauthorized_access",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get roles from configured claim names
            token_roles = get_claim_from_token(payload, "ROLES") or []

            if check_roles(token_roles, view_roles[0]):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def has_required_permissions(*view_permissions):
    """Decorator to enforce permission-based authorization.

    Checks if the authenticated user's token contains any of the required permissions.
    Uses OR logic: the token must have at least ONE of the specified permissions.

    To require ALL permissions (AND logic), chain multiple decorators.

    Args:
        *view_permissions: Variable length list of required permission strings.

    Returns:
        Callable: Decorated function that enforces permission check.

    Raises:
        AxiomsError: If token is missing or doesn't contain required permissions.

    Example (OR logic - requires EITHER permission)::

        @app.route('/api/resource')
        @has_required_permissions('resource:read', 'resource:write')
        def resource_route():
            return {'data': 'success'}

    Example (AND logic - requires BOTH permissions via chaining)::

        @app.route('/api/critical')
        @has_required_permissions('resource:read')
        @has_required_permissions('resource:admin')
        def critical_route():
            return {'message': 'requires both permissions'}
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            payload = getattr(request, "auth_jwt", None)
            if payload is None:
                raise AxiomsError(
                    {
                        "error": "unauthorized_access",
                        "error_description": "Invalid Authorization Token",
                    },
                    401,
                )

            # Get permissions from configured claim names
            token_permissions = get_claim_from_token(payload, "PERMISSIONS") or []

            if check_permissions(token_permissions, view_permissions[0]):
                return fn(*args, **kwargs)
            raise AxiomsError(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
            )

        return wrapper

    return decorator


def has_valid_access_token(fn):
    """Decorator to enforce JWT token authentication.

    Validates the JWT access token in the Authorization header and sets
    the token payload in request.auth_jwt for use in the route handler.

    Required config:
        - AXIOMS_AUDIENCE: The expected audience claim
        - AXIOMS_JWKS_URL (or AXIOMS_DOMAIN): JWKS endpoint URL or domain

    Args:
        fn: The Flask route function to decorate.

    Returns:
        Callable: Decorated function that enforces token validation.

    Raises:
        AxiomsError: If token is missing or invalid.
        Exception: If required config is not set.

    Example::

        @app.route('/api/protected')
        @has_valid_access_token
        def protected_route():
            user_id = request.auth_jwt.sub
            return {'user_id': user_id}
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Check AXIOMS_AUDIENCE
        if "AXIOMS_AUDIENCE" not in app.config:
            raise Exception(
                "Please set AXIOMS_AUDIENCE in your config. "
                "For more details review axioms-flask-py docs."
            )

        # Check for JWKS URL or domain
        if "AXIOMS_JWKS_URL" not in app.config and "AXIOMS_DOMAIN" not in app.config:
            raise Exception(
                "Please set either AXIOMS_JWKS_URL or AXIOMS_DOMAIN in your config. "
                "For more details review axioms-flask-py docs."
            )
        token = has_bearer_token(request)
        if token and has_valid_token(token):
            return fn(*args, **kwargs)
        else:
            raise AxiomsError(
                {
                    "error": "unauthorized_access",
                    "error_description": "Invalid Authorization Token",
                },
                401,
            )

    return wrapper
