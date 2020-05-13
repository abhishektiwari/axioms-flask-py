from functools import wraps
from flask import Flask, jsonify, request
from flask import current_app as app
from .error import AxiomsError
from .token import (
    has_bearer_token,
    has_valid_token,
    check_scopes,
    check_roles,
    check_permissions,
)


def has_required_scopes(*required_scopes):
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
            if check_scopes(payload.scope, required_scopes[0]):
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
            token_roles = []
            token_roles = getattr(
                payload,
                "https://{}/claims/roles".format(app.config["AXIOMS_DOMAIN"]),
                [],
            )
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
            token_permissions = []
            token_permissions = getattr(
                payload,
                "https://{}/claims/permissions".format(app.config["AXIOMS_DOMAIN"]),
                [],
            )
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
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            app.config["AXIOMS_DOMAIN"]
            app.config["AXIOMS_AUDIENCE"]
        except KeyError as e:
            raise Exception(
                "🔥🔥 Please set value for {} in a .env file. For more details review axioms-flask-py docs.".format(
                    e
                )
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
