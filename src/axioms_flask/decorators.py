from functools import wraps
from flask import Flask, jsonify, request
from flask import current_app as app
from .error import AxiomsError
from .token import has_bearer_token, has_valid_token, check_scopes

def has_required_scopes(*required_scopes):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            payload = getattr(request, 'auth_jwt', None)
            if payload is None:
                raise AxiomsError({"code": "invalid_authorization_token",
                                "description": "Invalid Authorization Token"}, 401)
            if check_scopes(payload.scope, required_scopes[0]):
                    return fn(*args, **kwargs)
            raise AxiomsError({"code": "unauthorized_access",
                               "description": "Unauthorized access"}, 403)
        return wrapper
    return decorator

def is_authenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            app.config["AXIOMS_DOMAIN"]
            app.config["AXIOMS_AUDIENCE"]
            app.config["URL_LIB_SSL_IGNORE"]
        except KeyError as e:
            raise Exception("Please set value for {} in a .env file. For more details review axioms-flask-py docs."
                           .format(e))
        token = has_bearer_token(request)
        if token and has_valid_token(token):
            return fn(*args, **kwargs)
        else:
            raise AxiomsError({"code": "invalid_authorization_token",
                               "description": "Invalid Authorization Token"}, 401)
    return wrapper