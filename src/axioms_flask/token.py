import json
import ssl
import jwt
from jwcrypto import jwk, jws
from flask import request
from flask import current_app as app
from werkzeug.contrib.cache import SimpleCache
from datetime import datetime
from six.moves.urllib.request import urlopen
from box import Box
from .error import AxiomsError

cache = SimpleCache()


def has_bearer_token(request_obj):
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
    kid = jwt.get_unverified_header(token)["kid"]
    key = get_key_from_jwks_json(app.config["AXIOMS_DOMAIN"], kid)
    payload = check_token_validity(token, key)
    if payload and app.config["AXIOMS_AUDIENCE"] in payload.aud:
        request.auth_jwt = payload
        return True
    else:
        raise AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid access token"}, 401
        )


def check_token_validity(token, key):
    payload = get_payload_from_token(token, key)
    now = datetime.utcnow().timestamp()
    if payload and (now <= payload.exp):
        return payload
    else:
        return False


def get_payload_from_token(token, key):
    jws_token = jws.JWS()
    jws_token.deserialize(token)
    try:
        jws_token.verify(key)
        return Box(json.loads(jws_token.payload))
    except jws.InvalidJWSSignature:
        return None


def check_scopes(provided_scopes, required_scopes):
    if not required_scopes:
        return True

    token_scopes = set(provided_scopes.split())
    scopes = set(required_scopes)
    return len(token_scopes.intersection(scopes)) > 0


def check_roles(token_roles, view_roles):
    if not view_roles:
        return True

    token_roles = set(token_roles)
    view_roles = set(view_roles)
    return len(token_roles.intersection(view_roles)) > 0


def check_permissions(token_permissions, view_permissions):
    if not view_permissions:
        return True

    token_permissions = set(token_permissions)
    view_permissions = set(view_permissions)
    return len(token_permissions.intersection(view_permissions)) > 0


def get_key_from_jwks_json(tenant, kid):
    fetcher = CacheFetcher()
    data = fetcher.fetch("https://" + tenant + "/oauth2/.well-known/jwks.json", 600)
    try:
        key = jwk.JWKSet().from_json(data).get_key(kid)
        return key
    except Exception:
        raise AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid access token"}, 401
        )


class CacheFetcher:
    def fetch(self, url, max_age=300):
        # Redis cache
        cached = cache.get("jwks" + url)
        if cached:
            return cached
        # Retrieve and cache
        context = ssl._create_unverified_context()
        data = urlopen(url, context=context).read()
        cache.set("jwks" + url, data, timeout=max_age)
        return data
