"""Tests for axioms_flask.methodview module."""

import json
import time
from functools import wraps

import pytest
from flask import Flask, jsonify
from jwcrypto import jwk, jwt

from axioms_flask.decorators import (
    has_required_permissions,
    has_required_roles,
    has_required_scopes,
    has_valid_access_token,
)
from axioms_flask.error import register_axioms_error_handler
from axioms_flask.methodview import MethodView


def generate_test_keys():
    """Generate RSA key pair for JWT signing and verification."""
    key = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key-id")
    return key


def get_mock_jwks(key):
    """Generate mock JWKS response."""
    public_key = key.export_public(as_dict=True)
    return {"keys": [public_key]}


def generate_jwt_token(key, claims):
    """Generate a JWT token with specified claims."""
    token = jwt.JWT(header={"alg": "RS256", "kid": key.kid, "typ": "JWT"}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


@pytest.fixture
def test_key():
    """Generate test RSA key."""
    return generate_test_keys()


@pytest.fixture
def mock_jwks_data(test_key):
    """Generate mock JWKS data."""
    return json.dumps(get_mock_jwks(test_key)).encode("utf-8")


@pytest.fixture(autouse=True)
def mock_jwks_fetch(monkeypatch, mock_jwks_data):
    """Mock JWKS fetch to return test keys."""
    import axioms_core.helper as helper

    # Mock the JWKS manager's get_jwks method
    def mock_get_jwks(url):
        return mock_jwks_data

    monkeypatch.setattr(helper._jwks_manager, "get_jwks", mock_get_jwks)


class TestBasicMethodView:
    """Test basic MethodView functionality without decorators."""

    def test_methodview_get(self):
        """Test basic GET method on MethodView."""
        app = Flask(__name__)

        class BasicAPI(MethodView):
            def get(self):
                return jsonify({"method": "GET"})

        app.add_url_rule("/api/basic", view_func=BasicAPI.as_view("basic_api"))

        client = app.test_client()
        response = client.get("/api/basic")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["method"] == "GET"

    def test_methodview_post(self):
        """Test basic POST method on MethodView."""
        app = Flask(__name__)

        class BasicAPI(MethodView):
            def post(self):
                return jsonify({"method": "POST"})

        app.add_url_rule(
            "/api/basic", view_func=BasicAPI.as_view("basic_api"), methods=["POST"]
        )

        client = app.test_client()
        response = client.post("/api/basic")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["method"] == "POST"

    def test_methodview_multiple_methods(self):
        """Test MethodView with multiple HTTP methods."""
        app = Flask(__name__)

        class MultiMethodAPI(MethodView):
            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST"})

            def put(self):
                return jsonify({"method": "PUT"})

            def delete(self):
                return jsonify({"method": "DELETE"})

        app.add_url_rule(
            "/api/multi",
            view_func=MultiMethodAPI.as_view("multi_api"),
            methods=["GET", "POST", "PUT", "DELETE"],
        )

        client = app.test_client()

        # Test all methods
        for method in ["get", "post", "put", "delete"]:
            response = getattr(client, method)("/api/multi")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["method"] == method.upper()


class TestMethodViewWithClassDecorators:
    """Test MethodView with class-level decorators."""

    def test_class_level_decorator(self, test_key):
        """Test class-level decorator applies to all methods."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class ProtectedAPI(MethodView):
            decorators = [has_valid_access_token]

            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST"})

        app.add_url_rule(
            "/api/protected",
            view_func=ProtectedAPI.as_view("protected_api"),
            methods=["GET", "POST"],
        )

        client = app.test_client()

        # Without token, both methods should fail
        assert client.get("/api/protected").status_code == 401
        assert client.post("/api/protected").status_code == 401

        # With valid token, both should succeed
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }
        )
        token = generate_jwt_token(test_key, claims)

        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/protected", headers=headers).status_code == 200
        assert client.post("/api/protected", headers=headers).status_code == 200


class TestMethodViewWithMethodSpecificDecorators:
    """Test MethodView with method-specific decorators."""

    def test_method_specific_decorator(self, test_key):
        """Test method-specific decorators via _decorators attribute."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class UserAPI(MethodView):
            decorators = [has_valid_access_token]
            _decorators = {
                "post": [has_required_permissions(["user:create"])],
                "delete": [has_required_permissions(["user:delete"])],
            }

            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST", "action": "created"})

            def delete(self):
                return jsonify({"method": "DELETE", "action": "deleted"})

        app.add_url_rule(
            "/api/users",
            view_func=UserAPI.as_view("user_api"),
            methods=["GET", "POST", "DELETE"],
        )

        client = app.test_client()

        # Token with no permissions - only GET should work
        claims_no_perms = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }
        )
        token_no_perms = generate_jwt_token(test_key, claims_no_perms)
        headers_no_perms = {"Authorization": f"Bearer {token_no_perms}"}

        assert client.get("/api/users", headers=headers_no_perms).status_code == 200
        assert client.post("/api/users", headers=headers_no_perms).status_code == 403
        assert client.delete("/api/users", headers=headers_no_perms).status_code == 403

        # Token with user:create permission - GET and POST should work
        claims_create = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "permissions": ["user:create"],
            }
        )
        token_create = generate_jwt_token(test_key, claims_create)
        headers_create = {"Authorization": f"Bearer {token_create}"}

        assert client.get("/api/users", headers=headers_create).status_code == 200
        assert client.post("/api/users", headers=headers_create).status_code == 200
        assert client.delete("/api/users", headers=headers_create).status_code == 403

        # Token with user:delete permission - GET and DELETE should work
        claims_delete = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "permissions": ["user:delete"],
            }
        )
        token_delete = generate_jwt_token(test_key, claims_delete)
        headers_delete = {"Authorization": f"Bearer {token_delete}"}

        assert client.get("/api/users", headers=headers_delete).status_code == 200
        assert client.post("/api/users", headers=headers_delete).status_code == 403
        assert client.delete("/api/users", headers=headers_delete).status_code == 200

    def test_multiple_method_specific_decorators(self, test_key):
        """Test multiple decorators on a single method."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class AdminAPI(MethodView):
            decorators = [has_valid_access_token]
            _decorators = {
                "post": [
                    has_required_roles(["admin"]),
                    has_required_permissions(["resource:create"]),
                ]
            }

            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST", "action": "created"})

        app.add_url_rule(
            "/api/admin",
            view_func=AdminAPI.as_view("admin_api"),
            methods=["GET", "POST"],
        )

        client = app.test_client()

        # Token with only role - should fail
        claims_role_only = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "roles": ["admin"],
            }
        )
        token_role_only = generate_jwt_token(test_key, claims_role_only)
        headers_role_only = {"Authorization": f"Bearer {token_role_only}"}

        assert client.get("/api/admin", headers=headers_role_only).status_code == 200
        assert client.post("/api/admin", headers=headers_role_only).status_code == 403

        # Token with only permission - should fail
        claims_perm_only = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "permissions": ["resource:create"],
            }
        )
        token_perm_only = generate_jwt_token(test_key, claims_perm_only)
        headers_perm_only = {"Authorization": f"Bearer {token_perm_only}"}

        assert client.get("/api/admin", headers=headers_perm_only).status_code == 200
        assert client.post("/api/admin", headers=headers_perm_only).status_code == 403

        # Token with both role and permission - should succeed
        claims_both = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "roles": ["admin"],
                "permissions": ["resource:create"],
            }
        )
        token_both = generate_jwt_token(test_key, claims_both)
        headers_both = {"Authorization": f"Bearer {token_both}"}

        assert client.get("/api/admin", headers=headers_both).status_code == 200
        assert client.post("/api/admin", headers=headers_both).status_code == 200

    def test_different_decorators_per_method(self, test_key):
        """Test different decorators for different HTTP methods."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class ResourceAPI(MethodView):
            decorators = [has_valid_access_token]
            _decorators = {
                "get": [has_required_scopes(["read"])],
                "post": [has_required_roles(["creator"])],
                "put": [has_required_permissions(["resource:update"])],
            }

            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST"})

            def put(self):
                return jsonify({"method": "PUT"})

        app.add_url_rule(
            "/api/resource",
            view_func=ResourceAPI.as_view("resource_api"),
            methods=["GET", "POST", "PUT"],
        )

        client = app.test_client()

        # Token with scope - only GET should work
        claims_scope = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "scope": "read",
            }
        )
        token_scope = generate_jwt_token(test_key, claims_scope)
        headers_scope = {"Authorization": f"Bearer {token_scope}"}

        assert client.get("/api/resource", headers=headers_scope).status_code == 200
        assert client.post("/api/resource", headers=headers_scope).status_code == 403
        assert client.put("/api/resource", headers=headers_scope).status_code == 403

        # Token with role - only POST should work
        claims_role = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "roles": ["creator"],
            }
        )
        token_role = generate_jwt_token(test_key, claims_role)
        headers_role = {"Authorization": f"Bearer {token_role}"}

        assert client.get("/api/resource", headers=headers_role).status_code == 403
        assert client.post("/api/resource", headers=headers_role).status_code == 200
        assert client.put("/api/resource", headers=headers_role).status_code == 403

        # Token with permission - only PUT should work
        claims_perm = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "permissions": ["resource:update"],
            }
        )
        token_perm = generate_jwt_token(test_key, claims_perm)
        headers_perm = {"Authorization": f"Bearer {token_perm}"}

        assert client.get("/api/resource", headers=headers_perm).status_code == 403
        assert client.post("/api/resource", headers=headers_perm).status_code == 403
        assert client.put("/api/resource", headers=headers_perm).status_code == 200


class TestMethodViewWithoutMethodSpecificDecorators:
    """Test MethodView when _decorators is not defined for certain methods."""

    def test_method_without_specific_decorator(self, test_key):
        """Test method without specific decorator still works with class decorators."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class MixedAPI(MethodView):
            decorators = [has_valid_access_token]
            _decorators = {
                "post": [has_required_permissions(["create"])],
                # GET has no specific decorator
            }

            def get(self):
                return jsonify({"method": "GET"})

            def post(self):
                return jsonify({"method": "POST"})

        app.add_url_rule(
            "/api/mixed",
            view_func=MixedAPI.as_view("mixed_api"),
            methods=["GET", "POST"],
        )

        client = app.test_client()

        # Token without permission
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }
        )
        token = generate_jwt_token(test_key, claims)
        headers = {"Authorization": f"Bearer {token}"}

        # GET should work (only class decorator)
        assert client.get("/api/mixed", headers=headers).status_code == 200

        # POST should fail (needs permission)
        assert client.post("/api/mixed", headers=headers).status_code == 403


class TestMethodViewEdgeCases:
    """Test edge cases and error handling."""

    def test_methodview_with_empty_decorators(self):
        """Test MethodView with empty _decorators dict."""
        app = Flask(__name__)

        class EmptyDecoratorsAPI(MethodView):
            _decorators = {}

            def get(self):
                return jsonify({"method": "GET"})

        app.add_url_rule(
            "/api/empty", view_func=EmptyDecoratorsAPI.as_view("empty_api")
        )

        client = app.test_client()
        response = client.get("/api/empty")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["method"] == "GET"

    def test_methodview_with_url_parameters(self, test_key):
        """Test MethodView with URL parameters."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_JWKS_URL"] = (
            "https://test-domain.com/.well-known/jwks.json"
        )
        app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"
        register_axioms_error_handler(app)

        class ItemAPI(MethodView):
            decorators = [has_valid_access_token]
            _decorators = {"delete": [has_required_permissions(["item:delete"])]}

            def get(self, item_id):
                return jsonify({"item_id": item_id, "method": "GET"})

            def delete(self, item_id):
                return jsonify({"item_id": item_id, "method": "DELETE"})

        app.add_url_rule(
            "/api/items/<int:item_id>",
            view_func=ItemAPI.as_view("item_api"),
            methods=["GET", "DELETE"],
        )

        client = app.test_client()

        # Token with permission
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "permissions": ["item:delete"],
            }
        )
        token = generate_jwt_token(test_key, claims)
        headers = {"Authorization": f"Bearer {token}"}

        # Test GET with URL parameter
        response = client.get("/api/items/123", headers=headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["item_id"] == 123

        # Test DELETE with URL parameter
        response = client.delete("/api/items/456", headers=headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["item_id"] == 456
