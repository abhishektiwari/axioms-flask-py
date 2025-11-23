"""Tests for safe_methods parameter in axioms-flask decorators.

This module tests that decorators correctly bypass authorization checks
for safe HTTP methods (e.g., OPTIONS for CORS preflight requests).
"""

import json
import time

import pytest
from flask import Blueprint, Flask, jsonify, request
from jwcrypto import jwk, jwt

from axioms_flask.decorators import (
    check_object_ownership,
    has_required_permissions,
    has_required_roles,
    has_required_scopes,
    has_valid_access_token,
    require_ownership,
)
from axioms_flask.error import register_axioms_error_handler


# Generate RSA key pair for testing
def generate_test_keys():
    """Generate RSA key pair for JWT signing and verification."""
    key = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key-id")
    return key


# Mock JWKS response
def get_mock_jwks(key):
    """Generate mock JWKS response."""
    public_key = key.export_public(as_dict=True)
    return {"keys": [public_key]}


# Generate JWT token
def generate_jwt_token(key, claims):
    """Generate a JWT token with specified claims."""
    token = jwt.JWT(
        header={"alg": "RS256", "kid": key.kid, "typ": "JWT"}, claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()


# Dummy object for ownership tests
class DummyObject:
    """Dummy object for testing ownership decorators."""

    def __init__(self, user_id):
        self.user = user_id


# Create test Flask application
@pytest.fixture
def app():
    """Create Flask test application with protected routes."""
    flask_app = Flask(__name__)

    # Configuration
    flask_app.config["TESTING"] = True
    flask_app.config["AXIOMS_AUDIENCE"] = "test-audience"
    flask_app.config["AXIOMS_JWKS_URL"] = (
        "https://test-domain.com/.well-known/jwks.json"
    )
    flask_app.config["AXIOMS_ISS_URL"] = "https://test-domain.com"

    # Register error handler
    register_axioms_error_handler(flask_app)

    # Blueprint for testing has_valid_access_token
    auth_api = Blueprint("auth_api", __name__)

    @auth_api.route("/auth/default", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    def auth_default():
        return jsonify({"message": "Authenticated with default safe methods"})

    @auth_api.route("/auth/custom", methods=["GET", "HEAD"])
    @has_valid_access_token(safe_methods=["HEAD"])
    def auth_custom():
        return jsonify({"message": "Authenticated with custom safe methods"})

    # Blueprint for testing has_required_scopes
    scope_api = Blueprint("scope_api", __name__)

    @scope_api.route("/scope/default", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    @has_required_scopes(["admin:write"])
    def scope_default():
        return jsonify({"message": "Scope check with default safe methods"})

    @scope_api.route("/scope/custom", methods=["GET", "POST"])
    @has_valid_access_token(safe_methods=["POST"])
    @has_required_scopes(["admin:write"], safe_methods=["POST"])
    def scope_custom():
        return jsonify({"message": "Scope check with custom safe methods"})

    # Blueprint for testing has_required_roles
    role_api = Blueprint("role_api", __name__)

    @role_api.route("/role/default", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    @has_required_roles(["admin"])
    def role_default():
        return jsonify({"message": "Role check with default safe methods"})

    @role_api.route("/role/custom", methods=["GET", "PATCH"])
    @has_valid_access_token(safe_methods=["PATCH"])
    @has_required_roles(["admin"], safe_methods=["PATCH"])
    def role_custom():
        return jsonify({"message": "Role check with custom safe methods"})

    # Blueprint for testing has_required_permissions
    perm_api = Blueprint("perm_api", __name__)

    @perm_api.route("/perm/default", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    @has_required_permissions(["resource:delete"])
    def perm_default():
        return jsonify({"message": "Permission check with default safe methods"})

    @perm_api.route("/perm/custom", methods=["GET", "DELETE"])
    @has_valid_access_token(safe_methods=["DELETE"])
    @has_required_permissions(["resource:delete"], safe_methods=["DELETE"])
    def perm_custom():
        return jsonify({"message": "Permission check with custom safe methods"})

    # Blueprint for testing check_object_ownership
    ownership_api = Blueprint("ownership_api", __name__)

    def get_object(obj_id):
        """Mock function to fetch object."""
        return DummyObject(user_id="user123")

    @ownership_api.route("/ownership/default/<obj_id>", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    @check_object_ownership(get_object, owner_field="user", claim_field="sub")
    def ownership_default(obj_id):
        return jsonify({"message": "Ownership check with default safe methods"})

    @ownership_api.route("/ownership/custom/<obj_id>", methods=["GET", "PUT"])
    @has_valid_access_token(safe_methods=["PUT"])
    @check_object_ownership(
        get_object, owner_field="user", claim_field="sub", safe_methods=["PUT"]
    )
    def ownership_custom(obj_id):
        return jsonify({"message": "Ownership check with custom safe methods"})

    # Blueprint for testing require_ownership
    require_api = Blueprint("require_api", __name__)

    @require_api.route("/require/default/<obj_id>", methods=["GET", "OPTIONS"])
    @has_valid_access_token
    @require_ownership(owner_field="user", claim_field="sub")
    def require_default(obj_id):
        obj = DummyObject(user_id="user123")
        return jsonify({"message": "Require ownership with default safe methods"})

    @require_api.route("/require/custom/<obj_id>", methods=["GET", "DELETE"])
    @has_valid_access_token(safe_methods=["DELETE"])
    @require_ownership(owner_field="user", claim_field="sub", safe_methods=["DELETE"])
    def require_custom(obj_id):
        obj = DummyObject(user_id="user123")
        return jsonify({"message": "Require ownership with custom safe methods"})

    # Register blueprints
    flask_app.register_blueprint(auth_api)
    flask_app.register_blueprint(scope_api)
    flask_app.register_blueprint(role_api)
    flask_app.register_blueprint(perm_api)
    flask_app.register_blueprint(ownership_api)
    flask_app.register_blueprint(require_api)

    return flask_app


@pytest.fixture
def client(app):
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture
def test_key():
    """Generate test RSA key."""
    return generate_test_keys()


@pytest.fixture
def mock_jwks(test_key, monkeypatch):
    """Mock JWKS endpoint."""
    import requests

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
            self.text = json.dumps(json_data)

        def json(self):
            return self.json_data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.exceptions.HTTPError()

    def mock_get(*args, **kwargs):
        return MockResponse(get_mock_jwks(test_key))

    monkeypatch.setattr(requests, "get", mock_get)


class TestHasValidAccessTokenSafeMethods:
    """Test has_valid_access_token decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_auth(self, client, mock_jwks):
        """Test that OPTIONS method bypasses authentication by default."""
        response = client.options("/auth/default")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Authenticated with default safe methods"

    def test_default_non_safe_method_requires_auth(self, client, mock_jwks):
        """Test that non-safe methods require authentication."""
        response = client.get("/auth/default")
        assert response.status_code == 401

    def test_custom_safe_method_bypasses_auth(self, client, mock_jwks):
        """Test that custom safe method bypasses authentication."""
        response = client.head("/auth/custom")
        assert response.status_code == 200

    def test_custom_non_safe_method_requires_auth(self, client, mock_jwks):
        """Test that non-safe methods require auth with custom safe_methods."""
        response = client.get("/auth/custom")
        assert response.status_code == 401


class TestHasRequiredScopesSafeMethods:
    """Test has_required_scopes decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_scope_check(self, client, mock_jwks):
        """Test that OPTIONS method bypasses scope check by default."""
        response = client.options("/scope/default")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Scope check with default safe methods"

    def test_default_non_safe_method_requires_scope(
        self, client, mock_jwks, test_key
    ):
        """Test that non-safe methods require authentication."""
        # GET without auth should fail
        response = client.get("/scope/default")
        assert response.status_code == 401

    def test_custom_safe_method_bypasses_scope_check(self, client, mock_jwks):
        """Test that custom safe method bypasses scope check."""
        response = client.post("/scope/custom")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Scope check with custom safe methods"

    def test_custom_non_safe_method_requires_scope(
        self, client, mock_jwks, test_key
    ):
        """Test that non-safe methods require authentication with custom safe_methods."""
        # GET without auth should fail
        response = client.get("/scope/custom")
        assert response.status_code == 401


class TestHasRequiredRolesSafeMethods:
    """Test has_required_roles decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_role_check(self, client, mock_jwks):
        """Test that OPTIONS method bypasses role check by default."""
        response = client.options("/role/default")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Role check with default safe methods"

    def test_default_non_safe_method_requires_role(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication."""
        # GET without auth should fail
        response = client.get("/role/default")
        assert response.status_code == 401

    def test_custom_safe_method_bypasses_role_check(self, client, mock_jwks):
        """Test that custom safe method bypasses role check."""
        response = client.patch("/role/custom")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Role check with custom safe methods"

    def test_custom_non_safe_method_requires_role(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication with custom safe_methods."""
        # GET without auth should fail
        response = client.get("/role/custom")
        assert response.status_code == 401


class TestHasRequiredPermissionsSafeMethods:
    """Test has_required_permissions decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_permission_check(
        self, client, mock_jwks
    ):
        """Test that OPTIONS method bypasses permission check by default."""
        response = client.options("/perm/default")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Permission check with default safe methods"

    def test_default_non_safe_method_requires_permission(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication."""
        # GET without auth should fail
        response = client.get("/perm/default")
        assert response.status_code == 401

    def test_custom_safe_method_bypasses_permission_check(self, client, mock_jwks):
        """Test that custom safe method bypasses permission check."""
        response = client.delete("/perm/custom")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Permission check with custom safe methods"

    def test_custom_non_safe_method_requires_permission(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication with custom safe_methods."""
        # GET without auth should fail
        response = client.get("/perm/custom")
        assert response.status_code == 401


class TestCheckObjectOwnershipSafeMethods:
    """Test check_object_ownership decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_ownership_check(
        self, client, mock_jwks
    ):
        """Test that OPTIONS method bypasses ownership check by default."""
        response = client.options("/ownership/default/123")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Ownership check with default safe methods"

    def test_default_non_safe_method_requires_ownership(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication."""
        # GET without auth should fail
        response = client.get("/ownership/default/123")
        assert response.status_code == 401

    def test_custom_safe_method_bypasses_ownership_check(self, client, mock_jwks):
        """Test that custom safe method bypasses ownership check."""
        response = client.put("/ownership/custom/123")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Ownership check with custom safe methods"

    def test_custom_non_safe_method_requires_ownership(self, client, mock_jwks, test_key):
        """Test that non-safe methods require authentication with custom safe_methods."""
        # GET without auth should fail
        response = client.get("/ownership/custom/123")
        assert response.status_code == 401


class TestRequireOwnershipSafeMethods:
    """Test require_ownership decorator with safe_methods."""

    def test_default_safe_method_options_bypasses_ownership_check(
        self, client, mock_jwks
    ):
        """Test that OPTIONS method bypasses ownership check by default."""
        response = client.options("/require/default/123")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Require ownership with default safe methods"

    def test_custom_safe_method_bypasses_ownership_check(self, client, mock_jwks):
        """Test that custom safe method bypasses ownership check."""
        response = client.delete("/require/custom/123")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["message"] == "Require ownership with custom safe methods"
