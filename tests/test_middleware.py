"""Tests for middleware token extraction and validation."""

import json
import time

import pytest
from flask import Flask, g, jsonify

from axioms_flask import (
    register_axioms_error_handler,
    setup_token_middleware,
)


@pytest.fixture
def test_app(test_key, mock_jwks_data, monkeypatch):
    """Create Flask app with middleware for testing."""
    import axioms_core.helper as helper

    # Mock JWKS fetch
    def mock_get_jwks(url):
        return mock_jwks_data

    monkeypatch.setattr(helper._jwks_manager, "get_jwks", mock_get_jwks)

    app = Flask(__name__)
    app.config["AXIOMS_AUDIENCE"] = "test-audience"
    app.config["AXIOMS_DOMAIN"] = "test-domain.com"
    app.config["TESTING"] = True

    # Setup middleware without init_axioms (for testing)
    setup_token_middleware(app)
    register_axioms_error_handler(app)

    # Add test routes
    @app.route("/public")
    def public():
        return jsonify({"message": "Public endpoint"})

    @app.route("/check-state")
    def check_state():
        """Route to inspect middleware state."""
        return jsonify(
            {
                "auth_jwt": (
                    dict(g.auth_jwt)
                    if g.auth_jwt and g.auth_jwt is not False
                    else g.auth_jwt
                ),
                "missing_auth_header": g.missing_auth_header,
                "invalid_bearer_token": g.invalid_bearer_token,
            }
        )

    @app.route("/protected")
    def protected():
        """Route that requires authentication."""
        if not g.auth_jwt:
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({"message": "Protected endpoint", "user": g.auth_jwt.sub})

    return app


def generate_jwt_token(test_key, claims_dict):
    """Generate a JWT token using test keys."""
    from jwcrypto import jwk, jws

    key = jwk.JWK(**test_key)
    token = jws.JWS(claims_dict.encode("utf-8"))
    token.add_signature(
        key,
        alg="RS256",
        protected=json.dumps({"alg": "RS256", "typ": "JWT", "kid": test_key["kid"]}),
    )
    return token.serialize(compact=True)


class TestMiddlewareTokenExtraction:
    """Test middleware token extraction and validation."""

    def test_public_endpoint_without_token(self, test_app):
        """Test that public endpoints work without token."""
        with test_app.test_client() as client:
            response = client.get("/public")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["message"] == "Public endpoint"

    def test_middleware_sets_missing_auth_header(self, test_app):
        """Test that middleware sets missing_auth_header when no Authorization header."""
        with test_app.test_client() as client:
            response = client.get("/check-state")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is None
            assert data["missing_auth_header"] is True
            assert data["invalid_bearer_token"] is False

    def test_middleware_sets_invalid_bearer_token_for_malformed_header(self, test_app):
        """Test that middleware detects malformed Bearer token."""
        with test_app.test_client() as client:
            response = client.get(
                "/check-state", headers={"Authorization": "NotBearer token123"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is None
            assert data["missing_auth_header"] is False
            assert data["invalid_bearer_token"] is True

    def test_middleware_sets_invalid_bearer_token_for_empty_token(self, test_app):
        """Test that middleware detects empty token."""
        with test_app.test_client() as client:
            response = client.get("/check-state", headers={"Authorization": "Bearer "})
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is None
            assert data["missing_auth_header"] is False
            assert data["invalid_bearer_token"] is True

    def test_middleware_validates_valid_token(self, test_app, test_key):
        """Test that middleware validates and extracts valid token."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "scope": "openid profile",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/check-state", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is not None
            assert data["auth_jwt"]["sub"] == "user123"
            assert data["missing_auth_header"] is False
            assert data["invalid_bearer_token"] is False

    def test_middleware_sets_false_for_expired_token(self, test_app, test_key):
        """Test that middleware sets auth_jwt=False for expired token."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now - 3600,  # Expired
                "iat": now - 7200,
            }
        )

        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/check-state", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is False
            assert data["missing_auth_header"] is False
            assert data["invalid_bearer_token"] is False

    def test_middleware_case_insensitive_bearer(self, test_app, test_key):
        """Test that Bearer scheme is case-insensitive."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            # Test lowercase
            response = client.get(
                "/check-state", headers={"Authorization": f"bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is not None

            # Test uppercase
            response = client.get(
                "/check-state", headers={"Authorization": f"BEARER {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is not None


class TestMiddlewareProtectedRoutes:
    """Test protected routes using middleware."""

    def test_protected_route_without_token(self, test_app):
        """Test that protected route rejects request without token."""
        with test_app.test_client() as client:
            response = client.get("/protected")
            assert response.status_code == 401
            data = json.loads(response.data)
            assert data["error"] == "Unauthorized"

    def test_protected_route_with_invalid_token(self, test_app):
        """Test that protected route rejects invalid token."""
        with test_app.test_client() as client:
            response = client.get(
                "/protected", headers={"Authorization": "Bearer invalid.token.here"}
            )
            assert response.status_code == 401
            data = json.loads(response.data)
            assert data["error"] == "Unauthorized"

    def test_protected_route_with_valid_token(self, test_app, test_key):
        """Test that protected route accepts valid token."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "scope": "openid profile",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/protected", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["message"] == "Protected endpoint"
            assert data["user"] == "user123"


class TestMiddlewareWhitespace:
    """Test middleware handles tokens with whitespace."""

    def test_middleware_strips_token_whitespace(self, test_app, test_key):
        """Test that middleware strips whitespace from token."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            # Token with trailing spaces
            response = client.get(
                "/check-state", headers={"Authorization": f"Bearer {token}   "}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["auth_jwt"] is not None
            assert data["auth_jwt"]["sub"] == "user123"
