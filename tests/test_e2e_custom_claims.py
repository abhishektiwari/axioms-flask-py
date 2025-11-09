"""End-to-end tests for custom claim name configuration.

Tests support for different authorization servers (AWS Cognito, Auth0, Okta, etc.)
that use non-standard claim names.
"""

import json
import time
import pytest
from flask import Flask, jsonify, Blueprint
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt
from axioms_flask.decorators import (
    has_valid_access_token,
    has_required_scopes,
    has_required_roles,
    has_required_permissions,
)
from axioms_flask.error import AxiomsError


# Generate RSA key pair for testing
def generate_test_keys():
    """Generate RSA key pair for JWT signing and verification."""
    key = jwk.JWK.generate(kty='RSA', size=2048, kid='test-key-id')
    return key


# Generate JWT token
def generate_jwt_token(key, claims):
    """Generate a JWT token with specified claims."""
    token = jwcrypto_jwt.JWT(
        header={"alg": "RS256", "kid": key.kid},
        claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()


# Create test Flask application
@pytest.fixture
def app():
    """Create Flask test application with protected routes."""
    flask_app = Flask(__name__)

    # Configuration
    flask_app.config['TESTING'] = True
    flask_app.config['AXIOMS_AUDIENCE'] = 'test-audience'
    flask_app.config['AXIOMS_JWKS_URL'] = 'https://test-domain.com/.well-known/jwks.json'

    # Error handler
    @flask_app.errorhandler(AxiomsError)
    def handle_axioms_error(error):
        return jsonify(error.error), error.status_code

    # Create test endpoints
    @flask_app.route('/private', methods=['GET'])
    @has_valid_access_token
    @has_required_scopes(['openid', 'profile'])
    def api_private():
        return jsonify({'message': 'Private endpoint'})

    @flask_app.route('/role', methods=['GET'])
    @has_valid_access_token
    @has_required_roles(['admin', 'editor'])
    def sample_role():
        return jsonify({'message': 'Sample read.'})

    @flask_app.route('/permission/read', methods=['GET'])
    @has_valid_access_token
    @has_required_permissions(['sample:read'])
    def sample_read():
        return jsonify({'message': 'Sample read.'})

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
def mock_jwks_data(test_key):
    """Generate mock JWKS data."""
    public_key = test_key.export_public(as_dict=True)
    jwks = {'keys': [public_key]}
    return json.dumps(jwks).encode('utf-8')


@pytest.fixture(autouse=True)
def mock_jwks_fetch(monkeypatch, mock_jwks_data):
    """Mock JWKS fetch to return test keys."""
    from axioms_flask import token

    class MockCacheFetcher:
        def fetch(self, url, max_age=300):
            return mock_jwks_data

    monkeypatch.setattr(token, 'CacheFetcher', MockCacheFetcher)


# Test classes
class TestCognitoClaimNames:
    """Test AWS Cognito claim name configuration."""

    def test_cognito_groups_claim(self, client, test_key, app):
        """Test role authorization with Cognito-style cognito:groups claim."""
        app.config['AXIOMS_ROLES_CLAIMS'] = ['cognito:groups', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'cognito:groups': ['admin', 'users'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample read.'

    def test_cognito_roles_claim(self, client, test_key, app):
        """Test permission authorization with Cognito-style cognito:roles claim."""
        app.config['AXIOMS_PERMISSIONS_CLAIMS'] = ['cognito:roles', 'permissions']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'cognito:roles': ['sample:read', 'sample:write'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample read.'


class TestOktaClaimNames:
    """Test Okta claim name configuration."""

    def test_okta_groups_claim(self, client, test_key, app):
        """Test role authorization with Okta-style groups claim."""
        app.config['AXIOMS_ROLES_CLAIMS'] = ['groups', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'groups': ['admin', 'developers'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200


class TestAlternateScopeClaimNames:
    """Test alternate scope claim names."""

    def test_scp_scope_claim(self, client, test_key, app):
        """Test scope authorization with alternate 'scp' claim name."""
        app.config['AXIOMS_SCOPE_CLAIMS'] = ['scp', 'scope']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scp': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200


class TestClaimPriority:
    """Test claim priority and fallback behavior."""

    def test_priority_order_first_claim_wins(self, client, test_key, app):
        """Test that claims are checked in priority order, first non-None wins."""
        app.config['AXIOMS_ROLES_CLAIMS'] = ['custom:roles', 'roles', 'groups']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'custom:roles': ['admin'],  # This should be found first
            'roles': ['viewer'],  # This should be ignored
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_fallback_to_second_claim(self, client, test_key, app):
        """Test fallback when first claim is not present."""
        app.config['AXIOMS_ROLES_CLAIMS'] = ['custom:roles', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # custom:roles not present, should use this
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_no_matching_claims_fails(self, client, test_key, app):
        """Test that request fails when none of the configured claims are present."""
        app.config['AXIOMS_ROLES_CLAIMS'] = ['custom:roles', 'special:roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # Configured claims not present
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
