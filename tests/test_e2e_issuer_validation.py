"""End-to-end tests for JWT issuer claim validation.

Tests the issuer validation feature that validates the 'iss' claim in JWT tokens
to ensure cryptographic keys belong to the expected issuer, preventing token
substitution attacks.
"""

import json
import time
import pytest
from flask import Flask, jsonify
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt
from axioms_flask.decorators import has_valid_access_token, has_required_scopes
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
class TestIssuerValidation:
    """Test issuer claim validation for token security."""

    def test_valid_token_with_matching_issuer(self, client, test_key, app):
        """Test that token with matching issuer is accepted."""
        app.config['AXIOMS_ISS_URL'] = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Private endpoint'

    def test_token_with_wrong_issuer(self, client, test_key, app):
        """Test that token with wrong issuer is rejected."""
        app.config['AXIOMS_ISS_URL'] = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://malicious-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'
        assert data['error_description'] == 'Invalid issuer'

    def test_token_without_issuer_claim_when_validation_enabled(self, client, test_key, app):
        """Test that token without issuer is rejected when validation is enabled."""
        app.config['AXIOMS_ISS_URL'] = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'
        assert data['error_description'] == 'Missing issuer claim in token'

    def test_issuer_derived_from_domain(self, client, test_key, app):
        """Test that issuer is correctly derived from AXIOMS_DOMAIN."""
        app.config['AXIOMS_DOMAIN'] = 'test-domain.com'
        # Remove AXIOMS_JWKS_URL to use domain-based construction
        del app.config['AXIOMS_JWKS_URL']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_backward_compatibility_no_issuer_validation(self, client, test_key, app):
        """Test backward compatibility: tokens without issuer work when validation not configured."""
        # Only set AXIOMS_JWKS_URL, no AXIOMS_ISS_URL or AXIOMS_DOMAIN
        app.config['AXIOMS_JWKS_URL'] = 'https://test-domain.com/.well-known/jwks.json'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Private endpoint'

    def test_issuer_with_path(self, client, test_key, app):
        """Test that issuer URL with path is correctly validated."""
        app.config['AXIOMS_ISS_URL'] = 'https://auth.example.com/oauth2'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/oauth2',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_issuer_mismatch_with_path(self, client, test_key, app):
        """Test that issuer path must match exactly."""
        app.config['AXIOMS_ISS_URL'] = 'https://auth.example.com/oauth2'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/different',  # Different path
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'
        assert data['error_description'] == 'Invalid issuer'
