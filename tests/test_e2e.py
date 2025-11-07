"""End-to-end tests for axioms-flask decorators.

This module creates a Flask test application with protected routes
and verifies that authentication and authorization work correctly.
"""

import json
import time
import pytest
from flask import Flask, jsonify, Blueprint
from jwcrypto import jwk, jwt
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


# Mock JWKS response
def get_mock_jwks(key):
    """Generate mock JWKS response."""
    public_key = key.export_public(as_dict=True)
    return {
        "keys": [public_key]
    }


# Generate JWT token
def generate_jwt_token(key, claims):
    """Generate a JWT token with specified claims."""
    token = jwt.JWT(
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

    # Public API Blueprint
    public_api = Blueprint("public_api", __name__)

    @public_api.route('/public', methods=['GET'])
    def api_public():
        return jsonify({'message': 'Public endpoint - no authentication required'})

    # Private API Blueprint
    private_api = Blueprint("private_api", __name__)

    @private_api.route('/private', methods=['GET'])
    @has_valid_access_token
    @has_required_scopes(['openid', 'profile'])
    def api_private():
        return jsonify({'message': 'Private endpoint - authenticated'})

    # Role-based API Blueprint
    role_api = Blueprint("role_api", __name__)

    @role_api.route('/role', methods=['GET', 'POST', 'PATCH', 'DELETE'])
    @has_valid_access_token
    @has_required_roles(['admin', 'editor'])
    def sample_role():
        if flask_app.testing:  # Use testing flag to avoid request context issues
            method = 'GET'
        else:
            from flask import request
            method = request.method

        if method == 'POST':
            return jsonify({'message': 'Sample created.'})
        if method == 'PATCH':
            return jsonify({'message': 'Sample updated.'})
        if method == 'GET':
            return jsonify({'message': 'Sample read.'})
        if method == 'DELETE':
            return jsonify({'message': 'Sample deleted.'})

    # Permission-based API Blueprint
    permission_api = Blueprint("permission_api", __name__)

    @permission_api.route('/permission/create', methods=['POST'])
    @has_valid_access_token
    @has_required_permissions(['sample:create'])
    def sample_create():
        return jsonify({'message': 'Sample created.'})

    @permission_api.route('/permission/update', methods=['PATCH'])
    @has_valid_access_token
    @has_required_permissions(['sample:update'])
    def sample_update():
        return jsonify({'message': 'Sample updated.'})

    @permission_api.route('/permission/read', methods=['GET'])
    @has_valid_access_token
    @has_required_permissions(['sample:read'])
    def sample_read():
        return jsonify({'message': 'Sample read.'})

    @permission_api.route('/permission/delete', methods=['DELETE'])
    @has_valid_access_token
    @has_required_permissions(['sample:delete'])
    def sample_delete():
        return jsonify({'message': 'Sample deleted.'})

    # Chaining API Blueprint (AND logic tests)
    chaining_api = Blueprint("chaining_api", __name__)

    @chaining_api.route('/chaining/scopes', methods=['GET'])
    @has_valid_access_token
    @has_required_scopes(['read:resource'])
    @has_required_scopes(['write:resource'])
    def chaining_scopes():
        return jsonify({'message': 'Requires both read and write scopes'})

    @chaining_api.route('/chaining/roles', methods=['GET'])
    @has_valid_access_token
    @has_required_roles(['admin'])
    @has_required_roles(['superuser'])
    def chaining_roles():
        return jsonify({'message': 'Requires both admin and superuser roles'})

    @chaining_api.route('/chaining/permissions', methods=['GET'])
    @has_valid_access_token
    @has_required_permissions(['sample:create'])
    @has_required_permissions(['sample:delete'])
    def chaining_permissions():
        return jsonify({'message': 'Requires both create and delete permissions'})

    @chaining_api.route('/chaining/mixed', methods=['GET'])
    @has_valid_access_token
    @has_required_scopes(['openid'])
    @has_required_roles(['editor'])
    @has_required_permissions(['sample:read'])
    def chaining_mixed():
        return jsonify({'message': 'Requires scope AND role AND permission'})

    # Register blueprints
    flask_app.register_blueprint(public_api)
    flask_app.register_blueprint(private_api)
    flask_app.register_blueprint(role_api)
    flask_app.register_blueprint(permission_api)
    flask_app.register_blueprint(chaining_api)

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
    return json.dumps(get_mock_jwks(test_key)).encode('utf-8')


@pytest.fixture(autouse=True)
def mock_jwks_fetch(monkeypatch, mock_jwks_data):
    """Mock JWKS fetch to return test keys."""
    from axioms_flask import token

    class MockCacheFetcher:
        def fetch(self, url, max_age=300):
            return mock_jwks_data

    monkeypatch.setattr(token, 'CacheFetcher', MockCacheFetcher)


# Test cases
class TestPublicEndpoints:
    """Test public endpoints that don't require authentication."""

    def test_public_endpoint_no_auth(self, client):
        """Test that public endpoint is accessible without authentication."""
        response = client.get('/public')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert data['message'] == 'Public endpoint - no authentication required'


class TestAuthentication:
    """Test authentication with valid and invalid tokens."""

    def test_private_endpoint_no_token(self, client):
        """Test that private endpoint rejects requests without token."""
        response = client.get('/private')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'

    def test_private_endpoint_invalid_bearer(self, client):
        """Test that private endpoint rejects invalid bearer format."""
        response = client.get('/private', headers={'Authorization': 'InvalidBearer token'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'

    def test_private_endpoint_with_valid_token(self, client, test_key):
        """Test that private endpoint accepts valid token with required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Private endpoint - authenticated'

    def test_private_endpoint_expired_token(self, client, test_key):
        """Test that private endpoint rejects expired tokens."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'

    def test_private_endpoint_wrong_audience(self, client, test_key):
        """Test that private endpoint rejects token with wrong audience."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['wrong-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'


class TestScopeAuthorization:
    """Test scope-based authorization."""

    def test_scope_with_required_scope(self, client, test_key):
        """Test that endpoint accepts token with required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_scope_without_required_scope(self, client, test_key):
        """Test that endpoint rejects token without required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'email',  # Missing 'openid' and 'profile'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'


class TestRoleAuthorization:
    """Test role-based authorization."""

    def test_role_with_required_role(self, client, test_key):
        """Test that endpoint accepts token with required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample read.'

    def test_role_without_required_role(self, client, test_key):
        """Test that endpoint rejects token without required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['viewer'],  # Missing 'admin' or 'editor'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_role_with_namespaced_claims(self, client, test_key, app):
        """Test role checking with namespaced claims."""
        app.config['AXIOMS_DOMAIN'] = 'test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/roles': ['admin'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_role_with_expired_token(self, client, test_key):
        """Test that role endpoint rejects expired token even with valid role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # Has required role but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'


class TestPermissionAuthorization:
    """Test permission-based authorization."""

    def test_permission_create_with_valid_permission(self, client, test_key):
        """Test create endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.post('/permission/create', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample created.'

    def test_permission_create_without_permission(self, client, test_key):
        """Test create endpoint without required permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Missing 'sample:create'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.post('/permission/create', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_permission_update_with_valid_permission(self, client, test_key):
        """Test update endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:update'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.patch('/permission/update', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample updated.'

    def test_permission_read_with_valid_permission(self, client, test_key):
        """Test read endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample read.'

    def test_permission_delete_with_valid_permission(self, client, test_key):
        """Test delete endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:delete'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.delete('/permission/delete', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Sample deleted.'

    def test_permission_with_namespaced_claims(self, client, test_key, app):
        """Test permission checking with namespaced claims."""
        app.config['AXIOMS_DOMAIN'] = 'test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_permission_with_expired_token(self, client, test_key):
        """Test that permission endpoint rejects expired token even with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Has required permission but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'unauthorized_access'


class TestMultipleMethodsEndpoint:
    """Test endpoint that handles multiple HTTP methods with role authorization."""

    def test_role_endpoint_get(self, client, test_key):
        """Test GET method on role-protected endpoint."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['editor'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data


class TestChainingDecorators:
    """Test chaining decorators for AND logic."""

    def test_chaining_scopes_with_both_scopes(self, client, test_key):
        """Test chaining scopes succeeds when token has both required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'read:resource write:resource other:scope',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Requires both read and write scopes'

    def test_chaining_scopes_with_only_one_scope(self, client, test_key):
        """Test chaining scopes fails when token has only one of the required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'read:resource other:scope',  # Missing write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_scopes_with_no_scopes(self, client, test_key):
        """Test chaining scopes fails when token has neither required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'other:scope',  # Missing both read:resource and write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_roles_with_both_roles(self, client, test_key):
        """Test chaining roles succeeds when token has both required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'superuser', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/roles', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Requires both admin and superuser roles'

    def test_chaining_roles_with_only_one_role(self, client, test_key):
        """Test chaining roles fails when token has only one of the required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],  # Missing superuser
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/roles', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_permissions_with_both_permissions(self, client, test_key):
        """Test chaining permissions succeeds when token has both required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:delete', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/permissions', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Requires both create and delete permissions'

    def test_chaining_permissions_with_only_one_permission(self, client, test_key):
        """Test chaining permissions fails when token has only one of the required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],  # Missing sample:delete
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/permissions', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_mixed_with_all_claims(self, client, test_key):
        """Test mixed chaining succeeds when token has all required claims."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'roles': ['editor', 'viewer'],
            'permissions': ['sample:read', 'sample:write'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Requires scope AND role AND permission'

    def test_chaining_mixed_missing_scope(self, client, test_key):
        """Test mixed chaining fails when scope is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'profile email',  # Missing openid
            'roles': ['editor'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_mixed_missing_role(self, client, test_key):
        """Test mixed chaining fails when role is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['viewer'],  # Missing editor
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'

    def test_chaining_mixed_missing_permission(self, client, test_key):
        """Test mixed chaining fails when permission is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['editor'],
            'permissions': ['sample:write'],  # Missing sample:read
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['error'] == 'insufficient_permission'
