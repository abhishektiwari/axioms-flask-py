"""Example Flask application demonstrating axioms-flask-py usage.

QUICK START:
------------
1. Install dependencies:
   pip install axioms-flask-py

2. Set environment variables:
   export AXIOMS_AUDIENCE='your-api-audience'
   export AXIOMS_DOMAIN='your-auth.domain.com'

   Or create a .env file (copy from .env.example):
   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_DOMAIN=your-auth.domain.com

3. Run the application:
   python example_app.py

4. Test with curl:
   # Public endpoint (no authentication)
   curl http://localhost:5000/

   # Protected endpoint (requires valid JWT token)
   curl -H "Authorization: Bearer <your-token>" http://localhost:5000/api/profile

WHAT THIS EXAMPLE DEMONSTRATES:
--------------------------------
- Configure Flask application with axioms-flask-py
- Register the error handler with WWW-Authenticate headers
- Protect routes with authentication and authorization
- Scope-based authorization (OR logic - needs ANY of the scopes)
- Role-based authorization (OR logic - needs ANY of the roles)
- Permission-based authorization (different permission per HTTP method)
- Chaining decorators for AND logic (needs ALL specified claims)
- Mixed OR and AND logic for complex authorization

CONFIGURATION OPTIONS:
----------------------
The SDK supports three configuration approaches:

Option 1 - AXIOMS_DOMAIN (Simplest, recommended):
  AXIOMS_DOMAIN=your-auth.domain.com
  Automatically constructs:
  - Issuer URL: https://your-auth.domain.com
  - JWKS URL: https://your-auth.domain.com/.well-known/jwks.json

Option 2 - AXIOMS_ISS_URL (Custom issuer with path):
  AXIOMS_ISS_URL=https://your-auth.domain.com/oauth2
  Automatically constructs:
  - JWKS URL: https://your-auth.domain.com/oauth2/.well-known/jwks.json

Option 3 - AXIOMS_JWKS_URL (Non-standard JWKS endpoint):
  AXIOMS_JWKS_URL=https://your-auth.domain.com/custom/jwks.json

ENDPOINTS AVAILABLE:
--------------------
Public (no auth):
  GET  /              - Home with API documentation
  GET  /health        - Health check

Authenticated (valid token required):
  GET  /api/profile   - User profile
  GET  /api/articles  - List articles

Scope-protected (OR logic):
  GET  /api/data      - Requires: read:data OR admin
  POST /api/data      - Requires: write:data OR admin

Role-protected (OR logic):
  GET  /api/admin/users  - Requires: admin OR moderator
  POST /api/admin/users  - Requires: admin

Permission-protected (different per method):
  GET    /api/resources  - Requires: resource:read OR resource:admin
  POST   /api/resources  - Requires: resource:create OR resource:admin
  PUT    /api/resources  - Requires: resource:update OR resource:admin
  DELETE /api/resources  - Requires: resource:delete OR resource:admin

Complex (AND logic - chained decorators):
  POST /api/critical/operation  - Requires ALL: openid AND profile scopes, admin role, critical:execute permission
  POST /api/advanced/action     - Requires: (read:data OR read:all) AND editor AND (action:execute OR action:admin)

TESTING WITH DIFFERENT AUTH SERVERS:
-------------------------------------
AWS Cognito:
  export AXIOMS_AUDIENCE='your-cognito-client-id'
  export AXIOMS_DOMAIN='your-user-pool.auth.us-east-1.amazoncognito.com'

Auth0:
  export AXIOMS_AUDIENCE='https://your-api.auth0.com'
  export AXIOMS_DOMAIN='your-tenant.auth0.com'

Okta:
  export AXIOMS_AUDIENCE='api://default'
  export AXIOMS_DOMAIN='your-domain.okta.com'

Microsoft Entra (Azure AD):
  export AXIOMS_AUDIENCE='api://your-app-id'
  export AXIOMS_ISS_URL='https://login.microsoftonline.com/your-tenant-id/v2.0'
"""

import os
from flask import Flask, jsonify
from axioms_flask.error import register_axioms_error_handler
from axioms_flask.decorators import (
    has_valid_access_token,
    has_required_scopes,
    has_required_roles,
    has_required_permissions,
)

# Create Flask application
app = Flask(__name__)

# Configuration
# In production, use environment variables or .env file
app.config['AXIOMS_AUDIENCE'] = os.getenv('AXIOMS_AUDIENCE', 'your-api-audience')
app.config['AXIOMS_DOMAIN'] = os.getenv('AXIOMS_DOMAIN', 'your-auth.domain.com')

# Optional: Use explicit issuer URL if your auth server has a custom path
# app.config['AXIOMS_ISS_URL'] = os.getenv('AXIOMS_ISS_URL', 'https://your-auth.domain.com/oauth2')

# Optional: Use explicit JWKS URL for non-standard endpoints
# app.config['AXIOMS_JWKS_URL'] = os.getenv('AXIOMS_JWKS_URL', 'https://your-auth.domain.com/.well-known/jwks.json')

# Optional: Configure custom claim names (for AWS Cognito, Okta, etc.)
# app.config['AXIOMS_ROLES_CLAIMS'] = ['roles', 'cognito:groups']
# app.config['AXIOMS_PERMISSIONS_CLAIMS'] = ['permissions']
# app.config['AXIOMS_SCOPE_CLAIMS'] = ['scope', 'scp']

# Register error handler
register_axioms_error_handler(app)


# ============================================================================
# PUBLIC ENDPOINTS (No authentication required)
# ============================================================================

@app.route('/')
def home():
    """Public home endpoint."""
    return jsonify({
        'message': 'Welcome to the Axioms Flask API',
        'version': '1.0.0',
        'endpoints': {
            'public': [
                'GET /',
                'GET /health',
            ],
            'authenticated': [
                'GET /api/profile',
                'GET /api/articles',
            ],
            'scope_protected': [
                'GET /api/data',
                'POST /api/data',
            ],
            'role_protected': [
                'GET /api/admin/users',
                'POST /api/admin/users',
            ],
            'permission_protected': [
                'GET /api/resources',
                'POST /api/resources',
                'PUT /api/resources',
                'DELETE /api/resources',
            ],
        }
    })


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})


# ============================================================================
# AUTHENTICATED ENDPOINTS (Requires valid access token)
# ============================================================================

@app.route('/api/profile')
@has_valid_access_token
def profile():
    """Protected endpoint requiring any valid access token.

    Token must be valid (not expired) and have correct audience.
    No specific scopes, roles, or permissions required.
    """
    return jsonify({
        'message': 'User profile data',
        'user': 'authenticated'
    })


@app.route('/api/articles')
@has_valid_access_token
def articles():
    """Protected endpoint for reading articles.

    Requires valid authentication but no specific authorization.
    """
    return jsonify({
        'articles': [
            {'id': 1, 'title': 'Getting Started with OAuth2'},
            {'id': 2, 'title': 'JWT Best Practices'},
        ]
    })


# ============================================================================
# SCOPE-BASED AUTHORIZATION (OR logic - needs ANY of the scopes)
# ============================================================================

@app.route('/api/data', methods=['GET'])
@has_valid_access_token
@has_required_scopes(['read:data', 'admin'])
def read_data():
    """Read data endpoint requiring 'read:data' OR 'admin' scope.

    Token must contain at least one of: 'read:data' or 'admin' in scope claim.
    """
    return jsonify({
        'data': [
            {'id': 1, 'value': 'Sample data 1'},
            {'id': 2, 'value': 'Sample data 2'},
        ]
    })


@app.route('/api/data', methods=['POST'])
@has_valid_access_token
@has_required_scopes(['write:data', 'admin'])
def create_data():
    """Create data endpoint requiring 'write:data' OR 'admin' scope.

    Token must contain at least one of: 'write:data' or 'admin' in scope claim.
    """
    return jsonify({
        'message': 'Data created successfully',
        'id': 3
    })


# ============================================================================
# ROLE-BASED AUTHORIZATION (OR logic - needs ANY of the roles)
# ============================================================================

@app.route('/api/admin/users', methods=['GET'])
@has_valid_access_token
@has_required_roles(['admin', 'moderator'])
def list_users():
    """List users endpoint requiring 'admin' OR 'moderator' role.

    Token must contain at least one of: 'admin' or 'moderator' in roles claim.
    """
    return jsonify({
        'users': [
            {'id': 1, 'name': 'Alice', 'role': 'admin'},
            {'id': 2, 'name': 'Bob', 'role': 'user'},
        ]
    })


@app.route('/api/admin/users', methods=['POST'])
@has_valid_access_token
@has_required_roles(['admin'])
def create_user():
    """Create user endpoint requiring 'admin' role.

    Token must contain 'admin' in roles claim.
    """
    return jsonify({
        'message': 'User created successfully',
        'id': 3
    })


# ============================================================================
# PERMISSION-BASED AUTHORIZATION (Different permission per HTTP method)
# ============================================================================

@app.route('/api/resources', methods=['GET'])
@has_valid_access_token
@has_required_permissions(['resource:read', 'resource:admin'])
def read_resources():
    """Read resources endpoint requiring 'resource:read' OR 'resource:admin'.

    Token must contain at least one of these permissions.
    """
    return jsonify({
        'resources': [
            {'id': 1, 'name': 'Resource 1'},
            {'id': 2, 'name': 'Resource 2'},
        ]
    })


@app.route('/api/resources', methods=['POST'])
@has_valid_access_token
@has_required_permissions(['resource:create', 'resource:admin'])
def create_resource():
    """Create resource endpoint requiring 'resource:create' OR 'resource:admin'."""
    return jsonify({
        'message': 'Resource created',
        'id': 3
    })


@app.route('/api/resources', methods=['PUT'])
@has_valid_access_token
@has_required_permissions(['resource:update', 'resource:admin'])
def update_resource():
    """Update resource endpoint requiring 'resource:update' OR 'resource:admin'."""
    return jsonify({
        'message': 'Resource updated'
    })


@app.route('/api/resources', methods=['DELETE'])
@has_valid_access_token
@has_required_permissions(['resource:delete', 'resource:admin'])
def delete_resource():
    """Delete resource endpoint requiring 'resource:delete' OR 'resource:admin'."""
    return jsonify({
        'message': 'Resource deleted'
    })


# ============================================================================
# AND LOGIC - Chaining decorators (Requires ALL specified claims)
# ============================================================================

@app.route('/api/critical/operation', methods=['POST'])
@has_valid_access_token
@has_required_scopes(['openid'])
@has_required_scopes(['profile'])
@has_required_roles(['admin'])
@has_required_permissions(['critical:execute'])
def critical_operation():
    """Critical operation requiring multiple claims (AND logic).

    Token must have ALL of:
    - 'openid' scope AND 'profile' scope
    - 'admin' role
    - 'critical:execute' permission
    """
    return jsonify({
        'message': 'Critical operation executed successfully',
        'status': 'completed'
    })


# ============================================================================
# MIXED OR AND AND LOGIC
# ============================================================================

@app.route('/api/advanced/action', methods=['POST'])
@has_valid_access_token
@has_required_scopes(['read:data', 'read:all'])  # Needs read:data OR read:all
@has_required_roles(['editor'])                   # AND needs editor role
@has_required_permissions(['action:execute', 'action:admin'])  # AND execute OR admin permission
def advanced_action():
    """Advanced action with mixed OR and AND logic.

    Token must have:
    - (read:data OR read:all) scope
    - AND editor role
    - AND (action:execute OR action:admin) permission
    """
    return jsonify({
        'message': 'Advanced action completed',
        'result': 'success'
    })


# ============================================================================
# ERROR HANDLING EXAMPLES
# ============================================================================

@app.route('/api/test/no-auth')
def test_no_auth():
    """This will return 401 with WWW-Authenticate header if called with invalid/missing token."""
    # This is intentionally not decorated - for testing purposes
    return jsonify({
        'message': 'This endpoint should be protected but is not for testing'
    })


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, port=5000)
