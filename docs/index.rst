Welcome to axioms-flask-py documentation!
==========================================

OAuth2/OIDC authentication and authorization for Flask APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access token issued by various authorization servers including `AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_, `Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_, `Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_, etc.

.. note::
   **Using FastAPI or Django REST Framework?** This package is specifically for Flask. For FastAPI applications, use `axioms-fastapi <https://github.com/abhishektiwari/axioms-fastapi>`_. For DRF applications, use `axioms-drf-py <https://github.com/abhishektiwari/axioms-drf-py>`_.

.. image:: https://img.shields.io/github/v/release/abhishektiwari/axioms-flask-py
   :alt: GitHub Release
   :target: https://github.com/abhishektiwari/axioms-flask-py/releases

.. image:: https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-flask-py/test.yml?label=tests
   :alt: GitHub Actions Test Workflow Status
   :target: https://github.com/abhishektiwari/axioms-flask-py/actions/workflows/test.yml

.. image:: https://img.shields.io/github/license/abhishektiwari/axioms-flask-py
   :alt: License

.. image:: https://img.shields.io/github/last-commit/abhishektiwari/axioms-flask-py
   :alt: GitHub Last Commit

.. image:: https://img.shields.io/pypi/v/axioms-flask-py
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/status/axioms-flask-py
   :alt: PyPI - Status

.. image:: https://img.shields.io/pepy/dt/axioms-flask-py?label=PyPI%20Downloads
   :alt: PyPI Downloads
   :target: https://pypi.org/project/axioms-flask-py/

.. image:: https://img.shields.io/pypi/pyversions/axioms-flask-py?logo=python&logoColor=white
   :alt: Python Versions

Features
--------

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (``iss`` claim) to prevent token substitution attacks
* Middleware support for automatic token extraction and validation on all requests
* Authorization decorators for standard claims: ``scopes``, ``roles``, and ``permissions``
* Object-level permissions for enforcing row-level security and ownership checks
* Flexible configuration with support for custom JWKS and issuer URLs
* Simple integration with Flask based Resource Server or API backends
* Support for custom claim and/or namespaced claims names to support different authorization servers

Prerequisite
------------

* Python 3.9+
* An OAuth2/OIDC client which can obtain access token after user's authentication and authorization and include obtained access token as bearer in ``Authorization`` header of all API request sent to Python/Flask application server.

Installation
------------

Install the package using pip:

.. code-block:: bash

   pip install axioms-flask-py

Quick Start
-----------

1. Configure your Flask application:

.. code-block:: python

   from flask import Flask
   from flask_dotenv import DotEnv
   from axioms_flask import setup_token_middleware, init_axioms, register_axioms_error_handler

   app = Flask(__name__)
   env = DotEnv(app)

   # Initialize Axioms
   init_axioms(app)

   # Optional: Setup middleware for automatic token validation
   # Before route handlers are called
   setup_token_middleware(app)

   # Register global error handler for Axioms errors
   register_axioms_error_handler(app)

2. Create a ``.env`` file with your configuration (see `.env.example <https://github.com/abhishektiwari/axioms-flask-py/blob/main/.env.example>`_ for reference):

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_ISS_URL=https://your-auth.domain.com  # Recommended - constructs JWKS URL

   # Explicit JWKS URL (for non-standard JWKS endpoints)
   # AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json

3. Use decorators to protect your routes:

.. code-block:: python

   from axioms_flask.decorators import has_valid_access_token, has_required_permissions

   @app.route('/api/protected')
   @has_valid_access_token
   def protected_route():
       return {'message': 'This is protected'}

   @app.route('/api/admin')
   @has_valid_access_token
   @has_required_permissions(['admin:write'])
   def admin_route():
       return {'message': 'Admin access'}

Configuration
-------------

At minimum, ``axioms-flask-py`` requires the following environment variables to be configured. For full list of configuration options, see :ref:`core-configuration`.

* ``AXIOMS_AUDIENCE`` (required): Your resource identifier or API audience
* ``AXIOMS_ISS_URL`` (optional): Full issuer URL for validating the ``iss`` claim (recommended)
* ``AXIOMS_JWKS_URL`` (optional): Full URL to your JWKS endpoint
* ``AXIOMS_DOMAIN`` (optional): Your auth domain - constructs issuer and JWKS URLs (not recommended)

**Configuration Hierarchy:**

1. ``AXIOMS_ISS_URL`` → constructs → ``AXIOMS_JWKS_URL`` (if not explicitly set)
2. ``AXIOMS_DOMAIN`` → constructs → ``AXIOMS_ISS_URL`` → ``AXIOMS_JWKS_URL`` (if not explicitly set)

.. important::
   You must provide at least one of: ``AXIOMS_ISS_URL``, ``AXIOMS_DOMAIN``, or ``AXIOMS_JWKS_URL``.

   For most use cases, setting only ``AXIOMS_ISS_URL`` is recommended. ``axioms-flask-py`` will automatically construct the JWKS endpoint URL.

Guard Your Flask API Views
---------------------------

Use the following decorators to protect your API views:

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Decorator
     - Description
     - Parameters
   * - ``has_valid_access_token``
     - Checks if API request includes a valid bearer access token as authorization header. Performs token signature validation, expiry datetime validation, token audience validation, and issuer validation (if configured). Should be always the **first** decorator on the protected or private view.
     - None
   * - ``has_required_scopes``
     - Check any of the given scopes included in ``scope`` claim of the access token. Should be after ``has_valid_access_token``.
     - An array of strings as ``conditional OR`` representing any of the allowed scopes for the view. For instance, to check ``openid`` or ``profile`` pass ``['profile', 'openid']``.
   * - ``has_required_roles``
     - Check any of the given roles included in ``roles`` claim of the access token. Should be after ``has_valid_access_token``.
     - An array of strings as ``conditional OR`` representing any of the allowed roles for the view. For instance, to check ``sample:role1`` or ``sample:role2`` pass ``['sample:role1', 'sample:role2']``.
   * - ``has_required_permissions``
     - Check any of the given permissions included in ``permissions`` claim of the access token. Should be after ``has_valid_access_token``.
     - An array of strings as ``conditional OR`` representing any of the allowed permissions for the view. For instance, to check ``sample:create`` or ``sample:update`` pass ``['sample:create', 'sample:update']``.
   * - ``check_object_ownership``
     - Enforces object-level permissions by verifying the authenticated user owns the requested object. Compares a field on the object with a claim in the JWT token. Useful for row-level security.
     - ``get_object``: Function to fetch the object; ``owner_field``: Object attribute containing owner ID (default: ``"user"``); ``claim_field``: JWT claim containing user ID (default: ``"sub"``); ``inject_as``: Optional - inject object into handler
   * - ``require_ownership``
     - Simpler ownership check when object is already fetched by route handler. Checks ownership of object passed as first argument.
     - ``owner_field``: Object attribute with owner ID (default: ``"user"``); ``claim_field``: JWT claim with user ID (default: ``"sub"``)

OR vs AND Logic
^^^^^^^^^^^^^^^

By default, authorization decorators use **OR logic** - the token must have **at least ONE** of the specified claims. To require **ALL claims (AND logic)**, chain multiple decorators.

**OR Logic (Default)** - Requires ANY of the specified claims:

.. code-block:: python

   @app.route('/api/resource')
   @has_valid_access_token
   @has_required_scopes(['read:resource', 'write:resource'])
   def resource_route():
       # User needs EITHER 'read:resource' OR 'write:resource' scope
       return {'data': 'success'}

   @app.route('/admin/users')
   @has_valid_access_token
   @has_required_roles(['admin', 'superuser'])
   def admin_route():
       # User needs EITHER 'admin' OR 'superuser' role
       return {'users': []}

**AND Logic (Chaining)** - Requires ALL of the specified claims:

.. code-block:: python

   @app.route('/api/strict')
   @has_valid_access_token
   @has_required_scopes(['read:resource'])
   @has_required_scopes(['write:resource'])
   def strict_route():
       # User needs BOTH 'read:resource' AND 'write:resource' scopes
       return {'data': 'requires both scopes'}

   @app.route('/admin/critical')
   @has_valid_access_token
   @has_required_roles(['admin'])
   @has_required_roles(['superuser'])
   def critical_route():
       # User needs BOTH 'admin' AND 'superuser' roles
       return {'message': 'requires both roles'}

**Mixed Logic** - Combine OR and AND by chaining:

.. code-block:: python

   @app.route('/api/advanced')
   @has_valid_access_token
   @has_required_scopes(['openid', 'profile'])  # Needs openid OR profile
   @has_required_roles(['editor'])               # AND must have editor role
   @has_required_permissions(['resource:read', 'resource:write'])  # AND read OR write permission
   def advanced_route():
       # User needs: (openid OR profile) AND (editor) AND (read OR write)
       return {'data': 'complex authorization'}

Safe Methods for CORS Support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All authorization decorators support a ``safe_methods`` parameter to bypass authorization checks for specific HTTP methods. This is particularly useful for **CORS preflight requests** which use the ``OPTIONS`` method.

**Default Behavior** - OPTIONS bypasses authorization:

.. code-block:: python

   @app.route('/api/resource', methods=['GET', 'OPTIONS'])
   @has_valid_access_token
   @has_required_scopes(['read:resource'])
   def resource_route():
       # OPTIONS requests bypass authentication (for CORS preflight)
       # GET requests require valid token with read:resource scope
       return {'data': 'success'}

**Custom Safe Methods** - Specify different methods:

.. code-block:: python

   @app.route('/api/resource', methods=['GET', 'HEAD'])
   @has_valid_access_token(safe_methods=['HEAD'])
   @has_required_scopes(['read:resource'], safe_methods=['HEAD'])
   def resource_route():
       # HEAD requests bypass authorization
       # GET requests require valid token with read:resource scope
       return {'data': 'success'}

**Configuration** - Set default safe methods globally:

.. code-block:: python

   # In your .env or Flask config
   AXIOMS_SAFE_METHODS = ["OPTIONS", "HEAD"]  # Default: ["OPTIONS"]

.. note::
   When using multiple decorators, ensure the ``safe_methods`` parameter is consistent across all decorators in the chain for the bypass to work correctly.

Object-Level Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^

Enforce row-level security by checking if the authenticated user owns the requested object:

.. code-block:: python

   from axioms_flask.decorators import has_valid_access_token, check_object_ownership

   def get_article(article_id):
       article = Article.query.get_or_404(article_id)
       return article

   @app.route('/articles/<int:article_id>', methods=['PATCH'])
   @has_valid_access_token
   @check_object_ownership(get_article, inject_as='article')
   def update_article(article_id, article):
       # Only owner can update - article.user must match token.sub
       article.title = request.json.get('title')
       db.session.commit()
       return {'id': article.id}

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Documentation:

   examples
   api
   core

Complete Examples
-----------------

For complete working examples, check out:

* The :doc:`examples` section in this documentation for comprehensive code examples
* The `example <https://github.com/abhishektiwari/axioms-flask-py/tree/main/example>`_ folder in the repository for a working Django project

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
