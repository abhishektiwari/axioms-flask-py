API Reference
=============

This page contains the full API reference for axioms-flask-py, automatically generated from the source code docstrings.

Configuration
-------------

The SDK requires the following environment variables to be configured:

=====================  ========  =========================================================================
Parameter              Required  Description
=====================  ========  =========================================================================
``AXIOMS_AUDIENCE``    Yes       Expected audience claim in the JWT token.
``AXIOMS_JWKS_URL``    No        Full URL to JWKS endpoint (e.g.,
                                 ``https://my-auth.domain.com/oauth2/.well-known/jwks.json``).
                                 If provided, this takes precedence over ``AXIOMS_DOMAIN``.
``AXIOMS_DOMAIN``      No        Axioms domain name. If ``AXIOMS_JWKS_URL`` is not provided,
                                 the JWKS URL will be constructed as:
                                 ``https://{AXIOMS_DOMAIN}/oauth2/.well-known/jwks.json``
=====================  ========  =========================================================================

.. important::

    Either ``AXIOMS_JWKS_URL`` or ``AXIOMS_DOMAIN`` must be configured for token validation.


Setting Environment Variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can set these environment variables using a ``.env`` file with Flask-DotEnv:

1. Create a ``.env`` file in your project root (see `.env.example <https://github.com/abhishektiwari/axioms-flask-py/blob/main/.env.example>`_ for reference)

2. Add your configuration:

   .. code-block:: bash

      # Required
      AXIOMS_AUDIENCE=your-api-audience-or-resource-identifier

      # Option 1: Use AXIOMS_DOMAIN
      AXIOMS_DOMAIN=your-domain.axioms.io

      # Option 2: Use AXIOMS_JWKS_URL (takes precedence)
      # AXIOMS_JWKS_URL=https://my-auth.domain.com/oauth2/.well-known/jwks.json

3. Load the environment variables in your Flask app:

   .. code-block:: python

      from flask import Flask
      from flask_dotenv import DotEnv

      app = Flask(__name__)
      env = DotEnv(app)

Alternatively, you can set environment variables directly in your application:

.. code-block:: python

   app.config['AXIOMS_AUDIENCE'] = 'your-api-audience'
   app.config['AXIOMS_JWKS_URL'] = 'https://my-auth.domain.com/oauth2/.well-known/jwks.json'


Claim Handling
--------------

The SDK checks for authorization claims (scopes, roles, permissions) in JWT tokens:

**Standard Claims (Checked First)**

- **Scopes**: Checked from the standard ``scope`` claim (space-separated string)
- **Roles**: Checked from the ``roles`` claim (array of strings)
- **Permissions**: Checked from the ``permissions`` claim (array of strings)

**Namespaced Claims (Fallback)**

If ``AXIOMS_DOMAIN`` is configured and standard claims are not found, the SDK falls back to namespaced claims:

- **Roles**: ``https://{AXIOMS_DOMAIN}/claims/roles``
- **Permissions**: ``https://{AXIOMS_DOMAIN}/claims/permissions``

This dual-claim approach ensures compatibility with both standard OAuth2/OIDC tokens and custom authorization servers that use namespaced claims.

.. seealso::

   See :doc:`examples` for complete JWT token payload examples showing both standard and namespaced claims.


Decorators
----------

The decorators module provides Flask route decorators for authentication and authorization.

.. automodule:: axioms_flask.decorators
   :members:
   :undoc-members:
   :show-inheritance:

Token Validation
----------------

The token module handles JWT token validation and verification.

.. automodule:: axioms_flask.token
   :members:
   :undoc-members:
   :show-inheritance:

Error Handling
--------------

The error module defines custom exceptions for authentication and authorization errors.

.. automodule:: axioms_flask.error
   :members:
   :undoc-members:
   :show-inheritance:

Method View
-----------

The methodview module provides an extended Flask MethodView with per-method decorator support.

.. automodule:: axioms_flask.methodview
   :members:
   :undoc-members:
   :show-inheritance:
