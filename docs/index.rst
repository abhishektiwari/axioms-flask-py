Welcome to axioms-flask-py documentation!
==========================================

OAuth2/OIDC authentication and authorization for Flask APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

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
* Scope-based authorization decorators
* Role-based authorization decorators
* Permission-based authorization decorators
* Flexible configuration with support for custom JWKS URLs
* Simple integration with Flask applications
* Support for both standard and namespaced claims

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

   app = Flask(__name__)
   env = DotEnv(app)

2. Create a ``.env`` file with your configuration:

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_JWKS_URL=https://your-auth.domain.com/oauth2/.well-known/jwks.json
   # OR
   AXIOMS_DOMAIN=your-auth.domain.com

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

The SDK supports the following configuration options:

* ``AXIOMS_AUDIENCE`` (required): Your resource identifier or API audience
* ``AXIOMS_JWKS_URL`` (optional): Full URL to your JWKS endpoint
* ``AXIOMS_DOMAIN`` (optional): Your auth domain

.. note::
   You must provide either ``AXIOMS_JWKS_URL`` or ``AXIOMS_DOMAIN``.

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
     - Checks if API request includes a valid bearer access token as authorization header. Performs token signature validation, expiry datetime validation, and token audience validation. Should be always the **first** decorator on the protected or private view.
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

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Documentation:

   examples
   api

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
