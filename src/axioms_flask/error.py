"""Error handling for Axioms authentication and authorization."""

from axioms_core import AxiomsError, get_expected_issuer
from flask import jsonify


def register_axioms_error_handler(app):
    """Register the Axioms error handler with the Flask application.

    This convenience function registers a default error handler for
    ``AxiomsError`` exceptions. The handler returns appropriate HTTP status
    codes and includes the ``WWW-Authenticate`` header for 401 and 403 responses.

    The realm in the WWW-Authenticate header uses ``get_expected_issuer()``
    which returns ``AXIOMS_ISS_URL`` if configured, otherwise constructs it
    from ``AXIOMS_DOMAIN`` as ``https://{AXIOMS_DOMAIN}``.

    Args:
        app: Flask application instance.

    Example::

        from flask import Flask
        from axioms_flask.error import register_axioms_error_handler

        app = Flask(__name__)
        app.config['AXIOMS_AUDIENCE'] = 'your-api-audience'
        app.config['AXIOMS_DOMAIN'] = 'auth.example.com'
        register_axioms_error_handler(app)

    Note:
        - 401 responses: Authentication failure (missing/invalid token)
        - 403 responses: Authorization failure (insufficient permissions)
    """
    from .config import get_config

    @app.errorhandler(AxiomsError)
    def handle_axioms_error(ex):
        """Handle AxiomsError exceptions."""
        response = jsonify(ex.error)
        response.status_code = ex.status_code

        # Add WWW-Authenticate header for 401 and 403 responses
        if ex.status_code in (401, 403):
            config = get_config()
            realm = get_expected_issuer(config) or ""
            error_code = ex.error.get("error", "")
            error_desc = ex.error.get("error_description", "")
            response.headers["WWW-Authenticate"] = (
                f"Bearer realm='{realm}', "
                f"error='{error_code}', "
                f"error_description='{error_desc}'"
            )

        return response
