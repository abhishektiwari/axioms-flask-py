"""Error handling for Axioms authentication and authorization."""

from flask import jsonify


class AxiomsError(Exception):
    """Custom exception for Axioms authentication and authorization errors.

    This exception is raised when authentication or authorization checks fail,
    such as missing tokens, invalid tokens, or insufficient permissions.

    Attributes:
        error: Error details dictionary containing error code and description.
        status_code: HTTP status code to return with the error.
    """

    def __init__(self, error, status_code):
        """Initialize AxiomsError.

        Args:
            error: Dictionary containing error information with keys like
                   'error' and 'error_description'.
            status_code: HTTP status code (e.g., 401 for unauthorized, 403 for forbidden).
        """
        self.error = error
        self.status_code = status_code


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
    # Import here to avoid circular dependency
    from axioms_flask.token import get_expected_issuer

    @app.errorhandler(AxiomsError)
    def handle_axioms_error(ex):
        """Handle AxiomsError exceptions."""
        response = jsonify(ex.error)
        response.status_code = ex.status_code

        # Add WWW-Authenticate header for 401 and 403 responses
        if ex.status_code in (401, 403):
            realm = get_expected_issuer() or ""
            error_code = ex.error.get("error", "")
            error_desc = ex.error.get("error_description", "")
            response.headers["WWW-Authenticate"] = (
                f"Bearer realm='{realm}', "
                f"error='{error_code}', "
                f"error_description='{error_desc}'"
            )

        return response
