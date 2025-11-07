"""Error handling for Axioms authentication and authorization."""


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
