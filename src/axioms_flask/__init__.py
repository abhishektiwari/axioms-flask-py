"""Axioms Flask SDK for authentication and authorization."""

from .config import get_config, init_axioms, shutdown_axioms
from .decorators import (
    check_object_ownership,
    has_required_permissions,
    has_required_roles,
    has_required_scopes,
    has_valid_access_token,
    require_ownership,
)
from .error import AxiomsError, register_axioms_error_handler
from .methodview import MethodView
from .middleware import setup_token_middleware

# Try to get version from setuptools_scm generated file
try:
    from axioms_flask._version import version as __version__
except ImportError:
    # Version file doesn't exist yet (development mode without build)
    __version__ = "0.0.0.dev0"

__all__ = [
    "__version__",
    "AxiomsError",
    "MethodView",
    "check_object_ownership",
    "get_config",
    "has_required_permissions",
    "has_required_roles",
    "has_required_scopes",
    "has_valid_access_token",
    "init_axioms",
    "register_axioms_error_handler",
    "require_ownership",
    "setup_token_middleware",
    "shutdown_axioms",
]
