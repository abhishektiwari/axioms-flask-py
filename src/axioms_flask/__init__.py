"""Axioms Flask SDK for authentication and authorization."""

# Try to get version from setuptools_scm generated file
try:
    from axioms_flask._version import version as __version__
except ImportError:
    # Version file doesn't exist yet (development mode without build)
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
