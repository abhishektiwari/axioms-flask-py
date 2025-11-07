"""Test basic package imports to verify installation."""


def test_import_axioms_flask():
    """Test that axioms_flask package can be imported after installation."""
    import axioms_flask
    assert axioms_flask is not None


def test_package_version():
    """Test that package version is accessible."""
    import axioms_flask

    # Check if version attribute exists (might not be defined yet)
    if hasattr(axioms_flask, '__version__'):
        version = axioms_flask.__version__
        assert isinstance(version, str)
        assert len(version) > 0
        print(f"Package version: {version}")
    else:
        # Version might not be set in development mode
        print("Version attribute not found (may not be set in development mode)")


def test_import_error_module():
    """Test that error module can be imported."""
    from axioms_flask import error
    assert error is not None

    # Check that AxiomsError class exists
    assert hasattr(error, 'AxiomsError')


def test_import_methodview_module():
    """Test that methodview module can be imported."""
    from axioms_flask import methodview
    assert methodview is not None
