"""Extended MethodView class with per-method decorator support."""

from flask import request
from flask.views import MethodView


class MethodView(MethodView):
    """Extended Flask MethodView with method-specific decorator support.

    This class extends Flask's MethodView to allow decorators to be applied
    to specific HTTP methods (GET, POST, etc.) in addition to the standard
    class-level decorators.

    Attributes:
        _decorators: Dictionary mapping HTTP method names to lists of decorators.

    Example::

        class UserAPI(MethodView):
            decorators = [has_valid_access_token]  # applies to all methods
            _decorators = {
                'post': [has_required_permissions("user:create")],
                'delete': [has_required_permissions("user:delete")]
            }

            def get(self, user_id):
                return {'user': user_id}

            def post(self):
                return {'created': True}
    """

    _decorators = {}

    def dispatch_request(self, *args, **kwargs):
        """Dispatch request with method-specific decorators applied.

        Overrides the standard MethodView dispatch to apply any decorators
        defined in _decorators for the current HTTP method.

        Args:
            *args: Positional arguments passed to the view method.
            **kwargs: Keyword arguments passed to the view method.

        Returns:
            Response from the view method after applying decorators.
        """

        view = super(MethodView, self).dispatch_request
        decorators = self._decorators.get(request.method.lower())
        if decorators:
            for decorator in decorators:
                view = decorator(view)

        return view(*args, **kwargs)
