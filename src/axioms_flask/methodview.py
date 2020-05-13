from flask.views import MethodView


class MethodView(MethodView):

    _decorators = {}

    def dispatch_request(self, *args, **kwargs):
        """Derived MethodView dispatch to allow for decorators to be
            applied to specific individual request methods - in addition
            to the standard decorator assignment.
            
            Example decorator use:
            decorators = [has_valid_access_token] # applies to all methods
            _decorators = {
                'post': [has_required_permissions("sample:create")]
            }    
        """

        view = super(MethodView, self).dispatch_request
        decorators = self._decorators.get(request.method.lower())
        if decorators:
            for decorator in decorators:
                view = decorator(view)

        return view(*args, **kwargs)
