"""Read this API's bounded JSON body before CSRF's multipart handling."""
from accounts.views import api_error


class ConnectionBodyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path_info.startswith('/api/v1/connections/') and request.method == 'POST':
            if request.content_type != 'application/json':
                return api_error('invalid_request',400)
            raw = request.read(96*1024+1)
            if len(raw) > 96*1024:
                return api_error('invalid_request',400)
            request._connections_body = raw
            # CSRF never needs to parse this JSON body. Keep it available for
            # Django without changing the global limit used by legacy APIs.
            request._body = raw
        return self.get_response(request)
