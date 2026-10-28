from .sessions import validate_human_session


class HumanSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        human_api = request.path_info.startswith(("/api/v1/", "/api/v2/"))
        if human_api or request.path_info.startswith("/admin/"):
            validate_human_session(request)
        response = self.get_response(request)
        if human_api:
            response["Cache-Control"] = "no-store"
        return response
