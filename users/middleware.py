from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication


class SessionVersionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            jwt_authenticator = JWTAuthentication()
            response = jwt_authenticator.authenticate(request)
            if response is not None:
                request.user, request.auth = response
                token_version = request.auth.payload.get("session_version")
                if (
                    token_version is None
                    or token_version != request.user.session_version
                ):
                    print("Session has been revoked.")
                    return JsonResponse(
                        {"detail": "Session has been revoked."}, status=401
                    )
        return self.get_response(request)
