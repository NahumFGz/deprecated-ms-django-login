from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView

from users.api.views import (
    BlacklistAllTokensView,
    MyTokenObtainPairView,
    PasswordResetConfirmView,
    PasswordResetView,
    UserApiView,
    UserApiViewSet,
)

router = routers.DefaultRouter()
router.register(prefix="users", viewset=UserApiViewSet, basename="users")

urlpatterns = [
    path("", include(router.urls)),
    path("auth/me/", UserApiView.as_view()),
    path("auth/login/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path(
        "auth/password-reset-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "auth/blacklist-all-tokens/",
        BlacklistAllTokensView.as_view(),
        name="blacklist_all_tokens",
    ),
]
