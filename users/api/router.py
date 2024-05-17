from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from users.api import views

router = routers.DefaultRouter()
router.register(prefix="users", viewset=views.UserApiViewSet, basename="users")

urlpatterns = [
    path("", include(router.urls)),
    path("auth/me/", views.UserApiView.as_view()),
    path("auth/login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
