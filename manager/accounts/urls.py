from django.urls import path

from . import views
from .overview import overview

urlpatterns = [
    path("auth/session", views.auth_session),
    path("auth/login", views.auth_login),
    path("auth/logout", views.auth_logout),
    path("auth/password", views.auth_password),
    path("users", views.users),
    path("users/permissions", views.user_permissions),
    path("users/<int:user_id>", views.user_update),
    path("users/<int:user_id>/reset-password", views.user_reset_password),
    path("overview", overview),
]
