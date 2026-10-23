from django.urls import path

from . import views

urlpatterns = [
    path("auth/session", views.auth_session),
    path("auth/login", views.auth_login),
    path("auth/logout", views.auth_logout),
    path("auth/password", views.auth_password),
]
