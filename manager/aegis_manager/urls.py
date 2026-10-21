from django.contrib import admin
from django.urls import path, include
urlpatterns = [path("admin/", admin.site.urls), path("agent/v1/", include("control.urls"))]
